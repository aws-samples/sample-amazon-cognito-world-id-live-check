# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
# SPDX-License-Identifier: Apache-2.0

"""
Cognito custom-authentication triggers for World ID Live Check (World ID 4.0).

This module wires three Cognito Lambda triggers into a single handler:

  * DefineAuthChallenge         - enforces SRP password -> Live Check -> tokens
  * CreateAuthChallenge         - issues the World ID proof request to the client
  * VerifyAuthChallengeResponse - verifies the returned World ID proof

World ID 4.0 flow (session proofs)
----------------------------------
Each Cognito user is enrolled once and proves the same World ID session on every
later sign-in:

  * **enroll** (no session saved for this ``sub``). The request type depends on
    ENFORCE_UNIQUE_ENROLLMENT:

      - "true" (one-to-one): a uniqueness request for the enrollment action,
        ``IDKit.request({ action, session_id: "create" })``, which returns one
        uniqueness proof that also creates a session. World allows each person
        that action once, and we claim its nullifier so a second account for
        the same person is rejected.
      - "false" (one-to-many): a session-only request, ``IDKit.createSession``,
        with no action, so the same person can enroll several accounts.

    VerifyAuthChallengeResponse verifies the proof and, in one DynamoDB
    transaction, saves ``sub -> session_id`` with the matching nullifier claim.
  * **prove** (session saved): CreateAuthChallenge signs a session request with
    NO action and returns the saved ``session_id``. The browser runs
    ``IDKit.proveSession(session_id, ...)``. VerifyAuthChallengeResponse requires
    the proof's ``session_id`` to match and rejects a reused
    ``session_nullifier`` (per-proof replay protection).

Security:
  * The password is mandatory: tokens are issued only after the exact passed
    sequence SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE. There is no
    passwordless entry; without this an attacker could enroll their own World ID
    to an un-enrolled account knowing only its username.
  * The RP signing key never leaves the backend / Secrets Manager.
  * The proof is forwarded to the World verify API unchanged.
  * Legacy (World ID 3.0) proofs are rejected.
  * An enrolled session is never silently replaced (conditional writes).
  * Events, responses, proofs, signatures and World ID identifiers are not
    logged; each step logs a short outcome summary only.
"""

import json
import os
import time
import urllib.request
import urllib.error

import boto3
from aws_lambda_powertools import Logger

logger = Logger()

# --- Configuration (from environment) --------------------------------------
APP_ID = os.getenv("WORLDID_APP_ID", "")
RP_ID = os.getenv("WORLDID_RP_ID", "")
WORLDID_ACTION = os.getenv("WORLDID_ACTION", "livecheck-signin")
WORLDID_ENV = os.getenv("WORLDID_ENVIRONMENT", "staging")  # production | staging | sandbox
RP_SIGNER_FUNCTION_ARN = os.getenv("RP_SIGNER_FUNCTION_ARN", "")
NULLIFIER_TABLE = os.getenv("NULLIFIER_TABLE", "")
ACCOUNT_TABLE = os.getenv("ACCOUNT_TABLE", "")
ENFORCE_UNIQUE_ENROLLMENT = os.getenv("ENFORCE_UNIQUE_ENROLLMENT", "true").lower() == "true"
VERIFY_URL_TMPL = "https://developer.world.org/api/v4/verify/{rp_id}"

# Session replay-guard items only need to outlive the RP signature (300 s by
# default); a day is a generous margin. DynamoDB TTL removes them afterwards.
SESSION_REPLAY_TTL_SECONDS = 24 * 60 * 60

MODE_ENROLL = "enroll"
MODE_PROVE = "prove"
SELFIE_IDENTIFIER = "selfie"
EXPECTED_SEQUENCE = ["SRP_A", "PASSWORD_VERIFIER", "CUSTOM_CHALLENGE"]

_lambda = boto3.client("lambda")
_ddb = boto3.client("dynamodb")


# ---------------------------------------------------------------------------
# DefineAuthChallenge
# ---------------------------------------------------------------------------
def define_auth_challenge(event):
    """Enforce the exact sequence SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE.

    Cognito calls this after every step with the running ``session``. A client
    starts the flow with ``InitiateAuth(CUSTOM_AUTH, SRP_A)``; Cognito then
    verifies the password (PASSWORD_VERIFIER) and we issue the World ID Live
    Check (CUSTOM_CHALLENGE). Any other shape - an empty session (no password),
    a failed step, a repeated or unknown step - fails the sign-in.
    """
    session = event["request"]["session"]
    response = event["response"]
    response["issueTokens"] = False
    response["failAuthentication"] = False

    names = [step.get("challengeName") for step in session]
    all_passed = all(step.get("challengeResult") is True for step in session)

    if not session or not all_passed:
        response["failAuthentication"] = True
    elif names == EXPECTED_SEQUENCE[:1]:
        response["challengeName"] = "PASSWORD_VERIFIER"
    elif names == EXPECTED_SEQUENCE[:2]:
        response["challengeName"] = "CUSTOM_CHALLENGE"
    elif names == EXPECTED_SEQUENCE:
        response["issueTokens"] = True
    else:
        response["failAuthentication"] = True

    logger.info({"step": "define", "sequence": names, "passed": all_passed,
                 "next": response.get("challengeName"),
                 "issueTokens": response["issueTokens"],
                 "fail": response["failAuthentication"]})
    return event


def _password_verified(session):
    """True only if the session so far is a passed SRP_A + PASSWORD_VERIFIER."""
    names = [step.get("challengeName") for step in session]
    return names == EXPECTED_SEQUENCE[:2] and all(
        step.get("challengeResult") is True for step in session
    )


# ---------------------------------------------------------------------------
# CreateAuthChallenge
# ---------------------------------------------------------------------------
class RpSignatureException(Exception):
    """Raised when the RP signature could not be obtained from the signer."""


class PasswordNotVerifiedException(Exception):
    """Raised when CreateAuthChallenge runs before the password step passed."""


def create_auth_challenge(event):
    """Issue the World ID proof request: enroll a new session or prove the saved one.

    ``publicChallengeParameters`` go to the browser (everything IDKit needs);
    ``privateChallengeParameters`` stay in the backend and carry what the verify
    step must check. Any failure raises, which makes Cognito fail the sign-in.
    """
    request = event["request"]
    # Defense in depth: DefineAuthChallenge already enforces this order.
    if not _password_verified(request.get("session", [])):
        logger.error({"step": "create", "result": "rejected", "reason": "password_not_verified"})
        raise PasswordNotVerifiedException

    sub = request["userAttributes"]["sub"]
    account = _get_account(sub)

    if account is None:
        mode = MODE_ENROLL
        if ENFORCE_UNIQUE_ENROLLMENT:
            # One-to-one: a uniqueness request for the enrollment action that also
            # creates a session. World allows each person this action only once.
            rp = _sign_rp_request(WORLDID_ACTION)
            public = {"mode": mode, "action": WORLDID_ACTION}
            private = {"mode": mode, "unique": "true", "nonce": rp["nonce"], "action": WORLDID_ACTION}
        else:
            # One-to-many: a session-only request (no action), so the same person
            # can create a separate session for each account they enroll.
            rp = _sign_rp_request(None)
            public = {"mode": mode}
            private = {"mode": mode, "unique": "false", "nonce": rp["nonce"]}
    else:
        mode = MODE_PROVE
        session_id = account["session_id"]["S"]
        rp = _sign_rp_request(None)  # session proofs are signed without an action
        public = {"mode": mode, "session_id": session_id}
        private = {"mode": mode, "nonce": rp["nonce"], "session_id": session_id}

    public.update({
        "app_id": APP_ID,
        "rp_id": RP_ID,
        "environment": WORLDID_ENV,
        "rp_nonce": rp["nonce"],
        "rp_created_at": str(rp["created_at"]),
        "rp_expires_at": str(rp["expires_at"]),
        "rp_signature": rp["sig"],
    })
    event["response"]["publicChallengeParameters"] = public
    event["response"]["privateChallengeParameters"] = private
    event["response"]["challengeMetadata"] = "WORLDID_LIVE_CHECK"
    logger.info({"step": "create", "result": "issued", "mode": mode})
    return event


def _get_account(sub):
    """Return the enrolled account item for ``sub``, or None if not enrolled.

    Errors propagate (fail closed): an unreadable table must not be mistaken for
    "not enrolled", which would let a new session be bound to the account.
    """
    if not ACCOUNT_TABLE:
        raise RuntimeError("ACCOUNT_TABLE not configured")
    out = _ddb.get_item(TableName=ACCOUNT_TABLE, Key={"sub": {"S": sub}}, ConsistentRead=True)
    return out.get("Item")


def _sign_rp_request(action):
    """Invoke the Node signer Lambda for an RP signature.

    ``action`` is the enrollment action for a uniqueness request, or None for a
    session proof (World ID 4.0 signs session requests without an action).
    """
    payload = {"action": action} if action else {}
    try:
        resp = _lambda.invoke(
            FunctionName=RP_SIGNER_FUNCTION_ARN,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        body = json.loads(resp["Payload"].read().decode("utf-8"))
        if resp.get("FunctionError") or "sig" not in body:
            logger.error({"step": "create", "result": "rejected", "reason": "rp_signer_failed",
                          "functionError": resp.get("FunctionError")})
            raise RpSignatureException
        return body
    except RpSignatureException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error({"step": "create", "result": "rejected", "reason": "rp_signer_invoke_error",
                      "error": type(exc).__name__})
        raise RpSignatureException from exc


# ---------------------------------------------------------------------------
# VerifyAuthChallengeResponse
# ---------------------------------------------------------------------------
def verify_auth_challenge(event):
    """Verify the World ID 4.0 proof for the mode chosen in CreateAuthChallenge.

    Never raises: any failure leaves ``answerCorrect = False`` so Cognito fails
    the sign-in cleanly.
    """
    event["response"]["answerCorrect"] = False
    request = event["request"]
    private = request.get("privateChallengeParameters") or {}
    mode = private.get("mode")

    def reject(reason):
        logger.warning({"step": "verify", "result": "rejected", "mode": mode, "reason": reason})
        return event

    try:
        proof = json.loads(request["challengeAnswer"])
    except (KeyError, TypeError, ValueError):
        return reject("answer_not_json")
    if not isinstance(proof, dict):
        return reject("answer_not_object")

    # Cheap local checks first, so an obviously wrong proof never reaches World.
    if proof.get("protocol_version") != "4.0":
        return reject("not_world_id_4")
    if not private.get("nonce") or proof.get("nonce") != private["nonce"]:
        return reject("nonce_mismatch")
    item = _selfie_response(proof)
    if item is None:
        return reject("no_selfie_credential")

    # The enrollment type was fixed by CreateAuthChallenge (private parameters),
    # so a client can't downgrade a one-to-one deployment by sending a
    # session-only proof, or the reverse.
    unique = private.get("unique")
    nullifier = session_nullifier = None
    expected_action = None  # session requests carry no action

    if mode == MODE_ENROLL:
        if unique not in ("true", "false"):
            return reject("unknown_enrollment_type")
        session_id = proof.get("session_id")
        if not isinstance(session_id, str) or not session_id.startswith("session_"):
            return reject("session_not_created")
        if unique == "true":
            # Uniqueness request that also created the session.
            expected_action = private.get("action")
            if not expected_action or proof.get("action") != expected_action:
                return reject("action_mismatch")
            nullifier = item.get("nullifier")
            if not isinstance(nullifier, str) or not nullifier:
                return reject("missing_nullifier")
        else:
            # Session-only creation (createSession): no action, per-proof nullifier.
            if proof.get("action") is not None:
                return reject("unexpected_action")
            session_nullifier = _session_nullifier(item)
            if session_nullifier is None:
                return reject("missing_session_nullifier")
    elif mode == MODE_PROVE:
        session_id = private.get("session_id")
        if not session_id or proof.get("session_id") != session_id:
            return reject("session_mismatch")
        if proof.get("action") is not None:
            return reject("unexpected_action")
        session_nullifier = _session_nullifier(item)
        if session_nullifier is None:
            return reject("missing_session_nullifier")
    else:
        return reject("unknown_mode")

    ok, world = _verify_proof_with_world(proof)
    if not ok:
        return reject("world_verify_failed")
    if world.get("environment") != WORLDID_ENV:
        return reject("environment_mismatch")
    if world.get("session_id") is not None and world["session_id"] != session_id:
        return reject("world_session_mismatch")
    if world.get("action") is not None and world["action"] != expected_action:
        return reject("world_action_mismatch")

    sub = request["userAttributes"]["sub"]
    if mode == MODE_ENROLL:
        stored, reason = _enroll(sub, session_id, enroll_nullifier=nullifier,
                                 action=expected_action, session_nullifier=session_nullifier)
    else:
        stored, reason = _claim_session_nullifier(session_nullifier)
    if not stored:
        return reject(reason)

    event["response"]["answerCorrect"] = True
    logger.info({"step": "verify", "result": "accepted", "mode": mode,
                 "uniqueEnrollment": unique == "true" if mode == MODE_ENROLL else None,
                 "sybil_score": item.get("sybil_score")})
    return event


def _selfie_response(proof):
    """Return the Selfie Check credential response item from a 4.0 proof, or None."""
    for item in proof.get("responses") or []:
        if isinstance(item, dict) and item.get("identifier") == SELFIE_IDENTIFIER:
            return item
    return None


def _session_nullifier(item):
    """Return the per-proof nullifier from a session response item, or None.

    World ID returns ``session_nullifier`` as the tuple ``[nullifier, action]``.
    """
    value = item.get("session_nullifier")
    if isinstance(value, list) and len(value) == 2 and isinstance(value[0], str) and value[0]:
        return value[0]
    return None


def _enroll(sub, session_id, *, enroll_nullifier=None, action=None, session_nullifier=None):
    """Atomically bind ``sub -> session_id`` together with one nullifier claim.

    * One-to-one (``enroll_nullifier``): claim ``enroll#<nullifier>`` permanently,
      so a person who already enrolled another account is rejected.
    * One-to-many (``session_nullifier``): claim ``session#<nullifier>`` with a
      TTL, the same per-proof replay guard used for returning users.

    Returns (stored, reason). Both writes are conditional and in one transaction,
    so an enrolled account is never re-bound, even under concurrent attempts.
    """
    if not ACCOUNT_TABLE or not NULLIFIER_TABLE:
        return False, "tables_not_configured"
    if bool(enroll_nullifier) == bool(session_nullifier):
        return False, "enroll_claim_invalid"
    now = int(time.time())
    account = {
        "sub": {"S": sub},
        "session_id": {"S": session_id},
        "enrolled_at": {"N": str(now)},
    }
    if enroll_nullifier:
        account["enroll_nullifier"] = {"S": enroll_nullifier}
        account["action"] = {"S": action}
        claim = {
            "nullifier": {"S": f"enroll#{enroll_nullifier}"},
            "sub": {"S": sub},
            "action": {"S": action},
            "created_at": {"N": str(now)},
        }
        claim_conflict = "person_already_enrolled"
    else:
        claim = {
            "nullifier": {"S": f"session#{session_nullifier}"},
            "created_at": {"N": str(now)},
            "expires_at": {"N": str(now + SESSION_REPLAY_TTL_SECONDS)},
        }
        claim_conflict = "session_proof_replayed"
    items = [
        {"Put": {
            "TableName": ACCOUNT_TABLE,
            "Item": account,
            "ConditionExpression": "attribute_not_exists(#k)",
            "ExpressionAttributeNames": {"#k": "sub"},
        }},
        {"Put": {
            "TableName": NULLIFIER_TABLE,
            "Item": claim,
            "ConditionExpression": "attribute_not_exists(nullifier)",
        }},
    ]
    try:
        _ddb.transact_write_items(TransactItems=items)
        return True, None
    except _ddb.exceptions.TransactionCanceledException as exc:
        codes = [r.get("Code") for r in exc.response.get("CancellationReasons", [])]
        if len(codes) > 0 and codes[0] == "ConditionalCheckFailed":
            return False, "account_already_enrolled"
        if len(codes) > 1 and codes[1] == "ConditionalCheckFailed":
            return False, claim_conflict
        return False, "enroll_transaction_canceled"
    except Exception as exc:  # noqa: BLE001
        logger.error({"step": "verify", "reason": "enroll_write_error", "error": type(exc).__name__})
        return False, "enroll_write_error"


def _claim_session_nullifier(session_nullifier):
    """Record a session proof's nullifier once; a second claim is a replay."""
    if not NULLIFIER_TABLE:
        return False, "tables_not_configured"
    now = int(time.time())
    try:
        _ddb.put_item(
            TableName=NULLIFIER_TABLE,
            Item={
                "nullifier": {"S": f"session#{session_nullifier}"},
                "created_at": {"N": str(now)},
                "expires_at": {"N": str(now + SESSION_REPLAY_TTL_SECONDS)},
            },
            ConditionExpression="attribute_not_exists(nullifier)",
        )
        return True, None
    except _ddb.exceptions.ConditionalCheckFailedException:
        return False, "session_proof_replayed"
    except Exception as exc:  # noqa: BLE001
        logger.error({"step": "verify", "reason": "session_write_error", "error": type(exc).__name__})
        return False, "session_write_error"


def _verify_proof_with_world(proof):
    """POST the IDKit proof as-is to the World verify API.

    Returns ``(ok, body)``: ``ok`` is True only on a 200 with ``success == True``.
    Only the outcome code/detail is logged - never the proof or identifiers.
    """
    url = VERIFY_URL_TMPL.format(rp_id=RP_ID)
    # Scheme guard (Bandit B310 / CWE-939): VERIFY_URL_TMPL is a hardcoded https
    # constant and RP_ID is deployment config, not end-user input, so this URL is
    # not attacker controlled. We still assert the scheme so urllib can only ever
    # open an https endpoint and never a local file:// or ftp:// target.
    if not url.startswith("https://"):
        raise ValueError("World verify URL must use https")
    req = urllib.request.Request(
        url,
        data=json.dumps(proof).encode("utf-8"),
        # A browser-like User-Agent is REQUIRED: developer.world.org sits behind
        # Cloudflare, which blocks the default ``Python-urllib/x.y`` agent with a
        # 403 (Cloudflare error 1010) before the request ever reaches the World
        # verifier. Send a normal UA + Accept so the proof actually gets verified.
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:  # nosec B310 - scheme guarded to https above; URL is a hardcoded constant, not user input
            body = json.loads(r.read().decode("utf-8"))
            ok = r.status == 200 and body.get("success") is True
            logger.info({"step": "verify", "world_status": r.status, "world_success": body.get("success"),
                         "world_environment": body.get("environment")})
            return ok, body
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace"))
        except ValueError:
            detail = {}
        logger.warning({"step": "verify", "world_status": exc.code,
                        "world_code": detail.get("code"), "world_detail": detail.get("detail")})
        return False, {}
    except Exception as exc:  # noqa: BLE001
        logger.error({"step": "verify", "reason": "world_request_error", "error": type(exc).__name__})
        return False, {}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
@logger.inject_lambda_context(log_event=False)
def lambda_handler(event, context):
    """Route the Cognito trigger to the matching handler.

    Neither the event nor the response is logged: they carry the RP signature,
    nonce, private challenge parameters, the proof, and World ID identifiers.
    """
    handlers = {
        "DefineAuthChallenge": define_auth_challenge,
        "CreateAuthChallenge": create_auth_challenge,
        "VerifyAuthChallengeResponse": verify_auth_challenge,
    }
    trigger_source = event["triggerSource"].split("_")[0]
    handler = handlers.get(trigger_source)
    if not handler:
        logger.error({"reason": "invalid_trigger_source", "triggerSource": event.get("triggerSource")})
        return None

    logger.append_keys(handler_name=handler.__name__)
    return handler(event)
