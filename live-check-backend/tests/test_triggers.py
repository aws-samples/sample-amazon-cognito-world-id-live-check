# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
# SPDX-License-Identifier: Apache-2.0

import copy
import json

import pytest

from functions.triggers import app

SUB_A = "6d82908b-7199-4ec2-8ea1-ef0961ae12a4"
SUB_B = "0f1e2d3c-4b5a-4968-8776-655443322110"
ACTION = "livecheck-signin"
NONCE = "0xnonce"
SESSION_ID = "session_" + "ab" * 64
NULLIFIER = "0xenrollnullifier"
SESSION_NULLIFIER = "0xsessionnullifier"
NULLIFIER_TABLE = "test-nullifiers"
ACCOUNT_TABLE = "test-accounts"


# ---------------------------------------------------------------------------
# In-memory DynamoDB with the semantics the triggers rely on: conditional
# attribute_not_exists puts, and all-or-nothing TransactWriteItems.
# ---------------------------------------------------------------------------
class _ConditionalCheckFailed(Exception):
    pass


class _TransactionCanceled(Exception):
    def __init__(self, reasons):
        super().__init__("TransactionCanceled")
        self.response = {"CancellationReasons": reasons}


class FakeDynamoDB:
    KEYS = {NULLIFIER_TABLE: "nullifier", ACCOUNT_TABLE: "sub"}

    class exceptions:  # noqa: N801 - mirrors the boto3 client attribute
        ConditionalCheckFailedException = _ConditionalCheckFailed
        TransactionCanceledException = _TransactionCanceled

    def __init__(self):
        self.tables = {NULLIFIER_TABLE: {}, ACCOUNT_TABLE: {}}
        self.fail_reads = False

    def _key(self, table, item):
        return item[self.KEYS[table]]["S"]

    def _blocked(self, table, item, condition):
        return condition is not None and "attribute_not_exists" in condition and \
            self._key(table, item) in self.tables[table]

    def get_item(self, TableName, Key, ConsistentRead=False):
        if self.fail_reads:
            raise RuntimeError("table unavailable")
        item = self.tables[TableName].get(Key[self.KEYS[TableName]]["S"])
        return {"Item": copy.deepcopy(item)} if item else {}

    def put_item(self, TableName, Item, ConditionExpression=None, **_):
        if self._blocked(TableName, Item, ConditionExpression):
            raise _ConditionalCheckFailed
        self.tables[TableName][self._key(TableName, Item)] = copy.deepcopy(Item)

    def transact_write_items(self, TransactItems):
        reasons, blocked = [], False
        for entry in TransactItems:
            put = entry["Put"]
            hit = self._blocked(put["TableName"], put["Item"], put.get("ConditionExpression"))
            blocked = blocked or hit
            reasons.append({"Code": "ConditionalCheckFailed" if hit else "None"})
        if blocked:
            raise _TransactionCanceled(reasons)
        for entry in TransactItems:
            put = entry["Put"]
            self.tables[put["TableName"]][self._key(put["TableName"], put["Item"])] = copy.deepcopy(put["Item"])


@pytest.fixture
def ddb(monkeypatch):
    fake = FakeDynamoDB()
    monkeypatch.setattr(app, "_ddb", fake)
    monkeypatch.setattr(app, "NULLIFIER_TABLE", NULLIFIER_TABLE)
    monkeypatch.setattr(app, "ACCOUNT_TABLE", ACCOUNT_TABLE)
    monkeypatch.setattr(app, "ENFORCE_UNIQUE_ENROLLMENT", True)
    monkeypatch.setattr(app, "APP_ID", "app_test")
    monkeypatch.setattr(app, "RP_ID", "rp_test")
    monkeypatch.setattr(app, "WORLDID_ACTION", ACTION)
    monkeypatch.setattr(app, "WORLDID_ENV", "staging")
    return fake


def enroll_account(ddb, sub=SUB_A, session_id=SESSION_ID):
    ddb.tables[ACCOUNT_TABLE][sub] = {"sub": {"S": sub}, "session_id": {"S": session_id}}


# --- Cognito session builders ----------------------------------------------
def step(name, passed=True):
    return {"challengeName": name, "challengeResult": passed, "challengeMetadata": None}


PASSWORD_DONE = [step("SRP_A"), step("PASSWORD_VERIFIER")]


def base_event(trigger, sub=SUB_A):
    return {
        "version": "1",
        "region": "us-west-2",
        "userPoolId": "us-west-2_TESTPOOL",
        "userName": sub,
        "callerContext": {"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": "testclient"},
        "triggerSource": f"{trigger}_Authentication",
        "request": {
            "userAttributes": {"sub": sub, "email_verified": "true", "email": "user1@example.com"},
            "userNotFound": False,
        },
        "response": {},
    }


# --- World ID 4.0 proof builders (shapes from the World verify API) ---------
def enroll_proof(**overrides):
    proof = {
        "protocol_version": "4.0",
        "nonce": NONCE,
        "action": ACTION,
        "session_id": SESSION_ID,
        "environment": "staging",
        "integrity_bundle": {"version": 2},
        "responses": [{
            "identifier": "selfie",
            "issuer_schema_id": 11,
            "nullifier": NULLIFIER,
            "expires_at_min": 1788302888,
            "proof": ["0x1", "0x2", "0x3", "0x4", "0x5"],
            "signal_hash": "0x0",
            "sybil_score": 1,
        }],
    }
    proof.update(overrides)
    return proof


def prove_proof(**overrides):
    proof = {
        "protocol_version": "4.0",
        "nonce": NONCE,
        "session_id": SESSION_ID,
        "environment": "staging",
        "integrity_bundle": {"version": 2},
        "responses": [{
            "identifier": "selfie",
            "issuer_schema_id": 11,
            "session_nullifier": [SESSION_NULLIFIER, "0xactionfield"],
            "expires_at_min": 1788302888,
            "proof": ["0x1", "0x2", "0x3", "0x4", "0x5"],
            "sybil_score": 1,
        }],
    }
    proof.update(overrides)
    return proof


def session_create_proof(**overrides):
    """A createSession result: like a session proof, but the session is new."""
    return prove_proof(**{"session_id": NEW_SESSION_ID, **overrides})


NEW_SESSION_ID = "session_" + "cd" * 64


def verify_event(proof, mode, sub=SUB_A, unique="true", **private_overrides):
    event = base_event("VerifyAuthChallengeResponse", sub)
    private = {"mode": mode, "nonce": NONCE}
    if mode == "enroll":
        private["unique"] = unique
        if unique == "true":
            private["action"] = ACTION
    else:
        private["session_id"] = SESSION_ID
    private.update(private_overrides)
    event["request"]["privateChallengeParameters"] = private
    event["request"]["challengeAnswer"] = proof if isinstance(proof, str) else json.dumps(proof)
    event["response"] = {"answerCorrect": None}
    return event


@pytest.fixture
def world(monkeypatch):
    """Stub the World verify API; records calls and lets a test set the reply."""
    state = {"calls": 0, "reply": None}

    def _verify(proof):
        state["calls"] += 1
        if state["reply"] is not None:
            return state["reply"]
        body = {"success": True, "environment": "staging", "session_id": proof.get("session_id")}
        if proof.get("action"):
            body["action"] = proof["action"]
        return True, body

    monkeypatch.setattr(app, "_verify_proof_with_world", _verify)
    return state


# ===========================================================================
# DefineAuthChallenge: SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE -> tokens
# ===========================================================================
class TestDefineAuthChallenge:
    def run(self, session, lambda_context):
        event = base_event("DefineAuthChallenge")
        event["request"]["session"] = session
        return app.lambda_handler(event, lambda_context)["response"]

    def test_after_srp_a_requests_password(self, lambda_context):
        r = self.run([step("SRP_A")], lambda_context)
        assert r["challengeName"] == "PASSWORD_VERIFIER"
        assert r["issueTokens"] is False and r["failAuthentication"] is False

    def test_after_password_requests_live_check(self, lambda_context):
        r = self.run(PASSWORD_DONE, lambda_context)
        assert r["challengeName"] == "CUSTOM_CHALLENGE"
        assert r["issueTokens"] is False and r["failAuthentication"] is False

    def test_full_sequence_issues_tokens(self, lambda_context):
        r = self.run(PASSWORD_DONE + [step("CUSTOM_CHALLENGE")], lambda_context)
        assert r["issueTokens"] is True and r["failAuthentication"] is False

    def test_empty_session_is_denied_no_passwordless_entry(self, lambda_context):
        # Security regression: CUSTOM_AUTH without SRP_A must not skip the password.
        r = self.run([], lambda_context)
        assert r["failAuthentication"] is True and r["issueTokens"] is False
        assert "challengeName" not in r or r["challengeName"] is None

    def test_custom_challenge_without_password_is_denied(self, lambda_context):
        r = self.run([step("CUSTOM_CHALLENGE")], lambda_context)
        assert r["failAuthentication"] is True and r["issueTokens"] is False

    @pytest.mark.parametrize("failed_at", [0, 1, 2])
    def test_any_failed_step_is_denied(self, failed_at, lambda_context):
        session = PASSWORD_DONE + [step("CUSTOM_CHALLENGE")]
        session[failed_at] = step(session[failed_at]["challengeName"], passed=False)
        r = self.run(session, lambda_context)
        assert r["failAuthentication"] is True and r["issueTokens"] is False

    @pytest.mark.parametrize("names", [
        ["PASSWORD_VERIFIER"],
        ["SRP_A", "CUSTOM_CHALLENGE"],
        ["SRP_A", "PASSWORD_VERIFIER", "CUSTOM_CHALLENGE", "CUSTOM_CHALLENGE"],
        ["SRP_A", "PASSWORD_VERIFIER", "SMS_MFA"],
        ["NOT_A_CHALLENGE"],
    ])
    def test_unexpected_sequences_are_denied(self, names, lambda_context):
        r = self.run([step(n) for n in names], lambda_context)
        assert r["failAuthentication"] is True and r["issueTokens"] is False


# ===========================================================================
# CreateAuthChallenge: enroll (no saved session) vs prove (saved session)
# ===========================================================================
class TestCreateAuthChallenge:
    @pytest.fixture
    def signer(self, monkeypatch):
        calls = []

        def _sign(action):
            calls.append(action)
            return {"sig": "0xsig", "nonce": NONCE, "created_at": 1700000000, "expires_at": 1700000300}

        monkeypatch.setattr(app, "_sign_rp_request", _sign)
        return calls

    def run(self, lambda_context, session=PASSWORD_DONE):
        event = base_event("CreateAuthChallenge")
        event["request"]["challengeName"] = "CUSTOM_CHALLENGE"
        event["request"]["session"] = session
        return app.lambda_handler(event, lambda_context)["response"]

    def test_unenrolled_user_gets_enroll_request_signed_with_action(self, ddb, signer, lambda_context):
        r = self.run(lambda_context)
        pub, priv = r["publicChallengeParameters"], r["privateChallengeParameters"]
        assert signer == [ACTION]
        assert pub["mode"] == "enroll" and pub["action"] == ACTION
        assert "session_id" not in pub
        assert pub["app_id"] == "app_test" and pub["rp_id"] == "rp_test"
        assert pub["environment"] == "staging"
        assert pub["rp_signature"] == "0xsig" and pub["rp_nonce"] == NONCE
        assert pub["rp_created_at"] == "1700000000" and pub["rp_expires_at"] == "1700000300"
        assert priv == {"mode": "enroll", "unique": "true", "nonce": NONCE, "action": ACTION}
        assert r["challengeMetadata"] == "WORLDID_LIVE_CHECK"

    def test_unenrolled_user_one_to_many_gets_session_only_request(self, ddb, signer, monkeypatch, lambda_context):
        monkeypatch.setattr(app, "ENFORCE_UNIQUE_ENROLLMENT", False)
        r = self.run(lambda_context)
        pub, priv = r["publicChallengeParameters"], r["privateChallengeParameters"]
        assert signer == [None]  # session-only requests are signed without an action
        assert pub["mode"] == "enroll"
        assert "action" not in pub and "session_id" not in pub
        assert priv == {"mode": "enroll", "unique": "false", "nonce": NONCE}

    def test_enrolled_user_gets_session_proof_signed_without_action(self, ddb, signer, lambda_context):
        enroll_account(ddb)
        r = self.run(lambda_context)
        pub, priv = r["publicChallengeParameters"], r["privateChallengeParameters"]
        assert signer == [None]
        assert pub["mode"] == "prove" and pub["session_id"] == SESSION_ID
        assert "action" not in pub
        assert priv == {"mode": "prove", "nonce": NONCE, "session_id": SESSION_ID}

    def test_public_params_are_all_strings(self, ddb, signer, lambda_context):
        # Cognito requires string-to-string maps.
        r = self.run(lambda_context)
        for params in (r["publicChallengeParameters"], r["privateChallengeParameters"]):
            assert all(isinstance(v, str) for v in params.values())

    @pytest.mark.parametrize("session", [[], [step("SRP_A")], [step("SRP_A"), step("PASSWORD_VERIFIER", False)]])
    def test_refuses_before_password_verified(self, ddb, signer, session, lambda_context):
        with pytest.raises(app.PasswordNotVerifiedException):
            self.run(lambda_context, session=session)
        assert signer == []

    def test_account_table_error_fails_closed(self, ddb, signer, lambda_context):
        # An unreadable table must not be treated as "not enrolled".
        ddb.fail_reads = True
        with pytest.raises(RuntimeError):
            self.run(lambda_context)
        assert signer == []

    def test_signer_failure_raises(self, ddb, monkeypatch, lambda_context):
        def _boom(action):
            raise app.RpSignatureException

        monkeypatch.setattr(app, "_sign_rp_request", _boom)
        with pytest.raises(app.RpSignatureException):
            self.run(lambda_context)

    def test_sign_rp_request_omits_action_for_session(self, monkeypatch):
        payloads = []

        class _Payload:
            def read(self):
                return json.dumps({"sig": "s", "nonce": "n", "created_at": 1, "expires_at": 2}).encode()

        class _Lambda:
            def invoke(self, **kwargs):
                payloads.append(json.loads(kwargs["Payload"]))
                return {"Payload": _Payload()}

        monkeypatch.setattr(app, "_lambda", _Lambda())
        app._sign_rp_request(ACTION)
        app._sign_rp_request(None)
        assert payloads == [{"action": ACTION}, {}]


# ===========================================================================
# VerifyAuthChallengeResponse: enrollment
# ===========================================================================
class TestVerifyEnroll:
    def answer(self, event, lambda_context):
        return app.lambda_handler(event, lambda_context)["response"]["answerCorrect"]

    def test_valid_enrollment_binds_session_and_claims_nullifier(self, ddb, world, lambda_context):
        assert self.answer(verify_event(enroll_proof(), "enroll"), lambda_context) is True
        account = ddb.tables[ACCOUNT_TABLE][SUB_A]
        assert account["session_id"]["S"] == SESSION_ID
        assert account["enroll_nullifier"]["S"] == NULLIFIER
        claim = ddb.tables[NULLIFIER_TABLE][f"enroll#{NULLIFIER}"]
        assert claim["sub"]["S"] == SUB_A
        assert "expires_at" not in claim  # enrollment claims are permanent

    def test_second_account_same_person_rejected_when_enforced(self, ddb, world, lambda_context):
        assert self.answer(verify_event(enroll_proof(), "enroll", SUB_A), lambda_context) is True
        other = enroll_proof(session_id="session_" + "cd" * 64)
        assert self.answer(verify_event(other, "enroll", SUB_B), lambda_context) is False
        # Atomic: the second account was not bound either.
        assert SUB_B not in ddb.tables[ACCOUNT_TABLE]

    def test_uniqueness_proof_rejected_when_session_only_expected(self, ddb, world, lambda_context):
        # CreateAuthChallenge chose session-only; a uniqueness proof carries an action.
        assert self.answer(verify_event(enroll_proof(), "enroll", unique="false"), lambda_context) is False
        assert world["calls"] == 0

    def test_session_only_proof_rejected_when_uniqueness_expected(self, ddb, world, lambda_context):
        # A client can't downgrade one-to-one by answering with a createSession result.
        assert self.answer(verify_event(session_create_proof(), "enroll", unique="true"), lambda_context) is False
        assert world["calls"] == 0
        assert ddb.tables[ACCOUNT_TABLE] == {}

    @pytest.mark.parametrize("unique", [None, "", "yes"])
    def test_unknown_enrollment_type_rejected(self, ddb, world, unique, lambda_context):
        event = verify_event(enroll_proof(), "enroll")
        event["request"]["privateChallengeParameters"]["unique"] = unique
        assert self.answer(event, lambda_context) is False
        assert world["calls"] == 0

    def test_already_enrolled_account_is_never_rebound(self, ddb, world, lambda_context):
        enroll_account(ddb, session_id="session_" + "ee" * 64)
        assert self.answer(verify_event(enroll_proof(), "enroll"), lambda_context) is False
        assert ddb.tables[ACCOUNT_TABLE][SUB_A]["session_id"]["S"] == "session_" + "ee" * 64

    @pytest.mark.parametrize("proof", [
        enroll_proof(protocol_version="3.0"),     # legacy proofs rejected
        enroll_proof(nonce="0xother"),            # not the nonce we signed
        enroll_proof(action="other-action"),      # not the enrollment action
        enroll_proof(session_id=None),            # no session created
        enroll_proof(session_id="not-a-session"),
        enroll_proof(responses=[{"identifier": "proof_of_human", "nullifier": NULLIFIER}]),
        enroll_proof(responses=[{"identifier": "selfie"}]),  # no nullifier
    ])
    def test_local_checks_reject_without_calling_world(self, ddb, world, proof, lambda_context):
        assert self.answer(verify_event(proof, "enroll"), lambda_context) is False
        assert world["calls"] == 0
        assert ddb.tables[ACCOUNT_TABLE] == {} and ddb.tables[NULLIFIER_TABLE] == {}

    @pytest.mark.parametrize("reply", [
        (False, {}),                                                               # World rejected
        (True, {"success": True, "environment": "production"}),                    # wrong environment
        (True, {"success": True}),                                                 # environment missing
        (True, {"success": True, "environment": "staging", "session_id": "session_other"}),
        (True, {"success": True, "environment": "staging", "action": "other-action"}),
    ])
    def test_world_response_checks_reject_and_store_nothing(self, ddb, world, reply, lambda_context):
        world["reply"] = reply
        assert self.answer(verify_event(enroll_proof(), "enroll"), lambda_context) is False
        assert ddb.tables[ACCOUNT_TABLE] == {} and ddb.tables[NULLIFIER_TABLE] == {}


# ===========================================================================
# VerifyAuthChallengeResponse: one-to-many enrollment (createSession)
# ===========================================================================
class TestVerifyEnrollSessionOnly:
    def answer(self, event, lambda_context):
        return app.lambda_handler(event, lambda_context)["response"]["answerCorrect"]

    def test_session_only_enrollment_binds_session_and_claims_replay_guard(self, ddb, world, lambda_context):
        assert self.answer(verify_event(session_create_proof(), "enroll", unique="false"), lambda_context) is True
        account = ddb.tables[ACCOUNT_TABLE][SUB_A]
        assert account["session_id"]["S"] == NEW_SESSION_ID
        assert "enroll_nullifier" not in account and "action" not in account
        claim = ddb.tables[NULLIFIER_TABLE][f"session#{SESSION_NULLIFIER}"]
        assert int(claim["expires_at"]["N"]) > int(claim["created_at"]["N"])
        assert not any(k.startswith("enroll#") for k in ddb.tables[NULLIFIER_TABLE])

    def test_same_person_can_enroll_a_second_account(self, ddb, world, lambda_context):
        assert self.answer(verify_event(session_create_proof(), "enroll", SUB_A, unique="false"), lambda_context) is True
        second = session_create_proof(
            session_id="session_" + "ef" * 64,
            responses=[{"identifier": "selfie", "issuer_schema_id": 11,
                        "session_nullifier": ["0xsecondproof", "0xactionfield"]}])
        assert self.answer(verify_event(second, "enroll", SUB_B, unique="false"), lambda_context) is True
        assert {SUB_A, SUB_B} <= set(ddb.tables[ACCOUNT_TABLE])

    def test_replayed_session_creation_rejected_and_not_bound(self, ddb, world, lambda_context):
        assert self.answer(verify_event(session_create_proof(), "enroll", SUB_A, unique="false"), lambda_context) is True
        # The same createSession result replayed for another account.
        assert self.answer(verify_event(session_create_proof(), "enroll", SUB_B, unique="false"), lambda_context) is False
        assert SUB_B not in ddb.tables[ACCOUNT_TABLE]

    def test_already_enrolled_account_is_never_rebound(self, ddb, world, lambda_context):
        enroll_account(ddb, session_id="session_" + "ee" * 64)
        assert self.answer(verify_event(session_create_proof(), "enroll", unique="false"), lambda_context) is False
        assert ddb.tables[ACCOUNT_TABLE][SUB_A]["session_id"]["S"] == "session_" + "ee" * 64
        assert ddb.tables[NULLIFIER_TABLE] == {}  # transaction: no orphan replay claim

    @pytest.mark.parametrize("proof", [
        session_create_proof(session_id=None),
        session_create_proof(session_id="not-a-session"),
        session_create_proof(responses=[{"identifier": "selfie"}]),
        session_create_proof(responses=[{"identifier": "selfie", "session_nullifier": "0xnotalist"}]),
    ])
    def test_invalid_session_creation_rejected_locally(self, ddb, world, proof, lambda_context):
        assert self.answer(verify_event(proof, "enroll", unique="false"), lambda_context) is False
        assert world["calls"] == 0

    def test_world_reporting_an_action_rejected(self, ddb, world, lambda_context):
        world["reply"] = (True, {"success": True, "environment": "staging",
                                 "session_id": NEW_SESSION_ID, "action": ACTION})
        assert self.answer(verify_event(session_create_proof(), "enroll", unique="false"), lambda_context) is False
        assert ddb.tables[ACCOUNT_TABLE] == {}


# ===========================================================================
# VerifyAuthChallengeResponse: returning user (session proof)
# ===========================================================================
class TestVerifyProve:
    def answer(self, event, lambda_context):
        return app.lambda_handler(event, lambda_context)["response"]["answerCorrect"]

    def test_valid_session_proof_accepted_and_nullifier_recorded(self, ddb, world, lambda_context):
        assert self.answer(verify_event(prove_proof(), "prove"), lambda_context) is True
        claim = ddb.tables[NULLIFIER_TABLE][f"session#{SESSION_NULLIFIER}"]
        assert int(claim["expires_at"]["N"]) > int(claim["created_at"]["N"])

    def test_replayed_session_proof_rejected(self, ddb, world, lambda_context):
        assert self.answer(verify_event(prove_proof(), "prove"), lambda_context) is True
        assert self.answer(verify_event(prove_proof(), "prove"), lambda_context) is False

    def test_session_from_another_account_rejected(self, ddb, world, lambda_context):
        proof = prove_proof(session_id="session_" + "ff" * 64)
        assert self.answer(verify_event(proof, "prove"), lambda_context) is False
        assert world["calls"] == 0

    @pytest.mark.parametrize("responses", [
        [{"identifier": "selfie"}],
        [{"identifier": "selfie", "session_nullifier": "0xnotalist"}],
        [{"identifier": "selfie", "session_nullifier": [""]}],
    ])
    def test_missing_session_nullifier_rejected(self, ddb, world, responses, lambda_context):
        assert self.answer(verify_event(prove_proof(responses=responses), "prove"), lambda_context) is False
        assert world["calls"] == 0

    def test_world_rejection_records_nothing(self, ddb, world, lambda_context):
        world["reply"] = (False, {})
        assert self.answer(verify_event(prove_proof(), "prove"), lambda_context) is False
        assert ddb.tables[NULLIFIER_TABLE] == {}

    def test_proof_with_an_action_rejected(self, ddb, world, lambda_context):
        # A session proof never carries an action; a uniqueness proof is not a session proof.
        assert self.answer(verify_event(prove_proof(action=ACTION), "prove"), lambda_context) is False
        assert world["calls"] == 0


# ===========================================================================
# VerifyAuthChallengeResponse: malformed input and misc
# ===========================================================================
class TestVerifyMalformed:
    @pytest.mark.parametrize("answer", ["not json", json.dumps(["a", "list"]), json.dumps("str")])
    def test_bad_answer_rejected(self, ddb, world, answer, lambda_context):
        r = app.lambda_handler(verify_event(answer, "enroll"), lambda_context)
        assert r["response"]["answerCorrect"] is False
        assert world["calls"] == 0

    def test_unknown_mode_rejected(self, ddb, world, lambda_context):
        r = app.lambda_handler(verify_event(enroll_proof(), "bogus"), lambda_context)
        assert r["response"]["answerCorrect"] is False
        assert world["calls"] == 0

    def test_missing_private_params_rejected(self, ddb, world, lambda_context):
        event = verify_event(enroll_proof(), "enroll")
        event["request"]["privateChallengeParameters"] = {}
        assert app.lambda_handler(event, lambda_context)["response"]["answerCorrect"] is False

    def test_invalid_trigger_source_returns_none(self, lambda_context):
        assert app.lambda_handler(base_event("PreSignUp"), lambda_context) is None


# ===========================================================================
# Logging: no signatures, nonces, proofs, or World ID identifiers in logs
# ===========================================================================
class TestNoSensitiveLogging:
    def test_create_and_verify_logs_contain_no_identifiers(self, ddb, world, monkeypatch, caplog, lambda_context):
        monkeypatch.setattr(app, "_sign_rp_request", lambda action: {
            "sig": "0xSECRETSIG", "nonce": NONCE, "created_at": 1, "expires_at": 2})
        enroll_account(ddb)
        create = base_event("CreateAuthChallenge")
        create["request"]["session"] = PASSWORD_DONE
        app.lambda_handler(create, lambda_context)
        app.lambda_handler(verify_event(prove_proof(), "prove"), lambda_context)

        # Powertools binds its output stream at import time, so read the log
        # records themselves (every record, at every level) rather than stdout.
        logs = "\n".join(str(r.msg) for r in caplog.records)
        assert "'step': 'create'" in logs and "'step': 'verify'" in logs  # summaries still logged
        for value in ("0xSECRETSIG", NONCE, SESSION_ID, SESSION_NULLIFIER):
            assert value not in logs
