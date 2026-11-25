# Applying and Extending the Pattern

The sample splits two concerns, and that split is the part worth reusing:

- **Cognito orchestrates** the flow (`DefineAuthChallenge` decides the order:
  `SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE -> issue tokens`).
- **The custom challenge performs** the second factor, here, a World ID Live
  Check signed by the backend, collected by the browser, verified server-side.

You can change *when* the factor is required, *which enrollment policy* applies
(one account per person, or several), and *how a session is re-bound* to an
account, largely independently. The sections below cover the built behavior and
the most likely extensions.

## 1. Require the Live Check for everyone (built)

| Aspect | Value |
|---|---|
| Decision (where) | `define_auth_challenge`: after `PASSWORD_VERIFIER`, always issue `CUSTOM_CHALLENGE` |
| Perform (where) | `create_auth_challenge` signs an enroll or prove request; the browser runs IDKit; `verify_auth_challenge` verifies the proof |
| Identity | a World ID `session_id` per account in the `AccountTable`: created on the first sign-in, proved on every later one (ADR-7) |

Code: `functions/triggers/app.py`. Every authenticated sign-in requires a fresh
Live Check.

## 2. Step-up only (require the factor conditionally)

Requiring a Live Check on *every* sign-in is high friction and drives third-party
verification volume. Many deployments want it only for higher-risk sign-ins or
high-value actions.

Adaptation, keep the perform side unchanged; change only the **decision** in
`define_auth_challenge`. After the password step, decide whether to issue the
`CUSTOM_CHALLENGE` or go straight to issuing tokens:

```python
elif names == EXPECTED_SEQUENCE[:2]:           # SRP_A + PASSWORD_VERIFIER passed
    if requires_human_check(event):            # your risk decision
        response["challengeName"] = "CUSTOM_CHALLENGE"
    else:
        response["issueTokens"] = True         # password was enough
```

Common inputs to `requires_human_check`: a user group or `custom:` attribute (for
example, always step up admins), a `clientMetadata` flag the client passes for a
high-value action, or a risk signal. Amazon Cognito
[threat protection](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-threat-protection.html)
supports custom authentication flows and is one source of such signals.

Two things to plan for:

- **Enrollment happens on the first stepped-up sign-in.** An account that never
  steps up never enrolls, and its first stepped-up sign-in enrolls whoever completes
  that Live Check after the password. For sensitive accounts, require the check on
  the first sign-in (or another controlled moment) so enrollment isn't deferred.
- **Test both branches**: a gated sign-in issues the challenge, and an un-gated one
  issues tokens after `PASSWORD_VERIFIER`.

Reuse: the create/verify path and both tables are untouched; only the gating
predicate is new. This also lowers cost, because the per-verification third-party
charge applies only when the check fires.

## 3. One account per person, or several (built, a stack parameter)

Choose the policy with the `EnforceUniqueEnrollment` stack parameter (ADR-8):

| Value | Enrollment request | Effect |
|---|---|---|
| `true` (default) | Uniqueness request for the enrollment action that also creates the session | One account per person. World allows each person the action once, and the backend's `enroll#` claim rejects a second account. |
| `false` | Session-only request (`IDKit.createSession`) | One person can enroll several accounts, each with its own session. |

Things to know about `true`:

- **World remembers.** After a person enrolls one account, World refuses their
  second enrollment for the same action, even if you clear the DynamoDB tables.
  Testing repeated enrollment needs a new v4 action, or `false`.
- **Where it blocks.** A second account can still be *created* (account creation
  doesn't involve World ID); it can't complete enrollment, so it can never sign in.
  To block at *creation* instead, move the Live Check into a sign-up gate (a
  PreSignUp step), a larger change that turns the check into a registration gate.
- **Assurance.** Selfie Check is a medium-assurance credential, so this adds
  resistance to one person operating many accounts rather than a strict guarantee.

## 4. Re-binding a session (account recovery)

An enrolled account's session is never replaced automatically: the account item is
written only if absent (ADR-7), because World treats linking or replacing a session
as an account-security operation. Today, re-enrolling an account is an
administrative action: delete the account's item (keyed by `sub`) from the
`AccountTable`, and the next sign-in enrolls again.

A production deployment typically needs a **verified recovery flow** instead, for
example when a user reinstalls the World ID App or loses access to it:

- Gate re-enrollment behind a separate, strong verification (for example, an
  administrator approval or an identity-proofing step), not the password alone.
- Record re-binding as an auditable event, and notify the user.
- With `EnforceUniqueEnrollment=true`, the replacement session's enrollment must use
  a request World will accept for this person. Plan this with your World ID contact
  before relying on it.

## Where each change lands

| Extension | Decision (define) | Perform (create/verify) | Identity store |
|---|---|---|---|
| Require for all (built) | always issue `CUSTOM_CHALLENGE` | enroll or prove | `AccountTable` session + nullifier claims |
| Step-up only | conditional issue vs. `issueTokens` | unchanged | unchanged |
| Enrollment policy (built) | unchanged | `EnforceUniqueEnrollment` selects the enrollment request | `enroll#` claim (one-to-one) or `session#` claim (one-to-many) |
| Re-binding / recovery | unchanged | a separate, verified recovery step | replace the `AccountTable` item deliberately |

## Testing guidance

`live-check-backend/tests/test_triggers.py` runs without AWS: DynamoDB is an
in-memory fake with conditional-put and transaction semantics, and the RP signer and
World verify call are stubbed. It keeps the *decision* (`define_auth_challenge`)
separate from the *perform* side (`create_auth_challenge`, `verify_auth_challenge`).
Keep that split when you extend the pattern:

- **Step-up:** add decision cases for gated vs. not gated, including that an
  un-gated sign-in issues tokens after `PASSWORD_VERIFIER` and a gated one issues
  `CUSTOM_CHALLENGE`.
- **Recovery:** test that a normal sign-in can never replace an enrolled session,
  and that only the recovery path does.
