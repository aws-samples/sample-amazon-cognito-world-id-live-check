# Architectural Decision Records

Decisions taken while building the World ID Live Check custom-authentication
sample. Each record captures the context, the decision, the alternatives
considered, and the consequences.

| # | Decision | Status |
|---|---|---|
| ADR-1 | Cognito custom auth (CUSTOM_AUTH) for the second factor | Accepted |
| ADR-2 | Use a World ID Live Check (proof of a live person) as that factor | Accepted |
| ADR-3 | Isolate RP request signing in a Node Lambda; key in Secrets Manager | Accepted |
| ADR-4 | Treat the nullifier as a returning-user identity key | Superseded by ADR-7 |
| ADR-5 | Send a browser User-Agent on the verify call (Cloudflare) | Accepted |
| ADR-6 | Disable self-registration at pool creation (`AllowAdminCreateUserOnly`) | Accepted |
| ADR-7 | Use World ID 4.0 session proofs for returning-user continuity | Accepted |
| ADR-8 | Let `EnforceUniqueEnrollment` choose the enrollment request type | Accepted |

---

## ADR-1, Cognito CUSTOM_AUTH for the second factor

**Context.** We need to add a strong second factor to an Amazon Cognito sign-in
flow without replacing the existing password/SRP primary authentication or
migrating users.

**Decision.** Use Cognito's **custom authentication flow**: the
Define/Create/Verify auth-challenge Lambda triggers, to run the second factor
after password verification. `DefineAuthChallenge` accepts only the exact passed
sequence `SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE`. There is no
passwordless entry: a `CUSTOM_AUTH` start without `SRP_A` fails, because it would
let someone who knows only a username start the Live Check and enroll their own
World ID to an account that hasn't enrolled yet.

**Alternatives considered.**
- **Cognito built-in MFA (SMS/TOTP).** Rejected: built-in MFA proves possession
  of a device, not that a live person is present, and it is a pool-wide setting
  rather than a place to plug in an arbitrary factor.
- **A bespoke auth service outside Cognito.** Rejected: duplicates the challenge
  lifecycle and token issuance Cognito already provides, and adds a component the
  customer must own.

**Consequences.**
- (+) Additive to an existing pool: three Lambda triggers, no user migration.
- (+) The Define/Create/Verify shape is reusable for other factors/flows.
- (-) Custom auth is more code than built-in MFA and requires a client that
  speaks the CUSTOM_AUTH flow with SRP (here, the Amplify v6 auth module's
  `signIn` with `authFlowType: 'CUSTOM_WITH_SRP'`). It isn't available with managed
  login or federated sign-in.

---

## ADR-2, World ID Live Check as the custom factor

**Context.** The custom challenge can be anything. The engagement goal is to add
**proof that a live person is signing in**: resistance to bots, deepfakes, and
duplicate accounts, ideally without the relying party handling biometrics or PII.

**Decision.** Make the `CUSTOM_CHALLENGE` a **World ID Live Check**. The client
collects a proof via IDKit (QR -> World ID App -> Live Check); the backend verifies
it and stores only a World ID `session_id` per account and nullifier claims. No
face, name, or other identity data is ever seen by the relying party.

**Alternatives considered.**
- **Email/SMS OTP.** Rejected for this sample: proves possession of an inbox/
  phone, not personhood; farmable by bots at scale.
- **Document/ID upload.** Rejected: collects PII and biometrics, creating exactly
  the data-liability this design avoids.

**Consequences.**
- (+) Proof that a live person is present, with no PII/biometrics stored (privacy
  by architecture).
- (-) Requires the World ID App on a phone (heavier UX than an OTP tap) and depends
  on a third-party, access-gated service (Tools for Humanity) with its own terms
  and pricing.
- (-) Live Check (Selfie Check) is a **medium-assurance** credential: it adds
  resistance to one person operating many accounts, not a strict
  one-person-one-account guarantee.

---

## ADR-3, Isolate RP request signing in a Node Lambda; key in Secrets Manager

**Context.** Every World ID proof request must be signed with the Relying Party
signing key to prove it came from our app. The signing algorithm is World ID's
(Keccak-256 + secp256k1 EIP-191), implemented in `@worldcoin/idkit-core/signing`
(JavaScript). The trigger logic is Python.

**Decision.** Put signing in a **separate Node.js Lambda** (`functions/rp_signer/
index.mjs`) that `CreateAuthChallenge` invokes. It signs uniqueness requests with
the action and session requests without one, as World ID 4.0 requires. The **RP
signing key lives in AWS Secrets Manager**, is read only by this signer, and is
never logged or returned to the client. The signer checks the value is a 32-byte
hex private key (not the 40-character signer address the Developer Portal
displays) and caches it only after that check passes.

**Alternatives considered.**
- **Reimplement signing in Python.** Rejected: re-implementing World ID's signing
  scheme risks subtle incompatibility with the verifier; using the maintained
  official helper is safer.
- **Sign in the browser.** Rejected outright: leaking the signing key lets anyone
  forge proof requests for our app. Signing must stay server-side.

**Consequences.**
- (+) Uses the canonical signing implementation; no crypto libraries in the
  Python runtime; key isolated behind least-privilege (`secretsmanager:
  GetSecretValue` on one secret).
- (+) A wrong secret fails with a clear message, and a corrected secret is picked
  up on the next sign-in without a redeploy.
- (-) A second Lambda and a cross-Lambda invoke per sign-in. The signer caches the
  validated key to avoid a Secrets Manager call on every warm invocation.

---

## ADR-4, Nullifier as a returning-user identity key

**Status.** Superseded by ADR-7.

**Original decision.** With the legacy (World ID 3.0) Live Check proof, the
nullifier was stable per (identity, action), so the first version of this sample
treated it as a durable identity key: a first sighting enrolled the person, and a
repeat sighting was a returning user and was allowed.

**Why it was superseded.** In World ID 4.0, nullifiers are **one-time-use**: a
uniqueness request lets each person complete an action once, and World guides
relying parties not to carry a nullifier over as a persistent user identifier. The
stable link across sign-ins is now the session (ADR-7).

---

## ADR-5, Send a browser User-Agent on the World verify call

**Context.** `VerifyAuthChallengeResponse` POSTs the proof to
`https://developer.world.org/api/v4/verify/{rp_id}`. That host is fronted by
Cloudflare.

**Decision.** Send a normal browser-like `User-Agent` (and `Accept: application/
json`) header on the verify request.

**Alternatives considered.**
- **Default Python `urllib` request (no UA override).** Rejected: Cloudflare
  blocks the default `Python-urllib/x.y` agent with **HTTP 403 / error 1010**
  before the request reaches the World verifier, a valid proof fails, surfacing
  as a failed sign-in. Confirmed by direct test (default UA -> 403; browser UA ->
  the request reaches World and returns a real validation result).

**Consequences.**
- (+) Verify requests reach the World verifier reliably.
- (-) A pragmatic dependency on an edge (WAF) behavior. Documented in the code
  comment and the [RUNBOOK.md](RUNBOOK.md) troubleshooting table so it is not
  mistaken for cosmetic.

---

## ADR-6, Disable self-registration at pool creation

**Context.** For compliance, public self-service sign-up must be disabled; only an
administrator may create users.

**Decision.** Create the user pool with `AdminCreateUserConfig.
AllowAdminCreateUserOnly: true`. Users are created via `admin-create-user`; the
Cognito `SignUp` API is rejected with "SignUp is not permitted for this user pool",
and the sample UI has no sign-up screen. Admin-created users with a temporary
password set a new password on first sign-in, then complete the World ID
`CUSTOM_CHALLENGE`.

**Alternatives considered.**
- **Allow self-registration (`false`).** Rejected for the compliance posture; it
  is the right setting for open sign-up demos but not here.

**Consequences.**
- (+) Meets the compliance requirement; account creation is an administrative,
  auditable action.
- (-) CloudFormation does not reliably update this property in place after
  creation. If you change it, confirm the live value with
  `aws cognito-idp describe-user-pool` and reconcile with `update-user-pool` if it
  diverges.

---

## ADR-7, World ID 4.0 session proofs for returning-user continuity

**Context.** A sign-in factor must work on every sign-in, and it should confirm the
person signing in is the same person who enrolled the account. In World ID 4.0,
uniqueness nullifiers are one-time-use (ADR-4), and World's recommended flow for
repeated Selfie Check verification is a **session**: create it once, then prove it
on later checks.

**Decision.** On an account's first sign-in, the Live Check **creates a World ID
session**, and `VerifyAuthChallengeResponse` saves its `session_id` against the
account in a DynamoDB `AccountTable` (`sub -> session_id`), written only if the
account isn't already enrolled. On every later sign-in, `CreateAuthChallenge` sends
the saved `session_id`, the browser calls `IDKit.proveSession`, and the backend
requires the proof's `session_id` to match. Each accepted proof's
`session_nullifier` is claimed once in the `NullifierTable` (with a TTL) as a replay
guard. Legacy (3.0) proofs are rejected.

**Alternatives considered.**
- **Keep legacy proofs (`allow_legacy_proofs: true`).** Rejected: it keeps the
  sample on World's migration path rather than World ID 4.0, and sessions don't
  support legacy proofs.
- **A uniqueness request on every sign-in.** Rejected: World allows each person a
  uniqueness action once, so the second sign-in would be refused.
- **Store `session_id` as a Cognito custom attribute instead of DynamoDB.**
  Rejected: one-to-one enrollment needs an atomic "does another account already
  own this nullifier?" check across all users, which user attributes can't
  enforce, and an attribute can't be written conditionally to prevent silently
  re-binding a session. A separate table also keeps the World ID data decoupled from
  the user pool, so it can be reused outside Cognito.

**Consequences.**
- (+) Follows World ID 4.0 guidance; every sign-in confirms continuity with the
  enrolling person.
- (+) An enrolled session is never silently replaced; re-binding is a deliberate
  operation (delete the account's `AccountTable` item).
- (-) Two DynamoDB tables and a transactional write at enrollment.
- (-) The saved `session_id` is sent to the browser (after the password step),
  because IDKit proves the session client-side.

---

## ADR-8, `EnforceUniqueEnrollment` chooses the enrollment request type

**Context.** Some applications allow one account per person; others let a person
hold several accounts (for example, personal and work). A session alone doesn't
prevent the same person from enrolling more than once; a uniqueness request does,
but World allows it only once per person per action.

**Decision.** The `EnforceUniqueEnrollment` stack parameter decides which request
enrollment uses:
- **`true` (default, one-to-one):** a uniqueness request for the enrollment action
  that also creates the session (`IDKit.request({ action, session_id: "create" })`).
  The backend claims the enrollment nullifier as `enroll#<nullifier>` in the same
  transaction as the account item, so a second account for the same person is
  rejected.
- **`false` (one-to-many):** a session-only request (`IDKit.createSession`, no
  action), so the same person can enroll a separate session for each account.

`CreateAuthChallenge` records the type in `privateChallengeParameters`, and
`VerifyAuthChallengeResponse` enforces that type rather than inferring it from the
proof.

**Alternatives considered.**
- **Always use the uniqueness request and only toggle the backend's nullifier
  check.** Rejected after end-to-end testing: with the check off, World itself
  refused the second account's enrollment, because the person had already used the
  action.
- **Infer the enrollment type from the proof.** Rejected: a client could downgrade
  a one-to-one deployment by answering with a session-only result.

**Consequences.**
- (+) One parameter selects the policy, and each mode uses the request type World
  intends for it.
- (-) With `true`, World remembers each person per action: clearing the DynamoDB
  tables doesn't let the same person enroll a second account. Repeated enrollment
  demos need a new v4 action, or `false`.
