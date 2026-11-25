# Runbook: demo and end-to-end UI testing

This runbook covers running the **browser UI** against the deployed backend and
walking a real user through the custom-authentication flow: SRP sign-in ->
**World ID Live Check** -> tokens.

Use it to demo or test through the React app in a browser.

> [!NOTE]
> **Users are created by an administrator.** The user pool ships with
> self-registration disabled (`AllowAdminCreateUserOnly: true`, ADR-6), and the
> sample UI has no sign-up screen. Create test users with `admin-create-user` as
> shown below or in the [README](../README.md#6-create-a-test-user-and-sign-in).

> [!NOTE]
> The custom challenge is a **World ID Live Check**, so the browser is required:
> the app shows a QR code, the user scans it with the **World ID App** and completes a
> Live Check, and the returned proof is what unlocks tokens.

---

## 1. Five-minute demo

The fast path for showing the flow working. It has three beats: what the guest
sees (UI), what the backend did (CloudWatch), and the security posture. The
deeper, step-by-step version is in sections 3 to 7.

Set the shell variables the commands below use:

```bash
export REGION=us-east-1
export POOL=<CognitoUserPoolId>          # stack output
export CLIENT=<CognitoUserPoolClientId>  # stack output
export USER=user1@example.com            # a synthetic address you control

aws sts get-caller-identity              # confirm the non-prod account
```

Create the demo user (self-registration is off, ADR-6):

```bash
aws cognito-idp admin-create-user --region $REGION --user-pool-id $POOL --username $USER \
  --user-attributes Name=email,Value=$USER Name=email_verified,Value=true \
  --message-action SUPPRESS
aws cognito-idp admin-set-user-password --region $REGION --user-pool-id $POOL --username $USER \
  --password 'ChangeMe123!' --permanent
```

**Beat 1, the guest experience (UI).** Run the SPA locally (section 5) and open
`http://127.0.0.1:8080`. Sign in as `$USER`: the password is proven via SRP (never
sent), then the page shows **"Set up your Live Check"** with a QR code. Scan it with
the World ID App, complete the Live Check, and the page shows **"Welcome back"**
with the user's details. Sign out and sign in again: this time the page shows
**"Confirm it's you"**, because the user now proves the session saved at enrollment.

> Say: the password is the first factor; the Live Check proves a live person is
> present and that it's the same person who enrolled the account. The app stores a
> World ID session ID and a nullifier claim, never biometrics.

**Beat 2, what the backend did (CloudWatch).** Query the trigger function's log
group right after a sign-in:

```bash
aws logs start-query --region $REGION \
  --log-group-name /aws/lambda/<LiveCheckFunction-name> \
  --start-time $(($(date +%s) - 900)) --end-time $(date +%s) \
  --query-string 'fields @timestamp, message.step, message.mode, message.result, message.reason, message.next | filter ispresent(message.step) | sort @timestamp asc | limit 30'
# then: aws logs get-query-results --region $REGION --query-id <id>
```

Point out the ordered lines: `define` -> `PASSWORD_VERIFIER`, `define` ->
`CUSTOM_CHALLENGE`, `create` issued with `mode: enroll` (first sign-in) or
`mode: prove` (later), `verify` with `world_status: 200`, `verify` accepted, and a
final `define` with `issueTokens: true`.

> Say: the decision and verification happen server-side, and the logs show the
> outcome without any signatures, proofs, or World ID identifiers.

**Beat 3, security posture (optional).** Show that public sign-up is disabled:

```bash
# Self-registration is disabled (expect NotAuthorizedException)
aws cognito-idp sign-up --client-id $CLIENT \
  --username someone-new@example.com --password 'ChangeMe123!' --region $REGION
```

> Say: the SPA runs locally against the Cognito backend; public sign-up is off
> (admin-create only, ADR-6); the RP signing key never leaves Secrets Manager.
> Close on [PATTERNS.md](PATTERNS.md): step-up gating and the one-to-one vs
> one-to-many enrollment choice.

## 2. Components involved

The end-to-end flow, who calls whom, and the request path are documented in
[architecture.md](architecture.md) (component and flow diagrams) and
[worldid-integration.md](worldid-integration.md) (the backend seams). This runbook
does not repeat them; refer there when placing a failure.

---

## 3. Prerequisites

- The backend stack is deployed (see the main [README](../README.md)). The user
  pool client allows `ALLOW_USER_SRP_AUTH` + `ALLOW_CUSTOM_AUTH`.
- Node.js 22.13+ and npm (`live-check-frontend/.nvmrc` pins Node 22).
- The World ID app is registered for **World ID 4.0** in the Developer Portal, with
  a **v4 action** matching `WorldIdAction`, and the RP signing key is in Secrets
  Manager (see [README step 1](../README.md#1-store-the-rp-signing-key-in-secrets-manager)).
- A phone with the **World ID App** to complete the Live Check.

Grab the deployed pool/client IDs for the `.env`:

```bash
STACK=live-check-backend-stack
REGION=us-east-1

aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs" --output table
```

---

## 4. Configure the frontend

From `live-check-frontend/`, copy the example file and fill in the deploy outputs:

```bash
cp .env.example .env
```

```bash
VITE_USER_POOL_ID="us-east-1_XXXXXXXXX"
VITE_USER_POOL_CLIENT_ID="xxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Install dependencies:

```bash
npm install
```

> [!NOTE]
> If your npm registry is a locked private mirror without a public upstream,
> `npm install` fails to resolve public packages (`aws-amplify`, `react`,
> `@worldcoin/idkit-core`, etc.). For a local test you can install from public npm
> explicitly: `npm install --registry https://registry.npmjs.org/`. This bypasses
> the private mirror; confirm it's acceptable in your environment first.

---

## 5. Run the dev server

```bash
npm run dev
```

Open `http://127.0.0.1:8080`. You should see the **"Sign in to AnyCompany"** card.
The dev server binds to loopback only and fails fast if port 8080 is taken.

Confirm it's serving:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8080/
# expect: HTTP 200
```

---

## 6. Walk the flow in the browser

1. **Sign in**: enter the email and password of an admin-created user. Amplify runs
   SRP (`SRP_A` -> `PASSWORD_VERIFIER`).
2. **Set a new password** *(temporary-password users only)*: if the user was created
   without `admin-set-user-password --permanent`, the page asks for a new password
   first. The sign-in continues to the Live Check.
3. **Live Check**: the page shows a **QR code** (on mobile, an "Open the World ID App"
   link). Scan it with the **World ID App** and complete the Live Check. The page
   shows "Waiting for you to complete the Live Check in the World ID App…" for up to
   14 minutes, just under the 15-minute Cognito auth session.
   - **"Set up your Live Check"**: the account's first sign-in. This enrolls a World
     ID session for the account.
   - **"Confirm it's you"**: a later sign-in. The user proves the saved session.
4. **Signed in**: when the proof verifies, the page shows **"Welcome back"** with the
   user's email, user ID, and session times, and a **Sign out** button.

> **Re-testing tip:** once an account is enrolled, every later sign-in proves its
> session; you don't need to reset anything between runs. Two things to know:
>
> - **To re-enroll one account**, delete its item (keyed by the user's `sub`) from
>   the `AccountTable`. The next sign-in enrolls again.
> - **With `EnforceUniqueEnrollment=true`, World remembers.** World allows each person
>   the enrollment action once, so after your World ID enrolls one account, enrolling
>   a second account is refused by World itself, even if you clear the DynamoDB
>   tables. For repeated enrollment demos, create a new v4 action in the Developer
>   Portal and redeploy with it, or deploy with `EnforceUniqueEnrollment=false`.

---

## 7. Verify the result

- **In the UI:** the "Welcome back" card is the pass condition.
- **Token check (browser devtools):** Amplify stores tokens in `localStorage` under
  keys prefixed `CognitoIdentityServiceProvider.<clientId>.<username>.*`
  (`idToken`, `accessToken`, `refreshToken`).
- **Backend confirmation (CloudWatch Logs Insights):** run the query from section 1
  on the trigger function's log group. A healthy sign-in shows, in order:
  1. `define` with `next: PASSWORD_VERIFIER`
  2. `define` with `next: CUSTOM_CHALLENGE`
  3. `create` with `result: issued` and `mode: enroll` or `mode: prove`
  4. `verify` with `world_status: 200`
  5. `verify` with `result: accepted`
  6. `define` with `issueTokens: true`

  A rejected Live Check shows `verify` with `result: rejected` and a `reason`
  (see section 8).

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Page shows *"CreateAuthChallenge failed"*; no QR code | The RP signer can't sign. Its log says *"RP signing key secret must be a 32-byte hex private key"* (you stored the 40-character signer address) or it can't read the secret (different region) | Store the 64-character private key in the secret, in the stack's region. See [README step 1](../README.md#1-store-the-rp-signing-key-in-secrets-manager). The next sign-in picks it up. |
| World ID App: *"There's a problem with this request"*; page: *"This sign-in request couldn't be verified"* | `invalid_rp_signature`: the key in Secrets Manager doesn't derive the signer address registered for your RP | Store the key that matches the Portal's signer address, or rotate the signer key in the Portal and store the new key. |
| World ID App: *"Feature unavailable. Contact your World PoC to enable Selfie Check for your app"* | Live Check (shown as **Selfie Check**) isn't enabled for your Developer Portal app | Request access from Tools for Humanity. |
| Page: *"This World ID is already linked to another account."* | Expected with `EnforceUniqueEnrollment=true`: this person already enrolled another account | Sign in to that account, or see the re-testing tip in section 6. |
| World ID App: *"couldn't find the request"* | A stale or already-scanned QR code | Sign in again for a fresh QR code. |
| Live Check completes but sign-in fails | The backend rejected the proof | Find the `verify` line with `result: rejected` and look up its `reason` below. If the error is `NotAuthorizedException` instead, the 15-minute auth session expired; sign in again. |
| A parameter change (for example `EnforceUniqueEnrollment`) didn't take effect | A plain `sam deploy` read a different `samconfig.toml` environment | Check the function's environment variables, then redeploy with `sam deploy --guided`, keeping the `default` environment. |

**Rejection reasons** (`verify` log line, `reason` field):

| Reason | Meaning |
| --- | --- |
| `nonce_mismatch`, `not_world_id_4`, `action_mismatch`, `unexpected_action`, `session_not_created`, `session_mismatch`, `no_selfie_credential` | The proof doesn't match the request this challenge issued. Sign in again; if it repeats, check the frontend and backend are from the same version. |
| `world_verify_failed` | World's verify API rejected the proof; the `world_status` and `world_code` on the line before explain why. A `403` with Cloudflare `1010` means the browser User-Agent header was not sent. |
| `environment_mismatch` | `WorldIdEnvironment` doesn't match the environment the proof was made in. |
| `person_already_enrolled`, `account_already_enrolled` | One-to-one: this person already enrolled another account; or this account is already enrolled. |
| `session_proof_replayed` | The same proof was submitted twice. Sign in again. |

---

## 9. Cleanup

```bash
# Stop the dev server: Ctrl-C in its terminal.

# Remove a test user from the pool:
aws cognito-idp admin-delete-user --region "$REGION" \
  --user-pool-id "$POOL" --username "$USER"
```

Deleting a user doesn't remove its `AccountTable` item or nullifier claims; they're
removed with the stack (see the README's
[Cleanup / teardown](../README.md#cleanup--teardown)).

---

## Related

- [architecture.md](architecture.md), component, flow, and sequence diagrams plus
  the trigger deep-dive.
- [worldid-integration.md](worldid-integration.md), how the World ID Live Check
  is wired into the custom challenge (backend seams + frontend).
- [PATTERNS.md](PATTERNS.md), extending the pattern (step-up gating, one-to-one
  vs one-to-many enrollment).
