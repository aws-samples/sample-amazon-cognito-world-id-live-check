# World ID Live Check, Cognito Custom Authentication

A sample that adds a **World ID Live Check** step to an Amazon Cognito sign-in flow
using Cognito's [custom authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-challenge.html)
Lambda triggers and [World ID 4.0 session proofs](https://docs.world.org/world-id/idkit/session-proofs).

After password verification, Cognito issues a `CUSTOM_CHALLENGE` that the user must
clear before tokens are issued. That challenge is a real World ID verification:

- the backend signs a Relying Party (RP) request,
- the browser opens [IDKit](https://docs.world.org/world-id/idkit) and shows a QR code or deep link,
- the user completes the Live Check in the World ID App,
- the backend verifies the returned proof with the World ID verify API.

On a user's **first** sign-in, the Live Check **enrolls** a World ID session and
binds it to the Cognito account. On **later** sign-ins, the user **proves** that same
session, which confirms it's the same person who enrolled the account.

---

## Repository layout

```
sample-amazon-cognito-world-id-live-check/
├── live-check-backend/               # AWS SAM app: Cognito user pool + Lambda triggers
│   ├── template.yaml                   # Cognito, triggers, RP signer, account and nullifier tables
│   ├── functions/
│   │   ├── triggers/app.py             # The three Cognito triggers (Python)
│   │   └── rp_signer/index.mjs         # Node Lambda that signs the RP request (World ID signing helper)
│   └── tests/                          # pytest unit tests for the triggers
└── live-check-frontend/              # React + Vite single-page app that drives the sign-in
    ├── src/App.jsx                     # Sign-in UI: password, new password, Live Check, signed in
    ├── src/auth.js                     # Cognito sign-in (Amplify v6 auth module, CUSTOM_WITH_SRP)
    ├── src/worldid.js                  # Builds the IDKit request (enroll or prove) and maps IDKit errors
    └── vite.config.js                  # Dev server bound to 127.0.0.1:8080
```

## How the custom auth flow works

Cognito drives the flow by calling **one Python Lambda** three different ways. All
three are handled in `live-check-backend/functions/triggers/app.py`, routed by
`triggerSource`:

| Trigger | Role in this app |
| --- | --- |
| **DefineAuthChallenge** | The orchestrator. Runs after every step and decides what comes next: advance to the next challenge, issue tokens, or fail. It enforces the exact order `SRP_A -> PASSWORD_VERIFIER -> CUSTOM_CHALLENGE`. There is no passwordless entry: a sign-in that skips the password step fails. |
| **CreateAuthChallenge** | Produces the challenge. Looks up the user's saved World ID session in DynamoDB. With no saved session it issues an **enroll** request; with one it issues a **prove** request for that session. It invokes the **RP signer** Lambda to sign the request and returns what IDKit needs in `publicChallengeParameters`. |
| **VerifyAuthChallengeResponse** | Checks the answer. Requires a World ID 4.0 proof with the nonce that was signed for this challenge, forwards it unchanged to the World ID verify API, and checks the environment and session in the response. On enrollment it saves the account's `session_id` and a nullifier claim in one DynamoDB transaction; on a returning sign-in it requires the saved `session_id` and rejects a reused `session_nullifier`. |

The `EnforceUniqueEnrollment` stack parameter decides whether one person can enroll
more than one account:

| `EnforceUniqueEnrollment` | Enrollment request | Effect |
| --- | --- | --- |
| `true` (default) | Uniqueness request for the enrollment action that also creates a session (`IDKit.request` with `session_id: "create"`) | One account per person. World allows each person the action once, and the backend claims the enrollment nullifier. A second account for the same person is rejected. |
| `false` | Session-only request (`IDKit.createSession`), no action | One person can enroll several accounts, each with its own session. |

Returning sign-ins use `IDKit.proveSession` in both modes.

A second, Node.js Lambda (`functions/rp_signer/index.mjs`) exists purely to produce
the RP signature. World ID's signing helper (`@worldcoin/idkit-core/signing`)
implements the required Keccak-256 + secp256k1 EIP-191 signature; isolating it in a
Node function keeps crypto libraries out of the Python runtime. It signs uniqueness
requests with the action and session requests without one. The RP signing key
lives in **AWS Secrets Manager** and never leaves the backend.

Two Cognito parameter bags matter here:

- `publicChallengeParameters`: returned to the client. Carries the request mode,
  the World ID request context, and the signed `rp_context` the browser needs to
  open IDKit, plus the saved `session_id` when proving.
- `privateChallengeParameters`: never leaves the backend. Holds what the verify step
  must check: the mode, the signed nonce, the enrollment type, and the expected
  action or `session_id`.

See the full request/response sequence in [docs/architecture.md](docs/architecture.md)
and the deeper design notes in [docs/worldid-integration.md](docs/worldid-integration.md).

---

## Prerequisites

| Tool | Purpose | Link |
| --- | --- | --- |
| AWS account | Deploy Cognito, Lambda, DynamoDB, Secrets Manager, KMS | https://aws.amazon.com/resources/create-account/ |
| AWS credentials resolvable by boto3 | Auth + user management (see the note under step 3 — a working `aws` command isn't sufficient on its own) | https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html |
| AWS SAM CLI 1.145.0+ | Build & deploy the backend (1.145.0+ is required to use Finch; see [Installing Finch to use with the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-finch.html)) | https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html |
| A container runtime | `sam build --use-container` | Docker, **or** [Finch](https://runfinch.com/) with SAM CLI 1.145.0+ |
| Python 3.12 | Lambda runtime & tests | https://www.python.org/downloads/ |
| Node.js 22.13+ and npm | RP signer build + frontend (`live-check-frontend/.nvmrc` pins Node 22) | https://nodejs.org/en/download/ |
| A World ID Developer Portal app | Registered for **World ID 4.0**: `app_id`, `rp_id`, a **v4 action**, and the RP signing key | https://developer.worldcoin.org/ |


The versions above are what this sample was validated against. Older versions may
work, but Finch requires SAM CLI 1.145.0 or later.

> [!IMPORTANT]
> **World ID Live Check is an access-gated preview.** You must have the Live
> Check credential enabled for your Developer Portal app before the flow will
> complete. Request access from Tools for Humanity, then create the app, register
> the Relying Party for World ID 4.0, and create the v4 `action` you configure below.
>
> - The World ID App and the Developer Portal call this credential **Selfie Check**.
>   Without access, scanning the QR code shows *"Feature unavailable. Contact your
>   World PoC to enable Selfie Check for your app"* in the World ID App, and the
>   sample shows *"Live Check isn't enabled for this app yet."*
> - There is no way to confirm access before that first scan, so confirm with Tools
>   for Humanity before you deploy.
> - The stack includes a customer managed AWS KMS key, which is billed monthly until
>   you delete the stack. See [Cleanup / teardown](#cleanup--teardown).

> [!NOTE]
> **Finch users:** `sam build --use-container` needs SAM CLI 1.145.0 or later (the
> version that added Finch support) and a running Finch VM. The two failures look
> different:
>
> - On SAM CLI **older than 1.145.0**, the build fails with `Docker is unreachable.
>   Docker needs to be running to build inside a container.` even when Finch is
>   running. Upgrade SAM CLI rather than installing Docker.
> - On SAM CLI **1.145.0 or later** with the Finch VM stopped, it fails with
>   `Running AWS SAM projects locally requires Finch. Do you have Finch installed and
>   running?` Start the VM with `finch vm start` and check `finch vm status` shows
>   `Running`.
>
> As an alternative on SAM CLI older than 1.145.0, point SAM at Finch's
> Docker-compatible socket instead of installing Docker:
> `export DOCKER_HOST=unix:///Applications/Finch/lima/data/finch/sock/finch.sock`
> before `sam build`. This socket path is a Finch internal detail and may change, so
> upgrading SAM CLI is the better long-term fix.
>
> If Docker Desktop was previously installed, check `~/.docker/config.json` for stale
> entries: remove a `"credsStore": "desktop"` line (which causes
> `docker-credential-desktop not installed`) and a `"currentContext": "desktop-linux"`
> line pointing at a context that no longer exists. Also check whether
> `/var/run/docker.sock` is a dangling symlink into an empty `~/.docker/run/` directory,
> which makes SAM's Docker probe fail confusingly instead of reporting Docker as absent.

---

## Quick start

### 1. Store the RP signing key in Secrets Manager

Create the app in the World ID Developer Portal and obtain its RP signing key.
Store it as a secret, either the plaintext hex key or JSON `{"signing_key":"0x.."}`.
Use the same region for the secret, the stack, and the user pool:

```bash
aws secretsmanager create-secret --region us-east-1 \
  --name worldid/live-check/rp-signing-key \
  --secret-string '0xYOUR_RP_SIGNING_KEY'
```

Note the returned **ARN**: you'll pass it to the deploy.

> [!NOTE]
> **Store the private key, not the signer address.** The RP signing key is a
> 32-byte private key: `0x` followed by **64** hex characters. The Developer Portal
> also displays a **signer address**, `0x` followed by **40** hex characters, which
> is public and can't sign. The key must derive the signer address registered for
> your RP. Otherwise the World ID App shows *"There's a problem with this request"*
> and the sample shows *"This sign-in request couldn't be verified."*
> (`invalid_rp_signature`). For a managed RP, the Developer Portal shows the private
> key once, when you register the RP or rotate its signer key. If you store the
> address by mistake, the signer Lambda fails with *"RP signing key secret must be a
> 32-byte hex private key"*. Update the secret, and the next sign-in picks up the
> corrected value.

### 2. Install the RP signer dependencies and build

```bash
cd live-check-backend/functions/rp_signer
npm install
cd ../..
sam build --use-container
```

Expected tail:

```
Build Succeeded

Built Artifacts  : .aws-sam/build
Built Template   : .aws-sam/build/template.yaml
```

### 3. Deploy the backend

```bash
sam deploy --guided
```

You'll be prompted for these parameters:

| Prompt | What to enter |
| --- | --- |
| **Stack Name** | e.g. `live-check-backend-stack` |
| **AWS Region** | The region you created the secret in |
| **Parameter WorldIdAppId** | Your Developer Portal `app_...` id |
| **Parameter WorldIdRpId** | Your registered Relying Party `rp_...` id |
| **Parameter WorldIdAction** | The v4 enrollment action you created (default `livecheck-signin`) |
| **Parameter EnforceUniqueEnrollment** | `true` (default) for one account per person, or `false` to let one person enroll several accounts. See [How the custom auth flow works](#how-the-custom-auth-flow-works). |
| **Parameter WorldIdEnvironment** | `production`, `staging`, or `sandbox`: must match the action's environment |
| **Parameter RpSigningKeySecretArn** | ARN of the secret from step 1 |
| **Confirm changes before deploy** | `y` to review the changeset first |
| **Allow SAM CLI IAM role creation** | `Y` (the functions need execution roles) |
| **Save arguments to configuration file** | `Y` to reuse on the next deploy |
| **SAM configuration environment** | Keep `default`. This names a section in `samconfig.toml`, not the World ID environment. |

> [!NOTE]
> **Changing a parameter later:** run `sam deploy --guided` again and change only that
> answer. Don't use `sam deploy --parameter-overrides Name=value`: it replaces the saved
> overrides, so the other parameters fall back to their template defaults. If you
> saved to a `samconfig.toml` environment other than `default`, deploy it with
> `sam deploy --config-env <name>`, because a plain `sam deploy` reads `default`.

> [!NOTE]
> **`Error: Unable to locate credentials` on deploy?** The SAM CLI resolves credentials
> with boto3, which is independent of the AWS CLI, so `aws sts get-caller-identity` can
> succeed while SAM finds nothing. Verify what SAM sees with
> `python -c "import boto3; print(boto3.Session().get_credentials())"`. If it prints
> `None`, use a credential source boto3 supports, such as a `credential_process` profile,
> and pass it with `sam deploy --profile <name>`.

When it finishes, note the outputs, you'll need them for the frontend:

```
Key                 AccountTableName
Value               live-check-backend-stack-AccountTable-XXXX

Key                 CognitoUserPoolClientId
Value               XXXXXXXXXXXXXXXXXXXXXXXXXX

Key                 CognitoUserPoolId
Value               us-east-1_XXXXXXXXX

Key                 NullifierTableName
Value               live-check-backend-stack-NullifierTable-XXXX
```

### 4. Configure the frontend

Copy the example file, then edit `live-check-frontend/.env` with the deploy outputs:

```bash
cp live-check-frontend/.env.example live-check-frontend/.env
```

```bash
VITE_USER_POOL_ID="us-east-1_XXXXXXXXX"
VITE_USER_POOL_CLIENT_ID="XXXXXXXXXXXXXXXXXXXXXXXXXX"
```

The region comes from the user pool ID. The World ID request context (app id, rp id,
action, environment, signature, and saved session) is delivered to the browser by
the backend in `publicChallengeParameters`, so no World ID values go in the frontend
`.env`.

### 5. Run the frontend locally

```bash
cd live-check-frontend
npm install
npm run dev
```

Then open `http://127.0.0.1:8080`. The dev server binds to loopback only.

> This sample runs the SPA locally only. The browser talks directly to the deployed
> Cognito backend, so no frontend hosting (CloudFront/S3/Amplify) is provisioned.

### 6. Create a test user and sign in

```bash
aws cognito-idp admin-create-user --region us-east-1 \
  --user-pool-id us-east-1_XXXXXXXXX \
  --username user1@example.com \
  --temporary-password 'ChangeMe123!' \
  --user-attributes Name=email,Value=user1@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS

aws cognito-idp admin-set-user-password --region us-east-1 \
  --user-pool-id us-east-1_XXXXXXXXX \
  --username user1@example.com \
  --password 'ChangeMe123!' \
  --permanent
```

If you skip `admin-set-user-password`, the first sign-in asks the user to set a new
password before the Live Check.

Sign in with those credentials. After the password step the app shows a **World ID
QR code**. Scan it with the World ID App and complete the Live Check; Cognito issues
tokens once the proof verifies.

- **First sign-in:** the page says *"Set up your Live Check"*. This enrolls a World
  ID session for the account.
- **Later sign-ins:** the page says *"Confirm it's you"*. The user proves the
  session saved at enrollment.
- **A second account for the same person** with `EnforceUniqueEnrollment=true`: the
  enrollment is refused with *"This World ID is already linked to another account."*

---

## Cleanup / teardown

Remove everything the Quick start created, in this order. Substitute the stack
name, region, and secret ARN you used above. For the exact command syntax and
flags, see the
[SAM CLI `sam delete` reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-delete.html)
and the
[Secrets Manager](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/delete-secret.html)
delete command.

1. **Delete the backend stack** (step 3). From `live-check-backend/`, delete the
   SAM stack by the name you deployed under. This removes the Cognito user pool
   (and its users), the trigger and RP signer Lambda functions with their roles,
   the DynamoDB account and nullifier tables, and schedules the customer managed
   KMS key for deletion.

   ```bash
   sam delete --stack-name live-check-backend-stack --region us-east-1
   ```

   The frontend runs locally (`npm run dev`), so there is no frontend stack or
   hosting bucket to tear down. Just stop the dev server.

2. **Delete the RP signing key secret** (step 1). Secrets Manager schedules a
   recovery window by default; add `--force-delete-without-recovery` only if you
   are certain you will not need it back.

   ```bash
   aws secretsmanager delete-secret --region us-east-1 \
     --secret-id worldid/live-check/rp-signing-key
   ```

> [!NOTE]
> The signing key in the World ID Developer Portal is separate from the Secrets
> Manager copy. Deleting the secret does not deregister the on-chain signer or
> remove the app / Relying Party / action in the Developer Portal; do that in the
> portal if you are fully decommissioning.

---

## Running the tests

Backend (from `live-check-backend/`):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r functions/triggers/requirements.txt -r tests/requirements.txt
python -m pytest
```

The trigger tests stub the RP signer, the World ID verify call, and DynamoDB, so
they run without any network or AWS access. They cover the strict sign-in order,
enrollment in both `EnforceUniqueEnrollment` modes, returning-user session proofs,
replay and mismatch rejections, and that logs carry no signatures, nonces, proofs,
or World ID identifiers.

Frontend (from `live-check-frontend/`):

```bash
npm run test:unit
```

These tests cover how the IDKit request is built for each mode and the error
messages shown for IDKit error codes. `npm run lint` and `npm run build` run ESLint
and the production build.

---

## Verifying the flow

Testing and demoing the custom-auth flow against a deployed stack is covered by
the **runbook**: a five-minute demo script, dev-server setup, a per-step browser
walkthrough, and UI troubleshooting: [docs/RUNBOOK.md](docs/RUNBOOK.md).

---

## Documentation

- [docs/ADRs.md](docs/ADRs.md): key architectural decisions with context,
  alternatives, and consequences.
- [docs/PATTERNS.md](docs/PATTERNS.md): extending the pattern, including step-up
  gating and the one-to-one vs one-to-many enrollment choice.
- [docs/RUNBOOK.md](docs/RUNBOOK.md): a five-minute demo plus the full
  end-to-end UI testing walkthrough, dev-server setup, and troubleshooting.
- [docs/architecture.md](docs/architecture.md): components and request sequence
  (see also [docs/auth_sequence.pu](docs/auth_sequence.pu) / the rendered SVG).
- [docs/worldid-integration.md](docs/worldid-integration.md): how the World ID
  seams map onto the Cognito triggers, and the security rules that go with them.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications).

## Notes

- **Sample code, not for production.** This is a reference implementation for
  learning and demonstration, tested with synthetic data only. Review and adapt
  it, including security controls, monitoring, and error handling, before using
  it in a production environment.
- **Third-party dependency.** The World ID Live Check is a Tools for Humanity
  service (access-gated) with its own terms and pricing, separate from AWS. See
  [NOTICE](NOTICE).

## License

Apache-2.0. See [LICENSE](LICENSE) for the full license text and [NOTICE](NOTICE)
for attribution (the AWS sample this derives from and the third-party World ID
components).
