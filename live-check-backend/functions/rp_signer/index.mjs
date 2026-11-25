/**
 * World ID RP-signature signer (SKILL Step 3).
 *
 * The Cognito CreateAuthChallenge trigger (Python) invokes this Node Lambda to
 * produce an RP signature for a World ID proof request. Signing MUST happen on
 * the backend: the signing key authenticates our app to the World ID protocol,
 * and leaking it lets anyone forge proof requests for our app.
 *
 * The RP signing key is read from AWS Secrets Manager (never from the client,
 * never logged). The secret's plaintext value is the hex signing key returned
 * once by the Developer Portal `configure_world_id` step.
 *
 * Input event:  { "action": "<action-id>" }  -> uniqueness request (enrollment)
 *               {}                          -> session proof (returning user);
 *               World ID 4.0 session proofs are signed WITHOUT an action.
 * Output:       { "sig": "0x..", "nonce": "0x..", "created_at": <int>, "expires_at": <int> }
 */
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager'
import { signRequest } from '@worldcoin/idkit-core/signing'

const SECRET_ARN = process.env.RP_SIGNING_KEY_SECRET_ARN
const sm = new SecretsManagerClient({})

let cachedKey // reuse across warm invocations

// A World ID RP signing key is a 32-byte secp256k1 private key (64 hex chars).
// A 20-byte (40 hex char) value is the signer *address* the Developer Portal
// displays, not the key.
const SIGNING_KEY_PATTERN = /^(0x)?[0-9a-fA-F]{64}$/

async function getSigningKey () {
  if (cachedKey) return cachedKey
  const out = await sm.send(new GetSecretValueCommand({ SecretId: SECRET_ARN }))
  // Store the raw hex key as the secret string. If stored as JSON
  // ({"signing_key":"0x.."}), unwrap it here.
  const raw = (out.SecretString ?? '').trim()
  const key = raw.startsWith('{') ? String(JSON.parse(raw).signing_key ?? '').trim() : raw
  if (!SIGNING_KEY_PATTERN.test(key)) {
    // Never log the value; its length is enough to diagnose an address mix-up.
    throw new Error(
      `RP signing key secret must be a 32-byte hex private key (64 hex chars); got ${key.replace(/^0x/, '').length} hex chars. ` +
      'A 40-char value is the signer address, not the key.'
    )
  }
  // Cache only a key that passed validation, so a corrected secret is picked up
  // on the next call without a redeploy.
  cachedKey = key
  return cachedKey
}

export const handler = async (event) => {
  const action = event?.action
  // action is optional: present for the enrollment uniqueness request, absent
  // for session proofs. If present it must be a non-empty string.
  if (action !== undefined && (typeof action !== 'string' || action.length === 0 || action.length > 128)) {
    throw new Error('invalid action')
  }

  const signingKeyHex = await getSigningKey()
  const { sig, nonce, createdAt, expiresAt } = signRequest(
    action ? { signingKeyHex, action } : { signingKeyHex }
  )

  // Do NOT log sig/nonce/key. Return only what CreateAuthChallenge needs.
  return { sig, nonce, created_at: createdAt, expires_at: expiresAt }
}
