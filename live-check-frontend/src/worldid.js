/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * World ID 4.0 Live Check request builder.
 *
 * CreateAuthChallenge returns the request context as Cognito public challenge
 * parameters (all strings). Two modes:
 *
 *   enroll - first sign-in for this account. Creates a World ID session:
 *            with an action, a uniqueness request that also creates the
 *            session (one account per person); without one, a session-only
 *            request (one person may enroll several accounts).
 *   prove  - returning user. Prove the session saved for this account.
 *
 * The backend decides the mode and signs the request; the browser only builds
 * it. The IDKit result is sent back to Cognito unchanged.
 */
import { IDKit, CredentialRequest } from '@worldcoin/idkit-core'

// Just under the Cognito app client's 15-minute auth session, so the proof is
// submitted before Cognito's session for this sign-in expires.
export const LIVE_CHECK_TIMEOUT_MS = 14 * 60 * 1000

const REQUIRED = ['mode', 'app_id', 'rp_id', 'environment', 'rp_nonce', 'rp_created_at', 'rp_expires_at', 'rp_signature']

/** Build the IDKit request for the challenge parameters. Resolves to an IDKitRequest. */
export function buildLiveCheckRequest (params, idkit = IDKit, credentialRequest = CredentialRequest) {
  const missing = REQUIRED.filter((key) => !params || !params[key])
  if (missing.length) {
    throw new Error(`Live Check request is missing: ${missing.join(', ')}`)
  }

  const common = {
    app_id: params.app_id,
    environment: params.environment,
    rp_context: {
      rp_id: params.rp_id,
      nonce: params.rp_nonce,
      created_at: Number(params.rp_created_at),
      expires_at: Number(params.rp_expires_at),
      signature: params.rp_signature
    }
  }
  const selfie = credentialRequest('selfie')

  if (params.mode === 'enroll') {
    // One-to-one: the backend sends the enrollment action. A uniqueness request
    // that also creates a session; World allows each person that action once.
    if (params.action) {
      return idkit.request({
        ...common,
        action: params.action,
        session_id: 'create',
        allow_legacy_proofs: false
      }).constraints(selfie)
    }
    // One-to-many: no action. A session-only request, so the same person can
    // enroll a separate session for each account.
    return idkit.createSession(common).constraints(selfie)
  }

  if (params.mode === 'prove') {
    if (!params.session_id || !params.session_id.startsWith('session_')) {
      throw new Error('Live Check is missing the saved World ID session')
    }
    return idkit.proveSession(params.session_id, common).constraints(selfie)
  }

  throw new Error(`Unknown Live Check mode: ${params.mode}`)
}

// User-facing copy for IDKit error codes (World ID IDKit error-code reference).
const MESSAGES = {
  user_rejected: 'You cancelled the Live Check in the World ID App.',
  verification_rejected: 'You cancelled the Live Check in the World ID App.',
  cancelled: 'The Live Check was cancelled.',
  timeout: 'The Live Check timed out. Sign in again to retry.',
  credential_unavailable: 'Live Check isn\'t available for your World ID. Open the World ID App and try again.',
  feature_unavailable: 'Live Check isn\'t enabled for this app yet. The app owner must ask Tools for Humanity to enable it (the World ID App calls it Selfie Check).',
  world_id_4_not_available: 'This sign-in needs World ID 4.0. Update the World ID App and try again.',
  user_presence_failed: 'The Live Check couldn\'t confirm you were present. Please try again.',
  connection_failed: 'Couldn\'t reach the World ID App. Check your connection and try again.',
  inclusion_proof_pending: 'Your World ID isn\'t ready yet. Try again in a few minutes.',
  invalid_network: 'The World ID App is on a different environment (staging or production) than this app.',
  invalid_rp_signature: 'This sign-in request couldn\'t be verified. Sign in again.',
  rp_signature_expired: 'This sign-in request expired. Sign in again.',
  timestamp_too_old: 'This sign-in request expired. Sign in again.',
  duplicate_nonce: 'This sign-in request was already used. Sign in again.',
  // Only a one-to-one enrollment (uniqueness request) can hit this: World allows
  // each person the enrollment action once, so they already enrolled an account.
  nullifier_replayed: 'This World ID is already linked to another account.',
  max_verifications_reached: 'This World ID has reached its verification limit for this app.'
}

export function liveCheckErrorMessage (code) {
  return MESSAGES[code] || `Live Check failed (${code || 'unknown error'}). Sign in again to retry.`
}
