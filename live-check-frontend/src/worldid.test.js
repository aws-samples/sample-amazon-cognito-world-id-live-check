/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, expect, it } from 'vitest'
import { CredentialRequest, IDKit } from '@worldcoin/idkit-core'
import { LIVE_CHECK_TIMEOUT_MS, buildLiveCheckRequest, liveCheckErrorMessage } from './worldid.js'

const SESSION_ID = 'session_' + 'ab'.repeat(64)

// Public challenge parameters as CreateAuthChallenge returns them (all strings).
function params (overrides = {}) {
  return {
    mode: 'enroll',
    action: 'livecheck-signin',
    app_id: 'app_test',
    rp_id: 'rp_test',
    environment: 'staging',
    rp_nonce: '0xnonce',
    rp_created_at: '1700000000',
    rp_expires_at: '1700000300',
    rp_signature: '0xsig',
    ...overrides
  }
}

// Records how the builder drives IDKit without touching the network.
function fakeIDKit () {
  const calls = []
  const builder = (kind, args) => ({
    constraints: (constraint) => {
      calls.push({ kind, args, constraint })
      return Promise.resolve({ connectorURI: 'https://world.org/verify?t=x' })
    }
  })
  return {
    calls,
    request: (config) => builder('request', [config]),
    createSession: (config) => builder('createSession', [config]),
    proveSession: (sessionId, config) => builder('proveSession', [sessionId, config])
  }
}

const RP_CONTEXT = { rp_id: 'rp_test', nonce: '0xnonce', created_at: 1700000000, expires_at: 1700000300, signature: '0xsig' }

describe('buildLiveCheckRequest', () => {
  it('enroll: uniqueness request that creates a session, v4 only, Selfie credential', async () => {
    const idkit = fakeIDKit()
    const request = await buildLiveCheckRequest(params(), idkit)
    expect(request.connectorURI).toMatch(/^https:/)
    expect(idkit.calls).toHaveLength(1)
    const [{ kind, args: [config], constraint }] = idkit.calls
    expect(kind).toBe('request')
    expect(config).toEqual({
      app_id: 'app_test',
      environment: 'staging',
      action: 'livecheck-signin',
      session_id: 'create',
      allow_legacy_proofs: false,
      rp_context: RP_CONTEXT
    })
    expect(constraint).toEqual(CredentialRequest('selfie'))
  })

  it('prove: proves the saved session, with no action', async () => {
    const idkit = fakeIDKit()
    await buildLiveCheckRequest(params({ mode: 'prove', action: undefined, session_id: SESSION_ID }), idkit)
    const [{ kind, args: [sessionId, config], constraint }] = idkit.calls
    expect(kind).toBe('proveSession')
    expect(sessionId).toBe(SESSION_ID)
    expect(config).toEqual({ app_id: 'app_test', environment: 'staging', rp_context: RP_CONTEXT })
    expect(config).not.toHaveProperty('action')
    expect(constraint).toEqual(CredentialRequest('selfie'))
  })

  it('converts the string timestamps from Cognito to numbers', async () => {
    const idkit = fakeIDKit()
    await buildLiveCheckRequest(params(), idkit)
    const { rp_context: rp } = idkit.calls[0].args[0]
    expect(typeof rp.created_at).toBe('number')
    expect(typeof rp.expires_at).toBe('number')
  })

  it.each(['app_id', 'rp_id', 'environment', 'rp_nonce', 'rp_signature', 'rp_created_at', 'rp_expires_at', 'mode'])(
    'rejects parameters missing %s before calling IDKit', (key) => {
      const idkit = fakeIDKit()
      expect(() => buildLiveCheckRequest(params({ [key]: '' }), idkit)).toThrow(key)
      expect(idkit.calls).toHaveLength(0)
    })

  it.each([undefined, ''])('enroll without an action (%s): session-only createSession, one-to-many', async (action) => {
    const idkit = fakeIDKit()
    await buildLiveCheckRequest(params({ action }), idkit)
    expect(idkit.calls).toHaveLength(1)
    const [{ kind, args: [config], constraint }] = idkit.calls
    expect(kind).toBe('createSession')
    expect(config).toEqual({ app_id: 'app_test', environment: 'staging', rp_context: RP_CONTEXT })
    expect(config).not.toHaveProperty('action')
    expect(config).not.toHaveProperty('session_id')
    expect(config).not.toHaveProperty('allow_legacy_proofs')
    expect(constraint).toEqual(CredentialRequest('selfie'))
  })

  it.each([undefined, '', 'not-a-session'])('rejects prove with session_id %s', (sessionId) => {
    const idkit = fakeIDKit()
    expect(() => buildLiveCheckRequest(params({ mode: 'prove', session_id: sessionId }), idkit)).toThrow(/session/)
    expect(idkit.calls).toHaveLength(0)
  })

  it('rejects an unknown mode', () => {
    const idkit = fakeIDKit()
    expect(() => buildLiveCheckRequest(params({ mode: 'legacy' }), idkit)).toThrow(/mode/)
    expect(idkit.calls).toHaveLength(0)
  })

  it('passes configs the real IDKit 4.6 builders accept (stops before the network call)', () => {
    // Wrap the REAL IDKit so we get its builders, but don't call .constraints(),
    // which is where IDKit contacts the World bridge.
    const built = []
    const realWrapped = {
      request: (config) => { const b = IDKit.request(config); built.push(b); return { constraints: () => b } },
      createSession: (config) => { const b = IDKit.createSession(config); built.push(b); return { constraints: () => b } },
      proveSession: (s, config) => { const b = IDKit.proveSession(s, config); built.push(b); return { constraints: () => b } }
    }
    buildLiveCheckRequest(params(), realWrapped)
    buildLiveCheckRequest(params({ action: undefined }), realWrapped)
    buildLiveCheckRequest(params({ mode: 'prove', session_id: SESSION_ID }), realWrapped)
    expect(built).toHaveLength(3)
    for (const b of built) expect(typeof b.constraints).toBe('function')
  })
})

describe('liveCheckErrorMessage', () => {
  it('explains the access gate the World ID App shows as "Selfie Check"', () => {
    expect(liveCheckErrorMessage('feature_unavailable')).toMatch(/Selfie Check/)
  })

  it('explains a one-to-one enrollment refused because the person already enrolled', () => {
    expect(liveCheckErrorMessage('nullifier_replayed')).toBe('This World ID is already linked to another account.')
  })

  it.each(['user_rejected', 'timeout', 'credential_unavailable', 'world_id_4_not_available', 'duplicate_nonce', 'invalid_network'])(
    'has specific copy for %s', (code) => {
      expect(liveCheckErrorMessage(code)).not.toMatch(/unknown error/)
    })

  it('falls back with the raw code for anything else', () => {
    expect(liveCheckErrorMessage('generic_error')).toMatch(/generic_error/)
    expect(liveCheckErrorMessage(undefined)).toMatch(/unknown error/)
  })
})

describe('timeouts', () => {
  it('stays under the 15-minute Cognito auth session', () => {
    expect(LIVE_CHECK_TIMEOUT_MS).toBeLessThan(15 * 60 * 1000)
  })
})
