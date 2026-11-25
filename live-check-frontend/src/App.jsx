/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 */
import { useEffect, useRef, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { currentUser, signOut, startSignIn, submitLiveCheckProof, submitNewPassword } from './auth.js'
import { LIVE_CHECK_TIMEOUT_MS, buildLiveCheckRequest, liveCheckErrorMessage } from './worldid.js'

// Sign-in states: password -> (newPassword) -> liveCheck -> signedIn
export default function App () {
  const [view, setView] = useState('loading')
  const [challenge, setChallenge] = useState(null)
  const [user, setUser] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    currentUser().then((u) => {
      setUser(u)
      setView(u ? 'signedIn' : 'password')
    })
  }, [])

  async function handleNextStep ({ nextStep }) {
    switch (nextStep.signInStep) {
      case 'DONE': {
        setUser(await currentUser())
        setView('signedIn')
        break
      }
      case 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED':
        setView('newPassword')
        break
      case 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE':
        setChallenge(nextStep.additionalInfo || {})
        setView('liveCheck')
        break
      default:
        throw new Error(`Unsupported sign-in step: ${nextStep.signInStep}`)
    }
  }

  function fail (message) {
    setChallenge(null)
    setError(message)
    setView('password')
  }

  async function run (action) {
    setError('')
    try {
      await handleNextStep(await action())
    } catch (err) {
      fail(err?.message || 'Sign-in failed.')
    }
  }

  async function handleSignOut () {
    await signOut()
    setUser(null)
    setView('password')
  }

  return (
    <div className="app">
      <Header />
      <main className="page">
        <div className="card">
          {error && <div className="error" role="alert">{error}</div>}
          {view === 'loading' && <p className="card-sub">Loading…</p>}
          {view === 'password' && (
            <PasswordForm onSubmit={(email, password) => run(() => startSignIn(email, password))} />
          )}
          {view === 'newPassword' && (
            <NewPasswordForm onSubmit={(password) => run(() => submitNewPassword(password))} />
          )}
          {view === 'liveCheck' && challenge && (
            <LiveCheck
              key={challenge.rp_nonce}
              params={challenge}
              onProof={(result) => run(() => submitLiveCheckProof(result))}
              onError={fail}
            />
          )}
          {view === 'signedIn' && user && <SignedIn user={user} onSignOut={handleSignOut} />}
        </div>
        <p className="footer-note">
          Demo environment · AnyCompany is a fictitious company · Identity by{' '}
          <a href="https://world.org/world-id-live-check" target="_blank" rel="noopener noreferrer">World ID</a>
        </p>
      </main>
    </div>
  )
}

function LiveCheck ({ params, onProof, onError }) {
  const [connectorURI, setConnectorURI] = useState('')
  const [status, setStatus] = useState('Preparing your Live Check…')
  const started = useRef(false)
  // Callbacks live in a ref so a parent re-render can't restart (and abort)
  // the poll while the user is completing the Live Check.
  const callbacks = useRef({ onProof, onError })
  useEffect(() => { callbacks.current = { onProof, onError } }, [onProof, onError])

  useEffect(() => {
    // One IDKit request per signed challenge: the RP nonce can't be reused.
    if (started.current) return undefined
    started.current = true
    const abort = new AbortController()
    const reportProof = (result) => callbacks.current.onProof(result)
    const reportError = (message) => callbacks.current.onError(message)

    ;(async () => {
      try {
        const request = await buildLiveCheckRequest(params)
        setConnectorURI(request.connectorURI)
        setStatus('Waiting for you to complete the Live Check in the World ID App…')
        const outcome = await request.pollUntilCompletion({
          timeout: LIVE_CHECK_TIMEOUT_MS,
          signal: abort.signal
        })
        if (abort.signal.aborted) return
        if (!outcome.success) {
          reportError(liveCheckErrorMessage(outcome.error))
          return
        }
        setConnectorURI('')
        setStatus('Verifying…')
        reportProof(outcome.result)
      } catch (err) {
        if (!abort.signal.aborted) reportError(err?.message || 'Live Check failed. Sign in again to retry.')
      }
    })()

    return () => abort.abort()
  }, [params])

  const enrolling = params.mode === 'enroll'
  return (
    <div>
      <h2 className="card-title">{enrolling ? 'Set up your Live Check' : 'Confirm it\u2019s you'}</h2>
      <p className="card-sub">
        Scan this code with the <strong>World ID App</strong> and complete the Live Check.
        {enrolling
          ? ' This first check links your World ID to this account.'
          : ' This confirms you\u2019re the same person who set up this account.'}
        {' '}AnyCompany never sees your face, only a proof.
      </p>
      {connectorURI && (
        <div className="qr">
          <QRCodeSVG value={connectorURI} size={240} level="M" />
          <p className="hint">
            On a phone? <a href={connectorURI} target="_blank" rel="noopener noreferrer">Open the World ID App</a>
          </p>
        </div>
      )}
      <p className="status"><span className="spinner" aria-hidden="true" />{status}</p>
    </div>
  )
}

function PasswordForm ({ onSubmit }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); await onSubmit(email, password); setBusy(false) }}>
      <h2 className="card-title">Sign in to AnyCompany</h2>
      <p className="card-sub">Your password, then a World ID Live Check.</p>
      <label>Work email<input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
      <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  )
}

function NewPasswordForm ({ onSubmit }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); await onSubmit(password); setBusy(false) }}>
      <h2 className="card-title">Set a new password</h2>
      <p className="card-sub">Your account was created with a temporary password.</p>
      <label>New password<input type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
      <button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Set password'}</button>
    </form>
  )
}

function SignedIn ({ user, onSignOut }) {
  const rows = [
    ['Email', user.email],
    ['User ID (sub)', user.sub],
    ['Username', user.username],
    ['Signed in at', user.authTime],
    ['Session expires', user.expiresAt]
  ]
  return (
    <div>
      <h2 className="card-title">Welcome back</h2>
      <div className="verified">Verified with password and World ID Live Check</div>
      <ul className="details">
        {rows.map(([label, value]) => <li key={label}><span>{label}</span><b>{value || ' - '}</b></li>)}
      </ul>
      <button type="button" className="secondary" onClick={onSignOut}>Sign out</button>
    </div>
  )
}

function Header () {
  return (
    <header className="brand-bar">
      <div className="brand">
        <svg viewBox="0 0 48 48" width="40" height="40" aria-hidden="true">
          <defs>
            <linearGradient id="acg" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#3b6ef6" />
              <stop offset="1" stopColor="#00c2a8" />
            </linearGradient>
          </defs>
          <path d="M24 2 42 9v12c0 11.5-7.6 20.3-18 25C13.6 41.3 6 32.5 6 21V9z" fill="url(#acg)" />
          <path d="M16.5 24.5l5 5 10-11" fill="none" stroke="#fff" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div className="brand-text">
          <span className="brand-name">AnyCompany<span className="brand-accent"> Security</span></span>
          <span className="brand-tag">Proof-of-human access control</span>
        </div>
      </div>
      <span className="badge"><span className="dot" />Secured by World ID</span>
    </header>
  )
}
