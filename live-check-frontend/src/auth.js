/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Cognito sign-in with the Amplify v6 auth module only.
 *
 * CUSTOM_WITH_SRP starts the CUSTOM_AUTH flow with the SRP password step
 * (SRP_A -> PASSWORD_VERIFIER); Amplify performs the SRP computation, which the
 * plain AWS SDK v3 Cognito client does not implement. The backend's
 * DefineAuthChallenge then issues the World ID Live Check as CUSTOM_CHALLENGE.
 */
import { Amplify } from 'aws-amplify'
import { confirmSignIn, fetchAuthSession, getCurrentUser, signIn, signOut } from 'aws-amplify/auth'

export function configureAuth (env = import.meta.env) {
  const userPoolId = env.VITE_USER_POOL_ID
  const userPoolClientId = env.VITE_USER_POOL_CLIENT_ID
  if (!userPoolId || !userPoolClientId) {
    throw new Error('Set VITE_USER_POOL_ID and VITE_USER_POOL_CLIENT_ID in live-check-frontend/.env')
  }
  Amplify.configure({ Auth: { Cognito: { userPoolId, userPoolClientId } } })
}

export function startSignIn (username, password) {
  return signIn({ username, password, options: { authFlowType: 'CUSTOM_WITH_SRP' } })
}

export function submitNewPassword (newPassword) {
  return confirmSignIn({ challengeResponse: newPassword })
}

// The IDKit result goes to VerifyAuthChallengeResponse unchanged.
export function submitLiveCheckProof (result) {
  return confirmSignIn({ challengeResponse: JSON.stringify(result) })
}

export async function currentUser () {
  try {
    const { username } = await getCurrentUser()
    const { tokens } = await fetchAuthSession()
    const claims = tokens?.idToken?.payload || {}
    const when = (secs) => (secs ? new Date(secs * 1000).toLocaleString() : '')
    return {
      username,
      email: claims.email || '',
      sub: claims.sub || '',
      authTime: when(claims.auth_time),
      expiresAt: when(claims.exp)
    }
  } catch {
    return null
  }
}

export { signOut }
