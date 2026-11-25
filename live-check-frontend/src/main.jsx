/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 */
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import { configureAuth } from './auth.js'
import './App.css'

configureAuth()

// No <React.StrictMode>: in development it mounts components twice, which would
// open the World ID request twice with the same backend-signed RP nonce, and
// World rejects a reused nonce (duplicate_nonce).
createRoot(document.getElementById('root')).render(<App />)
