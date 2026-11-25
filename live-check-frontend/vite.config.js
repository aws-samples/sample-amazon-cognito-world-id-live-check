/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at http://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev and preview servers bind to loopback only, so the sign-in app is
// never exposed to the local network. strictPort fails fast instead of
// silently moving to another port.
const loopback = { host: '127.0.0.1', port: 8080, strictPort: true }

export default defineConfig({
  plugins: [react()],
  server: loopback,
  preview: loopback,
  test: {
    environment: 'node',
    include: ['src/**/*.test.js']
  }
})
