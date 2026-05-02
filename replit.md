# Microsoft Account Lookup

## Overview
A Node.js/Express web app that looks up Microsoft/Outlook accounts and reveals the masked recovery email and phone hint Microsoft exposes via its public APIs.

## Architecture
- **Backend**: Express.js (server.js) running on port 5000
- **Frontend**: Static HTML/CSS/JS served from `/public` using Tailwind CSS via CDN

## Key Features
- Single email lookup via `GET /api/credential-check`
- Bulk lookup (up to 100 emails) via `/api/credential-check/bulk`
- Send One-Time Code (OTP) to a recovery proof via `/api/send-otc`

## API Endpoints
- `POST /api/credential-check` — look up a single email; returns account existence, masked recovery email, phone hint, and all proofs
- `POST /api/credential-check/bulk` — bulk lookup with configurable delay between requests
- `POST /api/send-otc` — trigger sending an OTP to a recovery email/phone for a given account

## How It Works
1. Fetches a Microsoft session (PPFT flow token, uaid, cookies) from `login.live.com`
2. Calls `GetCredentialType.srf` to check if an account exists and retrieve masked recovery proof hints
3. Optionally calls `GetOneTimeCode.srf` to send an OTP to the recovery email/phone (State 201 = sent successfully)

## Running
```
npm run dev   # development (with --watch)
npm start     # production
```

## Deployment
- Target: autoscale
- Run command: `node server.js`
