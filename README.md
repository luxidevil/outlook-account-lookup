# Microsoft / Outlook Account Lookup

A small Node.js + Express tool that talks to Microsoft's public sign-in endpoints (`login.live.com`) to:

1. **Check whether a Microsoft / Outlook account exists** for a given email and reveal the **masked recovery email and phone hint** Microsoft itself shows on the "We need to verify your identity" page.
2. **Trigger a one-time code (OTP)** to be sent to that recovery email or phone.
3. **Submit the OTP back to Microsoft** to complete the verification step.

It is purely a thin client over Microsoft's own browser-facing endpoints — no SDK, no scraping of HTML beyond the few hidden form fields Microsoft requires (PPFT, uaid, canary).

> **For academic / research use only.** The tool only retrieves data Microsoft already exposes to any browser visiting the consumer login flow. It is not a credential-stuffing or password-cracking tool.

---

## Table of contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [How the Microsoft sign-in dance works](#how-the-microsoft-sign-in-dance-works)
- [API reference](#api-reference)
- [Running locally](#running-locally)
- [Project layout](#project-layout)
- [Deployment](#deployment)
- [Security & ethics](#security--ethics)
- [Limitations](#limitations)
- [License](#license)

---

## Features

| Feature | Endpoint | UI tab |
| --- | --- | --- |
| Single account lookup | `POST /api/credential-check` | **Single Email** |
| Bulk lookup (up to 100) | `POST /api/credential-check/bulk` | **Bulk Lookup** |
| Send OTP to recovery proof (single) | `POST /api/send-otc` | inline button on Single panel |
| Bulk send OTP (`email:alternate` pairs, up to 50) | `POST /api/send-otc/bulk` | **Bulk Send OTC** |
| Submit / verify a previously-sent OTP | `POST /api/verify-otc` | (programmatic) |

Per-result CSV export, per-domain filtering, and per-row "Send OTP" buttons are built into the UI.

---

## Tech stack

- **Node.js ≥ 20** (uses native `fetch`, `getSetCookie`, `crypto.randomUUID`)
- **Express 4** for the HTTP layer
- **Tailwind CSS via CDN** for the frontend (one self-contained `index.html`, no build step)
- **No database** — short-lived OTP sessions live in an in-memory `Map` with a 10-minute TTL.

---

## Architecture

```
                          ┌────────────────────────┐
                          │   Browser (index.html) │
                          │   Tabs: Single / Bulk /│
                          │   Bulk Send OTC        │
                          └──────────┬─────────────┘
                                     │ JSON over fetch()
                                     ▼
        ┌──────────────────────────────────────────────────┐
        │                Express server (server.js)         │
        │                                                   │
        │  /api/credential-check         /api/send-otc      │
        │  /api/credential-check/bulk    /api/send-otc/bulk │
        │                       /api/verify-otc             │
        │                                                   │
        │  In-memory otcSessions Map  (10 min TTL)          │
        └────────────────────────┬──────────────────────────┘
                                 │ HTTPS (manual fetch)
                                 ▼
              ┌─────────────────────────────────────┐
              │        login.live.com               │
              │  GET  login.srf      (HTML + PPFT)  │
              │  POST GetCredentialType.srf         │
              │  POST GetOneTimeCode.srf            │
              │  POST ppsecure/post.srf             │
              └─────────────────────────────────────┘
```

Everything in `server.js` is one file, organised in four blocks:

1. `getMicrosoftSession()` — fetches `login.srf`, follows redirects manually, builds a cookie jar, and extracts `PPFT`, `uaid`, and `apiCanary` from the returned HTML / inline JSON.
2. `lookupOne(email, session)` — POSTs to `GetCredentialType.srf` and parses `IfExistsResult` and `Credentials.OtcLoginEligibleProofs` (each entry has `type`, `display`, and the encrypted **`data`** field — that's the `AltEmailE` / `AltPhoneE` token).
3. `sendOneTimeCode(...)` — POSTs to `GetOneTimeCode.srf` with `purpose=eOTT_OtcLogin`, the encrypted proof token (`AltEmailE` / `AltPhoneE`), and the **full un-masked alternate** as `ProofConfirmation`. State `201` means "code sent".
4. `verifyOneTimeCode(...)` — POSTs to `ppsecure/post.srf` with the OTP plus `SentProofIDE`, `ProofConfirmation`, `ProofType`, `PPFT`, and the rest of the form fields a real browser sends (`type=27`, `LoginOptions=3`, `PPSX=P`, etc.). Detects accept / wrong-code / expired from the response.

---

## How the Microsoft sign-in dance works

This is the most interesting part for a viva — it's a four-hop flow and every hop has at least one quirky required field that isn't documented anywhere.

### Hop 1 — Bootstrap a session

```
GET https://login.live.com/login.srf?wa=wsignin1.0&...&wreply=https%3A%2F%2Foutlook.live.com%2Fowa%2F
```

The server follows up to six redirects manually (so it can collect every `Set-Cookie` along the way) and finally lands on the HTML sign-in page. From that page it extracts:

| Field | Where it comes from | Why it matters |
| --- | --- | --- |
| `PPFT` | hidden `<input name="PPFT">` | anti-CSRF flow token; required by **every** subsequent POST |
| `uaid` | inline JSON (`"correlationId":"…"`) or `uaid=…` cookie | per-session correlation id; goes in the URL query string |
| `apiCanary` | inline JSON (`"apiCanary":"…"`) | header value for the JSON API |
| Cookies | accumulated `Set-Cookie` headers | every hop after this re-uses them |

### Hop 2 — Does this account exist? What recovery methods does it have?

```
POST https://login.live.com/GetCredentialType.srf?mkt=EN-US&lc=1033&uaid=…
Content-Type: application/json
canary: <apiCanary>

{ "username": "<email>", "flowToken": "<PPFT>", "uaid": "<uaid>", … }
```

Microsoft replies with JSON. The two interesting fields:

- `IfExistsResult` — `0` = consumer account, `6` = federated tenant, `1` = no account.
- `Credentials.OtcLoginEligibleProofs[]` — an array of recovery methods. Each entry has:
  - `type` — `1` = email, `3` = phone, `5` = authenticator app
  - `display` — the **masked** hint (`el****@de****.space`)
  - `data` — the **encrypted proof token** (≈100 chars). This is what Microsoft calls `AltEmailE` (for email) or `AltPhoneE` (for phone). **Note: not `proof`, not `proofToken` — the field is literally named `data`.**

> 🐛 **Real bug we hit:** earlier code read `p.proof ?? p.proofToken`, which is `null`, so the OTC send always failed with State 8001. Reading `p.data` was the fix — confirmed by capturing the live response in DevTools.

### Hop 3 — Send the OTP

```
POST https://login.live.com/GetOneTimeCode.srf?id=292841&client_id=00000000487A244A
Content-Type: application/x-www-form-urlencoded

login=<email>&flowtoken=<PPFT>&purpose=eOTT_OtcLogin
&channel=Email&AltEmailE=<encrypted-token>
&ProofConfirmation=<FULL-unmasked-alternate>
&uaid=<uaid>&lcid=2057&ChallengeViewSupported=1
```

The non-obvious requirement: **`ProofConfirmation` must be the full un-masked address**, exactly as the user types it on the "Verify your identity" page. Sending the masked `display` value (`el****@de****.space`) is rejected. We learned this by diffing a successful HAR against a failing one.

A successful response is JSON with `State: 201` and a new `FlowToken`. The new flow token replaces `PPFT` for the next hop.

### Hop 4 — Submit the OTP

```
POST https://login.live.com/ppsecure/post.srf?username=<email>&uaid=<uaid>&pid=15216
Content-Type: application/x-www-form-urlencoded

otc=<6-digit-code>
&PPFT=<new-flow-token-from-hop-3>
&SentProofIDE=<encrypted-token-from-hop-2>
&ProofConfirmation=<full-unmasked-alternate>
&ProofType=1   # 1 = email, 3 = phone
&type=27       # OTC login
&LoginOptions=3&PPSX=P
&login=<email>&loginfmt=<email>
&IsFidoSupported=1&CookieDisclosure=0&...
```

Many fields can be empty strings, but the names must be present — Microsoft's parser is strict. We send the same cookie jar from hop 1, plus the `Cache-Control` and `Upgrade-Insecure-Requests` headers a real browser sends so the response isn't an HTML interstitial.

The server interprets the response with a small heuristic:

- **3xx redirect away from `login.live.com`** → success (Microsoft is forwarding to OWA / passkey interrupt / consent page).
- **200 with body containing `interrupt/passkey` or `account.live.com`** → success.
- **Body matches `/InvalidOtc/`, `/otcInvalid/`, `the code you entered is not valid`** → wrong code.
- Otherwise → expired / unknown.

---

## API reference

All endpoints accept and return JSON.

### `POST /api/credential-check`

```json
// request
{ "email": "someone@outlook.com" }
```
```json
// response
{
  "email": "someone@outlook.com",
  "success": true,
  "accountExists": true,
  "ifExistsResult": 0,
  "alternateEmail": "el*****@de*****.space",
  "alternateDomain": "de*****.space",
  "phoneHint": "+1 *** *** **34",
  "allProofs": [
    { "type": "email", "display": "el*****@de*****.space", "isDefault": true,  "proofToken": "..." },
    { "type": "phone", "display": "+1 *** *** **34",     "isDefault": false, "proofToken": "..." }
  ]
}
```

### `POST /api/credential-check/bulk`

```json
{ "emails": ["a@outlook.com", "b@hotmail.com"], "delayMs": 800 }
```

Returns `{ summary: { total, succeeded, accountsFound, failed }, results: [...] }`. Maximum 100 emails per call. The server pauses `delayMs` (≥ 0, ≤ 5000) between requests so Microsoft doesn't throttle.

### `POST /api/send-otc`

```json
{
  "email": "target@outlook.com",
  "channel": "Email",
  "proofConfirmation": "full-unmasked-alt@example.com"
}
```

`proofConfirmation` is **required** — see hop 3 above. Returns:

```json
{
  "success": true,
  "state": 201,
  "newFlowToken": "...",
  "email": "target@outlook.com",
  "proofDisplay": "el*****@de*****.space",
  "channel": "Email",
  "sessionId": "8c3ff415-3646-49f8-b880-c10315c7368d"
}
```

The `sessionId` is the key into the in-memory store and is what `/api/verify-otc` consumes.

### `POST /api/send-otc/bulk`

```json
{
  "pairs": [
    { "email": "alice@outlook.com", "alternate": "alice.recovery@example.com" }
  ],
  "channel": "Email",
  "delayMs": 1500
}
```

Maximum 50 pairs. Each pair gets its own fresh Microsoft session (because `flowToken` is single-use). Per-row response includes a `sessionId` you can later submit a code against.

### `POST /api/verify-otc`

```json
{ "sessionId": "8c3ff415-...", "otc": "606649" }
```

Returns:

```json
{
  "success": true,
  "httpStatus": 302,
  "redirectLocation": "https://account.live.com/...",
  "nextFlowToken": "...",
  "error": null,
  "email": "target@outlook.com",
  "proofDisplay": "el*****@de*****.space",
  "channel": "Email"
}
```

If the session has expired (10 min TTL) you'll get a 404 — re-send the OTP to start a new session.

---

## Running locally

```bash
# requires Node ≥ 20
npm install
npm run dev      # node --watch server.js  (auto-restart on edits)
# or
npm start        # plain node server.js
```

The server listens on `process.env.PORT || 5000`. Open `http://localhost:5000` and you'll see the three-tab UI.

### Quick smoke test (curl)

```bash
# 1. Lookup
curl -s -X POST localhost:5000/api/credential-check \
  -H 'Content-Type: application/json' \
  -d '{"email":"someone@outlook.com"}' | jq

# 2. Send OTP, capture sessionId
SID=$(curl -s -X POST localhost:5000/api/send-otc/bulk \
  -H 'Content-Type: application/json' \
  -d '{"pairs":[{"email":"someone@outlook.com","alternate":"recovery@example.com"}]}' \
  | jq -r '.results[0].sessionId')

# 3. Submit the code that landed in the recovery inbox
curl -s -X POST localhost:5000/api/verify-otc \
  -H 'Content-Type: application/json' \
  -d "{\"sessionId\":\"$SID\",\"otc\":\"123456\"}" | jq
```

---

## Project layout

```
.
├── server.js          ← all backend logic (≈ 700 LOC, single file by design)
├── public/
│   └── index.html     ← single-page UI, vanilla JS + Tailwind CDN
├── package.json
├── replit.md          ← short architecture notes (used by the agent)
└── README.md          ← you are here
```

Why one file each? The whole point is to be readable end-to-end during a viva. Splitting `server.js` into `routes/`, `services/`, `dto/` would hide the four-hop Microsoft dance behind layers of abstraction.

---

## Deployment

**Replit autoscale** (current target):

- Run command: `node server.js`
- Open port: `5000`
- No env vars required.

**Any Node host (DigitalOcean, Fly, Render, etc.):**

```bash
git clone https://github.com/luxidevil/outlook-account-lookup
cd outlook-account-lookup
npm ci --omit=dev
PORT=8080 node server.js
```

Front a reverse proxy (nginx / Caddy) for TLS. There's no state to back up — sessions are in-memory and short-lived.

---

## Security & ethics

- The server stores **no credentials**. The only thing it ever holds is a 10-minute reference to a Microsoft-issued flow token plus the user-supplied recovery hint, both of which Microsoft already knows about.
- All session material is purely in-memory — restarting the server purges it.
- Captured **HAR files** used during reverse engineering are explicitly excluded from version control (`.gitignore` covers `*.har` and `attached_assets/`). They contain live session cookies and OAuth tokens and **must not be committed**. If they ever are, treat the captured tokens as compromised and rotate them.
- This is a research / educational project. Use only on accounts you own or have explicit permission to test. Sending unsolicited OTPs to other people's recovery channels can constitute harassment and may be illegal in your jurisdiction.

---

## Limitations

- The "verify identity" hop only handles the simple OTC-by-email / OTC-by-SMS branch. Microsoft may also push **passkey**, **Authenticator notification**, or **federated tenant** flows — those return different JSON shapes and are out of scope.
- `IfExistsResult` distinguishes consumer (0) and other-tenant (6) accounts but does not tell you *which* tenant a "6" lives in.
- Session storage is process-local. If you horizontally scale the server, a sticky-session reverse proxy is required (or move sessions to Redis).
- Microsoft can change any of these endpoints at any time. The fields documented here were correct as of the last successful capture — keep a recent HAR around for diffing if you ever see new failure modes.

---

## License

MIT — see `package.json`.
