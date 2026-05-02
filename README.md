# Microsoft / Outlook Account Lookup

A small Node.js + Express tool that queries Microsoft's public
`GetCredentialType.srf` endpoint (the same endpoint that the Outlook login
page uses) to tell you, for any email address:

- whether a Microsoft account exists for that email
- the **masked recovery email** Microsoft has on file (e.g. `te*****@example.com`)
- the **domain** of that recovery email (fully revealed by Microsoft)
- a masked phone number hint, when one is configured
- every recovery method Microsoft is willing to disclose

The same data is shown on the real `login.live.com` page when you click
"Forgot password" — this tool just gives you a clean UI and a bulk mode.

> **Important:** Microsoft only ever returns masked hints. You will **not**
> get the full recovery email or phone number — only the domain, the first
> two characters, and the last few digits. That is by design.

---

## Screenshot

The UI has two modes:

- **Single Email** — one email at a time, full detail view.
- **Bulk (up to 100)** — paste a list, get a results table and CSV export.

---

## Tech stack

- **Node.js 20+** (uses the built-in `fetch`, ESM modules)
- **Express 4** for the HTTP server
- **Vanilla HTML + Tailwind (CDN)** for the frontend — no build step

There are no external API keys, no databases, and no third-party services.
Everything runs locally.

---

## Quick start

```bash
git clone <this-repo>
cd outlook-lookup
npm install
npm start
```

Then open `http://localhost:3000` in your browser.

To enable file watching during development:

```bash
npm run dev
```

You can change the port with the `PORT` environment variable:

```bash
PORT=8080 npm start
```

---

## How it works

Microsoft's `GetCredentialType.srf` endpoint cannot be called directly with
just an email — it requires a session that the login page hands out. The
server-side flow is:

1. **Bootstrap a session.** Make a `GET` request to
   `https://login.live.com/login.srf?...id=292841&aadredir=1` and **manually
   follow redirects**, accumulating every `Set-Cookie` header into a cookie
   jar.
2. **Scrape the page.** Extract:
   - the `PPFT` flow token from the embedded HTML form
   - the `correlationId` / `uaid`
   - (optional) the `apiCanary` value
3. **Call the API.** Send a `POST` to
   `https://login.live.com/GetCredentialType.srf` with the cookies, the
   flow token, the uaid, and a small JSON body containing the username
   you're looking up.
4. **Parse the response.** The interesting fields are:
   - `IfExistsResult`
     - `0` → account exists (consumer)
     - `1` → no account
     - `6` → account exists in another tenant (work/school)
   - `Credentials.OtcLoginEligibleProofs[]` → the list of recovery
     methods, each with a `type` (1 = email, 3 = phone, 5 = authenticator)
     and a masked `display` string.

The cookie + flow-token dance is what most third-party guides leave out —
without it Microsoft returns `{"ErrorHR":"80046703"}`.

---

## API

### `POST /api/credential-check`

Single-email lookup.

**Request**

```json
{ "email": "someone@outlook.com" }
```

**Response (account found)**

```json
{
  "email": "someone@outlook.com",
  "success": true,
  "accountExists": true,
  "ifExistsResult": 0,
  "alternateEmail": "te*****@example.com",
  "alternateDomain": "example.com",
  "phoneHint": "+** *******45",
  "allProofs": [
    { "type": "email", "display": "te*****@example.com", "isDefault": true }
  ]
}
```

**Response (no account)**

```json
{
  "email": "noone@outlook.com",
  "success": true,
  "accountExists": false,
  "ifExistsResult": 1,
  "alternateEmail": null,
  "alternateDomain": null,
  "phoneHint": null,
  "allProofs": []
}
```

### `POST /api/credential-check/bulk`

Look up multiple emails in a single request. The server reuses one
Microsoft session across the whole batch (faster + lighter on Microsoft).
If the session goes stale mid-batch, it is automatically refreshed and the
failed email is retried once.

**Request**

```json
{
  "emails": ["alice@outlook.com", "bob@hotmail.com"],
  "delayMs": 800
}
```

- `emails` — array of email strings (max 100)
- `delayMs` — delay between each lookup (0–5000, default 800)

**Response**

```json
{
  "success": true,
  "summary": { "total": 2, "succeeded": 2, "accountsFound": 1, "failed": 0 },
  "results": [
    {
      "email": "alice@outlook.com",
      "success": true,
      "accountExists": true,
      "alternateEmail": "al*****@example.com",
      "alternateDomain": "example.com",
      "phoneHint": null,
      "allProofs": [...]
    },
    {
      "email": "bob@hotmail.com",
      "success": true,
      "accountExists": false,
      "alternateEmail": null,
      "alternateDomain": null,
      "phoneHint": null,
      "allProofs": []
    }
  ]
}
```

---

## Project structure

```
outlook-lookup/
├── package.json        # npm metadata + start script
├── server.js           # Express server with the credential-check routes
├── public/
│   └── index.html      # vanilla HTML + Tailwind CDN frontend
└── README.md
```

Everything fits in two real source files (`server.js` and
`public/index.html`) — easy to read, easy to demo.

---

## Notes on responsible use

This project queries a **public, unauthenticated** Microsoft endpoint that
was deliberately designed to expose masked recovery hints to anyone who
clicks "Forgot password" on the Outlook login page. Nothing here bypasses
authentication, decrypts data, or reveals private information.

That said, please use it responsibly:

- Only look up addresses you have a legitimate reason to check — for
  example, your own accounts, accounts you administer, or addresses you
  are investigating with permission.
- The tool intentionally does **not** include proxy rotation, IP
  randomisation, fingerprint spoofing, or any other anti-detection
  measures. Adding them would turn a legitimate "is this account mine?"
  helper into an account-enumeration tool, which violates Microsoft's
  Services Agreement.
- For high-volume / production use cases, switch to the official
  [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/), which
  is the supported way to query account state at scale.

---

## License

MIT — do whatever you want, no warranty.
