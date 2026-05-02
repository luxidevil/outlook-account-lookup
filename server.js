import express from "express";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { ImapFlow } from "imapflow";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 5000;
const UA =
  "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36";

/* ------------------------------------------------------------------ */
/*  Microsoft session helper                                          */
/* ------------------------------------------------------------------ */
async function getMicrosoftSession() {
  let url =
    "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=13&ct=1&rver=7.0.6737.0" +
    "&wp=MBI_SSL&wreply=https%3A%2F%2Foutlook.live.com%2Fowa%2F&id=292841&aadredir=1";

  const cookieJar = new Map();
  let html = "";

  for (let hop = 0; hop < 6; hop++) {
    const cookieHeader = [...cookieJar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

    const res = await fetch(url, {
      redirect: "manual",
      headers: {
        "User-Agent": UA,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
    });

    const setCookies = res.headers.getSetCookie?.() ?? [];
    for (const sc of setCookies) {
      const first = sc.split(";")[0];
      const eq = first.indexOf("=");
      if (eq > 0) cookieJar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
    }

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) break;
      url = new URL(loc, url).toString();
      continue;
    }

    html = await res.text();
    break;
  }

  const flowTokenMatch = html.match(/name=\\?"PPFT\\?"[^>]*?value=\\?"([^"\\]+)/);
  const uaidMatch =
    html.match(/"correlationId":"([^"]+)"/) || html.match(/uaid=([a-f0-9]{20,})/);
  const apiCanaryMatch = html.match(/"apiCanary":"([^"]+)"/);

  if (!flowTokenMatch || !uaidMatch) return null;

  const cookies = [...cookieJar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

  return {
    flowToken: flowTokenMatch[1],
    uaid: uaidMatch[1],
    cookies,
    apiCanary: apiCanaryMatch
      ? apiCanaryMatch[1].replace(/\\u002f/g, "/").replace(/\\u003d/g, "=")
      : null,
  };
}

/* ------------------------------------------------------------------ */
/*  Lookup a single email                                             */
/* ------------------------------------------------------------------ */
async function lookupOne(email, session) {
  const { flowToken, uaid, cookies, apiCanary } = session;

  const body = JSON.stringify({
    checkPhones: false,
    country: "",
    federationFlags: 3,
    flowToken,
    forceotclogin: false,
    isCookieBannerShown: false,
    isExternalFederationDisallowed: false,
    isFederationDisabled: false,
    isFidoSupported: true,
    isOtherIdpSupported: false,
    isReactLoginRequest: true,
    isRemoteConnectSupported: false,
    isRemoteNGCSupported: true,
    isSignup: false,
    originalRequest: "",
    otclogindisallowed: false,
    uaid,
    username: email,
  });

  try {
    const apiRes = await fetch(
      `https://login.live.com/GetCredentialType.srf?mkt=EN-US&lc=1033&uaid=${uaid}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": UA,
          Origin: "https://login.live.com",
          Referer: "https://login.live.com/",
          Accept: "application/json",
          "Accept-Language": "en-GB,en-US;q=0.9",
          hpgact: "0",
          hpgid: "33",
          "client-request-id": uaid,
          correlationId: uaid,
          ...(cookies ? { Cookie: cookies } : {}),
          ...(apiCanary ? { canary: apiCanary } : {}),
        },
        body,
      },
    );

    const rawText = await apiRes.text();
    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      return {
        email,
        success: false,
        error: `Microsoft returned non-JSON (status ${apiRes.status})`,
      };
    }

    if (data.ErrorHR) {
      return {
        email,
        success: false,
        error: `Microsoft error ${data.ErrorHR} (session expired or rate-limited)`,
      };
    }

    const ifExists = data.IfExistsResult;
    // 0 = exists on consumer side, 6 = exists in another tenant, 1 = does not exist
    const accountExists = ifExists === 0 || ifExists === 6;

    let alternateEmail = null;
    let alternateDomain = null;
    let phoneHint = null;
    const allProofs = [];

    const proofs = data?.Credentials?.OtcLoginEligibleProofs;
    if (Array.isArray(proofs)) {
      for (const p of proofs) {
        const display = p.display ?? "";
        if (!display) continue;
        const typeName =
          p.type === 1
            ? "email"
            : p.type === 3
              ? "phone"
              : p.type === 5
                ? "authenticator"
                : `type_${p.type ?? "?"}`;

        // Capture encrypted proof token (AltEmailE / AltPhoneE) — the
        // server-side response field is `data`, not `proof`. Confirmed via
        // captured HAR + live debug log of GetCredentialType response.
        const proofToken = p.data ?? p.proof ?? p.proofToken ?? null;

        allProofs.push({
          type: typeName,
          display,
          isDefault: !!p.isDefault,
          proofToken,
        });

        if (p.type === 1 && !alternateEmail) {
          alternateEmail = display;
          const at = display.indexOf("@");
          if (at !== -1) alternateDomain = display.slice(at + 1);
        }
        if (p.type === 3 && !phoneHint) phoneHint = display;
      }
    }

    return {
      email,
      success: true,
      accountExists,
      ifExistsResult: ifExists,
      alternateEmail,
      alternateDomain,
      phoneHint,
      allProofs,
    };
  } catch (err) {
    return { email, success: false, error: err?.message ?? "Unknown error" };
  }
}

/* ------------------------------------------------------------------ */
/*  Send a One-Time Code to a recovery proof                         */
/* ------------------------------------------------------------------ */
async function sendOneTimeCode(
  email,
  session,
  proofToken,
  proofDisplay,
  channel = "Email",
  proofConfirmation = null,
) {
  const { flowToken, uaid, cookies } = session;

  // Microsoft's "Verify your identity" step requires the FULL un-masked
  // alternate email or phone as a plain value (no leading tab). The masked
  // `proofDisplay` (e.g. el****@de****.space) will be rejected.
  // Confirmed against captured HAR: `ProofConfirmation=<full alt>`.
  const confirmationValue = proofConfirmation
    ? proofConfirmation
    : proofDisplay;

  const params = new URLSearchParams({
    login: email,
    flowtoken: flowToken,
    purpose: "eOTT_OtcLogin",
    channel,
    ChallengeViewSupported: "1",
    uaid,
    lcid: "2057",
    ProofConfirmation: confirmationValue,
  });

  // Only include AltEmailE / AltPhoneE if we have the encrypted token
  if (proofToken) {
    if (channel === "Email") {
      params.set("AltEmailE", proofToken);
    } else if (channel === "SMS") {
      params.set("AltPhoneE", proofToken);
    }
  }

  const otcRes = await fetch(
    "https://login.live.com/GetOneTimeCode.srf?id=292841&client_id=00000000487A244A",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": UA,
        Origin: "https://login.live.com",
        Referer: "https://login.live.com/",
        Accept: "application/json",
        "Accept-Language": "en-GB,en-US;q=0.9",
        hpgact: "0",
        hpgid: "33",
        "client-request-id": uaid,
        correlationId: uaid,
        ...(cookies ? { Cookie: cookies } : {}),
      },
      body: params.toString(),
    },
  );

  const rawText = await otcRes.text();
  let otcData;
  try {
    otcData = JSON.parse(rawText);
  } catch {
    return {
      success: false,
      error: `Microsoft returned non-JSON (status ${otcRes.status})`,
      rawText,
    };
  }

  // State 201 = OTC sent successfully
  const sent = otcData.State === 201;
  return {
    success: sent,
    state: otcData.State,
    newFlowToken: otcData.FlowToken ?? null,
    error: sent ? null : `OTC send failed with state ${otcData.State}`,
    raw: otcData,
  };
}

/* ------------------------------------------------------------------ */
/*  In-memory OTC session store                                       */
/*  Holds the cookies + uaid + new flow token + proof metadata that   */
/*  GetOneTimeCode.srf returns, so a later /api/verify-otc call has   */
/*  everything it needs to POST the OTP back to Microsoft.            */
/*  TTL is 10 min — Microsoft codes expire fast anyway.               */
/* ------------------------------------------------------------------ */
const otcSessions = new Map();
const OTC_TTL_MS = 10 * 60 * 1000;

function saveOtcSession(data) {
  const id = crypto.randomUUID();
  otcSessions.set(id, { ...data, createdAt: Date.now() });
  const t = setTimeout(() => otcSessions.delete(id), OTC_TTL_MS);
  if (typeof t.unref === "function") t.unref();
  return id;
}

function getOtcSession(id) {
  const s = otcSessions.get(id);
  if (!s) return null;
  if (Date.now() - s.createdAt > OTC_TTL_MS) {
    otcSessions.delete(id);
    return null;
  }
  return s;
}

/* ------------------------------------------------------------------ */
/*  Verify a One-Time Code                                            */
/*  Posts the OTP to ppsecure/post.srf with the FULL un-masked        */
/*  alternate as ProofConfirmation and the encrypted proof token as   */
/*  SentProofIDE. Reads the response to detect accept / wrong code.   */
/* ------------------------------------------------------------------ */
async function verifyOneTimeCode(
  email,
  session,
  newFlowToken,
  otcCode,
  sentProofIDE,
  proofConfirmation,
  proofType,
) {
  const { uaid, cookies } = session;
  const proofTypeNum = proofType === "phone" ? "3" : "1";

  const params = new URLSearchParams({
    SentProofIDE: sentProofIDE ?? "",
    ProofConfirmation: proofConfirmation ?? "",
    ProofType: proofTypeNum,
    otc: otcCode,
    ps: "3",
    psRNGCDefaultType: "",
    psRNGCEntropy: "",
    psRNGCSLK: "",
    canary: "",
    ctx: "",
    hpgrequestid: "",
    PPFT: newFlowToken,
    PPSX: "P",
    NewUser: "1",
    FoundMSAs: "",
    fspost: "0",
    i21: "0",
    CookieDisclosure: "0",
    IsFidoSupported: "1",
    isSignupPost: "0",
    isRecoveryAttemptPost: "0",
    i13: "0",
    login: email,
    loginfmt: email,
    type: "27",
    LoginOptions: "3",
    lrt: "",
    lrtPartition: "",
    hisRegion: "",
    hisScaleUnit: "",
    cpr: "0",
  });

  const verifyUrl =
    `https://login.live.com/ppsecure/post.srf?` +
    `username=${encodeURIComponent(email)}&uaid=${uaid}&pid=15216`;

  const verifyRes = await fetch(verifyUrl, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": UA,
      Origin: "https://login.live.com",
      Referer: "https://login.live.com/",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-GB,en-US;q=0.9",
      "Cache-Control": "max-age=0",
      "Upgrade-Insecure-Requests": "1",
      ...(cookies ? { Cookie: cookies } : {}),
    },
    body: params.toString(),
  });

  const status = verifyRes.status;
  const location = verifyRes.headers.get("location") ?? "";
  const bodyText = await verifyRes.text().catch(() => "");

  // New flow token in case Microsoft hands us a chained step (e.g. passkey interrupt)
  const newPPFTMatch = bodyText.match(/name=\\?"PPFT\\?"[^>]*?value=\\?"([^"\\]+)/);

  // Success heuristics
  const redirectedOut =
    status >= 300 && status < 400 && !location.includes("login.live.com");

  const bodyHasPasskeyInterrupt =
    bodyText.includes("interrupt/passkey") ||
    bodyText.includes("account.live.com");

  // Wrong-code signals
  const wrongCode =
    bodyText.includes("otcInvalid") ||
    bodyText.includes("InvalidOtc") ||
    /the code you entered is( not| in)?valid/i.test(bodyText) ||
    /that code didn't work/i.test(bodyText);

  const otcAccepted =
    redirectedOut ||
    bodyHasPasskeyInterrupt ||
    (status === 200 && !!newPPFTMatch && !wrongCode);

  return {
    success: otcAccepted && !wrongCode,
    httpStatus: status,
    redirectLocation: location || null,
    nextFlowToken: newPPFTMatch ? newPPFTMatch[1] : null,
    error: otcAccepted && !wrongCode
      ? null
      : wrongCode
        ? "Incorrect OTP — please check the code and try again"
        : "OTP verification failed — code may be expired",
  };
}

/* ------------------------------------------------------------------ */
/*  IMAP — fetch the single-use code from the recovery mailbox        */
/*  Microsoft sends a plain-text email that always contains the line  */
/*    "Your single-use code is: 720651"                               */
/*  We connect to the user-supplied IMAP server, poll INBOX (+Junk)   */
/*  for messages from accountprotection.microsoft.com newer than      */
/*  `since`, and regex out the 6-digit code.                          */
/* ------------------------------------------------------------------ */
const OTC_REGEX = /single-use code is[:\s]*([0-9]{6,8})/i;
const FALLBACK_REGEX = /\b([0-9]{6,8})\b/;
const MS_FROM = "accountprotection.microsoft.com";

async function searchMailboxForOtc(client, mailbox, since) {
  try {
    const lock = await client.getMailboxLock(mailbox);
    try {
      const uids = await client.search(
        { since, from: MS_FROM },
        { uid: true },
      );
      if (!uids || uids.length === 0) return null;
      // newest first
      const latest = uids.slice(-5).reverse();
      for (const uid of latest) {
        const msg = await client.fetchOne(
          uid,
          { source: true, envelope: true, internalDate: true },
          { uid: true },
        );
        if (!msg) continue;
        if (msg.internalDate && msg.internalDate < since) continue;
        const text = msg.source ? msg.source.toString("utf8") : "";
        const m = text.match(OTC_REGEX) || text.match(FALLBACK_REGEX);
        if (m) {
          return {
            code: m[1],
            mailbox,
            messageId: msg.envelope?.messageId ?? null,
            subject: msg.envelope?.subject ?? null,
            from: msg.envelope?.from?.[0]?.address ?? null,
            receivedAt: msg.internalDate ?? null,
          };
        }
      }
      return null;
    } finally {
      lock.release();
    }
  } catch {
    return null;
  }
}

async function fetchOtcViaImap({
  host,
  port,
  secure,
  user,
  pass,
  sinceMs,
  timeoutMs,
}) {
  if (!host || !user || !pass) {
    return { success: false, error: "host, user and pass are required" };
  }
  const since = new Date(sinceMs ? sinceMs - 30_000 : Date.now() - 5 * 60_000);
  const deadline = Date.now() + Math.max(10_000, Math.min(180_000, timeoutMs ?? 90_000));

  const client = new ImapFlow({
    host,
    port: port || 993,
    secure: secure !== false,
    auth: { user, pass },
    logger: false,
    socketTimeout: 30_000,
  });

  try {
    await client.connect();
  } catch (e) {
    return { success: false, error: `IMAP connect failed: ${e?.message ?? e}` };
  }

  // Discover candidate folders (INBOX + anything that looks like Junk/Spam)
  let folders = ["INBOX"];
  try {
    const list = await client.list();
    for (const m of list) {
      const p = m?.path ?? "";
      const flags = (m?.specialUse ?? "") + " " + (m?.name ?? "");
      if (/junk|spam|bulk/i.test(flags) || m?.specialUse === "\\Junk") {
        if (!folders.includes(p)) folders.push(p);
      }
    }
  } catch { /* keep INBOX-only */ }

  try {
    let attempt = 0;
    while (Date.now() < deadline) {
      attempt++;
      for (const folder of folders) {
        const hit = await searchMailboxForOtc(client, folder, since);
        if (hit) {
          return { success: true, attempts: attempt, foldersChecked: folders, ...hit };
        }
      }
      // Wait 3s and re-poll
      await new Promise((r) => setTimeout(r, 3000));
    }
    return {
      success: false,
      error: "Timed out waiting for OTP email — check Junk folder, IMAP creds, or sender address",
      foldersChecked: folders,
      attempts: attempt,
    };
  } finally {
    try { await client.logout(); } catch { /* ignore */ }
  }
}

/* IMAP host hints for common providers — used by the UI to autofill */
const IMAP_PRESETS = {
  "gmail.com":      { host: "imap.gmail.com",       port: 993, secure: true, note: "Requires an App Password (2FA on)." },
  "googlemail.com": { host: "imap.gmail.com",       port: 993, secure: true, note: "Requires an App Password (2FA on)." },
  "outlook.com":    { host: "outlook.office365.com", port: 993, secure: true, note: "Requires an App Password (2FA on) or modern auth." },
  "hotmail.com":    { host: "outlook.office365.com", port: 993, secure: true, note: "Requires an App Password (2FA on) or modern auth." },
  "live.com":       { host: "outlook.office365.com", port: 993, secure: true, note: "Requires an App Password (2FA on) or modern auth." },
  "yahoo.com":      { host: "imap.mail.yahoo.com",  port: 993, secure: true, note: "Requires an App Password." },
  "ymail.com":      { host: "imap.mail.yahoo.com",  port: 993, secure: true, note: "Requires an App Password." },
  "aol.com":        { host: "imap.aol.com",         port: 993, secure: true, note: "Requires an App Password." },
  "icloud.com":     { host: "imap.mail.me.com",     port: 993, secure: true, note: "Requires an App-Specific Password." },
  "me.com":         { host: "imap.mail.me.com",     port: 993, secure: true, note: "Requires an App-Specific Password." },
};

/* ------------------------------------------------------------------ */
/*  Routes                                                            */
/* ------------------------------------------------------------------ */
app.post("/api/credential-check", async (req, res) => {
  const { email } = req.body ?? {};
  if (!email || !email.includes("@")) {
    return res.status(400).json({ success: false, error: "A valid email is required" });
  }
  const session = await getMicrosoftSession();
  if (!session) {
    return res.status(502).json({ success: false, error: "Could not reach Microsoft login page" });
  }
  const result = await lookupOne(email, session);
  res.json(result);
});

app.post("/api/credential-check/bulk", async (req, res) => {
  const { emails, delayMs } = req.body ?? {};
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ success: false, error: "emails must be a non-empty array" });
  }
  if (emails.length > 100) {
    return res.status(400).json({ success: false, error: "Maximum 100 emails per request" });
  }

  const cleaned = emails
    .map((e) => (typeof e === "string" ? e.trim() : ""))
    .filter((e) => e.includes("@"));

  if (cleaned.length === 0) {
    return res.status(400).json({ success: false, error: "No valid emails" });
  }

  let session = await getMicrosoftSession();
  if (!session) {
    return res.status(502).json({ success: false, error: "Could not reach Microsoft" });
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const pause = Math.max(0, Math.min(5000, delayMs ?? 800));
  const results = [];

  for (let i = 0; i < cleaned.length; i++) {
    let result = await lookupOne(cleaned[i], session);

    // refresh session on a microsoft-side error and retry once
    if (!result.success && result.error?.startsWith("Microsoft error")) {
      const fresh = await getMicrosoftSession();
      if (fresh) {
        session = fresh;
        result = await lookupOne(cleaned[i], session);
      }
    }
    results.push(result);
    if (i < cleaned.length - 1) await wait(pause);
  }

  res.json({
    success: true,
    summary: {
      total: results.length,
      succeeded: results.filter((r) => r.success).length,
      accountsFound: results.filter((r) => r.accountExists).length,
      failed: results.filter((r) => !r.success).length,
    },
    results,
  });
});

/* ------------------------------------------------------------------ */
/*  Send OTC to a recovery proof for a given email                   */
/* ------------------------------------------------------------------ */
app.post("/api/send-otc", async (req, res) => {
  const { email, proofDisplay, channel, proofConfirmation } = req.body ?? {};
  if (!email || !email.includes("@")) {
    return res.status(400).json({ success: false, error: "A valid email is required" });
  }
  if (!proofConfirmation || typeof proofConfirmation !== "string" || proofConfirmation.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: "proofConfirmation is required (the full un-masked alternate email or phone the user typed in)",
    });
  }

  // Step 1: get a fresh Microsoft session
  const session = await getMicrosoftSession();
  if (!session) {
    return res.status(502).json({ success: false, error: "Could not reach Microsoft login page" });
  }

  // Step 2: credential check to get proof tokens
  const lookup = await lookupOne(email, session);
  if (!lookup.success) {
    return res.status(502).json({ success: false, error: lookup.error });
  }
  if (!lookup.accountExists) {
    return res.status(404).json({ success: false, error: "No Microsoft account found for this email" });
  }

  // Step 3: pick the target proof (by display hint or default to first email proof)
  const targetChannel = channel === "SMS" ? "SMS" : "Email";
  const proofType = targetChannel === "SMS" ? "phone" : "email";
  let proof = null;

  if (proofDisplay) {
    proof = lookup.allProofs.find((p) => p.type === proofType && p.display === proofDisplay);
  }
  if (!proof) {
    proof = lookup.allProofs.find((p) => p.type === proofType);
  }

  if (!proof) {
    return res.status(404).json({
      success: false,
      error: `No ${proofType} recovery method found on this account`,
      allProofs: lookup.allProofs,
    });
  }

  // Step 4: send the OTC, passing the full un-masked alternate email/phone
  // the user typed in (Microsoft's "Verify your identity" step)
  const otcResult = await sendOneTimeCode(
    email,
    session,
    proof.proofToken,
    proof.display,
    targetChannel,
    proofConfirmation.trim(),
  );

  let sessionId = null;
  if (otcResult.success && otcResult.newFlowToken) {
    sessionId = saveOtcSession({
      email,
      uaid: session.uaid,
      cookies: session.cookies,
      newFlowToken: otcResult.newFlowToken,
      proofDisplay: proof.display,
      proofType: proof.type,
      sentProofIDE: proof.proofToken ?? null,
      proofConfirmation: proofConfirmation.trim(),
      channel: targetChannel,
    });
  }

  res.json({
    ...otcResult,
    email,
    proofDisplay: proof.display,
    channel: targetChannel,
    sessionId,
  });
});

/* ------------------------------------------------------------------ */
/*  Verify a previously-sent OTC                                      */
/*  Body: { sessionId, otc }                                          */
/* ------------------------------------------------------------------ */
app.post("/api/verify-otc", async (req, res) => {
  const { sessionId, otc } = req.body ?? {};
  if (!sessionId || typeof sessionId !== "string") {
    return res.status(400).json({ success: false, error: "sessionId is required" });
  }
  if (!otc || !/^\d{4,12}$/.test(String(otc).trim())) {
    return res.status(400).json({ success: false, error: "otc must be 4-12 digits" });
  }

  const s = getOtcSession(sessionId);
  if (!s) {
    return res.status(404).json({
      success: false,
      error: "Session not found or expired (codes are valid ~10 min)",
    });
  }

  const fakeSession = { uaid: s.uaid, cookies: s.cookies };
  const result = await verifyOneTimeCode(
    s.email,
    fakeSession,
    s.newFlowToken,
    String(otc).trim(),
    s.sentProofIDE,
    s.proofConfirmation,
    s.proofType,
  );

  res.json({
    ...result,
    email: s.email,
    proofDisplay: s.proofDisplay,
    channel: s.channel,
  });
});

/* ------------------------------------------------------------------ */
/*  Bulk send OTC: accepts pairs of {email, alternate, channel?}      */
/*  Frontend parses lines like `email:alter` and posts the array.     */
/* ------------------------------------------------------------------ */
app.post("/api/send-otc/bulk", async (req, res) => {
  const { pairs, channel: defaultChannel, delayMs } = req.body ?? {};
  if (!Array.isArray(pairs) || pairs.length === 0) {
    return res.status(400).json({ success: false, error: "pairs must be a non-empty array" });
  }
  if (pairs.length > 50) {
    return res.status(400).json({ success: false, error: "Maximum 50 pairs per request" });
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  // Server-side floor of 800ms between pairs to avoid getting throttled by Microsoft.
  const pause = Math.max(800, Math.min(10000, delayMs ?? 1500));
  const fallbackChannel = defaultChannel === "SMS" ? "SMS" : "Email";
  const results = [];

  for (let i = 0; i < pairs.length; i++) {
    const raw = pairs[i] ?? {};
    const email = typeof raw.email === "string" ? raw.email.trim() : "";
    const alternate = typeof raw.alternate === "string" ? raw.alternate.trim() : "";
    const reqChannel = raw.channel === "SMS" ? "SMS" : raw.channel === "Email" ? "Email" : fallbackChannel;
    const proofType = reqChannel === "SMS" ? "phone" : "email";

    // The full unmasked alternate is intentionally NOT echoed back in the
    // response (it's recovery contact data). The frontend keeps its own
    // copy of what it sent and merges by index for display.
    const base = { index: i, email, channel: reqChannel };

    if (!email || !email.includes("@") || !alternate) {
      results.push({ ...base, success: false, error: "Invalid pair (expected email:alternate)" });
      if (i < pairs.length - 1) await wait(pause);
      continue;
    }

    try {
      // Each pair gets its own fresh Microsoft session (the flowToken is
      // tied to one credential check + one OTC send).
      const session = await getMicrosoftSession();
      if (!session) {
        results.push({ ...base, success: false, error: "Could not reach Microsoft login page" });
        if (i < pairs.length - 1) await wait(pause);
        continue;
      }

      const lookup = await lookupOne(email, session);
      if (!lookup.success) {
        results.push({ ...base, success: false, error: lookup.error });
        if (i < pairs.length - 1) await wait(pause);
        continue;
      }
      if (!lookup.accountExists) {
        results.push({ ...base, success: false, error: "No Microsoft account found" });
        if (i < pairs.length - 1) await wait(pause);
        continue;
      }

      const proof = lookup.allProofs.find((p) => p.type === proofType);
      if (!proof) {
        results.push({
          ...base,
          success: false,
          error: `No ${proofType} recovery method on file`,
          availableProofs: lookup.allProofs.map((p) => ({ type: p.type, display: p.display })),
        });
        if (i < pairs.length - 1) await wait(pause);
        continue;
      }

      const otc = await sendOneTimeCode(
        email,
        session,
        proof.proofToken,
        proof.display,
        reqChannel,
        alternate,
      );

      // If Microsoft accepted the send (State 201), persist everything
      // /api/verify-otc will need: cookies + uaid + the new flow token
      // Microsoft handed back, plus the encrypted proof token and full
      // un-masked alternate so we can echo them as SentProofIDE +
      // ProofConfirmation when posting the OTP.
      let sessionId = null;
      if (otc.success && otc.newFlowToken) {
        sessionId = saveOtcSession({
          email,
          uaid: session.uaid,
          cookies: session.cookies,
          newFlowToken: otc.newFlowToken,
          proofDisplay: proof.display,
          proofType: proof.type,
          sentProofIDE: proof.proofToken ?? null,
          proofConfirmation: alternate,
          channel: reqChannel,
        });
      }

      results.push({
        ...base,
        proofDisplay: proof.display,
        success: otc.success,
        state: otc.state,
        error: otc.error,
        sessionId,
      });
    } catch (err) {
      results.push({ ...base, success: false, error: err?.message ?? "Unknown error" });
    }

    if (i < pairs.length - 1) await wait(pause);
  }

  res.json({
    success: true,
    summary: {
      total: results.length,
      sent: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
    },
    results,
  });
});

/* ------------------------------------------------------------------ */
/*  IMAP debug endpoint — manually fetch the latest OTP email         */
/*  Body: { imap:{host,port,secure,user,pass}, sinceMs?, timeoutMs? } */
/* ------------------------------------------------------------------ */
app.post("/api/imap-fetch-otc", async (req, res) => {
  const { imap, sinceMs, timeoutMs } = req.body ?? {};
  if (!imap || typeof imap !== "object") {
    return res.status(400).json({ success: false, error: "imap config object is required" });
  }
  const result = await fetchOtcViaImap({ ...imap, sinceMs, timeoutMs });
  res.json(result);
});

/* ------------------------------------------------------------------ */
/*  IMAP presets — UI calls this to autofill host/port for known      */
/*  providers based on the recovery email's domain.                   */
/* ------------------------------------------------------------------ */
app.get("/api/imap-presets", (_req, res) => res.json(IMAP_PRESETS));

/* ------------------------------------------------------------------ */
/*  Full end-to-end login: send OTP, poll IMAP, verify OTP            */
/*  Body: {                                                           */
/*    email, alternate, channel?,                                     */
/*    imap: { host, port, secure, user, pass },                       */
/*    timeoutMs?                                                      */
/*  }                                                                 */
/* ------------------------------------------------------------------ */
app.post("/api/login-with-imap", async (req, res) => {
  const { email, alternate, channel, imap, timeoutMs } = req.body ?? {};
  const steps = [];
  const log = (step, ok, detail) => steps.push({ step, ok, detail });

  if (!email || !email.includes("@")) {
    return res.status(400).json({ success: false, error: "A valid email is required", steps });
  }
  if (!alternate) {
    return res.status(400).json({ success: false, error: "alternate (recovery email/phone) is required", steps });
  }
  if (!imap || !imap.host || !imap.user || !imap.pass) {
    return res.status(400).json({ success: false, error: "imap.host / user / pass are required", steps });
  }

  const reqChannel = channel === "SMS" ? "SMS" : "Email";
  const proofType = reqChannel === "SMS" ? "phone" : "email";

  // 1. MS session
  const session = await getMicrosoftSession();
  if (!session) {
    log("microsoft-session", false, "Could not reach login.live.com");
    return res.status(502).json({ success: false, error: "Could not reach Microsoft", steps });
  }
  log("microsoft-session", true, `uaid=${session.uaid?.slice(0, 8)}…`);

  // 2. Lookup
  const lookup = await lookupOne(email, session);
  if (!lookup.success || !lookup.accountExists) {
    log("lookup", false, lookup.error ?? "Account does not exist");
    return res.json({ success: false, email, steps, error: log.error ?? "Lookup failed" });
  }
  log("lookup", true, `recovery hint: ${lookup.alternateEmail ?? lookup.phoneHint ?? "?"}`);

  const proof = lookup.allProofs.find((p) => p.type === proofType);
  if (!proof) {
    log("proof-select", false, `No ${proofType} proof on file`);
    return res.json({ success: false, email, steps, error: `No ${proofType} recovery method on file` });
  }
  log("proof-select", true, proof.display);

  // 3. Send OTC — record the wall time so IMAP only considers newer mail
  const sentAt = Date.now();
  const otc = await sendOneTimeCode(
    email, session, proof.proofToken, proof.display, reqChannel, alternate,
  );
  if (!otc.success) {
    log("send-otc", false, otc.error ?? `state=${otc.state}`);
    return res.json({ success: false, email, steps, error: otc.error ?? "Microsoft refused to send the OTP" });
  }
  log("send-otc", true, `state=${otc.state} (Microsoft accepted)`);

  // 4. Poll IMAP for the code
  const fetched = await fetchOtcViaImap({
    ...imap,
    sinceMs: sentAt,
    timeoutMs: timeoutMs ?? 90_000,
  });
  if (!fetched.success) {
    log("imap-fetch", false, fetched.error);
    return res.json({ success: false, email, steps, error: fetched.error });
  }
  log("imap-fetch", true, `code=${fetched.code} from ${fetched.mailbox} (subject: ${fetched.subject ?? "?"})`);

  // 5. Verify OTC
  const verifySession = { uaid: session.uaid, cookies: session.cookies };
  const verify = await verifyOneTimeCode(
    email, verifySession, otc.newFlowToken, fetched.code,
    proof.proofToken, alternate, proof.type,
  );
  log("verify-otc", verify.success, verify.error ?? `httpStatus=${verify.httpStatus}, redirect=${verify.redirectLocation ?? "(none)"}`);

  res.json({
    success: verify.success,
    email,
    proofDisplay: proof.display,
    channel: reqChannel,
    code: fetched.code,
    mailbox: fetched.mailbox,
    subject: fetched.subject,
    httpStatus: verify.httpStatus,
    redirectLocation: verify.redirectLocation,
    nextFlowToken: verify.nextFlowToken,
    error: verify.error,
    steps,
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Outlook Account Lookup running on http://0.0.0.0:${PORT}`);
});
