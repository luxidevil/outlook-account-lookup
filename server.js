import express from "express";
import path from "path";
import { fileURLToPath } from "url";

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

        // Capture encrypted proof token (AltEmailE / AltPhoneE) if present
        const proofToken = p.proof ?? p.proofToken ?? p.clearDigits ?? null;

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
async function sendOneTimeCode(email, session, proofToken, proofDisplay, channel = "Email") {
  const { flowToken, uaid, cookies } = session;

  const params = new URLSearchParams({
    login: email,
    flowtoken: flowToken,
    purpose: "eOTT_OtcLogin",
    channel,
    ChallengeViewSupported: "1",
    uaid,
    lcid: "2057",
    ProofConfirmation: proofDisplay,
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
  const { email, proofDisplay, channel } = req.body ?? {};
  if (!email || !email.includes("@")) {
    return res.status(400).json({ success: false, error: "A valid email is required" });
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

  // Step 4: send the OTC
  const otcResult = await sendOneTimeCode(
    email,
    session,
    proof.proofToken,
    proof.display,
    targetChannel,
  );

  res.json({
    ...otcResult,
    email,
    proofDisplay: proof.display,
    channel: targetChannel,
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Outlook Account Lookup running on http://0.0.0.0:${PORT}`);
});
