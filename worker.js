// src/lib.js
var HttpError = class extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
};
var bad = (msg, code) => new HttpError(400, msg, code);
var unauthorized = (msg = "Please sign in") => new HttpError(401, msg, "unauthorized");
var forbidden = (msg = "Not allowed") => new HttpError(403, msg, "forbidden");
var notFound = (msg = "Not found") => new HttpError(404, msg, "not_found");
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
  });
}
async function readJson(request, maxBytes = 64 * 1024) {
  const text = await request.text();
  if (text.length > maxBytes) throw bad("Request too large");
  if (!text) return {};
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw bad("Invalid JSON");
  }
}
var nowIso = () => (/* @__PURE__ */ new Date()).toISOString();
var newId = () => crypto.randomUUID();
var enc = new TextEncoder();
function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return b64url(a);
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(str2) {
  return Uint8Array.from(atob(str2), (c) => c.charCodeAt(0));
}
var hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256Hex(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
async function hmacHex(secret, text) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(text)));
}
function safeEqual(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
var PBKDF2_ITER = 1e5;
async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const bits = await pbkdf2(password, salt, PBKDF2_ITER);
  return `pbkdf2$${PBKDF2_ITER}$${b64(salt)}$${b64(bits)}`;
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const [, iter, saltB64, hashB64] = stored.split("$");
  const bits = await pbkdf2(password, unb64(saltB64), parseInt(iter, 10));
  return safeEqual(b64(bits), hashB64);
}
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}
var CURRENCIES = ["USD", "EUR", "GBP", "AUD", "CAD", "SGD", "JPY", "MXN", "HKD"];
var ZERO_DECIMAL = ["JPY"];
var isZeroDecimal = (c) => ZERO_DECIMAL.includes(c);
var minorFactor = (c) => isZeroDecimal(c) ? 1 : 100;
function toMinor(amount, currency) {
  const n = Number(amount);
  if (!Number.isFinite(n)) throw bad("Invalid amount");
  return Math.round(n * minorFactor(currency));
}
var toMajor = (minor, currency) => Number(minor) / minorFactor(currency);
function majorString(minor, currency) {
  return isZeroDecimal(currency) ? String(minor) : (minor / 100).toFixed(2);
}
function cleanCurrency(c) {
  const cur = String(c || "USD").toUpperCase();
  if (!CURRENCIES.includes(cur)) throw bad("Unsupported currency");
  return cur;
}
function str(v, { max = 200, required = false, field = "Field" } = {}) {
  const s = typeof v === "string" ? v.trim() : v == null ? "" : String(v).trim();
  if (required && !s) throw bad(`${field} is required`);
  if (s.length > max) throw bad(`${field} is too long (max ${max} characters)`);
  return s;
}
function emailOf(v) {
  const e = str(v, { max: 254, required: true, field: "Email" }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw bad("Enter a valid email address");
  return e;
}
function safeWebhookUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw bad("Enter a valid URL");
  }
  if (u.protocol !== "https:") throw bad("Webhook URL must start with https://");
  if (u.username || u.password) throw bad("Webhook URL must not contain a username or password");
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const privateHost = h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || /^\d+$/.test(h) || h === "::1" || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe80:/.test(h) || h.startsWith("::ffff:");
  if (privateHost) throw bad("Webhook URL must point to a public server");
  if (raw.length > 500) throw bad("Webhook URL is too long");
  return u.toString();
}
async function rateLimit(env, key, limit, windowMs) {
  const now = Date.now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start < ?3 THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start < ?3 THEN ?2 ELSE rate_limits.window_start END
     RETURNING count`
  ).bind(key, now, now - windowMs).first();
  if (row && row.count > limit) throw new HttpError(429, "Too many attempts. Please wait a few minutes and try again.", "rate_limited");
}
var clientIp = (request) => request.headers.get("CF-Connecting-IP") || "local";
async function audit(env, actorId, action, target, details) {
  await env.DB.prepare("INSERT INTO audit_log (id, actor_id, action, target, details) VALUES (?,?,?,?,?)").bind(newId(), actorId || null, action, target || null, details ? JSON.stringify(details) : null).run();
}
var holdDays = (env) => parseFloat(env.HOLD_DAYS || "7");
function holdDaysFor(env, u) {
  if (!u) return holdDays(env);
  if (u.hold_days != null) return u.hold_days;
  const ageDays = (Date.now() - new Date(u.created_at).getTime()) / 864e5;
  return ageDays < parseFloat(env.NEW_ACCOUNT_DAYS || "30") ? parseFloat(env.NEW_ACCOUNT_HOLD_DAYS || "14") : holdDays(env);
}
async function availableAtFor(env, userId) {
  const u = await env.DB.prepare("SELECT hold_days, created_at FROM users WHERE id = ?").bind(userId).first();
  const days = holdDaysFor(env, u);
  return days > 0 ? new Date(Date.now() + days * 864e5).toISOString() : null;
}
var MEDIA_KEY_RE = /^(p|a)\/[0-9a-f-]{36}\.(jpg|png|webp)$/;
var mediaUrl = (key) => key && MEDIA_KEY_RE.test(key) ? `/api/media/${key}` : null;

// src/human.js
var COOKIE = "vy_human";
var PASS_SECONDS = 30 * 60;
var enabled = (env) => !!(env.TURNSTILE_SECRET_KEY && env.TURNSTILE_SITE_KEY);
var signingKey = (env) => `human-pass:${env.TURNSTILE_SECRET_KEY}`;
function readCookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
async function verifyHuman(env, request) {
  const b = await readJson(request);
  if (!enabled(env)) return json({ ok: true, expires_in: PASS_SECONDS });
  await rateLimit(env, `human:${clientIp(request)}`, 60, 6e5);
  const token = typeof b.token === "string" ? b.token.slice(0, 4096) : "";
  if (!token) throw new HttpError(400, "Security check missing. Please try again.", "human_check");
  const res = await fetch(env.TURNSTILE_VERIFY_URL || "https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: clientIp(request) })
  });
  const d = await res.json().catch(() => ({}));
  if (!d.success) throw new HttpError(403, "Security check failed. Please try again.", "human_check");
  const exp = Math.floor(Date.now() / 1e3) + PASS_SECONDS;
  const sig = await hmacHex(signingKey(env), String(exp));
  return json({ ok: true, expires_in: PASS_SECONDS }, 200, {
    "Set-Cookie": `${COOKIE}=${exp}.${sig}; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=${PASS_SECONDS}`
  });
}
async function requireHuman(env, request) {
  if (!enabled(env)) return;
  const [exp, sig] = (readCookie(request, COOKIE) || "").split(".");
  const ok = exp && sig && parseInt(exp, 10) > Date.now() / 1e3 && safeEqual(sig, await hmacHex(signingKey(env), exp));
  if (!ok) throw new HttpError(403, "Please complete the security check.", "human_check");
}

// src/email.js
var escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
async function sendEmail(env, { to, subject, text, html }) {
  if (!env.RESEND_API_KEY) {
    if (env.DEV === "true") console.log(`[email to ${to}] ${subject}
${text}`);
    else console.warn("Email not sent (RESEND_API_KEY not set):", subject);
    return false;
  }
  try {
    const res = await fetch(env.RESEND_API_URL || "https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM || "VyCheckout <noreply@example.com>", to: [to], subject, text, html })
    });
    if (!res.ok) console.error("Resend error", res.status, await res.text());
    return res.ok;
  } catch (e) {
    console.error("Email failed", e);
    return false;
  }
}
function linkEmail(env, to, subject, intro, buttonText, url) {
  return sendEmail(env, {
    to,
    subject,
    text: `${intro}

${url}

If you didn't ask for this, you can ignore this email.`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px">
      <p>${escHtml(intro)}</p>
      <p><a href="${escHtml(url)}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">${escHtml(buttonText)}</a></p>
      <p style="color:#666;font-size:13px">If you didn't ask for this, you can ignore this email.</p></div>`
  });
}
function notifyAdmin(env, subject, lines) {
  const to = (env.ADMIN_EMAILS || "").split(",").map((s) => s.trim()).filter(Boolean)[0];
  if (!to) return Promise.resolve(false);
  const text = lines.join("\n");
  return sendEmail(env, { to, subject, text, html: `<pre style="font-family:system-ui,sans-serif">${escHtml(text)}</pre>` });
}
async function alert(env, subject, lines) {
  const jobs = [notifyAdmin(env, `\u26A0\uFE0F VyCheckout: ${subject}`, lines)];
  if (env.ALERT_WEBHOOK_URL) {
    const text = `*${subject}*
${lines.join("\n")}`;
    jobs.push(fetch(env.ALERT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, content: text.slice(0, 1900) })
      // "text" for Slack, "content" for Discord
    }).catch((e) => console.error("Alert webhook failed", e)));
  }
  await Promise.all(jobs);
}
var money = (minor, currency) => {
  const zero = currency === "JPY";
  const v = zero ? minor : minor / 100;
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(v);
  } catch {
    return `${v.toFixed(zero ? 0 : 2)} ${currency}`;
  }
};
function payerReceiptEmail(env, { to, business, description, grossMinor, currency, txnId, method, cancelUrl: cancelUrl2 }) {
  const lines = [
    `Thanks for your payment to ${business}.`,
    "",
    `Amount: ${money(grossMinor, currency)}`,
    `For: ${description || "\u2014"}`,
    `Paid with: ${method}`,
    `Reference: ${txnId}`,
    `Date: ${(/* @__PURE__ */ new Date()).toUTCString()}`
  ];
  if (cancelUrl2) lines.push("", `This is a recurring subscription. To cancel it, open: ${cancelUrl2}`);
  const text = lines.join("\n");
  const html = `<div style="font-family:system-ui,sans-serif;max-width:480px;line-height:1.55">
    <h2 style="margin:0 0 8px">Payment received \u2713</h2>
    <p>Thanks for your payment to <strong>${escHtml(business)}</strong>.</p>
    <table style="border-collapse:collapse;font-size:14px">
      <tr><td style="padding:3px 12px 3px 0;color:#666">Amount</td><td><strong>${escHtml(money(grossMinor, currency))}</strong></td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#666">For</td><td>${escHtml(description || "\u2014")}</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#666">Paid with</td><td>${escHtml(method)}</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#666">Reference</td><td style="font-family:monospace;font-size:12px">${escHtml(txnId)}</td></tr>
    </table>
    ${cancelUrl2 ? `<p style="font-size:13px;color:#555">This is a recurring subscription. <a href="${escHtml(cancelUrl2)}">Cancel it here</a> any time.</p>` : ""}
  </div>`;
  return sendEmail(env, { to, subject: `Receipt: ${money(grossMinor, currency)} to ${business}`, text, html });
}
function saleAlertEmail(env, { to, description, grossMinor, netMinor, currency, availableAt, payerName, appUrl: appUrl2 }) {
  const when = availableAt ? new Date(availableAt).toDateString() : "now";
  const lines = [
    `You received ${money(grossMinor, currency)} for ${description || "a payment"}${payerName ? ` from ${payerName}` : ""}.`,
    `After the platform fee you get ${money(netMinor, currency)}, available to withdraw: ${when}.`,
    "",
    `Dashboard: ${appUrl2}`,
    "You can turn these emails off in Account settings."
  ];
  return sendEmail(env, {
    to,
    subject: `\u{1F4B0} You got paid ${money(grossMinor, currency)}`,
    text: lines.join("\n"),
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;line-height:1.55"><p>${lines.slice(0, 2).map(escHtml).join("<br>")}</p>
      <p><a href="${escHtml(appUrl2)}">Open your dashboard</a></p><p style="font-size:12px;color:#777">You can turn these emails off in Account settings.</p></div>`
  });
}

// src/auth.js
var SESSION_COOKIE = "vy_session";
var SESSION_DAYS = 30;
var OAUTH_COOKIE = "vy_oauth";
var appUrl = (env, request) => (env.APP_URL || new URL(request.url).origin).replace(/\/$/, "");
function cookie(name, value, { maxAge, path = "/" } = {}) {
  return `${name}=${value}; Path=${path}; HttpOnly; Secure; SameSite=Lax${maxAge != null ? `; Max-Age=${maxAge}` : ""}`;
}
function readCookie2(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
function isAdmin(env, user) {
  if (!user || !user.email_verified) return false;
  if (user.is_admin) return true;
  const list = (env.ADMIN_EMAILS || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
  return list.includes(String(user.email).toLowerCase());
}
function selfView(env, u) {
  return {
    id: u.id,
    email: u.email,
    email_verified: !!u.email_verified,
    full_name: u.full_name,
    business_name: u.business_name,
    bio: u.bio,
    avatar: u.avatar,
    avatar_url: mediaUrl(u.avatar_key),
    ref_code: u.ref_code,
    has_referrer: !!u.referrer_id,
    created_at: u.created_at,
    is_admin: isAdmin(env, u),
    has_password: !!u.password_hash,
    has_google: !!u.google_sub,
    notify_sales: u.notify_sales == null ? true : !!u.notify_sales
  };
}
async function createSession(env, userId) {
  const token = randomToken(32);
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)").bind(await sha256Hex(token), userId, Date.now() + SESSION_DAYS * 864e5).run();
  return cookie(SESSION_COOKIE, token, { maxAge: SESSION_DAYS * 86400 });
}
var clearSessionCookie = () => cookie(SESSION_COOKIE, "", { maxAge: 0 });
async function getSessionUser(env, request) {
  const token = readCookie2(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? AND u.suspended = 0 AND u.deleted_at IS NULL`
  ).bind(await sha256Hex(token), Date.now()).first();
  return row || null;
}
async function requireUser(env, request) {
  const u = await getSessionUser(env, request);
  if (!u) throw unauthorized();
  return u;
}
async function requireAdmin(env, request) {
  const u = await requireUser(env, request);
  if (!isAdmin(env, u)) throw forbidden("Admin only");
  return u;
}
async function genRefCode(env) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let i = 0; i < 10; i++) {
    const a = new Uint8Array(6);
    crypto.getRandomValues(a);
    const code = [...a].map((b) => alphabet[b % alphabet.length]).join("");
    const taken = await env.DB.prepare("SELECT 1 FROM users WHERE ref_code = ?").bind(code).first();
    if (!taken) return code;
  }
  throw new HttpError(500, "Could not create account, please try again");
}
async function referrerIdFor(env, code) {
  const c = String(code || "").toUpperCase().trim();
  if (!c || !/^[A-Z0-9]{4,12}$/.test(c)) return null;
  const r = await env.DB.prepare("SELECT id FROM users WHERE ref_code = ? AND deleted_at IS NULL").bind(c).first();
  return r ? r.id : null;
}
async function issueToken(env, userId, purpose, ttlMs) {
  const token = randomToken(32);
  await env.DB.prepare("INSERT INTO auth_tokens (token_hash, user_id, purpose, expires_at) VALUES (?,?,?,?)").bind(await sha256Hex(token), userId, purpose, Date.now() + ttlMs).run();
  return token;
}
async function consumeToken(env, token, purpose) {
  if (!token || typeof token !== "string" || token.length > 100) return null;
  const row = await env.DB.prepare(
    `UPDATE auth_tokens SET used_at = ? WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
     RETURNING user_id`
  ).bind(nowIso(), await sha256Hex(token), purpose, Date.now()).first();
  return row ? row.user_id : null;
}
async function sendVerification(env, request, user) {
  const token = await issueToken(env, user.id, "verify", 3 * 864e5);
  const url = `${appUrl(env, request)}/api/auth/verify?token=${encodeURIComponent(token)}`;
  await linkEmail(env, user.email, "Confirm your VyCheckout email", "Confirm your email address to finish setting up VyCheckout.", "Confirm email", url);
}
async function signup(env, request, ctx) {
  const ip = clientIp(request);
  await rateLimit(env, `signup:${ip}`, 10, 36e5);
  await requireHuman(env, request);
  const b = await readJson(request);
  const full_name = str(b.full_name, { max: 80, required: true, field: "Name" });
  const business_name = str(b.business_name, { max: 80, required: true, field: "Business name" });
  const email = emailOf(b.email);
  const password = String(b.password || "");
  if (password.length < 8) throw bad("Password must be 8+ characters");
  if (password.length > 200) throw bad("Password is too long");
  const exists = await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(email).first();
  if (exists) throw bad("An account with this email already exists. Try signing in instead.", "email_taken");
  const id = newId();
  const user = {
    id,
    email,
    full_name,
    business_name,
    ref_code: await genRefCode(env),
    referrer_id: await referrerIdFor(env, b.ref),
    password_hash: await hashPassword(password)
  };
  await env.DB.prepare(
    `INSERT INTO users (id, email, password_hash, full_name, business_name, ref_code, referrer_id)
     VALUES (?,?,?,?,?,?,?)`
  ).bind(id, email, user.password_hash, full_name, business_name, user.ref_code, user.referrer_id).run();
  ctx.waitUntil(sendVerification(env, request, user));
  ctx.waitUntil(notifyAdmin(env, "New VyCheckout signup", [`Name: ${full_name}`, `Business: ${business_name}`, `Email: ${email}`]));
  const row = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
  return json({ user: selfView(env, row) }, 200, { "Set-Cookie": await createSession(env, id) });
}
async function login(env, request) {
  const b = await readJson(request);
  const email = emailOf(b.email);
  const ip = clientIp(request);
  await requireHuman(env, request);
  await rateLimit(env, `login-ip:${ip}`, 30, 9e5);
  await rateLimit(env, `login-email:${email}`, 10, 9e5);
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ? AND deleted_at IS NULL").bind(email).first();
  const ok = await verifyPassword(String(b.password || ""), u?.password_hash || "pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  if (!u || !ok) throw bad("Wrong email or password", "bad_credentials");
  if (u.suspended) throw forbidden("This account is suspended. Contact support.");
  return json({ user: selfView(env, u) }, 200, { "Set-Cookie": await createSession(env, u.id) });
}
async function logout(env, request) {
  const token = readCookie2(request, SESSION_COOKIE);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  return json({ ok: true }, 200, { "Set-Cookie": cookie(SESSION_COOKIE, "", { maxAge: 0 }) });
}
async function forgot(env, request, ctx) {
  const b = await readJson(request);
  const email = emailOf(b.email);
  await requireHuman(env, request);
  await rateLimit(env, `forgot:${clientIp(request)}`, 10, 36e5);
  await rateLimit(env, `forgot-email:${email}`, 3, 36e5);
  const u = await env.DB.prepare("SELECT id, email FROM users WHERE email = ? AND deleted_at IS NULL AND suspended = 0").bind(email).first();
  if (u) {
    const token = await issueToken(env, u.id, "reset", 36e5);
    const url = `${appUrl(env, request)}/?reset=${encodeURIComponent(token)}`;
    ctx.waitUntil(linkEmail(env, u.email, "Reset your VyCheckout password", "Someone asked to reset your VyCheckout password. The link works for 1 hour.", "Choose a new password", url));
  }
  return json({ ok: true });
}
async function resetPassword(env, request) {
  const b = await readJson(request);
  const password = String(b.password || "");
  if (password.length < 8) throw bad("Password must be 8+ characters");
  if (password.length > 200) throw bad("Password is too long");
  const userId = await consumeToken(env, b.token, "reset");
  if (!userId) throw bad("This reset link is invalid or has expired. Request a new one.", "bad_token");
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?").bind(await hashPassword(password), userId),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId)
  ]);
  const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first();
  return json({ user: selfView(env, u) }, 200, { "Set-Cookie": await createSession(env, userId) });
}
async function verifyEmail(env, request) {
  const token = new URL(request.url).searchParams.get("token");
  const userId = await consumeToken(env, token, "verify");
  if (userId) await env.DB.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").bind(userId).run();
  return Response.redirect(`${appUrl(env, request)}/?verified=${userId ? "1" : "0"}`, 302);
}
async function resendVerification(env, request, ctx) {
  const u = await requireUser(env, request);
  if (u.email_verified) return json({ ok: true, already: true });
  await rateLimit(env, `verify-resend:${u.id}`, 3, 36e5);
  ctx.waitUntil(sendVerification(env, request, u));
  return json({ ok: true });
}
async function googleStart(env, request) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) throw bad("Google sign-in is not set up");
  const url = new URL(request.url);
  const state = randomToken(24);
  const ref = (url.searchParams.get("ref") || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
  const auth = new URL(env.GOOGLE_AUTH_URL || "https://accounts.google.com/o/oauth2/v2/auth");
  auth.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${appUrl(env, request)}/api/auth/google/callback`,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account"
  }).toString();
  return new Response(null, {
    status: 302,
    headers: { Location: auth.toString(), "Set-Cookie": cookie(OAUTH_COOKIE, `${state}.${ref}`, { maxAge: 600, path: "/api/auth/google" }) }
  });
}
async function googleCallback(env, request, ctx) {
  const base = appUrl(env, request);
  const fail = (reason) => new Response(null, {
    status: 302,
    headers: { Location: `${base}/?login_error=${encodeURIComponent(reason)}`, "Set-Cookie": cookie(OAUTH_COOKIE, "", { maxAge: 0, path: "/api/auth/google" }) }
  });
  const url = new URL(request.url);
  const [state, ref] = (readCookie2(request, OAUTH_COOKIE) || "").split(".");
  if (!state || state !== url.searchParams.get("state") || !url.searchParams.get("code")) return fail("Google sign-in expired. Please try again.");
  const tokRes = await fetch(env.GOOGLE_TOKEN_URL || "https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code: url.searchParams.get("code"),
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${base}/api/auth/google/callback`,
      grant_type: "authorization_code"
    })
  });
  if (!tokRes.ok) return fail("Google sign-in failed. Please try again.");
  const tok = await tokRes.json();
  const infoRes = await fetch(env.GOOGLE_USERINFO_URL || "https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${tok.access_token}` }
  });
  if (!infoRes.ok) return fail("Google sign-in failed. Please try again.");
  const info = await infoRes.json();
  if (!info.sub || !info.email || info.email_verified !== true) return fail("Your Google email is not verified.");
  const email = String(info.email).toLowerCase();
  let u = await env.DB.prepare("SELECT * FROM users WHERE google_sub = ?").bind(info.sub).first() || await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (u && (u.deleted_at || u.suspended)) return fail("This account is suspended. Contact support.");
  if (u && !u.google_sub) {
    const stmts = [env.DB.prepare("UPDATE users SET google_sub = ?, email_verified = 1" + (u.email_verified ? "" : ", password_hash = NULL") + " WHERE id = ?").bind(info.sub, u.id)];
    if (!u.email_verified) stmts.push(env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id));
    await env.DB.batch(stmts);
  } else if (!u) {
    const id = newId();
    const name = String(info.name || "").slice(0, 80);
    await env.DB.prepare(
      `INSERT INTO users (id, email, email_verified, google_sub, full_name, business_name, ref_code, referrer_id)
       VALUES (?,?,1,?,?,?,?,?)`
    ).bind(id, email, info.sub, name, name, await genRefCode(env), await referrerIdFor(env, ref)).run();
    u = { id };
    ctx.waitUntil(notifyAdmin(env, "New VyCheckout signup (Google)", [`Name: ${name}`, `Email: ${email}`]));
  }
  const headers = new Headers({ Location: `${base}/` });
  headers.append("Set-Cookie", await createSession(env, u.id));
  headers.append("Set-Cookie", cookie(OAUTH_COOKIE, "", { maxAge: 0, path: "/api/auth/google" }));
  return new Response(null, { status: 302, headers });
}

// src/webhooks.js
var MAX_ATTEMPTS = 6;
var BACKOFF_MIN = [1, 5, 30, 120, 360, 720];
async function enqueueWebhook(env, ctx, userId, event, data) {
  const u = await env.DB.prepare("SELECT webhook_url, webhook_secret FROM users WHERE id = ?").bind(userId).first();
  if (!u?.webhook_url || !u.webhook_secret) return;
  const id = newId();
  const payload = JSON.stringify({ id, type: event, created: Math.floor(Date.now() / 1e3), data });
  await env.DB.prepare(
    "INSERT INTO webhook_deliveries (id, user_id, url, event, payload, next_attempt_at) VALUES (?,?,?,?,?,?)"
  ).bind(id, userId, u.webhook_url, event, payload, Date.now()).run();
  ctx.waitUntil(attempt(env, { id, user_id: userId, url: u.webhook_url, payload, attempts: 0 }));
}
async function attempt(env, row) {
  const u = await env.DB.prepare("SELECT webhook_secret FROM users WHERE id = ?").bind(row.user_id).first();
  if (!u?.webhook_secret) {
    await env.DB.prepare("UPDATE webhook_deliveries SET status = 'failed', last_error = 'webhook removed' WHERE id = ?").bind(row.id).run();
    return;
  }
  const t = Math.floor(Date.now() / 1e3);
  const sig = await hmacHex(u.webhook_secret, `${t}.${row.payload}`);
  let error = null;
  try {
    const res = await fetch(row.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "VyCheckout-Webhooks/1.0", "VyCheckout-Signature": `t=${t},v1=${sig}` },
      body: row.payload,
      redirect: "manual",
      signal: AbortSignal.timeout(1e4)
    });
    if (res.status < 200 || res.status >= 300) error = `HTTP ${res.status}`;
  } catch (e) {
    error = String(e?.message || e).slice(0, 200);
  }
  const attempts = row.attempts + 1;
  if (!error) {
    await env.DB.prepare("UPDATE webhook_deliveries SET status = 'delivered', attempts = ?, last_error = NULL WHERE id = ?").bind(attempts, row.id).run();
  } else if (attempts >= MAX_ATTEMPTS) {
    await env.DB.prepare("UPDATE webhook_deliveries SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?").bind(attempts, error, row.id).run();
  } else {
    const next = Date.now() + BACKOFF_MIN[attempts - 1] * 6e4;
    await env.DB.prepare("UPDATE webhook_deliveries SET attempts = ?, last_error = ?, next_attempt_at = ? WHERE id = ?").bind(attempts, error, next, row.id).run();
  }
}
async function retryDueWebhooks(env) {
  const { results } = await env.DB.prepare(
    // First attempts normally run right away; pick them up here only if that never happened (2+ min old)
    `SELECT * FROM webhook_deliveries WHERE status = 'pending'
       AND next_attempt_at <= CASE WHEN attempts = 0 THEN ?2 ELSE ?1 END
     ORDER BY next_attempt_at LIMIT 50`
  ).bind(Date.now(), Date.now() - 12e4).all();
  await Promise.all(results.map((r) => attempt(env, r)));
}

// src/payments.js
var feeBps = (env) => parseInt(env.PLATFORM_FEE_BPS || "1900", 10);
var refBps = (env) => parseInt(env.REFERRAL_BPS || "100", 10);
async function payableItem(env, itemId) {
  if (typeof itemId !== "string" || itemId.length > 64) throw notFound("This link is not valid.");
  const item = await env.DB.prepare(
    `SELECT i.*, u.business_name, u.full_name, u.suspended, u.deleted_at AS owner_deleted
     FROM items i JOIN users u ON u.id = i.user_id WHERE i.id = ? AND i.deleted_at IS NULL`
  ).bind(itemId).first();
  if (!item || item.owner_deleted) throw notFound("This link may have been removed.");
  if (item.suspended) throw bad("This merchant cannot accept payments right now.", "merchant_unavailable");
  if (item.expires_at && new Date(item.expires_at) < /* @__PURE__ */ new Date()) throw bad("This link has expired. Ask the sender for a new one.", "expired");
  return item;
}
function priceFor(env, item, requested) {
  if (!item.custom_amount) return item.amount_minor;
  if (requested == null || requested === "") throw bad("Enter an amount");
  const minor = toMinor(requested, item.currency);
  const min = isZeroDecimal(item.currency) ? 50 : 100;
  const max = toMinor(parseFloat(env.MAX_PAYMENT || "10000"), item.currency);
  if (minor < min) throw bad(`Minimum amount is ${majorString(min, item.currency)} ${item.currency}`);
  if (minor > max) throw bad(`Maximum amount is ${majorString(max, item.currency)} ${item.currency}`);
  return minor;
}
async function guardPayer(env, request) {
  await rateLimit(env, `order:${clientIp(request)}`, 40, 6e5);
  const user = await getSessionUser(env, request);
  if (!user) await requireHuman(env, request);
}
async function newOrder(env, request, provider) {
  const b = await readJson(request);
  await guardPayer(env, request);
  const item = await payableItem(env, b.item_id);
  if (item.type === "sub") throw bad("Subscriptions use the subscribe button", "use_subscription");
  const amount = priceFor(env, item, b.amount);
  if (amount <= 0) throw bad("Invalid amount");
  const order = { id: newId(), item_id: item.id, owner_id: item.user_id, provider, amount_minor: amount, currency: item.currency };
  await env.DB.prepare("INSERT INTO orders (id, item_id, owner_id, provider, amount_minor, currency) VALUES (?,?,?,?,?,?)").bind(order.id, order.item_id, order.owner_id, provider, amount, item.currency).run();
  return { order, item, body: b };
}
async function recordPayment(env, ctx, order, p) {
  if (p.currency !== order.currency || p.grossMinor !== order.amount_minor) {
    await audit(env, null, "payment_amount_mismatch", order.id || p.subscriptionId, { expected: [order.amount_minor, order.currency], got: [p.grossMinor, p.currency], ref: p.providerRef });
    ctx.waitUntil(alert(env, "Payment amount did not match", [
      `Provider: ${p.provider} ${p.providerRef}`,
      `Expected: ${money(order.amount_minor, order.currency)}`,
      `Got: ${money(p.grossMinor, p.currency)}`,
      "Nothing was credited. Check it in the PayPal/Stripe dashboard."
    ]));
    throw new HttpError(409, "Payment amount did not match the order. It has been flagged for review.", "amount_mismatch");
  }
  const item = await env.DB.prepare("SELECT id, type, name FROM items WHERE id = ?").bind(order.item_id).first();
  const owner = await env.DB.prepare("SELECT id, email, referrer_id, notify_sales, business_name, full_name FROM users WHERE id = ?").bind(order.owner_id).first();
  const gross = p.grossMinor;
  const fee = Math.round(gross * feeBps(env) / 1e4);
  const net = gross - fee;
  const referrer = owner?.referrer_id && owner.referrer_id !== owner.id ? owner.referrer_id : null;
  const refAmt = referrer ? Math.round(gross * refBps(env) / 1e4) : 0;
  const ownerAvail = await availableAtFor(env, order.owner_id);
  const refAvail = referrer ? await availableAtFor(env, referrer) : null;
  const txnId = newId();
  const onlyIfNew = "WHERE EXISTS (SELECT 1 FROM transactions WHERE id = ?)";
  const stmts = [
    env.DB.prepare(
      `INSERT OR IGNORE INTO transactions
        (id, owner_id, item_id, item_type, order_id, provider, provider_ref, description, payer_name, payer_email,
         currency, gross_minor, fee_minor, net_minor, referrer_id, referral_minor, subscription_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      txnId,
      order.owner_id,
      order.item_id,
      item?.type || null,
      order.id || null,
      p.provider,
      p.providerRef,
      item?.name || null,
      (p.payerName || "").slice(0, 120) || null,
      (p.payerEmail || "").slice(0, 254) || null,
      order.currency,
      gross,
      fee,
      net,
      referrer,
      refAmt,
      p.subscriptionId || null
    ),
    env.DB.prepare(`INSERT INTO ledger (id, user_id, currency, amount_minor, kind, txn_id, available_at) SELECT ?,?,?,?,'sale',?,? ${onlyIfNew}`).bind(newId(), order.owner_id, order.currency, net, txnId, ownerAvail, txnId)
  ];
  if (order.id) stmts.push(env.DB.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").bind(order.id));
  if (referrer && refAmt > 0) {
    stmts.push(env.DB.prepare(`INSERT INTO ledger (id, user_id, currency, amount_minor, kind, txn_id, available_at) SELECT ?,?,?,?,'referral',?,? ${onlyIfNew}`).bind(newId(), referrer, order.currency, refAmt, txnId, refAvail, txnId));
  }
  await env.DB.batch(stmts);
  const txn = await env.DB.prepare("SELECT * FROM transactions WHERE provider = ? AND provider_ref = ?").bind(p.provider, p.providerRef).first();
  if (txn.id === txnId) {
    const method = p.provider === "paypal" ? "PayPal" : "Card";
    const business = owner?.business_name || owner?.full_name || "VyCheckout";
    await enqueueWebhook(env, ctx, txn.owner_id, "payment.succeeded", {
      transaction_id: txn.id,
      item_id: txn.item_id,
      item_type: txn.item_type,
      description: txn.description,
      amount: toMajor(gross, txn.currency),
      net_amount: toMajor(net, txn.currency),
      currency: txn.currency,
      payer_name: txn.payer_name,
      payment_method: method,
      subscription_id: txn.subscription_id,
      created_at: txn.created_at
    });
    const base = env.APP_URL || "";
    if (txn.payer_email) ctx.waitUntil(payerReceiptEmail(env, {
      to: txn.payer_email,
      business,
      description: txn.description,
      grossMinor: gross,
      currency: txn.currency,
      txnId: txn.id,
      method,
      cancelUrl: p.cancelUrl
    }));
    if (owner?.notify_sales && owner.email) ctx.waitUntil(saleAlertEmail(env, {
      to: owner.email,
      description: txn.description,
      grossMinor: gross,
      netMinor: net,
      currency: txn.currency,
      availableAt: ownerAvail,
      payerName: txn.payer_name,
      appUrl: base || "your dashboard"
    }));
  }
  return txn;
}
async function applyRefund(env, ctx, txn, provider, refundRef, amountMinor) {
  const remaining = txn.gross_minor - txn.refunded_minor;
  const d = Math.min(Math.max(0, amountMinor), remaining);
  if (d <= 0) return;
  const refundId = newId();
  const merchantBack = Math.round(d * txn.net_minor / txn.gross_minor);
  const referralBack = txn.referral_minor ? Math.round(d * txn.referral_minor / txn.gross_minor) : 0;
  const holdOf = async (kind) => {
    const r = await env.DB.prepare("SELECT available_at FROM ledger WHERE txn_id = ? AND kind = ?").bind(txn.id, kind).first();
    return r?.available_at && r.available_at > nowIso() ? r.available_at : null;
  };
  const onlyIfNew = "WHERE EXISTS (SELECT 1 FROM refunds WHERE id = ?)";
  const stmts = [
    env.DB.prepare("INSERT OR IGNORE INTO refunds (id, provider, provider_refund_id, txn_id, amount_minor) VALUES (?,?,?,?,?)").bind(refundId, provider, refundRef, txn.id, d),
    env.DB.prepare(`INSERT INTO ledger (id, user_id, currency, amount_minor, kind, txn_id, note, available_at) SELECT ?,?,?,?,'refund',?,?,? ${onlyIfNew}`).bind(newId(), txn.owner_id, txn.currency, -merchantBack, txn.id, refundRef, await holdOf("sale"), refundId),
    env.DB.prepare(
      `UPDATE transactions SET refunded_minor = refunded_minor + ?,
         status = CASE WHEN refunded_minor + ? >= gross_minor THEN 'refunded' ELSE 'partially_refunded' END
       WHERE id = ? AND EXISTS (SELECT 1 FROM refunds WHERE id = ?)`
    ).bind(d, d, txn.id, refundId)
  ];
  if (txn.referrer_id && referralBack > 0) {
    stmts.push(env.DB.prepare(`INSERT INTO ledger (id, user_id, currency, amount_minor, kind, txn_id, note, available_at) SELECT ?,?,?,?,'referral_reversal',?,?,? ${onlyIfNew}`).bind(newId(), txn.referrer_id, txn.currency, -referralBack, txn.id, refundRef, await holdOf("referral"), refundId));
  }
  await env.DB.batch(stmts);
  const applied = await env.DB.prepare("SELECT 1 FROM refunds WHERE id = ?").bind(refundId).first();
  if (!applied) return;
  await enqueueWebhook(env, ctx, txn.owner_id, "payment.refunded", {
    transaction_id: txn.id,
    refunded_amount: toMajor(d, txn.currency),
    currency: txn.currency
  });
  const bal = await env.DB.prepare(
    `SELECT (SELECT COALESCE(SUM(amount_minor),0) FROM ledger WHERE user_id = ?1 AND currency = ?2)
          - (SELECT COALESCE(SUM(amount_minor),0) FROM withdrawals WHERE user_id = ?1 AND currency = ?2 AND status != 'rejected') AS b`
  ).bind(txn.owner_id, txn.currency).first();
  if (bal.b < 0) {
    const u = await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(txn.owner_id).first();
    ctx.waitUntil(alert(env, "Merchant balance is negative after a refund", [
      `Merchant: ${u?.email}`,
      `Balance: ${money(bal.b, txn.currency)}`,
      `Refund: ${money(d, txn.currency)} on ${txn.id}`,
      "Their next sales will cover it; withdrawals are blocked until then."
    ]));
  }
}
async function receiptView(env, txn) {
  const owner = await env.DB.prepare("SELECT business_name, full_name FROM users WHERE id = ?").bind(txn.owner_id).first();
  return {
    id: txn.id,
    amount: toMajor(txn.gross_minor, txn.currency),
    currency: txn.currency,
    description: txn.description,
    business: owner?.business_name || owner?.full_name || "VyCheckout",
    method: txn.provider === "paypal" ? "PayPal" : "Card",
    created_at: txn.created_at
  };
}
var ppBase = (env) => env.PAYPAL_API_BASE || (env.PAYPAL_ENV === "sandbox" ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com");
var ppTokenCache = null;
async function ppToken(env) {
  if (ppTokenCache && ppTokenCache.cid === env.PAYPAL_CLIENT_ID && ppTokenCache.exp > Date.now() + 6e4) return ppTokenCache.token;
  if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) throw new HttpError(503, "PayPal is not set up", "paypal_unconfigured");
  const res = await fetch(`${ppBase(env)}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`), "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials"
  });
  if (!res.ok) {
    console.error("PayPal auth failed", res.status, await res.text());
    throw new HttpError(502, "PayPal is unavailable, please try again");
  }
  const d = await res.json();
  ppTokenCache = { cid: env.PAYPAL_CLIENT_ID, token: d.access_token, exp: Date.now() + d.expires_in * 1e3 };
  return d.access_token;
}
async function pp(env, path, { method = "GET", body, requestId } = {}) {
  const headers = { Authorization: `Bearer ${await ppToken(env)}`, "Content-Type": "application/json" };
  if (requestId) headers["PayPal-Request-Id"] = requestId;
  const res = await fetch(`${ppBase(env)}${path}`, { method, headers, body: body ? JSON.stringify(body) : void 0 });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
  }
  return { ok: res.ok, status: res.status, data };
}
async function paypalCreateOrder(env, request) {
  const { order, item } = await newOrder(env, request, "paypal");
  const r = await pp(env, "/v2/checkout/orders", {
    method: "POST",
    requestId: `create-${order.id}`,
    body: {
      intent: "CAPTURE",
      purchase_units: [{
        reference_id: order.id,
        custom_id: order.id,
        description: String(item.name).slice(0, 127),
        amount: { currency_code: order.currency, value: majorString(order.amount_minor, order.currency) }
      }]
    }
  });
  if (!r.ok || !r.data?.id) {
    console.error("PayPal create failed", r.status, JSON.stringify(r.data));
    throw new HttpError(502, "Could not start PayPal checkout");
  }
  await env.DB.prepare("UPDATE orders SET provider_order_id = ? WHERE id = ?").bind(r.data.id, order.id).run();
  return json({ id: r.data.id });
}
async function recordFromPayPalOrder(env, ctx, order, ppOrder) {
  const pu = ppOrder?.purchase_units?.[0];
  const cap = pu?.payments?.captures?.[0];
  if (!cap) throw new HttpError(402, "The payment was not completed.", "not_captured");
  if (cap.status === "PENDING") return { pending: true };
  if (cap.status !== "COMPLETED") throw new HttpError(402, "The payment was not completed.", "not_captured");
  if ((cap.custom_id || pu.custom_id) !== order.id) throw new HttpError(409, "Payment does not belong to this order.");
  const payer = ppOrder.payer || {};
  const txn = await recordPayment(env, ctx, order, {
    provider: "paypal",
    providerRef: cap.id,
    grossMinor: toMinor(cap.amount.value, cap.amount.currency_code),
    currency: cap.amount.currency_code,
    payerName: [payer.name?.given_name, payer.name?.surname].filter(Boolean).join(" ") || payer.email_address || "",
    payerEmail: payer.email_address || ""
  });
  return { txn };
}
async function paypalCapture(env, request, ctx) {
  const b = await readJson(request);
  if (typeof b.order_id !== "string" || b.order_id.length > 64) throw bad("Invalid order");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE provider = 'paypal' AND provider_order_id = ?").bind(b.order_id).first();
  if (!order) throw notFound("Order not found");
  let r = await pp(env, `/v2/checkout/orders/${encodeURIComponent(b.order_id)}/capture`, { method: "POST", requestId: `capture-${order.id}` });
  if (!r.ok && r.data?.details?.some((d) => d.issue === "ORDER_ALREADY_CAPTURED")) {
    r = await pp(env, `/v2/checkout/orders/${encodeURIComponent(b.order_id)}`);
  }
  if (!r.ok) {
    const issue = r.data?.details?.[0]?.issue;
    if (issue === "INSTRUMENT_DECLINED") throw new HttpError(402, "Your payment method was declined. Please try another one.", "declined");
    console.error("PayPal capture failed", r.status, JSON.stringify(r.data));
    throw new HttpError(502, "PayPal could not complete the payment. You have not been charged.");
  }
  const res = await recordFromPayPalOrder(env, ctx, order, r.data);
  if (res.pending) return json({ pending: true, message: "PayPal is still processing this payment. It will appear once PayPal confirms it." });
  return json({ receipt: await receiptView(env, res.txn) });
}
var stripeBase = (env) => env.STRIPE_API_BASE || "https://api.stripe.com";
var STRIPE_VERSION = "2024-06-20";
async function stripe(env, path, { method = "GET", form, idempotencyKey } = {}) {
  if (!env.STRIPE_SECRET_KEY) throw new HttpError(503, "Card payments are not set up", "stripe_unconfigured");
  const headers = { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "Stripe-Version": STRIPE_VERSION };
  if (form) headers["Content-Type"] = "application/x-www-form-urlencoded";
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const res = await fetch(`${stripeBase(env)}${path}`, { method, headers, body: form ? new URLSearchParams(form).toString() : void 0 });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}
async function stripeCreateIntent(env, request) {
  const { order, item, body } = await newOrder(env, request, "stripe");
  let email = "";
  if (body.payer_email) email = emailOf(body.payer_email);
  const form = {
    amount: String(order.amount_minor),
    currency: order.currency.toLowerCase(),
    description: String(item.name).slice(0, 200),
    "payment_method_types[]": "card",
    "metadata[order_id]": order.id,
    "metadata[item_id]": item.id
  };
  if (email) {
    form.receipt_email = email;
    form["metadata[payer_email]"] = email;
  }
  const r = await stripe(env, "/v1/payment_intents", { method: "POST", idempotencyKey: `pi-${order.id}`, form });
  if (!r.ok || !r.data?.client_secret) {
    console.error("Stripe create failed", r.status, JSON.stringify(r.data?.error));
    throw new HttpError(502, "Could not start card payment");
  }
  await env.DB.prepare("UPDATE orders SET provider_order_id = ? WHERE id = ?").bind(r.data.id, order.id).run();
  return json({ client_secret: r.data.client_secret, intent_id: r.data.id });
}
async function recordFromIntent(env, ctx, pi, payer = {}) {
  const orderId = pi?.metadata?.order_id;
  const order = orderId && await env.DB.prepare("SELECT * FROM orders WHERE id = ? AND provider = 'stripe'").bind(orderId).first();
  if (!order || order.provider_order_id !== pi.id) throw notFound("Order not found");
  if (pi.status !== "succeeded") throw new HttpError(402, "The card payment did not complete.", "not_paid");
  return recordPayment(env, ctx, order, {
    provider: "stripe",
    providerRef: pi.id,
    grossMinor: pi.amount_received,
    currency: String(pi.currency).toUpperCase(),
    payerName: payer.name || "",
    payerEmail: payer.email || pi.metadata?.payer_email || pi.receipt_email || ""
  });
}
async function stripeConfirm(env, request, ctx) {
  const b = await readJson(request);
  if (typeof b.intent_id !== "string" || !/^pi_[A-Za-z0-9]+$/.test(b.intent_id)) throw bad("Invalid payment");
  const r = await stripe(env, `/v1/payment_intents/${b.intent_id}?expand[]=latest_charge`);
  if (!r.ok) throw notFound("Payment not found");
  const bd = r.data.latest_charge?.billing_details || {};
  const txn = await recordFromIntent(env, ctx, r.data, { name: bd.name, email: bd.email });
  return json({ receipt: await receiptView(env, txn) });
}
async function verifyStripeSignature(env, header, raw) {
  if (!env.STRIPE_WEBHOOK_SECRET || !header) return false;
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")).filter((p) => p.length === 2).map(([k, v]) => [k.trim(), v.trim()]));
  const sigs = header.split(",").filter((p) => p.trim().startsWith("v1=")).map((p) => p.trim().slice(3));
  const t = parseInt(parts.t, 10);
  if (!t || Math.abs(Date.now() / 1e3 - t) > 300) return false;
  const expected = await hmacHex(env.STRIPE_WEBHOOK_SECRET, `${t}.${raw}`);
  return sigs.some((s) => safeEqual(s, expected));
}
async function stripeOneTimeEvent(env, ctx, event) {
  const obj = event.data?.object || {};
  if (event.type === "payment_intent.succeeded") {
    if (obj.metadata?.order_id) await recordFromIntent(env, ctx, obj).catch((e) => {
      if (!(e instanceof HttpError)) throw e;
    });
    return true;
  }
  if (event.type === "charge.refunded") {
    const txn = obj.payment_intent && await env.DB.prepare("SELECT * FROM transactions WHERE provider = 'stripe' AND provider_ref = ?").bind(obj.payment_intent).first();
    if (txn) await applyRefund(env, ctx, txn, "stripe", `${obj.id}:${obj.amount_refunded}`, obj.amount_refunded - txn.refunded_minor);
    return true;
  }
  if (event.type === "charge.dispute.created") {
    ctx.waitUntil(alert(env, "New card dispute (chargeback)", [
      `Amount: ${money(obj.amount, String(obj.currency || "usd").toUpperCase())}`,
      `Reason: ${obj.reason}`,
      `Respond in the Stripe dashboard: https://dashboard.stripe.com/disputes/${obj.id}`
    ]));
    return true;
  }
  if (event.type === "charge.dispute.funds_withdrawn") {
    const txn = obj.payment_intent && await env.DB.prepare("SELECT * FROM transactions WHERE provider = 'stripe' AND provider_ref = ?").bind(obj.payment_intent).first();
    if (txn) await applyRefund(env, ctx, txn, "stripe", `dispute-${obj.id}`, obj.amount);
    return true;
  }
  return false;
}
async function paypalOneTimeEvent(env, ctx, event) {
  const res = event.resource || {};
  if (event.event_type === "PAYMENT.CAPTURE.COMPLETED") {
    const order = res.custom_id && await env.DB.prepare("SELECT * FROM orders WHERE id = ? AND provider = 'paypal'").bind(res.custom_id).first();
    if (order) {
      await recordPayment(env, ctx, order, {
        provider: "paypal",
        providerRef: res.id,
        grossMinor: toMinor(res.amount.value, res.amount.currency_code),
        currency: res.amount.currency_code
      }).catch((e) => {
        if (!(e instanceof HttpError)) throw e;
      });
    }
    return true;
  }
  if (event.event_type === "PAYMENT.CAPTURE.REFUNDED") {
    const captureId = (res.links || []).find((l) => l.rel === "up")?.href?.split("/").pop();
    const txn = captureId && await env.DB.prepare("SELECT * FROM transactions WHERE provider = 'paypal' AND provider_ref = ?").bind(captureId).first();
    if (txn) await applyRefund(env, ctx, txn, "paypal", res.id, toMinor(res.amount.value, res.amount.currency_code));
    return true;
  }
  if (event.event_type === "PAYMENT.CAPTURE.REVERSED") {
    const txn = await env.DB.prepare("SELECT * FROM transactions WHERE provider = 'paypal' AND provider_ref = ?").bind(res.id).first();
    if (txn) await applyRefund(env, ctx, txn, "paypal", `reversal-${event.id}`, txn.gross_minor);
    return true;
  }
  if (event.event_type === "CUSTOMER.DISPUTE.CREATED") {
    const amt = res.dispute_amount || {};
    ctx.waitUntil(alert(env, "New PayPal dispute", [
      `Amount: ${amt.value || "?"} ${amt.currency_code || ""}`,
      `Reason: ${res.reason || "?"}`,
      `Respond in PayPal Resolution Center (dispute ${res.dispute_id || ""}).`
    ]));
    return true;
  }
  return false;
}
async function verifyPayPalWebhook(env, request, event) {
  if (!env.PAYPAL_WEBHOOK_ID) return false;
  const h = (n) => request.headers.get(n);
  const v = await pp(env, "/v1/notifications/verify-webhook-signature", {
    method: "POST",
    body: {
      auth_algo: h("paypal-auth-algo"),
      cert_url: h("paypal-cert-url"),
      transmission_id: h("paypal-transmission-id"),
      transmission_sig: h("paypal-transmission-sig"),
      transmission_time: h("paypal-transmission-time"),
      webhook_id: env.PAYPAL_WEBHOOK_ID,
      webhook_event: event
    }
  });
  return v.ok && v.data?.verification_status === "SUCCESS";
}

// src/subscriptions.js
var CYCLES = {
  WEEKLY: { stripe: ["week", 1], paypal: ["WEEK", 1] },
  MONTHLY: { stripe: ["month", 1], paypal: ["MONTH", 1] },
  QUARTERLY: { stripe: ["month", 3], paypal: ["MONTH", 3] },
  ANNUALLY: { stripe: ["year", 1], paypal: ["YEAR", 1] }
};
var cycleOf = (c) => CYCLES[c] || CYCLES.MONTHLY;
var cancelUrl = (env, row) => `${(env.APP_URL || "").replace(/\/$/, "")}/?cancel_sub=${encodeURIComponent(row.cancel_token)}`;
var orderFor = (row) => ({ id: null, owner_id: row.owner_id, item_id: row.item_id, amount_minor: row.amount_minor, currency: row.currency });
async function startRow(env, request, provider) {
  const b = await readJson(request);
  await guardPayer(env, request);
  const item = await payableItem(env, b.item_id);
  if (item.type !== "sub") throw bad("This link is not a subscription");
  const row = {
    id: newId(),
    item_id: item.id,
    owner_id: item.user_id,
    provider,
    payer_email: emailOf(b.email),
    payer_name: str(b.name, { max: 120, field: "Name" }) || null,
    amount_minor: item.amount_minor,
    currency: item.currency,
    cycle: item.cycle || "MONTHLY",
    cancel_token: randomToken(24)
  };
  await env.DB.prepare(
    `INSERT INTO subscriptions (id, item_id, owner_id, provider, payer_email, payer_name, amount_minor, currency, cycle, cancel_token)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(row.id, row.item_id, row.owner_id, provider, row.payer_email, row.payer_name, row.amount_minor, row.currency, row.cycle, row.cancel_token).run();
  return { row, item };
}
function subReceipt(env, row, item, business, extra = {}) {
  return {
    id: row.id,
    amount: toMajor(row.amount_minor, row.currency),
    currency: row.currency,
    description: `${item.name} (${row.cycle.toLowerCase()})`,
    business,
    method: row.provider === "paypal" ? "PayPal" : "Card",
    created_at: nowIso(),
    ...extra
  };
}
async function setStatus(env, row, status) {
  if (row.status === status) return;
  const now = nowIso();
  await env.DB.prepare(
    `UPDATE subscriptions SET status = ?,
       activated_at = CASE WHEN ? = 'active' AND activated_at IS NULL THEN ? ELSE activated_at END,
       cancelled_at = CASE WHEN ? = 'cancelled' THEN ? ELSE cancelled_at END
     WHERE id = ?`
  ).bind(status, status, now, status, now, row.id).run();
  row.status = status;
}
async function ensureStripeProduct(env, item) {
  if (item.stripe_product_id) return item.stripe_product_id;
  const r = await stripe(env, "/v1/products", {
    method: "POST",
    idempotencyKey: `prod-${item.id}`,
    form: { name: String(item.name).slice(0, 200), "metadata[item_id]": item.id }
  });
  if (!r.ok) {
    console.error("Stripe product failed", JSON.stringify(r.data?.error));
    throw new HttpError(502, "Could not set up the subscription");
  }
  await env.DB.prepare("UPDATE items SET stripe_product_id = ? WHERE id = ?").bind(r.data.id, item.id).run();
  return r.data.id;
}
async function stripeSubscribe(env, request) {
  const { row, item } = await startRow(env, request, "stripe");
  const product = await ensureStripeProduct(env, item);
  const cust = await stripe(env, "/v1/customers", {
    method: "POST",
    idempotencyKey: `cus-${row.id}`,
    form: { email: row.payer_email, ...row.payer_name ? { name: row.payer_name } : {}, "metadata[sub_id]": row.id }
  });
  if (!cust.ok) throw new HttpError(502, "Could not start the subscription");
  const [interval, count] = cycleOf(row.cycle).stripe;
  const sub = await stripe(env, "/v1/subscriptions", {
    method: "POST",
    idempotencyKey: `sub-${row.id}`,
    form: {
      customer: cust.data.id,
      "items[0][price_data][currency]": row.currency.toLowerCase(),
      "items[0][price_data][product]": product,
      "items[0][price_data][unit_amount]": String(row.amount_minor),
      "items[0][price_data][recurring][interval]": interval,
      "items[0][price_data][recurring][interval_count]": String(count),
      payment_behavior: "default_incomplete",
      "payment_settings[save_default_payment_method]": "on_subscription",
      "payment_settings[payment_method_types][]": "card",
      "metadata[sub_id]": row.id,
      "metadata[item_id]": item.id,
      "expand[]": "latest_invoice.payment_intent"
    }
  });
  const secret = sub.data?.latest_invoice?.payment_intent?.client_secret;
  if (!sub.ok || !secret) {
    console.error("Stripe subscription failed", JSON.stringify(sub.data?.error));
    throw new HttpError(502, "Could not start the subscription");
  }
  await env.DB.prepare("UPDATE subscriptions SET provider_sub_id = ?, stripe_customer_id = ? WHERE id = ?").bind(sub.data.id, cust.data.id, row.id).run();
  return json({ client_secret: secret, subscription_id: sub.data.id });
}
async function recordStripeInvoice(env, ctx, row, inv) {
  if (!inv || inv.status !== "paid" || !inv.amount_paid) return null;
  const piId = typeof inv.payment_intent === "string" ? inv.payment_intent : inv.payment_intent?.id;
  const txn = await recordPayment(env, ctx, orderFor(row), {
    provider: "stripe",
    providerRef: piId || inv.id,
    grossMinor: inv.amount_paid,
    currency: String(inv.currency).toUpperCase(),
    payerName: row.payer_name,
    payerEmail: row.payer_email,
    subscriptionId: row.id,
    cancelUrl: cancelUrl(env, row)
  });
  await setStatus(env, row, "active");
  return txn;
}
async function stripeSubscribeConfirm(env, request, ctx) {
  const b = await readJson(request);
  if (typeof b.subscription_id !== "string" || !/^sub_[A-Za-z0-9]+$/.test(b.subscription_id)) throw bad("Invalid subscription");
  const row = await env.DB.prepare("SELECT * FROM subscriptions WHERE provider = 'stripe' AND provider_sub_id = ?").bind(b.subscription_id).first();
  if (!row) throw notFound("Subscription not found");
  const r = await stripe(env, `/v1/subscriptions/${b.subscription_id}?expand[]=latest_invoice`);
  if (!r.ok || r.data.metadata?.sub_id !== row.id) throw notFound("Subscription not found");
  const txn = await recordStripeInvoice(env, ctx, row, r.data.latest_invoice);
  if (!txn) throw new HttpError(402, "The first payment has not gone through yet.", "not_paid");
  return json({ receipt: { ...await receiptView(env, txn), subscription: true } });
}
var STRIPE_STATUS = { active: "active", trialing: "active", past_due: "past_due", unpaid: "past_due", canceled: "cancelled", incomplete_expired: "cancelled" };
async function stripeSubscriptionEvent(env, ctx, event) {
  const obj = event.data?.object || {};
  if (event.type === "invoice.paid" || event.type === "invoice.payment_failed") {
    const r = await stripe(env, `/v1/invoices/${obj.id}`);
    const inv = r.ok ? r.data : null;
    const subId = inv?.subscription;
    const row = subId && await env.DB.prepare("SELECT * FROM subscriptions WHERE provider = 'stripe' AND provider_sub_id = ?").bind(subId).first();
    if (!row) return true;
    if (event.type === "invoice.paid") await recordStripeInvoice(env, ctx, row, inv).catch((e) => {
      if (!(e instanceof HttpError)) throw e;
    });
    else if (row.status === "active") await setStatus(env, row, "past_due");
    return true;
  }
  if (event.type === "customer.subscription.deleted" || event.type === "customer.subscription.updated") {
    const row = await env.DB.prepare("SELECT * FROM subscriptions WHERE provider = 'stripe' AND provider_sub_id = ?").bind(obj.id).first();
    const st = event.type === "customer.subscription.deleted" ? "cancelled" : STRIPE_STATUS[obj.status];
    if (row && st && !(row.status === "pending" && st === "past_due")) await setStatus(env, row, st);
    return true;
  }
  return false;
}
async function ensurePayPalPlan(env, item) {
  if (item.paypal_plan_id) return item.paypal_plan_id;
  let productId = item.paypal_product_id;
  if (!productId) {
    const p = await pp(env, "/v1/catalogs/products", {
      method: "POST",
      requestId: `prod-${item.id}`,
      body: { name: String(item.name).slice(0, 127), type: "SERVICE", category: "SOFTWARE" }
    });
    if (!p.ok) {
      console.error("PayPal product failed", JSON.stringify(p.data));
      throw new HttpError(502, "Could not set up the subscription");
    }
    productId = p.data.id;
    await env.DB.prepare("UPDATE items SET paypal_product_id = ? WHERE id = ?").bind(productId, item.id).run();
  }
  const [unit, count] = cycleOf(item.cycle).paypal;
  const plan = await pp(env, "/v1/billing/plans", {
    method: "POST",
    requestId: `plan-${item.id}`,
    body: {
      product_id: productId,
      name: String(item.name).slice(0, 127),
      status: "ACTIVE",
      billing_cycles: [{
        frequency: { interval_unit: unit, interval_count: count },
        tenure_type: "REGULAR",
        sequence: 1,
        total_cycles: 0,
        pricing_scheme: { fixed_price: { value: majorString(item.amount_minor, item.currency), currency_code: item.currency } }
      }],
      payment_preferences: { auto_bill_outstanding: true, payment_failure_threshold: 3 }
    }
  });
  if (!plan.ok) {
    console.error("PayPal plan failed", JSON.stringify(plan.data));
    throw new HttpError(502, "Could not set up the subscription");
  }
  await env.DB.prepare("UPDATE items SET paypal_plan_id = ? WHERE id = ?").bind(plan.data.id, item.id).run();
  return plan.data.id;
}
async function paypalSubscribeStart(env, request) {
  const { row, item } = await startRow(env, request, "paypal");
  const planId = await ensurePayPalPlan(env, item);
  return json({ plan_id: planId, custom_id: row.id, email: row.payer_email });
}
async function syncPayPalPayments(env, ctx, row) {
  if (!row.provider_sub_id) return [];
  const start = new Date(new Date(row.created_at).getTime() - 864e5).toISOString();
  const end = new Date(Date.now() + 864e5).toISOString();
  const r = await pp(env, `/v1/billing/subscriptions/${encodeURIComponent(row.provider_sub_id)}/transactions?start_time=${start}&end_time=${end}`);
  if (!r.ok) return [];
  const out = [];
  for (const t of r.data?.transactions || []) {
    if (t.status !== "COMPLETED") continue;
    const gross = t.amount_with_breakdown?.gross_amount;
    if (!gross) continue;
    const txn = await recordPayment(env, ctx, orderFor(row), {
      provider: "paypal",
      providerRef: t.id,
      grossMinor: toMinor(gross.value, gross.currency_code),
      currency: gross.currency_code,
      payerName: row.payer_name || [t.payer_name?.given_name, t.payer_name?.surname].filter(Boolean).join(" "),
      payerEmail: row.payer_email,
      subscriptionId: row.id,
      cancelUrl: cancelUrl(env, row)
    }).catch((e) => {
      if (e instanceof HttpError) return null;
      throw e;
    });
    if (txn) out.push(txn);
  }
  return out;
}
var PAYPAL_STATUS = { ACTIVE: "active", APPROVED: "active", SUSPENDED: "past_due", CANCELLED: "cancelled", EXPIRED: "cancelled" };
async function paypalSubscribeActivate(env, request, ctx) {
  const b = await readJson(request);
  if (typeof b.subscription_id !== "string" || !/^I-[A-Z0-9]+$/.test(b.subscription_id)) throw bad("Invalid subscription");
  const r = await pp(env, `/v1/billing/subscriptions/${encodeURIComponent(b.subscription_id)}`);
  if (!r.ok) throw notFound("Subscription not found");
  const row = await env.DB.prepare("SELECT * FROM subscriptions WHERE id = ? AND provider = 'paypal'").bind(r.data.custom_id || "").first();
  if (!row) throw notFound("Subscription not found");
  const item = await env.DB.prepare("SELECT i.*, u.business_name, u.full_name FROM items i JOIN users u ON u.id = i.user_id WHERE i.id = ?").bind(row.item_id).first();
  if (r.data.plan_id !== item.paypal_plan_id) throw new HttpError(409, "Subscription does not match this plan.");
  if (row.provider_sub_id && row.provider_sub_id !== b.subscription_id) throw new HttpError(409, "Subscription already linked.");
  const st = PAYPAL_STATUS[r.data.status];
  if (st !== "active") throw new HttpError(402, "PayPal has not activated this subscription.", "not_active");
  await env.DB.prepare("UPDATE subscriptions SET provider_sub_id = ? WHERE id = ?").bind(b.subscription_id, row.id).run();
  row.provider_sub_id = b.subscription_id;
  await setStatus(env, row, "active");
  const paid = await syncPayPalPayments(env, ctx, row);
  const business = item.business_name || item.full_name || "VyCheckout";
  if (paid.length) return json({ receipt: { ...await receiptView(env, paid[0]), subscription: true } });
  return json({ receipt: subReceipt(env, row, item, business, { subscription: true, pending: true }) });
}
async function paypalSubscriptionEvent(env, ctx, event) {
  const res = event.resource || {};
  const t = event.event_type;
  if (t === "PAYMENT.SALE.COMPLETED") {
    const row = res.billing_agreement_id && await env.DB.prepare("SELECT * FROM subscriptions WHERE provider = 'paypal' AND provider_sub_id = ?").bind(res.billing_agreement_id).first();
    if (row) await syncPayPalPayments(env, ctx, row);
    return true;
  }
  if (t === "PAYMENT.SALE.REFUNDED" || t === "PAYMENT.SALE.REVERSED") {
    const saleId = res.sale_id || res.id;
    const txn = saleId && await env.DB.prepare("SELECT * FROM transactions WHERE provider = 'paypal' AND provider_ref = ?").bind(saleId).first();
    if (txn) {
      const amt = res.amount?.total ? toMinor(res.amount.total, res.amount.currency || txn.currency) : txn.gross_minor;
      await applyRefund(env, ctx, txn, "paypal", `${t}-${res.id}`, amt);
    }
    return true;
  }
  if (t.startsWith("BILLING.SUBSCRIPTION.")) {
    const row = await env.DB.prepare("SELECT * FROM subscriptions WHERE provider = 'paypal' AND (provider_sub_id = ? OR id = ?)").bind(res.id || "", res.custom_id || "").first();
    if (!row) return true;
    if (t === "BILLING.SUBSCRIPTION.PAYMENT.FAILED") await setStatus(env, row, "past_due");
    else if (PAYPAL_STATUS[res.status]) {
      if (!row.provider_sub_id && res.id && res.custom_id === row.id) {
        await env.DB.prepare("UPDATE subscriptions SET provider_sub_id = ? WHERE id = ?").bind(res.id, row.id).run();
        row.provider_sub_id = res.id;
      }
      await setStatus(env, row, PAYPAL_STATUS[res.status]);
      if (row.status === "active") await syncPayPalPayments(env, ctx, row);
    }
    return true;
  }
  return false;
}
async function cancelAtProvider(env, row, reason) {
  if (row.status === "cancelled") return;
  if (row.provider_sub_id) {
    const r = row.provider === "stripe" ? await stripe(env, `/v1/subscriptions/${row.provider_sub_id}`, { method: "DELETE" }) : await pp(env, `/v1/billing/subscriptions/${encodeURIComponent(row.provider_sub_id)}/cancel`, { method: "POST", body: { reason: String(reason).slice(0, 120) } });
    if (!r.ok && ![404, 422].includes(r.status)) {
      console.error("Cancel failed", row.provider, r.status, JSON.stringify(r.data));
      throw new HttpError(502, "Could not cancel with the payment provider. Please try again.");
    }
  }
  await setStatus(env, row, "cancelled");
}
async function merchantCancel(env, request, id) {
  const u = await requireUser(env, request);
  const row = await env.DB.prepare("SELECT * FROM subscriptions WHERE id = ? AND owner_id = ?").bind(id, u.id).first();
  if (!row) throw notFound("Subscription not found");
  await cancelAtProvider(env, row, "Cancelled by the merchant");
  await audit(env, u.id, "subscription_cancel", id);
  return json({ ok: true });
}
async function rowByToken(env, token) {
  if (typeof token !== "string" || token.length < 20 || token.length > 64) throw notFound("This cancel link is not valid.");
  const row = await env.DB.prepare(
    `SELECT s.*, i.name AS item_name, u.business_name, u.full_name FROM subscriptions s
     JOIN items i ON i.id = s.item_id JOIN users u ON u.id = s.owner_id WHERE s.cancel_token = ?`
  ).bind(token).first();
  if (!row) throw notFound("This cancel link is not valid.");
  return row;
}
async function publicLookup(env, request) {
  const row = await rowByToken(env, (await readJson(request)).token);
  return json({
    item: row.item_name,
    business: row.business_name || row.full_name,
    amount: toMajor(row.amount_minor, row.currency),
    currency: row.currency,
    cycle: row.cycle,
    status: row.status,
    email: row.payer_email.replace(/^(.).*(@.*)$/, "$1\u2022\u2022\u2022$2")
  });
}
async function publicCancel(env, request) {
  const row = await rowByToken(env, (await readJson(request)).token);
  await cancelAtProvider(env, row, "Cancelled by the subscriber");
  return json({ ok: true });
}
async function listForOwner(env, ownerId) {
  const { results } = await env.DB.prepare(
    `SELECT s.id, s.item_id, s.provider, s.payer_email, s.payer_name, s.amount_minor, s.currency, s.cycle, s.status, s.created_at, s.activated_at, s.cancelled_at
     FROM subscriptions s WHERE s.owner_id = ? AND s.status != 'pending' ORDER BY s.created_at DESC LIMIT 500`
  ).bind(ownerId).all();
  return results.map((s) => ({ ...s, amount: toMajor(s.amount_minor, s.currency), amount_minor: void 0, method: s.provider === "paypal" ? "PayPal" : "Card" }));
}
async function cleanupPending(env) {
  await env.DB.prepare("DELETE FROM subscriptions WHERE status = 'pending' AND created_at < ?").bind(new Date(Date.now() - 2 * 864e5).toISOString()).run();
}

// src/media.js
var MAX_BYTES = 3 * 1024 * 1024;
var TYPES = { jpg: "image/jpeg", png: "image/png", webp: "image/webp" };
function sniff(b) {
  if (b[0] === 255 && b[1] === 216 && b[2] === 255) return "jpg";
  if (b[0] === 137 && b[1] === 80 && b[2] === 78 && b[3] === 71) return "png";
  if (b[0] === 82 && b[1] === 73 && b[2] === 70 && b[3] === 70 && b[8] === 87 && b[9] === 69 && b[10] === 66 && b[11] === 80) return "webp";
  return null;
}
async function upload(env, request) {
  const u = await requireUser(env, request);
  if (!env.MEDIA) throw new HttpError(503, "Photo uploads are not set up yet.", "media_off");
  const kind = new URL(request.url).searchParams.get("kind") === "avatar" ? "avatar" : "post";
  await rateLimit(env, `media:${u.id}`, 60, 36e5);
  const len = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (len > MAX_BYTES) throw bad("That photo is too large (max 3 MB).");
  const buf = new Uint8Array(await request.arrayBuffer());
  if (!buf.length) throw bad("No photo received.");
  if (buf.length > MAX_BYTES) throw bad("That photo is too large (max 3 MB).");
  const ext = sniff(buf);
  if (!ext) throw bad("Use a JPG, PNG or WebP photo.");
  const key = `${kind === "avatar" ? "a" : "p"}/${newId()}.${ext}`;
  await env.MEDIA.put(key, buf, { httpMetadata: { contentType: TYPES[ext] } });
  await env.DB.prepare("INSERT INTO media (key, user_id, kind, bytes) VALUES (?,?,?,?)").bind(key, u.id, kind, buf.length).run();
  return json({ key, url: mediaUrl(key) });
}
async function serve(env, request, key) {
  if (!env.MEDIA || !MEDIA_KEY_RE.test(key)) throw notFound();
  const etag = request.headers.get("If-None-Match");
  const obj = await env.MEDIA.get(key);
  if (!obj) throw notFound();
  const headers = {
    "Content-Type": TYPES[key.split(".").pop()],
    "Cache-Control": "public, max-age=31536000, immutable",
    "ETag": obj.httpEtag,
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox"
  };
  if (etag && etag === obj.httpEtag) return new Response(null, { status: 304, headers });
  return new Response(obj.body, { headers });
}
async function ownedKey(env, userId, key, kind) {
  if (key === null || key === "") return null;
  if (typeof key !== "string" || !MEDIA_KEY_RE.test(key)) throw bad("Invalid photo");
  const row = await env.DB.prepare("SELECT 1 FROM media WHERE key = ? AND user_id = ? AND kind = ?").bind(key, userId, kind).first();
  if (!row) throw bad("Photo not found. Please upload it again.");
  return key;
}

// src/app.js
var CYCLES2 = ["WEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"];
var MAX_ITEMS_PER_USER = 1e3;
function minWithdraw(env, method, currency) {
  const base = method === "paypal" ? parseFloat(env.MIN_WITHDRAW_PAYPAL || "100") : parseFloat(env.MIN_WITHDRAW_BANK || "500");
  return isZeroDecimal(currency) ? base * 100 : base;
}
var itemView = (i) => ({
  id: i.id,
  type: i.type,
  name: i.name,
  description: i.description,
  note: i.note,
  amount: toMajor(i.amount_minor, i.currency),
  currency: i.currency,
  cycle: i.cycle,
  custom_amount: !!i.custom_amount,
  expires_at: i.expires_at,
  source: i.source,
  created_at: i.created_at,
  expired: !!(i.expires_at && new Date(i.expires_at) < /* @__PURE__ */ new Date()),
  image: mediaUrl(i.image_key)
});
var txnView = (t) => ({
  id: t.id,
  item_id: t.item_id,
  item_type: t.item_type,
  description: t.description,
  payer_name: t.payer_name,
  currency: t.currency,
  gross_amount: toMajor(t.gross_minor, t.currency),
  fee_amount: toMajor(t.fee_minor, t.currency),
  net_amount: toMajor(t.net_minor, t.currency),
  refunded_amount: toMajor(t.refunded_minor, t.currency),
  payment_method: t.provider === "paypal" ? "PayPal" : "Card",
  status: t.status,
  created_at: t.created_at
});
var wdView = (w) => ({
  id: w.id,
  currency: w.currency,
  amount: toMajor(w.amount_minor, w.currency),
  method: w.method,
  destination: w.destination,
  status: w.status,
  notes: w.notes,
  admin_note: w.admin_note,
  created_at: w.created_at,
  payout_status: w.payout_status
});
var sumsToMajor = (rows) => Object.fromEntries(rows.filter((r) => r.total).map((r) => [r.currency, toMajor(r.total, r.currency)]));
var AVAILABLE_SQL = `SELECT currency, SUM(amt) AS total FROM (
    SELECT currency, amount_minor AS amt FROM ledger WHERE user_id = ?1 AND (available_at IS NULL OR available_at <= ?2)
    UNION ALL
    SELECT currency, -amount_minor AS amt FROM withdrawals WHERE user_id = ?1 AND status != 'rejected'
  ) GROUP BY currency`;
var HELD_SQL = `SELECT currency, SUM(amount_minor) AS total, MIN(available_at) AS next_release FROM ledger
  WHERE user_id = ?1 AND available_at > ?2 GROUP BY currency`;
async function balances(env, userId) {
  const now = nowIso();
  const [avail, held] = await env.DB.batch([
    env.DB.prepare(AVAILABLE_SQL).bind(userId, now),
    env.DB.prepare(HELD_SQL).bind(userId, now)
  ]);
  return { available: avail.results, held: held.results };
}
async function me(env, request) {
  const u = await getSessionUser(env, request);
  return json({ user: u ? selfView(env, u) : null });
}
async function dashboard(env, request) {
  const u = await requireUser(env, request);
  const monthStart = /* @__PURE__ */ new Date();
  monthStart.setUTCDate(1);
  monthStart.setUTCHours(0, 0, 0, 0);
  const q = (sql, ...args) => env.DB.prepare(sql).bind(...args);
  const now = nowIso();
  const [items, txns, wds, refs, bal, held, earned, refEarned, month, followers, key] = await env.DB.batch([
    q("SELECT * FROM items WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC", u.id),
    q("SELECT * FROM transactions WHERE owner_id = ? ORDER BY created_at DESC LIMIT 500", u.id),
    q("SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC", u.id),
    q("SELECT full_name, business_name, created_at FROM users WHERE referrer_id = ? AND deleted_at IS NULL ORDER BY created_at DESC", u.id),
    q(AVAILABLE_SQL, u.id, now),
    q(HELD_SQL, u.id, now),
    q("SELECT currency, SUM(amount_minor) AS total FROM ledger WHERE user_id = ? AND kind IN ('sale','refund') GROUP BY currency", u.id),
    q("SELECT currency, SUM(amount_minor) AS total FROM ledger WHERE user_id = ? AND kind IN ('referral','referral_reversal') GROUP BY currency", u.id),
    q("SELECT currency, SUM(amount_minor) AS total FROM ledger WHERE user_id = ? AND kind IN ('sale','refund') AND created_at >= ? GROUP BY currency", u.id, monthStart.toISOString()),
    q("SELECT COUNT(*) AS n FROM follows WHERE following_id = ?", u.id),
    q("SELECT prefix, created_at, last_used_at FROM api_keys WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1", u.id)
  ]);
  const apiCounts = {
    cols: items.results.filter((i) => i.source === "api" && i.type === "col").length,
    lnks: items.results.filter((i) => i.source === "api" && i.type === "lnk").length
  };
  return json({
    user: selfView(env, u),
    items: items.results.map(itemView),
    transactions: txns.results.map(txnView),
    withdrawals: wds.results.map(wdView),
    referrals: refs.results,
    balances: sumsToMajor(bal.results),
    held: sumsToMajor(held.results),
    next_release: Object.fromEntries(held.results.filter((r) => r.total).map((r) => [r.currency, r.next_release])),
    hold_days: holdDaysFor(env, u),
    subscriptions: await listForOwner(env, u.id),
    earned: sumsToMajor(earned.results),
    ref_earned: sumsToMajor(refEarned.results),
    month: sumsToMajor(month.results),
    followers: followers.results[0]?.n || 0,
    api_key: key.results[0] || null,
    api_counts: apiCounts,
    webhook: { url: u.webhook_url, secret: u.webhook_secret }
  });
}
async function updateProfile(env, request) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  const business_name = str(b.business_name, { max: 80, field: "Business name" }) || u.business_name;
  const bio = str(b.bio, { max: 300, field: "Bio" }) || null;
  const avatar = str(b.avatar, { max: 16, field: "Avatar" }) || null;
  const avatar_key = b.avatar_key === void 0 ? u.avatar_key || null : await ownedKey(env, u.id, b.avatar_key, "avatar");
  await env.DB.prepare("UPDATE users SET business_name = ?, bio = ?, avatar = ?, avatar_key = ? WHERE id = ?").bind(business_name, bio, avatar, avatar_key, u.id).run();
  return json({ ok: true, avatar_url: mediaUrl(avatar_key) });
}
async function createItemFor(env, userId, b, source) {
  await rateLimit(env, `items:${userId}`, 100, 36e5);
  const type = String(b.type || "");
  if (!["col", "sub", "lnk"].includes(type)) throw bad("Invalid item type");
  const name = str(b.name, { max: 100, required: true, field: "Name" });
  const currency = cleanCurrency(b.currency);
  const custom = !!b.custom_amount && type !== "sub";
  let amount = 0;
  if (!custom) {
    amount = toMinor(b.amount, currency);
    const min = 50;
    const max = toMinor(parseFloat(env.MAX_PAYMENT || "10000"), currency);
    if (amount < min) throw bad(`Minimum amount is ${toMajor(min, currency)} ${currency}`);
    if (amount > max) throw bad(`Maximum amount is ${toMajor(max, currency)} ${currency}`);
  }
  const cycle = type === "sub" ? CYCLES2.includes(String(b.cycle).toUpperCase()) ? String(b.cycle).toUpperCase() : "MONTHLY" : null;
  const days = parseInt(b.expires_days || "0", 10);
  if (!(days >= 0 && days <= 365)) throw bad("Invalid expiry");
  const expires_at = type === "lnk" && days ? new Date(Date.now() + days * 864e5).toISOString() : null;
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM items WHERE user_id = ? AND deleted_at IS NULL").bind(userId).first();
  if (count.n >= MAX_ITEMS_PER_USER) throw bad("You have reached the item limit. Delete some old items first.");
  const image_key = b.image_key ? await ownedKey(env, userId, b.image_key, "post") : null;
  const id = newId();
  await env.DB.prepare(
    `INSERT INTO items (id, user_id, type, name, description, note, amount_minor, currency, cycle, custom_amount, expires_at, source, image_key)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    id,
    userId,
    type,
    name,
    str(b.description, { max: 500, field: "Description" }) || null,
    str(b.note, { max: 500, field: "Note" }) || null,
    amount,
    currency,
    cycle,
    custom ? 1 : 0,
    expires_at,
    source,
    image_key
  ).run();
  return env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(id).first();
}
async function createItem(env, request) {
  const u = await requireUser(env, request);
  const item = await createItemFor(env, u.id, await readJson(request), "web");
  return json({ item: itemView(item) });
}
async function deleteItem(env, request, id) {
  const u = await requireUser(env, request);
  const r = await env.DB.prepare("UPDATE items SET deleted_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL").bind(nowIso(), id, u.id).run();
  if (!r.meta.changes) throw notFound("Item not found");
  const { results: subs } = await env.DB.prepare("SELECT * FROM subscriptions WHERE item_id = ? AND status IN ('active','past_due')").bind(id).all();
  let failed = 0;
  for (const s of subs) await cancelAtProvider(env, s, "Plan deleted by the merchant").catch(() => {
    failed++;
  });
  return json({ ok: true, cancelled: subs.length - failed, cancel_failed: failed });
}
var BANK_FIELDS = ["holder", "routing", "account", "type", "sort", "iban", "bic", "ifsc", "bank", "swift", "address"];
async function requestWithdrawal(env, request, ctx) {
  const u = await requireUser(env, request);
  if (!u.email_verified) throw forbidden("Confirm your email address before withdrawing. Check your inbox for the link.");
  await rateLimit(env, `wd:${u.id}`, 5, 36e5);
  const b = await readJson(request);
  const currency = cleanCurrency(b.currency);
  const method = b.method === "bank" ? "bank" : b.method === "paypal" ? "paypal" : null;
  if (!method) throw bad("Choose PayPal or bank transfer");
  const amount = toMinor(b.amount, currency);
  const min = minWithdraw(env, method, currency);
  if (amount < toMinor(min, currency)) throw bad(`Minimum for ${method === "paypal" ? "PayPal" : "bank"} is ${min} ${currency}`);
  let destination, country, bankDetails = null;
  if (method === "paypal") {
    destination = emailOf(b.paypal_email);
    country = "PayPal";
  } else {
    country = str(b.country, { max: 60, required: true, field: "Country" });
    const d = {};
    for (const k of BANK_FIELDS) {
      const v = str(b.bank_details?.[k], { max: 120, field: "Bank details" });
      if (v) d[k] = v;
    }
    if (!d.holder || !(d.account || d.iban)) throw bad("Please complete your bank details");
    bankDetails = JSON.stringify(d);
    const acct = String(d.account || d.iban);
    destination = `${d.holder} ****${acct.slice(-4)}`;
  }
  const notes = str(b.notes, { max: 500, field: "Notes" }) || null;
  const id = newId();
  const r = await env.DB.prepare(
    `INSERT INTO withdrawals (id, user_id, currency, amount_minor, method, destination, country, bank_details, notes)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
     WHERE (SELECT COALESCE(SUM(amount_minor), 0) FROM ledger WHERE user_id = ?2 AND currency = ?3 AND (available_at IS NULL OR available_at <= ?10))
         - (SELECT COALESCE(SUM(amount_minor), 0) FROM withdrawals WHERE user_id = ?2 AND currency = ?3 AND status != 'rejected')
         >= ?4`
  ).bind(id, u.id, currency, amount, method === "paypal" ? "PayPal" : "Bank Transfer", destination, country, bankDetails, notes, nowIso()).run();
  if (!r.meta.changes) throw bad(`Insufficient available ${currency} balance. New payments are on hold for ${holdDaysFor(env, u)} days before you can withdraw them.`, "insufficient_funds");
  ctx.waitUntil(notifyAdmin(env, "New withdrawal request", [
    `User: ${u.full_name} <${u.email}>`,
    `Amount: ${toMajor(amount, currency)} ${currency}`,
    `Method: ${method}`,
    `To: ${destination}`
  ]));
  return json({ ok: true, id });
}
async function createApiKey(env, request) {
  const u = await requireUser(env, request);
  await rateLimit(env, `apikey:${u.id}`, 10, 36e5);
  const key = `vy_live_${randomToken(32)}`;
  await env.DB.batch([
    env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(nowIso(), u.id),
    env.DB.prepare("INSERT INTO api_keys (id, user_id, prefix, key_hash) VALUES (?,?,?,?)").bind(newId(), u.id, key.slice(0, 16), await sha256Hex(key))
  ]);
  return json({ key, prefix: key.slice(0, 16) });
}
async function revokeApiKey(env, request) {
  const u = await requireUser(env, request);
  await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(nowIso(), u.id).run();
  return json({ ok: true });
}
async function setWebhook(env, request) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  const raw = str(b.url, { max: 500 });
  if (!raw) {
    await env.DB.prepare("UPDATE users SET webhook_url = NULL, webhook_secret = NULL WHERE id = ?").bind(u.id).run();
    return json({ url: null, secret: null });
  }
  const url = safeWebhookUrl(raw);
  const secret = b.rotate || !u.webhook_secret ? `whsec_${randomToken(24)}` : u.webhook_secret;
  await env.DB.prepare("UPDATE users SET webhook_url = ?, webhook_secret = ? WHERE id = ?").bind(url, secret, u.id).run();
  return json({ url, secret });
}
async function follow(env, request, targetId, on) {
  const u = await requireUser(env, request);
  if (targetId === u.id) throw bad("You can't follow yourself");
  if (on) {
    const t = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL").bind(targetId).first();
    if (!t) throw notFound("User not found");
    await env.DB.prepare("INSERT OR IGNORE INTO follows (follower_id, following_id) VALUES (?,?)").bind(u.id, targetId).run();
  } else {
    await env.DB.prepare("DELETE FROM follows WHERE follower_id = ? AND following_id = ?").bind(u.id, targetId).run();
  }
  return json({ ok: true, following: on });
}
var ownerView = (r) => ({
  id: r.user_id,
  business_name: r.owner_business || r.owner_name || "User",
  avatar: r.owner_avatar,
  avatar_url: mediaUrl(r.owner_avatar_key),
  ref_code: r.owner_ref
});
var OWNER_COLS = `o.business_name AS owner_business, o.full_name AS owner_name, o.avatar AS owner_avatar,
  o.avatar_key AS owner_avatar_key, o.ref_code AS owner_ref`;
var postView = (r) => ({ ...itemView(r), source: void 0, note: void 0, owner: ownerView(r) });
var PAGE = 20;
async function feed(env, request) {
  const u = await requireUser(env, request);
  const before = String(new URL(request.url).searchParams.get("before") || "9999").slice(0, 40);
  const [following, rows] = await env.DB.batch([
    env.DB.prepare("SELECT COUNT(*) AS n FROM follows WHERE follower_id = ?").bind(u.id),
    env.DB.prepare(
      `SELECT i.*, ${OWNER_COLS}
       FROM follows f JOIN items i ON i.user_id = f.following_id JOIN users o ON o.id = i.user_id
       WHERE f.follower_id = ? AND i.type IN ('col','lnk') AND i.deleted_at IS NULL AND i.created_at < ?
         AND (i.expires_at IS NULL OR i.expires_at > ?) AND o.suspended = 0 AND o.deleted_at IS NULL
       ORDER BY i.created_at DESC LIMIT ?`
    ).bind(u.id, before, nowIso(), PAGE)
  ]);
  const items = rows.results.map(postView);
  return json({
    following_count: following.results[0].n,
    items,
    next: items.length === PAGE ? items[items.length - 1].created_at : null
  });
}
async function explore(env, request) {
  const viewer = await getSessionUser(env, request);
  const page = Math.min(Math.max(parseInt(new URL(request.url).searchParams.get("page") || "0", 10) || 0, 0), 20);
  const since = new Date(Date.now() - 30 * 864e5).toISOString();
  const { results } = await env.DB.prepare(
    `SELECT * FROM (
       SELECT i.*, ${OWNER_COLS}, COALESCE(s.n, 0) AS sales,
              ROW_NUMBER() OVER (PARTITION BY i.user_id ORDER BY COALESCE(s.n, 0) DESC, i.created_at DESC) AS rn
       FROM items i JOIN users o ON o.id = i.user_id
       LEFT JOIN (SELECT item_id, COUNT(*) AS n FROM transactions WHERE status = 'succeeded' AND created_at > ?1 GROUP BY item_id) s
              ON s.item_id = i.id
       WHERE i.type = 'col' AND i.image_key IS NOT NULL AND i.deleted_at IS NULL
         AND o.suspended = 0 AND o.deleted_at IS NULL AND i.user_id != ?2
     ) WHERE rn <= 2
     ORDER BY sales DESC, created_at DESC LIMIT ?3 OFFSET ?4`
  ).bind(since, viewer?.id || "", PAGE, page * PAGE).all();
  return json({ items: results.map(postView), next: results.length === PAGE ? page + 1 : null });
}
async function suggested(env, request) {
  const viewer = await getSessionUser(env, request);
  const { results } = await env.DB.prepare(
    `SELECT o.id AS user_id, ${OWNER_COLS}, o.bio,
       (SELECT COUNT(*) FROM follows WHERE following_id = o.id) AS followers,
       (SELECT image_key FROM items WHERE user_id = o.id AND type = 'col' AND image_key IS NOT NULL AND deleted_at IS NULL
          ORDER BY created_at DESC LIMIT 1) AS cover_key
     FROM users o
     WHERE o.suspended = 0 AND o.deleted_at IS NULL AND o.id != ?1
       AND EXISTS (SELECT 1 FROM items WHERE user_id = o.id AND type IN ('col','lnk') AND deleted_at IS NULL)
       AND NOT EXISTS (SELECT 1 FROM follows WHERE follower_id = ?1 AND following_id = o.id)
     ORDER BY (cover_key IS NOT NULL) DESC, followers DESC, o.created_at DESC LIMIT 12`
  ).bind(viewer?.id || "").all();
  return json({ accounts: results.map((r) => ({ ...ownerView(r), bio: r.bio, followers: r.followers, cover: mediaUrl(r.cover_key) })) });
}
async function publicItem(env, request, id) {
  const i = await env.DB.prepare(
    `SELECT i.*, u.business_name, u.full_name FROM items i JOIN users u ON u.id = i.user_id
     WHERE i.id = ? AND i.deleted_at IS NULL AND u.suspended = 0 AND u.deleted_at IS NULL`
  ).bind(String(id).slice(0, 64)).first();
  if (!i) throw notFound("This link may have been removed.");
  return json({ item: { ...itemView(i), source: void 0 }, business: i.business_name || i.full_name || "VyCheckout" });
}
async function publicProfile(env, request, code) {
  const p = await env.DB.prepare(
    "SELECT id, full_name, business_name, avatar, avatar_key, bio, ref_code FROM users WHERE ref_code = ? AND deleted_at IS NULL AND suspended = 0"
  ).bind(String(code).toUpperCase().slice(0, 12)).first();
  if (!p) throw notFound("Profile not found");
  const viewer = await getSessionUser(env, request);
  const q = (sql, ...a) => env.DB.prepare(sql).bind(...a);
  const [items, followers, following, isFollowing] = await env.DB.batch([
    q(`SELECT * FROM items WHERE user_id = ? AND type IN ('col','lnk') AND deleted_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC LIMIT 100`, p.id, nowIso()),
    q("SELECT COUNT(*) AS n FROM follows WHERE following_id = ?", p.id),
    q("SELECT COUNT(*) AS n FROM follows WHERE follower_id = ?", p.id),
    q("SELECT COUNT(*) AS n FROM follows WHERE follower_id = ? AND following_id = ?", viewer?.id || "", p.id)
  ]);
  const { avatar_key, ...profile } = p;
  return json({
    profile: { ...profile, avatar_url: mediaUrl(avatar_key) },
    items: items.results.map((i) => ({ ...itemView(i), source: void 0 })),
    followers: followers.results[0].n,
    following: following.results[0].n,
    is_following: !!isFollowing.results[0].n,
    is_me: viewer?.id === p.id
  });
}
function publicConfig(env) {
  return json({
    paypal_client_id: env.PAYPAL_CLIENT_ID || null,
    stripe_publishable_key: env.STRIPE_PUBLISHABLE_KEY || null,
    google_enabled: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    fee_pct: parseInt(env.PLATFORM_FEE_BPS || "1900", 10) / 100,
    turnstile_site_key: env.TURNSTILE_SECRET_KEY ? env.TURNSTILE_SITE_KEY || null : null,
    referral_pct: parseInt(env.REFERRAL_BPS || "100", 10) / 100,
    min_withdraw: { paypal: parseFloat(env.MIN_WITHDRAW_PAYPAL || "100"), bank: parseFloat(env.MIN_WITHDRAW_BANK || "500") },
    hold_days: holdDays(env),
    new_account_hold_days: parseFloat(env.NEW_ACCOUNT_HOLD_DAYS || "14"),
    currencies: CURRENCIES
  });
}
async function apiUser(env, request) {
  const m = (request.headers.get("Authorization") || "").match(/^Bearer\s+(vy_live_[A-Za-z0-9_-]{20,80})$/);
  if (!m) throw unauthorized("Missing or invalid API key");
  const row = await env.DB.prepare(
    `SELECT u.*, k.id AS key_id FROM api_keys k JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ? AND k.revoked_at IS NULL AND u.suspended = 0 AND u.deleted_at IS NULL`
  ).bind(await sha256Hex(m[1])).first();
  if (!row) throw unauthorized("Missing or invalid API key");
  await rateLimit(env, `api:${row.key_id}`, 120, 6e4);
  await env.DB.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").bind(nowIso(), row.key_id).run();
  return row;
}
async function apiV1(env, request, path) {
  const u = await apiUser(env, request);
  const base = appUrl(env, request);
  if (request.method === "GET" && path === "/api/v1/balance") {
    const b = await balances(env, u.id);
    return json({ balances: sumsToMajor(b.available), available: sumsToMajor(b.available), on_hold: sumsToMajor(b.held), hold_days: holdDays(env) });
  }
  if (request.method === "GET" && path === "/api/v1/transactions") {
    const limit = Math.min(Math.max(parseInt(new URL(request.url).searchParams.get("limit") || "50", 10) || 50, 1), 200);
    const { results } = await env.DB.prepare("SELECT * FROM transactions WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?").bind(u.id, limit).all();
    return json({ transactions: results.map(txnView) });
  }
  if (request.method === "POST" && (path === "/api/v1/collections" || path === "/api/v1/links")) {
    const b = await readJson(request);
    const type = path.endsWith("collections") ? "col" : "lnk";
    const item = await createItemFor(env, u.id, { ...b, type }, "api");
    return json({ ...itemView(item), url: `${base}/?pay=${type}:${item.id}` }, 201);
  }
  throw notFound("Unknown API endpoint");
}

// src/payouts.js
var FAILED = ["FAILED", "RETURNED", "BLOCKED", "REFUNDED", "REVERSED", "DENIED", "CANCELED"];
async function sendPayout(env, request, id, ctx) {
  const admin = await requireAdmin(env, request);
  const claim = await env.DB.prepare(
    `UPDATE withdrawals SET payout_status = 'SENDING', payout_error = NULL, updated_at = ?
     WHERE id = ? AND status = 'approved' AND method = 'PayPal'
       AND (payout_status IS NULL OR payout_status IN (${FAILED.map(() => "?").join(",")}))`
  ).bind(nowIso(), id, ...FAILED).run();
  if (!claim.meta.changes) throw bad("Only approved PayPal withdrawals that have not been sent can be paid out.");
  const w = await env.DB.prepare("SELECT * FROM withdrawals WHERE id = ?").bind(id).first();
  const r = await pp(env, "/v1/payments/payouts", {
    method: "POST",
    body: {
      sender_batch_header: {
        sender_batch_id: `${w.id}-${Date.now()}`,
        // must be unique per attempt
        email_subject: "You have a payout from VyCheckout",
        email_message: "Your VyCheckout withdrawal has been sent."
      },
      items: [{
        recipient_type: "EMAIL",
        receiver: w.destination,
        sender_item_id: w.id,
        note: "VyCheckout withdrawal",
        amount: { value: majorString(w.amount_minor, w.currency), currency: w.currency }
      }]
    }
  });
  if (!r.ok || !r.data?.batch_header?.payout_batch_id) {
    const msg = r.data?.message || r.data?.name || `HTTP ${r.status}`;
    await env.DB.prepare("UPDATE withdrawals SET payout_status = 'FAILED', payout_error = ? WHERE id = ?").bind(String(msg).slice(0, 300), id).run();
    await audit(env, admin.id, "payout_send_failed", id, { msg });
    throw new HttpError(502, `PayPal refused the payout: ${msg}. Is PayPal Payouts enabled on your account?`);
  }
  await env.DB.prepare("UPDATE withdrawals SET payout_batch_id = ?, payout_status = 'PENDING' WHERE id = ?").bind(r.data.batch_header.payout_batch_id, id).run();
  await audit(env, admin.id, "payout_sent", id, { batch: r.data.batch_header.payout_batch_id });
  return json({ ok: true, payout_status: "PENDING" });
}
async function refreshPayout(env, ctx, w) {
  if (!w.payout_batch_id) return w.payout_status;
  const r = await pp(env, `/v1/payments/payouts/${encodeURIComponent(w.payout_batch_id)}`);
  const it = r.ok ? r.data?.items?.[0] : null;
  if (!it) return w.payout_status;
  const status = it.transaction_status;
  if (status === w.payout_status) return status;
  if (status === "SUCCESS") {
    const done = await env.DB.prepare(
      "UPDATE withdrawals SET status = 'completed', payout_status = 'SUCCESS', payout_error = NULL, updated_at = ? WHERE id = ? AND status = 'approved'"
    ).bind(nowIso(), w.id).run();
    if (done.meta.changes) {
      const u = await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(w.user_id).first();
      if (u?.email) ctx.waitUntil(sendEmail(env, {
        to: u.email,
        subject: `Your withdrawal of ${money(w.amount_minor, w.currency)} was sent`,
        text: `We sent ${money(w.amount_minor, w.currency)} to your PayPal account (${w.destination}).`
      }));
    }
  } else if (FAILED.includes(status) || status === "UNCLAIMED") {
    const err = it.errors?.message || (status === "UNCLAIMED" ? "The PayPal email has no PayPal account yet. PayPal returns the money after 30 days if it is not claimed." : status);
    await env.DB.prepare("UPDATE withdrawals SET payout_status = ?, payout_error = ? WHERE id = ?").bind(status, String(err).slice(0, 300), w.id).run();
    ctx.waitUntil(alert(env, `PayPal payout ${status.toLowerCase()}`, [
      `Withdrawal ${w.id}: ${money(w.amount_minor, w.currency)} to ${w.destination}`,
      `Reason: ${err}`,
      FAILED.includes(status) ? "The money is back in your PayPal. Retry or reject it in the admin panel." : "Ask the user to open a PayPal account with that email."
    ]));
  } else {
    await env.DB.prepare("UPDATE withdrawals SET payout_status = ? WHERE id = ?").bind(status, w.id).run();
  }
  return status;
}
async function refreshPayoutRoute(env, request, id, ctx) {
  await requireAdmin(env, request);
  const w = await env.DB.prepare("SELECT * FROM withdrawals WHERE id = ?").bind(id).first();
  if (!w) throw notFound("Withdrawal not found");
  return json({ payout_status: await refreshPayout(env, ctx, w) });
}
async function payoutEvent(env, ctx, event) {
  if (!event.event_type?.startsWith("PAYMENT.PAYOUTS-ITEM.") && !event.event_type?.startsWith("PAYMENT.PAYOUTSBATCH.")) return false;
  const res = event.resource || {};
  const batch = res.payout_batch_id || res.batch_header?.payout_batch_id;
  const w = batch && await env.DB.prepare("SELECT * FROM withdrawals WHERE payout_batch_id = ?").bind(batch).first();
  if (w) await refreshPayout(env, ctx, w);
  return true;
}
async function pollPayouts(env, ctx) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM withdrawals WHERE payout_batch_id IS NOT NULL AND payout_status IN ('PENDING','ONHOLD','UNCLAIMED') AND status = 'approved' ORDER BY updated_at LIMIT 10"
  ).all();
  for (const w of results) await refreshPayout(env, ctx, w).catch((e) => console.error("payout poll", e));
}

// src/account.js
async function checkPassword(env, u, password) {
  if (!u.password_hash) throw bad('Your account uses Google sign-in. Use "Forgot password" on the sign-in page to set a password first.', "no_password");
  await rateLimit(env, `pw-check:${u.id}`, 10, 9e5);
  if (!await verifyPassword(String(password || ""), u.password_hash)) throw bad("Your current password is wrong", "bad_password");
}
async function changePassword(env, request) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  if (u.password_hash) await checkPassword(env, u, b.current_password);
  const pw = String(b.new_password || "");
  if (pw.length < 8) throw bad("New password must be 8+ characters");
  if (pw.length > 200) throw bad("Password is too long");
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(await hashPassword(pw), u.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id)
  ]);
  await audit(env, u.id, "password_change", u.id);
  if (u.email) await sendEmail(env, { to: u.email, subject: "Your VyCheckout password was changed", text: "Your password was just changed. If this wasn't you, reset your password now and contact support." });
  return json({ ok: true }, 200, { "Set-Cookie": await createSession(env, u.id) });
}
async function changeEmail(env, request, ctx) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  await checkPassword(env, u, b.password);
  const email = emailOf(b.email);
  if (email === String(u.email).toLowerCase()) throw bad("That is already your email");
  const taken = await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(email).first();
  if (taken) throw bad("Another account already uses that email");
  await env.DB.prepare("UPDATE users SET email = ?, email_verified = 0, google_sub = NULL WHERE id = ?").bind(email, u.id).run();
  await audit(env, u.id, "email_change", u.id, { from: u.email, to: email });
  ctx.waitUntil(sendEmail(env, { to: u.email, subject: "Your VyCheckout email was changed", text: `Your account email was changed to ${email}. If this wasn't you, contact support right away.` }));
  ctx.waitUntil(sendVerification(env, request, { id: u.id, email }));
  const fresh = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(u.id).first();
  return json({ user: selfView(env, fresh) });
}
async function updateSettings(env, request) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  if ("notify_sales" in b) await env.DB.prepare("UPDATE users SET notify_sales = ? WHERE id = ?").bind(b.notify_sales ? 1 : 0, u.id).run();
  return json({ ok: true });
}
async function logoutAll(env, request) {
  const u = await requireUser(env, request);
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id).run();
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
}
async function deleteAccount(env, request, ctx) {
  const u = await requireUser(env, request);
  const b = await readJson(request);
  if (u.password_hash) await checkPassword(env, u, b.password);
  else if (b.confirm !== "DELETE") throw bad("Type DELETE to confirm");
  const [bal, open] = await env.DB.batch([
    env.DB.prepare(`SELECT currency, SUM(amt) AS b FROM (
        SELECT currency, amount_minor AS amt FROM ledger WHERE user_id = ?1
        UNION ALL SELECT currency, -amount_minor FROM withdrawals WHERE user_id = ?1 AND status != 'rejected'
      ) GROUP BY currency HAVING b > 0`).bind(u.id),
    env.DB.prepare("SELECT COUNT(*) AS n FROM withdrawals WHERE user_id = ? AND status IN ('pending','approved')").bind(u.id)
  ]);
  if (bal.results.length) throw forbidden("You still have money in your balance. Withdraw it first (pending money becomes available after the hold).");
  if (open.results[0].n) throw forbidden("You have a withdrawal in progress. Wait until it is paid, then delete your account.");
  const { results: subs } = await env.DB.prepare("SELECT * FROM subscriptions WHERE owner_id = ? AND status IN ('active','past_due')").bind(u.id).all();
  for (const s of subs) await cancelAtProvider(env, s, "Merchant closed their account").catch((e) => console.error("cancel on delete", e));
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare(`UPDATE users SET deleted_at = ?, suspended = 1, email = 'deleted+' || id || '@deleted.invalid', password_hash = NULL,
                    google_sub = NULL, full_name = 'Deleted user', business_name = '', bio = NULL, avatar = NULL,
                    webhook_url = NULL, webhook_secret = NULL WHERE id = ?`).bind(now, u.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id),
    env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, u.id),
    env.DB.prepare("UPDATE items SET deleted_at = ? WHERE user_id = ? AND deleted_at IS NULL").bind(now, u.id),
    env.DB.prepare("DELETE FROM follows WHERE follower_id = ? OR following_id = ?").bind(u.id, u.id)
  ]);
  await audit(env, u.id, "account_self_delete", u.id);
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
}

// src/admin.js
var sums = (rows) => Object.fromEntries(rows.filter((r) => r.total).map((r) => [r.currency, toMajor(r.total, r.currency)]));
async function listWithdrawals(env, request) {
  await requireAdmin(env, request);
  const status = new URL(request.url).searchParams.get("status") || "pending";
  const where = ["pending", "approved", "completed", "rejected"].includes(status) ? "WHERE w.status = ?" : "";
  const stmt = env.DB.prepare(
    `SELECT w.*, u.full_name AS user_name, u.email AS user_email FROM withdrawals w JOIN users u ON u.id = w.user_id
     ${where} ORDER BY w.created_at DESC LIMIT 500`
  );
  const { results } = await (where ? stmt.bind(status) : stmt).all();
  return json({
    withdrawals: results.map((w) => ({
      id: w.id,
      user_name: w.user_name,
      user_email: w.user_email,
      currency: w.currency,
      amount: toMajor(w.amount_minor, w.currency),
      method: w.method,
      destination: w.destination,
      country: w.country,
      bank_details: w.bank_details ? JSON.parse(w.bank_details) : null,
      notes: w.notes,
      status: w.status,
      admin_note: w.admin_note,
      created_at: w.created_at,
      payout_status: w.payout_status,
      payout_error: w.payout_error
    }))
  });
}
var ALLOWED_FROM = { approved: ["pending"], rejected: ["pending", "approved"], completed: ["approved"] };
async function updateWithdrawal(env, request, id, ctx) {
  const admin = await requireAdmin(env, request);
  const b = await readJson(request);
  const from = ALLOWED_FROM[b.status];
  if (!from) throw bad("Invalid status");
  const note = str(b.note, { max: 300, field: "Note" }) || null;
  const r = await env.DB.prepare(
    `UPDATE withdrawals SET status = ?, admin_note = COALESCE(?, admin_note), updated_at = ?
     WHERE id = ? AND status IN (${from.map(() => "?").join(",")})
       AND (? != 'rejected' OR payout_status IS NULL OR payout_status IN ('FAILED','RETURNED','BLOCKED','REFUNDED','REVERSED','DENIED','CANCELED'))`
  ).bind(b.status, note, nowIso(), id, ...from, b.status).run();
  if (!r.meta.changes) throw bad("This request was already handled, has a PayPal payout in progress, or does not exist. Refresh the list.");
  const w = await env.DB.prepare("SELECT w.*, u.email FROM withdrawals w JOIN users u ON u.id = w.user_id WHERE w.id = ?").bind(id).first();
  if (w?.email) {
    const what = { approved: "was approved and will be sent soon", rejected: "was rejected and the money is back in your balance", completed: "has been paid" }[b.status];
    ctx.waitUntil(sendEmail(env, {
      to: w.email,
      subject: `Your withdrawal ${what.split(" ").slice(0, 2).join(" ")}`,
      text: `Your withdrawal of ${money(w.amount_minor, w.currency)} ${what}.${note ? `
Note: ${note}` : ""}`
    }));
  }
  await audit(env, admin.id, `withdrawal_${b.status}`, id, { note });
  return json({ ok: true });
}
async function listUsers(env, request) {
  await requireAdmin(env, request);
  const [users, bals, held] = await env.DB.batch([
    env.DB.prepare("SELECT id, email, email_verified, full_name, business_name, ref_code, referrer_id, is_admin, suspended, hold_days, created_at FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 1000"),
    env.DB.prepare(`SELECT user_id, currency, SUM(amt) AS total FROM (
        SELECT user_id, currency, amount_minor AS amt FROM ledger WHERE available_at IS NULL OR available_at <= ?1
        UNION ALL SELECT user_id, currency, -amount_minor FROM withdrawals WHERE status != 'rejected'
      ) GROUP BY user_id, currency`).bind(nowIso()),
    env.DB.prepare(`SELECT user_id, currency, SUM(amount_minor) AS total FROM ledger WHERE available_at > ?1 GROUP BY user_id, currency`).bind(nowIso())
  ]);
  const heldBy = {};
  for (const r of held.results) (heldBy[r.user_id] ||= []).push(r);
  const byUser = {};
  for (const r of bals.results) (byUser[r.user_id] ||= []).push(r);
  return json({
    users: users.results.map((u) => ({
      ...u,
      email_verified: !!u.email_verified,
      suspended: !!u.suspended,
      is_admin: isAdmin(env, u),
      balances: sums(byUser[u.id] || []),
      held: sums(heldBy[u.id] || []),
      hold_days: holdDaysFor(env, u),
      hold_override: u.hold_days
    }))
  });
}
async function setSuspended(env, request, id) {
  const admin = await requireAdmin(env, request);
  const b = await readJson(request);
  if (id === admin.id) throw bad("You can't suspend yourself");
  const on = !!b.suspended;
  const stmts = [env.DB.prepare("UPDATE users SET suspended = ? WHERE id = ?").bind(on ? 1 : 0, id)];
  if (on) stmts.push(env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id));
  await env.DB.batch(stmts);
  await audit(env, admin.id, on ? "user_suspend" : "user_unsuspend", id);
  return json({ ok: true });
}
async function setHold(env, request, id) {
  const admin = await requireAdmin(env, request);
  const b = await readJson(request);
  let days = null;
  if (b.days !== null && b.days !== "" && b.days !== void 0) {
    days = Number(b.days);
    if (!Number.isInteger(days) || days < 0 || days > 180) throw bad("Hold must be a whole number of days between 0 and 180");
  }
  const r = await env.DB.prepare("UPDATE users SET hold_days = ? WHERE id = ? AND deleted_at IS NULL").bind(days, id).run();
  if (!r.meta.changes) throw notFound("User not found");
  await audit(env, admin.id, "hold_change", id, { days });
  return json({ ok: true });
}
async function adjustBalance(env, request, id) {
  const admin = await requireAdmin(env, request);
  const b = await readJson(request);
  const currency = cleanCurrency(b.currency);
  const amount = toMinor(b.amount, currency);
  if (!amount) throw bad("Enter a non-zero amount");
  const note = str(b.note, { max: 300, required: true, field: "Reason" });
  const u = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL").bind(id).first();
  if (!u) throw notFound("User not found");
  await env.DB.prepare("INSERT INTO ledger (id, user_id, currency, amount_minor, kind, note, created_by) VALUES (?,?,?,?,'adjustment',?,?)").bind(newId(), id, currency, amount, note, admin.id).run();
  await audit(env, admin.id, "balance_adjust", id, { currency, amount: toMajor(amount, currency), note });
  return json({ ok: true });
}
async function deleteUser(env, request, id) {
  const admin = await requireAdmin(env, request);
  if (id === admin.id) throw bad("You can't delete yourself");
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare(`UPDATE users SET deleted_at = ?, suspended = 1, email = 'deleted+' || id || '@deleted.invalid', password_hash = NULL,
                    google_sub = NULL, full_name = 'Deleted user', business_name = '', bio = NULL, avatar = NULL,
                    webhook_url = NULL, webhook_secret = NULL WHERE id = ? AND deleted_at IS NULL`).bind(now, id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
    env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, id),
    env.DB.prepare("UPDATE items SET deleted_at = ? WHERE user_id = ? AND deleted_at IS NULL").bind(now, id),
    env.DB.prepare("DELETE FROM follows WHERE follower_id = ? OR following_id = ?").bind(id, id)
  ]);
  await audit(env, admin.id, "user_delete", id);
  return json({ ok: true });
}
async function listTransactions(env, request) {
  await requireAdmin(env, request);
  const { results } = await env.DB.prepare(
    `SELECT t.*, u.full_name, u.email FROM transactions t JOIN users u ON u.id = t.owner_id ORDER BY t.created_at DESC LIMIT 300`
  ).all();
  return json({
    transactions: results.map((t) => ({
      id: t.id,
      created_at: t.created_at,
      user: t.full_name || t.email,
      description: t.description,
      currency: t.currency,
      gross_amount: toMajor(t.gross_minor, t.currency),
      fee_amount: toMajor(t.fee_minor, t.currency),
      net_amount: toMajor(t.net_minor, t.currency),
      referral_amount: toMajor(t.referral_minor, t.currency),
      payment_method: t.provider === "paypal" ? "PayPal" : "Card",
      status: t.status
    }))
  });
}
async function stats(env, request) {
  await requireAdmin(env, request);
  const since = /* @__PURE__ */ new Date();
  since.setUTCMonth(since.getUTCMonth() - 5, 1);
  since.setUTCHours(0, 0, 0, 0);
  const q = (sql) => env.DB.prepare(sql);
  const [vol, wds, users, monthly, top] = await env.DB.batch([
    q(`SELECT currency, COUNT(*) AS n, SUM(gross_minor) AS gross, SUM(fee_minor) AS fees, SUM(referral_minor) AS refs,
         COUNT(DISTINCT owner_id) AS sellers FROM transactions GROUP BY currency`),
    q(`SELECT currency, status, SUM(amount_minor) AS total FROM withdrawals GROUP BY currency, status`),
    q(`SELECT COUNT(*) AS total, SUM(referrer_id IS NOT NULL) AS referred,
         (SELECT COUNT(DISTINCT user_id) FROM api_keys WHERE revoked_at IS NULL) AS api_users
       FROM users WHERE deleted_at IS NULL`),
    env.DB.prepare(`SELECT substr(created_at, 1, 7) AS month, currency, SUM(fee_minor) AS fees FROM transactions
       WHERE created_at >= ? GROUP BY month, currency ORDER BY month`).bind(since.toISOString()),
    q(`SELECT u.full_name, u.business_name, u.email, l.currency, SUM(l.amount_minor) AS earned FROM ledger l
       JOIN users u ON u.id = l.user_id WHERE l.kind IN ('sale','refund') GROUP BY l.user_id, l.currency ORDER BY earned DESC LIMIT 5`)
  ]);
  const by = (rows, f) => Object.fromEntries(rows.map((r) => [r.currency, toMajor(r[f] || 0, r.currency)]));
  const wdBy = (status) => Object.fromEntries(wds.results.filter((w) => w.status === status).map((w) => [w.currency, toMajor(w.total, w.currency)]));
  return json({
    volume: by(vol.results, "gross"),
    fees: by(vol.results, "fees"),
    referral_paid: by(vol.results, "refs"),
    txn_count: vol.results.reduce((a, r) => a + r.n, 0),
    active_sellers: vol.results.reduce((a, r) => Math.max(a, r.sellers), 0),
    pending_payouts: wdBy("pending"),
    approved_payouts: wdBy("approved"),
    paid_out: wdBy("completed"),
    users: users.results[0].total,
    referred_users: users.results[0].referred || 0,
    api_users: users.results[0].api_users || 0,
    monthly_fees: monthly.results.map((m) => ({ month: m.month, currency: m.currency, fees: toMajor(m.fees, m.currency) })),
    top_earners: top.results.map((t) => ({ name: t.business_name || t.full_name || t.email, currency: t.currency, earned: toMajor(t.earned, t.currency) }))
  });
}

// src/alerts.js
async function dailyDigest(env) {
  const now = /* @__PURE__ */ new Date();
  if (now.getUTCHours() !== parseInt(env.DIGEST_HOUR_UTC ?? "3", 10)) return;
  const today = now.toISOString().slice(0, 10);
  const last = await env.DB.prepare("SELECT value FROM settings WHERE key = 'digest_day'").first();
  if (last?.value === today) return;
  await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('digest_day', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(today).run();
  const since = new Date(now.getTime() - 864e5).toISOString();
  const q = (sql, ...a) => env.DB.prepare(sql).bind(...a);
  const [pending, approved, failedHooks, mismatches, signups, volume, negative, failedPayouts] = await env.DB.batch([
    q("SELECT currency, COUNT(*) AS n, SUM(amount_minor) AS total, MIN(created_at) AS oldest FROM withdrawals WHERE status = 'pending' GROUP BY currency"),
    q("SELECT COUNT(*) AS n FROM withdrawals WHERE status = 'approved'"),
    q("SELECT COUNT(*) AS n FROM webhook_deliveries WHERE status = 'failed' AND created_at >= ?", since),
    q("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'payment_amount_mismatch' AND created_at >= ?", since),
    q("SELECT COUNT(*) AS n FROM users WHERE created_at >= ?", since),
    q("SELECT currency, COUNT(*) AS n, SUM(gross_minor) AS gross, SUM(fee_minor) AS fees FROM transactions WHERE created_at >= ? GROUP BY currency", since),
    q(`SELECT COUNT(*) AS n FROM (SELECT user_id, currency, SUM(amt) AS b FROM (
         SELECT user_id, currency, amount_minor AS amt FROM ledger
         UNION ALL SELECT user_id, currency, -amount_minor FROM withdrawals WHERE status != 'rejected'
       ) GROUP BY user_id, currency HAVING b < 0)`),
    q("SELECT COUNT(*) AS n FROM withdrawals WHERE status = 'approved' AND payout_status IN ('FAILED','RETURNED','BLOCKED','DENIED','UNCLAIMED')")
  ]);
  const lines = [];
  const vol = volume.results.map((v) => `${money(v.gross, v.currency)} (${v.n} payments, fees ${money(v.fees, v.currency)})`);
  lines.push(`Last 24h: ${vol.length ? vol.join(", ") : "no payments"} \xB7 ${signups.results[0].n} new signups`);
  for (const p of pending.results) {
    const days = Math.floor((now - new Date(p.oldest)) / 864e5);
    lines.push(`Pending withdrawals: ${p.n} \xD7 ${p.currency} = ${money(p.total, p.currency)} (oldest ${days} day${days === 1 ? "" : "s"})`);
  }
  if (approved.results[0].n) lines.push(`Approved, not yet paid: ${approved.results[0].n}`);
  if (failedPayouts.results[0].n) lines.push(`\u26A0\uFE0F PayPal payouts needing attention: ${failedPayouts.results[0].n}`);
  if (failedHooks.results[0].n) lines.push(`\u26A0\uFE0F Merchant webhooks that failed after all retries: ${failedHooks.results[0].n}`);
  if (mismatches.results[0].n) lines.push(`\u26A0\uFE0F Payment amount mismatches: ${mismatches.results[0].n}`);
  if (negative.results[0].n) lines.push(`\u26A0\uFE0F Merchants with a negative balance: ${negative.results[0].n}`);
  await alert(env, `Daily summary ${today}`, lines);
}

// src/index.js
function checkCsrf(request, env) {
  const origin = request.headers.get("Origin");
  const self = new URL(request.url).origin;
  const allowed = [self, env.APP_URL && env.APP_URL.replace(/\/$/, "")].filter(Boolean);
  if (origin && !allowed.includes(origin)) throw new HttpError(403, "Cross-site request blocked", "csrf");
  if (request.headers.get("X-Requested-With") !== "VyCheckout") throw new HttpError(403, "Missing request header", "csrf");
}
async function paypalWebhook(env, request, ctx) {
  const raw = await request.text();
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    return new Response("bad json", { status: 400 });
  }
  if (!env.PAYPAL_WEBHOOK_ID) return new Response("not configured", { status: 503 });
  if (!await verifyPayPalWebhook(env, request, event)) {
    console.warn("PayPal webhook signature rejected");
    return new Response("invalid signature", { status: 400 });
  }
  await paypalOneTimeEvent(env, ctx, event) || await paypalSubscriptionEvent(env, ctx, event) || await payoutEvent(env, ctx, event);
  return new Response("ok");
}
async function stripeWebhook(env, request, ctx) {
  const raw = await request.text();
  if (!await verifyStripeSignature(env, request.headers.get("Stripe-Signature"), raw)) {
    console.warn("Stripe webhook signature rejected");
    return new Response("invalid signature", { status: 400 });
  }
  const event = JSON.parse(raw);
  await stripeOneTimeEvent(env, ctx, event) || await stripeSubscriptionEvent(env, ctx, event);
  return new Response("ok");
}
async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;
  if (m === "POST" && p === "/webhooks/paypal") return paypalWebhook(env, request, ctx);
  if (m === "POST" && p === "/webhooks/stripe") return stripeWebhook(env, request, ctx);
  if (p.startsWith("/api/v1/")) return apiV1(env, request, p);
  if (m === "GET" && p === "/api/auth/google/start") return googleStart(env, request);
  if (m === "GET" && p === "/api/auth/google/callback") return googleCallback(env, request, ctx);
  if (m === "GET" && p === "/api/auth/verify") return verifyEmail(env, request);
  if ((m === "GET" || m === "HEAD") && p.startsWith("/api/media/")) return serve(env, request, p.slice("/api/media/".length));
  if (m !== "GET" && m !== "HEAD") checkCsrf(request, env);
  switch (`${m} ${p}`) {
    case "GET /api/config":
      return publicConfig(env);
    case "POST /api/human":
      return verifyHuman(env, request);
    case "GET /api/me":
      return me(env, request);
    case "PATCH /api/me":
      return updateProfile(env, request);
    case "GET /api/dashboard":
      return dashboard(env, request);
    case "GET /api/feed":
      return feed(env, request);
    case "GET /api/explore":
      return explore(env, request);
    case "GET /api/suggested":
      return suggested(env, request);
    case "POST /api/media":
      return upload(env, request);
    case "POST /api/auth/signup":
      return signup(env, request, ctx);
    case "POST /api/auth/login":
      return login(env, request);
    case "POST /api/auth/logout":
      return logout(env, request);
    case "POST /api/auth/forgot":
      return forgot(env, request, ctx);
    case "POST /api/auth/reset":
      return resetPassword(env, request);
    case "POST /api/auth/resend-verification":
      return resendVerification(env, request, ctx);
    case "POST /api/account/password":
      return changePassword(env, request);
    case "POST /api/account/email":
      return changeEmail(env, request, ctx);
    case "PATCH /api/account/settings":
      return updateSettings(env, request);
    case "POST /api/account/logout-all":
      return logoutAll(env, request);
    case "DELETE /api/account":
      return deleteAccount(env, request, ctx);
    case "POST /api/items":
      return createItem(env, request);
    case "POST /api/withdrawals":
      return requestWithdrawal(env, request, ctx);
    case "POST /api/api-key":
      return createApiKey(env, request);
    case "DELETE /api/api-key":
      return revokeApiKey(env, request);
    case "PUT /api/webhook":
      return setWebhook(env, request);
    case "POST /api/pay/paypal/order":
      return paypalCreateOrder(env, request);
    case "POST /api/pay/paypal/capture":
      return paypalCapture(env, request, ctx);
    case "POST /api/pay/stripe/intent":
      return stripeCreateIntent(env, request);
    case "POST /api/pay/stripe/confirm":
      return stripeConfirm(env, request, ctx);
    case "POST /api/pay/paypal/subscribe":
      return paypalSubscribeStart(env, request);
    case "POST /api/pay/paypal/subscribe/activate":
      return paypalSubscribeActivate(env, request, ctx);
    case "POST /api/pay/stripe/subscribe":
      return stripeSubscribe(env, request);
    case "POST /api/pay/stripe/subscribe/confirm":
      return stripeSubscribeConfirm(env, request, ctx);
    case "POST /api/public/subscriptions/lookup":
      return publicLookup(env, request);
    case "POST /api/public/subscriptions/cancel":
      return publicCancel(env, request);
    case "GET /api/admin/withdrawals":
      return listWithdrawals(env, request);
    case "GET /api/admin/users":
      return listUsers(env, request);
    case "GET /api/admin/transactions":
      return listTransactions(env, request);
    case "GET /api/admin/stats":
      return stats(env, request);
  }
  const seg = p.split("/").filter(Boolean);
  const [, res, rid] = seg;
  if (seg[0] === "api" && rid) {
    if (res === "items" && m === "DELETE" && seg.length === 3) return deleteItem(env, request, rid);
    if (res === "subscriptions" && m === "POST" && seg[3] === "cancel") return merchantCancel(env, request, rid);
    if (res === "follows" && seg.length === 3 && (m === "POST" || m === "DELETE")) return follow(env, request, rid, m === "POST");
    if (res === "public" && m === "GET" && rid === "items" && seg[3]) return publicItem(env, request, seg[3]);
    if (res === "public" && m === "GET" && rid === "profiles" && seg[3]) return publicProfile(env, request, seg[3]);
    if (res === "admin" && rid === "withdrawals" && seg[3] && m === "POST") {
      if (!seg[4]) return updateWithdrawal(env, request, seg[3], ctx);
      if (seg[4] === "payout") return sendPayout(env, request, seg[3], ctx);
      if (seg[4] === "payout-refresh") return refreshPayoutRoute(env, request, seg[3], ctx);
    }
    if (res === "admin" && rid === "users" && seg[3]) {
      if (m === "POST" && seg[4] === "suspend") return setSuspended(env, request, seg[3]);
      if (m === "POST" && seg[4] === "adjust") return adjustBalance(env, request, seg[3]);
      if (m === "POST" && seg[4] === "hold") return setHold(env, request, seg[3]);
      if (m === "DELETE" && !seg[4]) return deleteUser(env, request, seg[3]);
    }
  }
  return json({ error: "Not found" }, 404);
}
var index_default = {
  async fetch(request, env, ctx) {
    const p = new URL(request.url).pathname;
    if (!p.startsWith("/api/") && !p.startsWith("/webhooks/")) return env.ASSETS.fetch(request);
    try {
      return await route(request, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, code: e.code }, e.status);
      console.error("Unhandled error", p, e?.stack || e);
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  },
  // Every 5 minutes: retry merchant webhooks, check PayPal payouts, daily admin summary, tidy up
  async scheduled(event, env, ctx) {
    const job = async (name, fn) => {
      try {
        await fn();
      } catch (e) {
        console.error(`cron ${name}`, e?.stack || e);
      }
    };
    ctx.waitUntil((async () => {
      await job("webhooks", () => retryDueWebhooks(env));
      await job("payouts", () => pollPayouts(env, ctx));
      await job("digest", () => dailyDigest(env));
      await job("subscriptions", () => cleanupPending(env));
      await job("cleanup", async () => {
        const now = Date.now();
        await env.DB.batch([
          env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
          env.DB.prepare("DELETE FROM auth_tokens WHERE expires_at < ?").bind(now - 864e5),
          env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 864e5),
          env.DB.prepare("DELETE FROM orders WHERE status = 'created' AND created_at < ?").bind(new Date(now - 30 * 864e5).toISOString())
        ]);
      });
    })());
  }
};
export {
  index_default as default
};
