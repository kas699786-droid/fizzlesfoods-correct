import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

export const store = () => getStore({ name: "fizzlesfoods", consistency: "strong" });

export const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
  });

export function clean(value, max) {
  return String(value ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim().slice(0, max);
}

export async function readBody(req, maxChars = 50000) {
  try {
    const text = await req.text();
    if (text.length > maxChars) return null;
    const data = JSON.parse(text || "{}");
    return data && typeof data === "object" ? data : null;
  } catch {
    return null;
  }
}

export const clientIp = (req, context) =>
  String(context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown");

/* ---------- rate limiting ---------- */
const rlKey = (scope, ip) => `rl/${scope}/${ip.replace(/[^\w.:-]/g, "_").slice(0, 80)}`;

export async function rlStatus(st, scope, ip, max, windowMs) {
  const rec = await st.get(rlKey(scope, ip), { type: "json" });
  if (!rec || Date.now() - rec.start > windowMs) return { ok: true };
  if (rec.count >= max) return { ok: false, retryMin: Math.max(1, Math.ceil((rec.start + windowMs - Date.now()) / 60000)) };
  return { ok: true };
}
export async function rlHit(st, scope, ip, windowMs) {
  const key = rlKey(scope, ip);
  let rec = await st.get(key, { type: "json" });
  if (!rec || Date.now() - rec.start > windowMs) rec = { count: 0, start: Date.now() };
  rec.count++;
  await st.setJSON(key, rec);
}
export const rlClear = (st, scope, ip) => st.delete(rlKey(scope, ip));

/* ---------- owner password + session ---------- */
const COOKIE = "ff_owner";
const SESSION_MS = 8 * 3600 * 1000;
const sha = (v) => crypto.createHash("sha256").update(String(v)).digest();

export const sessionSecret = () => {
  const s = process.env.SESSION_SECRET;
  return s && s.length >= 24 ? s : null;
};

export async function getAuth(st) {
  return (await st.get("auth", { type: "json" })) || null;
}

/** true = correct, false = wrong, null = no password configured */
export const resetMode = () => process.env.RESET_PASSWORD === "true" && !!process.env.OWNER_PASSWORD;

export async function verifyPassword(st, password) {
  if (resetMode()) return crypto.timingSafeEqual(sha(password), sha(process.env.OWNER_PASSWORD));
  const auth = await getAuth(st);
  if (auth) {
    const h = crypto.scryptSync(String(password), auth.salt, 64);
    return crypto.timingSafeEqual(h, Buffer.from(auth.hash, "hex"));
  }
  const env = process.env.OWNER_PASSWORD;
  if (!env) return null;
  return crypto.timingSafeEqual(sha(password), sha(env));
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: crypto.scryptSync(String(password), salt, 64).toString("hex") };
}

const sign = (payload) => crypto.createHmac("sha256", sessionSecret()).update(payload).digest("hex");

export function sessionCookie(version) {
  const payload = `${Date.now() + SESSION_MS}.${version}`;
  return `${COOKIE}=${payload}.${sign(payload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

export async function isOwner(req, st) {
  if (!sessionSecret()) return false;
  const match = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!match) return false;
  const parts = match[1].split(".");
  if (parts.length !== 3) return false;
  const [exp, ver, sig] = parts;
  const expected = sign(`${exp}.${ver}`);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  if (!(Number(exp) > Date.now())) return false;
  const auth = await getAuth(st);
  return Number(ver) === (auth?.version || 1);
}

export const authVersion = async (st) => (await getAuth(st))?.version || 1;
export const unauthorized = () => json({ error: "Please log in as the owner first." }, 401);

/* ---------- customer accounts ---------- */
const CUST_COOKIE = "ff_cust";
const CUST_MS = 30 * 24 * 3600 * 1000;

export const normPhone = (p) => {
  let d = String(p || "").replace(/\D/g, "");
  if (d.startsWith("00")) d = d.slice(2);
  if (d.startsWith("0")) d = "233" + d.slice(1);
  return d;
};
export const validPhone = (p) => { const d = normPhone(p); return d.length >= 9 && d.length <= 15; };
export const custIdOf = (phone) => crypto.createHash("sha256").update("cust:" + normPhone(phone)).digest("hex").slice(0, 24);
const csign = (payload) => crypto.createHmac("sha256", sessionSecret()).update("cust." + payload).digest("hex");

export function customerCookie(id) {
  const payload = `${Date.now() + CUST_MS}.${id}`;
  return `${CUST_COOKIE}=${payload}.${csign(payload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${CUST_MS / 1000}`;
}
export const clearCustomerCookie = () => `${CUST_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

export async function getCustomer(req, st) {
  if (!sessionSecret()) return null;
  const match = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${CUST_COOKIE}=([^;]+)`));
  if (!match) return null;
  const parts = match[1].split(".");
  if (parts.length !== 3) return null;
  const [exp, id, sig] = parts;
  const expected = csign(`${exp}.${id}`);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  if (!(Number(exp) > Date.now()) || !/^[a-f0-9]{24}$/.test(id)) return null;
  const rec = await st.get(`customers/${id}`, { type: "json" });
  return rec ? { id: rec.id, name: rec.name, phone: rec.phone } : null;
}

export async function createCustomer(st, { name, phone, password }) {
  const id = custIdOf(phone);
  if (await st.get(`customers/${id}`, { type: "json" })) return { exists: true };
  const rec = { id, name, phone: normPhone(phone), ...hashPassword(password), createdAt: Date.now() };
  await st.setJSON(`customers/${id}`, rec);
  return { customer: { id, name, phone: rec.phone } };
}

export async function verifyCustomer(st, phone, password) {
  const rec = await st.get(`customers/${custIdOf(phone)}`, { type: "json" });
  if (!rec) { crypto.scryptSync(String(password), "0000000000000000", 64); return null; } // keep timing similar
  const h = crypto.scryptSync(String(password), rec.salt, 64);
  return crypto.timingSafeEqual(h, Buffer.from(rec.hash, "hex")) ? { id: rec.id, name: rec.name, phone: rec.phone } : null;
}

export const publicCustomer = (c) => (c ? { name: c.name, phone: c.phone } : null);
