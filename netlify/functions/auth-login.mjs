import { store, json, readBody, clientIp, rlStatus, rlHit, rlClear, verifyPassword, sessionSecret, sessionCookie, clearCookie, authVersion, isOwner, resetMode } from "../lib/common.mjs";

const WINDOW = 15 * 60 * 1000;

export default async (req, context) => {
  const st = store();

  if (req.method === "GET") return json({ authenticated: await isOwner(req, st) });
  if (req.method === "DELETE") return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  if (!sessionSecret()) return json({ error: "Server is not configured (SESSION_SECRET is missing)." }, 503);

  const ip = clientIp(req, context);
  const limit = await rlStatus(st, "login", ip, 5, WINDOW);
  if (!limit.ok) return json({ error: `Too many attempts. Try again in ${limit.retryMin} minute(s).` }, 429);

  const body = await readBody(req, 2000);
  const password = typeof body?.password === "string" ? body.password.slice(0, 200) : "";

  const ok = await verifyPassword(st, password);
  if (ok === null) return json({ error: "Owner password is not configured on the server." }, 503);
  if (!ok) {
    await rlHit(st, "login", ip, WINDOW);
    await new Promise((r) => setTimeout(r, 700));
    return json({ error: "Incorrect password." }, 401);
  }

  await rlClear(st, "login", ip);
  if (resetMode()) await st.delete("auth"); // recovery: forget the saved password, OWNER_PASSWORD is active again
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(await authVersion(st)) });
};

export const config = { path: "/api/auth-login" };
