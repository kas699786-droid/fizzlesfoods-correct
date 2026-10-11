import { store, json, readBody, clientIp, rlStatus, rlHit, rlClear, isOwner, unauthorized, verifyPassword, hashPassword, getAuth, sessionCookie } from "../lib/common.mjs";

const WINDOW = 15 * 60 * 1000;

export default async (req, context) => {
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  const st = store();
  if (!(await isOwner(req, st))) return unauthorized();

  const ip = clientIp(req, context);
  const limit = await rlStatus(st, "login", ip, 5, WINDOW);
  if (!limit.ok) return json({ error: `Too many attempts. Try again in ${limit.retryMin} minute(s).` }, 429);

  const body = await readBody(req, 2000);
  const current = typeof body?.currentPassword === "string" ? body.currentPassword : "";
  const next = typeof body?.newPassword === "string" ? body.newPassword : "";

  if (next.length < 8 || next.length > 100) return json({ error: "New password must be 8 to 100 characters." }, 400);
  if (!(await verifyPassword(st, current))) {
    await rlHit(st, "login", ip, WINDOW);
    return json({ error: "Current password is incorrect." }, 401);
  }
  await rlClear(st, "login", ip);

  const version = ((await getAuth(st))?.version || 1) + 1; // invalidates every older session
  await st.setJSON("auth", { ...hashPassword(next), version });
  return json({ message: "Password updated successfully." }, 200, { "Set-Cookie": sessionCookie(version) });
};

export const config = { path: "/api/password" };
