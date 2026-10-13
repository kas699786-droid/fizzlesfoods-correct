import { store, json, readBody, clean, clientIp, rlStatus, rlHit, isOwner, unauthorized } from "../lib/common.mjs";
import { getVapid, subId, notifyAll } from "../lib/pushlib.mjs";

const WINDOW = 60 * 60 * 1000;

export default async (req, context) => {
  const st = store();
  if (req.method === "GET") return json({ publicKey: (await getVapid(st)).publicKey });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const body = await readBody(req, 6000);
  if (!body) return json({ error: "Invalid request." }, 400);

  if (body.action === "subscribe") {
    const ip = clientIp(req, context);
    const limit = await rlStatus(st, "push", ip, 10, WINDOW);
    if (!limit.ok) return json({ error: "Too many requests. Please try again later." }, 429);
    const s = body.subscription;
    const ok = s && typeof s.endpoint === "string" && /^https:\/\//.test(s.endpoint) && s.endpoint.length <= 800
      && s.keys && typeof s.keys.p256dh === "string" && s.keys.p256dh.length <= 200 && typeof s.keys.auth === "string" && s.keys.auth.length <= 100;
    if (!ok) return json({ error: "Invalid subscription." }, 400);
    await st.setJSON(`push/${subId(s.endpoint)}`, { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } });
    await rlHit(st, "push", ip, WINDOW);
    return json({ ok: true });
  }

  if (body.action === "unsubscribe") {
    if (typeof body.endpoint === "string") await st.delete(`push/${subId(body.endpoint)}`);
    return json({ ok: true });
  }

  if (body.action === "broadcast") { // owner sends a manual update to everyone who allowed notifications
    if (!(await isOwner(req, st))) return unauthorized();
    const title = clean(body.title, 60), text = clean(body.body, 200);
    if (!title || !text) return json({ error: "Please enter a title and a message." }, 400);
    const r = await notifyAll(st, new URL(req.url).origin, { title, body: text, url: "/" });
    return json({ ok: true, sent: r.sent, note: r.error || "" });
  }

  return json({ error: "Unknown action." }, 400);
};

export const config = { path: "/api/push" };
