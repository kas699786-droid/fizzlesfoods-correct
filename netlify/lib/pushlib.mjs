import crypto from "node:crypto";

/** VAPID keys are created once and kept in the site's own storage, so no extra settings are needed. */
export async function getVapid(st) {
  let v = await st.get("push-vapid", { type: "json" });
  if (v) return v;
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = privateKey.export({ format: "jwk" });
  const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]).toString("base64url");
  v = { publicKey, privateKey: jwk.d };
  await st.setJSON("push-vapid", v);
  return v;
}

export const subId = (endpoint) => crypto.createHash("sha256").update(String(endpoint)).digest("hex").slice(0, 32);

/** Sends one notification to every saved subscriber. Never throws: a push problem must not break saving. */
export async function notifyAll(st, origin, payload) {
  try {
    const webpush = (await import("web-push")).default;
    const vapid = await getVapid(st);
    webpush.setVapidDetails(origin, vapid.publicKey, vapid.privateKey);
    const { blobs } = await st.list({ prefix: "push/" });
    let sent = 0;
    await Promise.all(blobs.map(async (b) => {
      const sub = await st.get(b.key, { type: "json" });
      if (!sub) return;
      try {
        await webpush.sendNotification(sub, JSON.stringify(payload), { TTL: 86400 });
        sent++;
      } catch (e) {
        if (e && (e.statusCode === 404 || e.statusCode === 410)) await st.delete(b.key); // subscriber uninstalled
      }
    }));
    return { sent };
  } catch (e) {
    return { sent: 0, error: String(e && e.message) };
  }
}
