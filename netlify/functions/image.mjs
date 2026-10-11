import crypto from "node:crypto";
import { store, json, readBody, isOwner, unauthorized } from "../lib/common.mjs";

const ID = /^[a-f0-9]{24}$/;
const MAX_BYTES = 2 * 1024 * 1024;

export default async (req) => {
  const st = store();
  const url = new URL(req.url);

  if (req.method === "GET") {
    const id = url.searchParams.get("id") || "";
    if (!ID.test(id)) return new Response("Not found", { status: 404 });
    const buf = await st.get(`img/${id}`, { type: "arrayBuffer" });
    if (!buf) return new Response("Not found", { status: 404 });
    return new Response(buf, {
      headers: {
        "Content-Type": "image/jpeg",
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  if (req.method === "POST") {
    if (!(await isOwner(req, st))) return unauthorized();
    const body = await readBody(req, 3 * 1024 * 1024);
    const m = typeof body?.data === "string" && body.data.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/);
    if (!m) return json({ error: "Only JPEG images are accepted." }, 400);
    const buf = Buffer.from(m[1], "base64");
    if (buf.length > MAX_BYTES) return json({ error: "Image is too large." }, 413);
    if (!(buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)) return json({ error: "Not a valid JPEG." }, 400);
    const id = crypto.randomBytes(12).toString("hex");
    await st.set(`img/${id}`, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    return json({ id, url: `/api/image?id=${id}` });
  }

  return json({ error: "Method not allowed." }, 405);
};

export const config = { path: "/api/image" };
