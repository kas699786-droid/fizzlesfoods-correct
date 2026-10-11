import crypto from "node:crypto";
import { store, json, readBody, clean, isOwner, unauthorized } from "../lib/common.mjs";

const KEYS = ["foods", "drinks", "events", "gallery1", "galleryTitles"];
const FOOD_CATEGORIES = ["Continental dishes", "Local dishes", "Ice cream", "Salad"];
const DRINK_CATEGORIES = ["Wine", "Juice", "Non-alcoholic soft drinks", "Alcoholic drink"];
const LEGACY = { "Wine/Bottles": "Wine", "Beverages": "Non-alcoholic soft drinks" };
const ID = /^[\w-]{1,60}$/;
const IMG_URL = /^\/api\/image\?id=([a-f0-9]{24})$/;

function cleanMenu(v, cats, fallback) {
  if (!Array.isArray(v) || v.length > 300) return null;
  const out = [];
  for (const x of v) {
    if (!x || !ID.test(String(x.id))) return null;
    out.push({
      id: String(x.id),
      name: clean(x.name, 80),
      category: cats.includes(LEGACY[x.category] || x.category) ? (LEGACY[x.category] || x.category) : fallback,
      price: clean(x.price, 40),
      description: clean(x.description, 400),
      image: IMG_URL.test(String(x.image || "")) ? String(x.image) : ""
    });
  }
  return out;
}

function cleanEvents(v) {
  if (!Array.isArray(v) || v.length > 100) return null;
  const out = [];
  for (const x of v) {
    if (!x || !ID.test(String(x.id))) return null;
    out.push({
      id: String(x.id),
      name: clean(x.name, 80),
      duration: clean(x.duration, 60),
      price: clean(x.price, 40),
      description: clean(x.description, 500),
      image: IMG_URL.test(String(x.image || "")) ? String(x.image) : ""
    });
  }
  return out;
}

function cleanGallery(v) {
  if (!Array.isArray(v) || v.length > 80) return null;
  const cats = [...FOOD_CATEGORIES, ...DRINK_CATEGORIES];
  const out = [];
  for (const x of v) {
    if (!x || !ID.test(String(x.id)) || !IMG_URL.test(String(x.url))) return null;
    out.push({
      id: String(x.id),
      name: clean(x.name, 120),
      category: cats.includes(x.category) ? x.category : "",
      url: String(x.url),
      createdAt: Number.isFinite(Number(x.createdAt)) ? Number(x.createdAt) : Date.now()
    });
  }
  return out;
}

function cleanTitles(v) {
  if (!v || typeof v !== "object") return null;
  const a = clean(v[1], 60), b = clean(v[2], 60);
  return a && b ? { 1: a, 2: b } : null;
}

export default async (req) => {
  const st = store();

  if (req.method === "GET") {
    const state = {};
    await Promise.all(KEYS.map(async (k) => {
      const val = await st.get(`state/${k}`, { type: "json" });
      if (val !== null) state[k] = val;
    }));
    const body = JSON.stringify({ state });
    const etag = `"${crypto.createHash("sha1").update(body).digest("hex")}"`;
    const headers = { "Cache-Control": "no-cache", ETag: etag };
    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });
    return new Response(body, { headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
  }

  if (req.method === "POST") {
    if (!(await isOwner(req, st))) return unauthorized();
    const body = await readBody(req, 200000);
    const key = body?.key;
    if (!KEYS.includes(key)) return json({ error: "Unknown data key." }, 400);

    const value = key === "foods" ? cleanMenu(body.value, FOOD_CATEGORIES, "Local dishes")
      : key === "drinks" ? cleanMenu(body.value, DRINK_CATEGORIES, "Non-alcoholic soft drinks")
      : key === "events" ? cleanEvents(body.value)
      : key === "gallery1" ? cleanGallery(body.value)
      : cleanTitles(body.value);
    if (value === null) return json({ error: "Invalid data." }, 400);

    if (key !== "galleryTitles") {
      const old = (await st.get(`state/${key}`, { type: "json" })) || [];
      const keep = new Set(value.map((x) => x.image || x.url).filter(Boolean));
      for (const item of old) {
        const u = item.image || item.url;
        const m = String(u || "").match(IMG_URL);
        if (m && !keep.has(u)) await st.delete(`img/${m[1]}`);
      }
    }
    await st.setJSON(`state/${key}`, value);
    return json({ ok: true });
  }

  return json({ error: "Method not allowed." }, 405);
};

export const config = { path: "/api/state" };
