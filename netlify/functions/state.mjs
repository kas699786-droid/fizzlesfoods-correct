import crypto from "node:crypto";
import { store, json, readBody, clean, isOwner, unauthorized } from "../lib/common.mjs";
import { notifyAll } from "../lib/pushlib.mjs";

const KEYS = ["foods", "drinks", "games", "events", "gallery1", "galleryTitles", "special", "openMondays"];
const MENU_LABEL = { foods: "Meals", drinks: "Drinks", games: "Games", events: "Events" };
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const todayStr = () => new Date().toISOString().slice(0, 10);
const isMonday = (d) => DATE.test(d) && new Date(d + "T00:00:00Z").getUTCDay() === 1;
const specialEnd = (x) => Date.parse(`${x.date}T${x.time}:00Z`) + 3 * 3600 * 1000; // hidden 3 hours after it starts
const liveSpecial = (list) => (Array.isArray(list) ? list : []).filter((x) => specialEnd(x) > Date.now()).sort((a, b) => `${a.date}${a.time}`.localeCompare(`${b.date}${b.time}`));
const liveMondays = (list) => (Array.isArray(list) ? list : []).filter((d) => typeof d === "string" && d >= todayStr()).sort();
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

function cleanGames(v) {
  if (!Array.isArray(v) || v.length > 200) return null;
  const out = [];
  for (const x of v) {
    if (!x || !ID.test(String(x.id))) return null;
    out.push({ id: String(x.id), name: clean(x.name, 80), price: clean(x.price, 40), description: clean(x.description, 400), image: IMG_URL.test(String(x.image || "")) ? String(x.image) : "" });
  }
  return out;
}

function cleanSpecial(v) {
  if (!Array.isArray(v) || v.length > 30) return null;
  const out = [];
  for (const x of v) {
    if (!x || !ID.test(String(x.id)) || !DATE.test(String(x.date)) || !TIME.test(String(x.time)) || !clean(x.name, 80)) return null;
    out.push({ id: String(x.id), name: clean(x.name, 80), date: x.date, time: x.time, price: clean(x.price, 40), description: clean(x.description, 500) });
  }
  return liveSpecial(out);
}

function cleanMondays(v) {
  if (!Array.isArray(v) || v.length > 100) return null;
  for (const d of v) if (typeof d !== "string" || !isMonday(d)) return null;
  return liveMondays([...new Set(v)]);
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
    if (state.special) state.special = liveSpecial(state.special);
    if (state.openMondays) state.openMondays = liveMondays(state.openMondays);
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
      : key === "games" ? cleanGames(body.value)
      : key === "special" ? cleanSpecial(body.value)
      : key === "openMondays" ? cleanMondays(body.value)
      : key === "events" ? cleanEvents(body.value)
      : key === "gallery1" ? cleanGallery(body.value)
      : cleanTitles(body.value);
    if (value === null) return json({ error: "Invalid data." }, 400);

    const old = (await st.get(`state/${key}`, { type: "json" })) || [];
    if (key !== "galleryTitles" && key !== "special" && key !== "openMondays") {
      const keep = new Set(value.map((x) => x.image || x.url).filter(Boolean));
      for (const item of old) {
        const u = item.image || item.url;
        const m = String(u || "").match(IMG_URL);
        if (m && !keep.has(u)) await st.delete(`img/${m[1]}`);
      }
    }
    await st.setJSON(`state/${key}`, value);

    // tell subscribers about genuinely new things (never blocks or fails the save)
    try {
      const origin = new URL(req.url).origin;
      const oldIds = new Set((Array.isArray(old) ? old : []).map((x) => x && x.id));
      const added = Array.isArray(value) ? value.filter((x) => x && x.id && !oldIds.has(x.id)) : [];
      if (key === "special" && added.length) {
        const x = added[0];
        await notifyAll(st, origin, { title: `Special event: ${x.name}`, body: `${x.date} at ${x.time}${x.price ? " - " + x.price : ""}`, url: "/" });
      } else if (MENU_LABEL[key] && added.length) {
        const meta = (await st.get(`pushmeta/${key}`, { type: "json" })) || { t: 0 };
        if (Date.now() - meta.t > 30 * 60 * 1000) { // at most one menu announcement per 30 minutes
          await st.setJSON(`pushmeta/${key}`, { t: Date.now() });
          const names = added.slice(0, 3).map((x) => x.name).join(", ") + (added.length > 3 ? ` and ${added.length - 3} more` : "");
          await notifyAll(st, origin, { title: `New on our ${MENU_LABEL[key]} menu`, body: names, url: "/" });
        }
      }
    } catch (e) { /* ignore */ }
    return json({ ok: true });
  }

  return json({ error: "Method not allowed." }, 405);
};

export const config = { path: "/api/state" };
