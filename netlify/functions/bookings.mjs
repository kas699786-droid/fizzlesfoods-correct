import crypto from "node:crypto";
import { store, json, readBody, clean, clientIp, rlStatus, rlHit, isOwner, unauthorized, getCustomer, createCustomer, customerCookie, validPhone, publicCustomer } from "../lib/common.mjs";

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const PHONE = /^[\d\s+()\-]{7,30}$/;
const ID = /^[\w-]{1,60}$/;
const WINDOW = 10 * 60 * 1000;

function durationMs(text) {
  const t = String(text || "").toLowerCase();
  const num = (re) => Number((t.match(re) || [])[1] || 0);
  return num(/(\d+(?:\.\d+)?)\s*(?:hours?|hrs?)/) * 3600000
    + num(/(\d+)\s*(?:minutes?|mins?)/) * 60000
    + num(/(\d+(?:\.\d+)?)\s*days?/) * 86400000;
}

const KINDS = { food: ["Food", "foods"], drink: ["Drink", "drinks"], event: ["Event", "events"] };

function money(price, qty) {
  const m = String(price ?? "").replace(/,/g, "").match(/-?\d+(?:\.\d+)?/);
  if (!m) return "Contact us";
  const total = Number(m[0]) * qty;
  const prefix = (String(price).match(/^\s*([^0-9-]*)/) || [, ""])[1].trim();
  const amount = Number.isInteger(total) ? String(total) : total.toFixed(2);
  return prefix ? `${prefix} ${amount}` : amount;
}

export default async (req, context) => {
  const st = store();

  if (req.method === "POST") {
    const body = await readBody(req, 30000);
    if (!body) return json({ error: "Invalid request." }, 400);
    if (clean(body.website, 100)) return json({ ok: true }); // honeypot: bots fill this in

    const ip = clientIp(req, context);
    const limit = await rlStatus(st, "booking", ip, 5, WINDOW);
    if (!limit.ok) return json({ error: "Too many bookings from this device. Please try again later." }, 429);

    const items = body.items;
    if (!Array.isArray(items) || items.length < 1 || items.length > 25) return json({ error: "Your order is empty." }, 400);

    const customerName = clean(body.customerName, 80);
    const customerPhone = clean(body.customerPhone, 30);
    const bookingDate = clean(body.bookingDate, 10);
    if (!customerName || !PHONE.test(customerPhone)) return json({ error: "Please enter a valid name and phone number." }, 400);

    const day = DATE.test(bookingDate) ? Date.parse(`${bookingDate}T23:59:59Z`) : NaN;
    const now = Date.now();
    if (!Number.isFinite(day) || day < now - 86400000 || day > now + 2 * 365 * 86400000) {
      return json({ error: "Please choose a valid date." }, 400);
    }

    const notes = clean(body.notes, 800);
    const orderId = `order-${now.toString(36)}-${crypto.randomBytes(3).toString("hex")}`;
    const lists = {};
    const records = [];
    for (const it of items) {
      const kind = KINDS[it?.type];
      if (!kind || !ID.test(String(it.itemId))) return json({ error: "Invalid booking." }, 400);
      if (!lists[kind[1]]) lists[kind[1]] = (await st.get(`state/${kind[1]}`, { type: "json" })) || [];
      const item = lists[kind[1]].find((x) => x.id === it.itemId);
      if (!item) return json({ error: "An item in your order is no longer available. Please refresh the page." }, 400);

      let itemQuantity = null, totalCost = "";
      if (it.type !== "event") {
        itemQuantity = Number.parseInt(it.quantity, 10);
        if (!Number.isFinite(itemQuantity) || itemQuantity < 1 || itemQuantity > 100000) return json({ error: "Invalid quantity." }, 400);
        totalCost = money(item.price, itemQuantity);
      }
      records.push({
        id: `booking-${now.toString(36)}-${crypto.randomBytes(4).toString("hex")}`,
        orderId, type: kind[0],
        selected: item.name, price: item.price,
        duration: it.type === "event" ? item.duration : "",
        customerName, customerPhone, bookingDate, itemQuantity, totalCost, notes,
        sentAt: now,
        expiresAt: day + (it.type === "event" ? durationMs(item.duration) : 0)
      });
    }
    let customer = await getCustomer(req, st);
    let setCookie = null;
    const password = typeof body.password === "string" ? body.password : "";
    if (!customer && password) { // optional: create an account so the customer can see their booking history
      if (password.length < 8 || password.length > 100) return json({ error: "Password must be 8 to 100 characters." }, 400);
      if (!validPhone(customerPhone)) return json({ error: "Please enter a valid phone number." }, 400);
      const res = await createCustomer(st, { name: customerName, phone: customerPhone, password });
      if (res.exists) return json({ error: "An account with this phone number already exists. Please sign in first, or leave the password empty to order as a guest." }, 409);
      customer = res.customer;
      setCookie = customerCookie(customer.id);
    }
    records.forEach((r) => { r.customerId = customer ? customer.id : ""; });
    await Promise.all(records.map((r) => st.setJSON(`bookings/${r.id}`, r)));
    if (customer) {
      const prefix = `cbookings/${customer.id}/`;
      await Promise.all(records.map((r) => st.setJSON(`${prefix}${r.id}`, r)));
      const { blobs } = await st.list({ prefix });
      if (blobs.length > 100) { // keep each customer's newest 100 bookings
        const rows = await Promise.all(blobs.map(async (b) => ({ key: b.key, t: (await st.get(b.key, { type: "json" }))?.sentAt || 0 })));
        rows.sort((a, b) => a.t - b.t);
        for (const r of rows.slice(0, blobs.length - 100)) await st.delete(r.key);
      }
    }
    await rlHit(st, "booking", ip, WINDOW);
    return json({ ok: true, customer: publicCustomer(customer) }, 200, setCookie ? { "Set-Cookie": setCookie } : {});
  }

  if (!(await isOwner(req, st))) return unauthorized();

  if (req.method === "GET") {
    const { blobs } = await st.list({ prefix: "bookings/" });
    const all = await Promise.all(blobs.map(async (b) => ({ key: b.key, data: await st.get(b.key, { type: "json" }) })));
    const bookings = [];
    for (const { key, data } of all) {
      if (!data) continue;
      if (Number(data.expiresAt) <= Date.now()) await st.delete(key);
      else bookings.push(data);
    }
    bookings.sort((a, b) => String(a.bookingDate).localeCompare(String(b.bookingDate)) || a.sentAt - b.sentAt);
    return json({ bookings });
  }

  if (req.method === "DELETE") {
    const id = new URL(req.url).searchParams.get("id") || "";
    if (!/^booking-[\w-]+$/.test(id)) return json({ error: "Invalid id." }, 400);
    await st.delete(`bookings/${id}`);
    return json({ ok: true });
  }

  return json({ error: "Method not allowed." }, 405);
};

export const config = { path: "/api/bookings" };
