import { store, json, getCustomer } from "../lib/common.mjs";

export default async (req) => {
  if (req.method !== "GET") return json({ error: "Method not allowed." }, 405);
  const st = store();
  const customer = await getCustomer(req, st);
  if (!customer) return json({ error: "Please sign in to see your bookings." }, 401);
  const { blobs } = await st.list({ prefix: `cbookings/${customer.id}/` });
  const rows = (await Promise.all(blobs.map((b) => st.get(b.key, { type: "json" })))).filter(Boolean);
  rows.sort((a, b) => b.sentAt - a.sentAt);
  return json({ bookings: rows.slice(0, 100) });
};

export const config = { path: "/api/my-bookings" };
