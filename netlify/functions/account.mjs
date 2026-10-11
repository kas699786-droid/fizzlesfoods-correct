import { store, json, readBody, clean, clientIp, rlStatus, rlHit, rlClear, sessionSecret, isOwner, unauthorized, hashPassword, custIdOf, validPhone, getCustomer, createCustomer, verifyCustomer, customerCookie, clearCustomerCookie, publicCustomer } from "../lib/common.mjs";

const LOGIN_WINDOW = 15 * 60 * 1000;
const REG_WINDOW = 60 * 60 * 1000;

export default async (req, context) => {
  const st = store();
  if (req.method === "GET") return json({ customer: publicCustomer(await getCustomer(req, st)) });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const body = await readBody(req, 3000);
  if (!body) return json({ error: "Invalid request." }, 400);
  const action = body.action;
  if (action === "logout") return json({ ok: true }, 200, { "Set-Cookie": clearCustomerCookie() });

  const phone = clean(body.phone, 30);
  const password = typeof body.password === "string" ? body.password.slice(0, 200) : "";

  if (action === "ownerReset") { // owner sets a temporary password for a customer who forgot theirs
    if (!(await isOwner(req, st))) return unauthorized();
    if (password.length < 8 || password.length > 100) return json({ error: "The new password must be 8 to 100 characters." }, 400);
    const key = `customers/${custIdOf(phone)}`;
    const rec = await st.get(key, { type: "json" });
    if (!rec) return json({ error: "No customer account was found for that phone number." }, 404);
    await st.setJSON(key, { ...rec, ...hashPassword(password) });
    return json({ message: `Password reset for ${rec.name}. Please tell the customer their new password.` });
  }

  if (!sessionSecret()) return json({ error: "Server is not configured (SESSION_SECRET is missing)." }, 503);
  if (!validPhone(phone)) return json({ error: "Please enter a valid phone number." }, 400);
  const ip = clientIp(req, context);

  if (action === "register") {
    const limit = await rlStatus(st, "register", ip, 5, REG_WINDOW);
    if (!limit.ok) return json({ error: "Too many new accounts from this device. Please try again later." }, 429);
    const name = clean(body.name, 80);
    if (!name) return json({ error: "Please enter your name." }, 400);
    if (password.length < 8 || password.length > 100) return json({ error: "Password must be 8 to 100 characters." }, 400);
    const res = await createCustomer(st, { name, phone, password });
    await rlHit(st, "register", ip, REG_WINDOW);
    if (res.exists) return json({ error: "An account with this phone number already exists. Please sign in." }, 409);
    return json({ customer: publicCustomer(res.customer) }, 200, { "Set-Cookie": customerCookie(res.customer.id) });
  }

  if (action === "login") {
    const limit = await rlStatus(st, "custlogin", ip, 8, LOGIN_WINDOW);
    if (!limit.ok) return json({ error: `Too many attempts. Try again in ${limit.retryMin} minute(s).` }, 429);
    const customer = await verifyCustomer(st, phone, password);
    if (!customer) {
      await rlHit(st, "custlogin", ip, LOGIN_WINDOW);
      await new Promise((r) => setTimeout(r, 600));
      return json({ error: "Incorrect phone number or password." }, 401);
    }
    await rlClear(st, "custlogin", ip);
    return json({ customer: publicCustomer(customer) }, 200, { "Set-Cookie": customerCookie(customer.id) });
  }

  return json({ error: "Unknown action." }, 400);
};

export const config = { path: "/api/account" };
