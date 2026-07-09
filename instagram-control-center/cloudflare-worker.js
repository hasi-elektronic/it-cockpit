const SESSION_COOKIE = "hasi_cockpit_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const LOGIN_HTML = "__LOGIN_HTML__";
const ADMIN_HTML = "__ADMIN_HTML__";

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", textBytes(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    textBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textBytes(value));
  return base64Url(new Uint8Array(signature));
}

function readCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

async function createSession(email, env) {
  const payload = base64Url(textBytes(JSON.stringify({
    email,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  })));
  const sig = await hmac(env.SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

async function verifySession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token || !token.includes(".")) return false;
  const [payload, sig] = token.split(".");
  const expected = await hmac(env.SESSION_SECRET, payload);
  if (sig !== expected) return false;
  try {
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replaceAll("-", "+").replaceAll("_", "/")), (char) => char.charCodeAt(0))));
    return json.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

async function serveAsset(env, path, request) {
  const url = new URL(request.url);
  url.pathname = path;
  return env.ASSETS.fetch(new Request(url, request));
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const expectedEmail = String(env.COCKPIT_EMAIL || "").trim().toLowerCase();
  const salt = env.COCKPIT_PASSWORD_SALT || "";
  const hash = await sha256Hex(`${salt}:${password}`);
  const hashMatches = env.COCKPIT_PASSWORD_HASH && hash === env.COCKPIT_PASSWORD_HASH;
  const secretMatches = env.COCKPIT_PASSWORD && password === env.COCKPIT_PASSWORD;
  if (!expectedEmail || email !== expectedEmail || (!hashMatches && !secretMatches)) {
    return json({ ok: false }, 401);
  }
  const session = await createSession(email, env);
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `${SESSION_COOKIE}=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
    },
  });
}

async function status(env, request) {
  const response = await serveAsset(env, "/data/status.json", request);
  if (!response.ok) return json({ error: "Status snapshot not found" }, 404);
  const snapshot = await response.json();
  snapshot.customers = await customers(env, request);
  return json(snapshot);
}

function slugify(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function parseTopics(value) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean).slice(0, 12);
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 12);
}

function boolValue(value) {
  return value === true || value === "true" || value === "on" || value === "1";
}

function normalizeOnboarding(input = {}, existing = {}) {
  return {
    profileComplete: boolValue(input.profileComplete ?? existing.profileComplete),
    brandComplete: boolValue(input.brandComplete ?? existing.brandComplete),
    productPhotos: boolValue(input.productPhotos ?? existing.productPhotos),
    productList: boolValue(input.productList ?? existing.productList),
    instagramBusiness: boolValue(input.instagramBusiness ?? existing.instagramBusiness),
    facebookPage: boolValue(input.facebookPage ?? existing.facebookPage),
    metaAccess: boolValue(input.metaAccess ?? existing.metaAccess),
    contentPlan: boolValue(input.contentPlan ?? existing.contentPlan),
    publishPermission: String(input.publishPermission || existing.publishPermission || "missing").trim(),
    notes: String(input.notes ?? existing.notes ?? "").trim(),
    updatedAt: new Date().toISOString(),
  };
}

function normalizeCadence(input = {}, existing = {}) {
  return {
    carousel: String(input.carouselTime || input.carousel || existing.carousel || "08:00").trim(),
    reel: String(input.reelTime || input.reel || existing.reel || "08:30").trim(),
    story: String(input.storyTime || input.story || existing.story || "09:00").trim(),
  };
}

function normalizeCustomer(input, existing = null) {
  const company = String(input.company || input.name || "").trim();
  if (!company) throw new Error("Firma fehlt");
  const id = slugify(existing?.id || input.id || company);
  if (!id) throw new Error("Kunden-ID fehlt");
  const onboardingInput = input.onboarding || input;
  const brandInput = input.brand || {};
  const cadenceInput = input.cadence || input;
  return {
    id,
    name: company,
    company,
    owner: String(input.owner || "").trim(),
    email: String(input.email || "").trim(),
    phone: String(input.phone || "").trim(),
    city: String(input.city || "").trim(),
    address: String(input.address || "").trim(),
    instagram: String(input.instagram || "").trim(),
    industry: String(input.industry || "").trim(),
    language: String(input.language || "de").trim(),
    status: String(input.status || "active").trim(),
    brand: {
      primary: String(input.primary || brandInput.primary || "#3ABADF").trim(),
      secondary: String(input.secondary || brandInput.secondary || input.primary || brandInput.primary || "#41AADE").trim(),
      accent: String(input.accent || brandInput.accent || "#FF6B00").trim(),
      font: String(input.font || brandInput.font || "Space Grotesk").trim(),
      logo: String(input.logo || brandInput.logo || "").trim(),
    },
    topics: parseTopics(input.topics),
    cadence: normalizeCadence(cadenceInput, existing?.cadence),
    positioning: String(input.positioning || "").trim(),
    onboarding: normalizeOnboarding(onboardingInput, existing?.onboarding),
    createdAt: existing?.createdAt || new Date().toISOString(),
  };
}

async function fallbackCustomers(env, request) {
  const response = await serveAsset(env, "/data/customers.json", request);
  if (!response.ok) return [];
  return response.json();
}

async function customers(env, request) {
  if (env.CUSTOMERS) {
    const stored = await env.CUSTOMERS.get("customers", "json");
    if (Array.isArray(stored)) return stored.map((row) => normalizeCustomer(row, row));
  }
  const rows = await fallbackCustomers(env, request);
  return rows.map((row) => normalizeCustomer(row, row));
}

async function saveCustomers(env, rows) {
  if (!env.CUSTOMERS) throw new Error("CUSTOMERS KV binding fehlt");
  await env.CUSTOMERS.put("customers", JSON.stringify(rows, null, 2));
}

async function addCustomer(request, env) {
  const customer = normalizeCustomer(await request.json());
  const rows = await customers(env, request);
  if (rows.some((row) => row.id === customer.id)) {
    return json({ error: "Kunde existiert bereits" }, 409);
  }
  const nextRows = [customer, ...rows];
  await saveCustomers(env, nextRows);
  return json({ customer }, 201);
}

async function updateCustomer(request, env, id) {
  const input = await request.json();
  const rows = await customers(env, request);
  const index = rows.findIndex((row) => row.id === id);
  if (index === -1) return json({ error: "Kunde nicht gefunden" }, 404);
  const customer = normalizeCustomer({ ...rows[index], ...input }, rows[index]);
  const nextRows = rows.map((row, rowIndex) => rowIndex === index ? customer : row);
  await saveCustomers(env, nextRows);
  return json({ customer });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/login" || url.pathname === "/login.html") {
      return new Response(LOGIN_HTML, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Set-Cookie": clearSessionCookie(),
        },
      });
    }
    if (url.pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/hasi-logo.png") {
      return serveAsset(env, "/hasi-logo.png", request);
    }
    if (url.pathname === "/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/login",
          "Set-Cookie": clearSessionCookie(),
        },
      });
    }

    if (!(await verifySession(request, env))) {
      if (url.pathname.startsWith("/api/")) return json({ error: "Unauthorized" }, 401);
      const next = `${url.pathname}${url.search}`;
      return Response.redirect(`${url.origin}/login?next=${encodeURIComponent(next)}`, 302);
    }

    if (url.pathname === "/admin" || url.pathname === "/admin.html") {
      return new Response(ADMIN_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (url.pathname.startsWith("/kunde/")) return serveAsset(env, "/index.html", request);
    if (url.pathname === "/api/status") return status(env, request);
    if (url.pathname === "/api/customers" && request.method === "GET") {
      return json({ customers: await customers(env, request) });
    }
    if (url.pathname === "/api/customers" && request.method === "POST") {
      return addCustomer(request, env);
    }
    if (url.pathname.startsWith("/api/customers/") && request.method === "PUT") {
      const id = decodeURIComponent(url.pathname.replace("/api/customers/", ""));
      return updateCustomer(request, env, id);
    }
    if (url.pathname.startsWith("/api/publish/")) {
      return json({ ok: false, error: "Cloud publish is disabled. Bitte lokal in Hasi Social Media veroeffentlichen." }, 403);
    }
    return env.ASSETS.fetch(request);
  },
};
