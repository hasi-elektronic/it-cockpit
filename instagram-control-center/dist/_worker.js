const SESSION_COOKIE = "hasi_cockpit_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const LOGIN_HTML = "<!doctype html>\n<html lang=\"de\">\n  <head>\n    <meta charset=\"utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n    <title>Hasi Content Cockpit Login</title>\n    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />\n    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />\n    <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&display=swap\" rel=\"stylesheet\" />\n    <style>\n      :root {\n        --blue: #3abadf;\n        --ink: #0d1b2a;\n        --muted: #667085;\n        --line: #d8eef5;\n        --orange: #ff6b00;\n      }\n      * { box-sizing: border-box; }\n      body {\n        min-height: 100vh;\n        margin: 0;\n        display: grid;\n        place-items: center;\n        padding: 24px;\n        font-family: \"Space Grotesk\", system-ui, sans-serif;\n        color: var(--ink);\n        background:\n          radial-gradient(circle at 78% 20%, rgba(58, 186, 223, .24), transparent 28%),\n          linear-gradient(145deg, #081522 0%, #0d1b2a 45%, #1a5f75 100%);\n      }\n      .shell {\n        width: min(980px, 100%);\n        display: grid;\n        grid-template-columns: 1.1fr .9fr;\n        overflow: hidden;\n        border-radius: 12px;\n        background: #fff;\n        box-shadow: 0 30px 90px rgba(0, 0, 0, .36);\n      }\n      .intro {\n        padding: 42px;\n        color: #fff;\n        background:\n          radial-gradient(circle at 88% 86%, rgba(255,255,255,.17), transparent 30%),\n          linear-gradient(155deg, #0d1b2a, #3abadf);\n      }\n      .brand {\n        display: flex;\n        align-items: center;\n        gap: 14px;\n        margin-bottom: 54px;\n      }\n      .logo {\n        width: 64px;\n        height: 64px;\n        border-radius: 14px;\n        background: #fff;\n        padding: 9px;\n        object-fit: contain;\n      }\n      h1 {\n        margin: 0;\n        font-size: 42px;\n        line-height: 1;\n        letter-spacing: 0;\n      }\n      .intro p {\n        max-width: 460px;\n        color: rgba(255,255,255,.82);\n        font-size: 17px;\n        line-height: 1.45;\n      }\n      .chips {\n        display: flex;\n        flex-wrap: wrap;\n        gap: 9px;\n        margin-top: 28px;\n      }\n      .chip {\n        padding: 8px 11px;\n        border-radius: 999px;\n        background: rgba(255,255,255,.13);\n        border: 1px solid rgba(255,255,255,.18);\n        font-size: 12px;\n        font-weight: 800;\n      }\n      .login {\n        padding: 42px;\n      }\n      .login h2 {\n        margin: 0 0 8px;\n        font-size: 28px;\n      }\n      .login p {\n        margin: 0 0 26px;\n        color: var(--muted);\n        line-height: 1.45;\n      }\n      label {\n        display: block;\n        margin: 16px 0 7px;\n        color: #344054;\n        font-size: 13px;\n        font-weight: 800;\n      }\n      input {\n        width: 100%;\n        height: 48px;\n        border: 1px solid var(--line);\n        border-radius: 8px;\n        padding: 0 13px;\n        font: inherit;\n        outline: none;\n      }\n      input:focus {\n        border-color: var(--blue);\n        box-shadow: 0 0 0 4px rgba(58, 186, 223, .14);\n      }\n      button {\n        width: 100%;\n        height: 50px;\n        margin-top: 22px;\n        border: 0;\n        border-radius: 8px;\n        background: var(--orange);\n        color: #fff;\n        font: inherit;\n        font-weight: 900;\n        cursor: pointer;\n      }\n      .error {\n        min-height: 20px;\n        margin-top: 14px;\n        color: #b42318;\n        font-size: 13px;\n        font-weight: 700;\n      }\n      .small {\n        margin-top: 24px;\n        color: var(--muted);\n        font-size: 12px;\n      }\n      @media (max-width: 820px) {\n        .shell { grid-template-columns: 1fr; }\n        .intro, .login { padding: 28px; }\n      }\n    </style>\n  </head>\n  <body>\n    <main class=\"shell\">\n      <section class=\"intro\">\n        <div class=\"brand\">\n          <img class=\"logo\" src=\"/hasi-logo.png\" alt=\"Hasi Elektronic\" />\n          <div>\n            <strong>Hasi Elektronic</strong><br />\n            <span>Content Cockpit</span>\n          </div>\n        </div>\n        <h1>Social Media<br />Control Center</h1>\n        <p>Planung, Vorschau und Status fuer Karussell, Reel und Story. Erst pruefen, dann veroeffentlichen.</p>\n        <div class=\"chips\">\n          <span class=\"chip\">Web-App</span>\n          <span class=\"chip\">iOS</span>\n          <span class=\"chip\">Android</span>\n          <span class=\"chip\">Automatisierung</span>\n        </div>\n      </section>\n      <section class=\"login\">\n        <h2>Anmelden</h2>\n        <p>Bitte mit dem Hasi Zugang anmelden, bevor das Cockpit geoeffnet wird.</p>\n        <form id=\"loginForm\">\n          <label for=\"email\">E-Mail</label>\n          <input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"username\" required />\n          <label for=\"password\">Passwort</label>\n          <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required />\n          <button type=\"submit\">Control Center oeffnen</button>\n          <div class=\"error\" id=\"error\"></div>\n        </form>\n        <div class=\"small\">Geschuetzter Bereich fuer Hasi Elektronic.</div>\n      </section>\n    </main>\n    <script>\n      document.querySelector(\"#loginForm\").addEventListener(\"submit\", async (event) => {\n        event.preventDefault();\n        const error = document.querySelector(\"#error\");\n        error.textContent = \"\";\n        const body = {\n          email: document.querySelector(\"#email\").value,\n          password: document.querySelector(\"#password\").value,\n        };\n        const response = await fetch(\"/api/login\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify(body),\n        });\n        if (response.ok) {\n          window.location.href = \"/\";\n          return;\n        }\n        error.textContent = \"Login fehlgeschlagen. Bitte Zugangsdaten pruefen.\";\n      });\n    </script>\n  </body>\n</html>\n";

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

function normalizeCustomer(input) {
  const company = String(input.company || input.name || "").trim();
  if (!company) throw new Error("Firma fehlt");
  const id = slugify(input.id || company);
  if (!id) throw new Error("Kunden-ID fehlt");
  const topics = String(input.topics || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 12);
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
      primary: String(input.primary || "#3ABADF").trim(),
      secondary: String(input.secondary || "#41AADE").trim(),
      accent: String(input.accent || "#FF6B00").trim(),
      font: String(input.font || "Space Grotesk").trim(),
      logo: String(input.logo || "").trim(),
    },
    topics,
    positioning: String(input.positioning || "").trim(),
    createdAt: new Date().toISOString(),
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
    if (Array.isArray(stored)) return stored;
  }
  return fallbackCustomers(env, request);
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/login" || url.pathname === "/login.html") {
      return new Response(LOGIN_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (url.pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/hasi-logo.png") {
      return serveAsset(env, "/hasi-logo.png", request);
    }

    if (!(await verifySession(request, env))) {
      if (url.pathname.startsWith("/api/")) return json({ error: "Unauthorized" }, 401);
      return Response.redirect(`${url.origin}/login`, 302);
    }

    if (url.pathname === "/admin") return serveAsset(env, "/admin.html", request);
    if (url.pathname === "/api/status") return status(env, request);
    if (url.pathname === "/api/customers" && request.method === "GET") {
      return json({ customers: await customers(env, request) });
    }
    if (url.pathname === "/api/customers" && request.method === "POST") {
      return addCustomer(request, env);
    }
    if (url.pathname.startsWith("/api/publish/")) {
      return json({ ok: false, error: "Cloud publish is disabled. Bitte lokal im Hasi Cockpit veroeffentlichen." }, 403);
    }
    if (url.pathname === "/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/login",
          "Set-Cookie": `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
        },
      });
    }
    return env.ASSETS.fetch(request);
  },
};
