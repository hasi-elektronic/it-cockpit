const SESSION_COOKIE = "hasi_cockpit_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const LOGIN_HTML = "__LOGIN_HTML__";
const ADMIN_HTML = "__ADMIN_HTML__";
const APP_HTML = "__APP_HTML__";
const HOME_HTML = "__HOME_HTML__";
const DEMO_HTML = "__DEMO_HTML__";

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

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store, no-cache, max-age=0, must-revalidate",
    ...extra,
  };
}

function safeRedirectTarget(value, fallback = "/app") {
  const target = String(value || "").trim();
  if (!target || !target.startsWith("/") || target.startsWith("//")) return fallback;
  if (target === "/app" || target.startsWith("/app?") || target.startsWith("/app#")) return target;
  if (target === "/admin" || target.startsWith("/admin?") || target.startsWith("/admin#")) return target;
  if (/^\/kunde\/[a-z0-9-]+([/?#].*)?$/i.test(target)) return target;
  return fallback;
}

async function serveAsset(env, path, request) {
  const url = new URL(request.url);
  url.pathname = path;
  return env.ASSETS.fetch(new Request(url, request));
}

async function handleLogin(request, env) {
  const contentType = request.headers.get("Content-Type") || "";
  const isFormPost = contentType.toLowerCase().includes("application/x-www-form-urlencoded");
  const body = isFormPost
    ? Object.fromEntries(new URLSearchParams(await request.text()))
    : await request.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const expectedEmail = String(env.COCKPIT_EMAIL || "").trim().toLowerCase();
  const salt = env.COCKPIT_PASSWORD_SALT || "";
  const hash = await sha256Hex(`${salt}:${password}`);
  const hashMatches = env.COCKPIT_PASSWORD_HASH && hash === env.COCKPIT_PASSWORD_HASH;
  const secretMatches = env.COCKPIT_PASSWORD && password === env.COCKPIT_PASSWORD;
  const redirectTo = safeRedirectTarget(body.next, "/app");
  if (!expectedEmail || email !== expectedEmail || (!hashMatches && !secretMatches)) {
    if (isFormPost) {
      return new Response(null, {
        status: 303,
        headers: noStoreHeaders({
          Location: `/login?next=${encodeURIComponent(redirectTo)}&error=1`,
          "Set-Cookie": clearSessionCookie(),
        }),
      });
    }
    return json({ ok: false }, 401);
  }
  const session = await createSession(email, env);
  const cookie = `${SESSION_COOKIE}=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
  if (isFormPost) {
    return new Response(null, {
      status: 303,
      headers: noStoreHeaders({
        Location: redirectTo,
        "Set-Cookie": cookie,
      }),
    });
  }
  return new Response(JSON.stringify({ ok: true, redirectTo }), {
    headers: noStoreHeaders({
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": cookie,
    }),
  });
}

function contentTypeOk(type, expected) {
  return String(type || "").toLowerCase().includes(expected);
}

function manifestSlug(file) {
  return String(file || "").replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, "");
}

function safePublishFile(value) {
  return String(value || "").replace(/[^a-zA-Z0-9._-]/g, "");
}

async function activityLog(env, request) {
  const fallbackResponse = await serveAsset(env, "/data/status.json", request);
  const snapshot = fallbackResponse.ok ? await fallbackResponse.json().catch(() => ({})) : {};
  const staticLog = Array.isArray(snapshot.log) ? snapshot.log : [];
  const storedLog = env.CUSTOMERS ? await env.CUSTOMERS.get("activity-log", "json") : [];
  const combined = [...(Array.isArray(storedLog) ? storedLog : []), ...staticLog];
  const seen = new Set();
  return combined.filter((entry) => {
    const key = `${entry.action || ""}:${entry.manifest || ""}:${entry.instagramId || ""}:${entry.time || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime());
}

async function appendActivityLog(env, request, entry) {
  if (!env.CUSTOMERS) throw new Error("CUSTOMERS KV binding fehlt");
  const log = await activityLog(env, request);
  const next = [entry, ...log].slice(0, 100);
  await env.CUSTOMERS.put("activity-log", JSON.stringify(next, null, 2));
}

function applyPublishedLog(snapshot, log) {
  const items = Array.isArray(snapshot.manifests) ? snapshot.manifests : [];
  snapshot.manifests = items.map((item) => {
    const published = log.find((entry) => {
      if (entry.status !== "published" && !entry.instagramId) return false;
      return entry.manifest === item.file || entry.slug === item.slug || entry.slug === manifestSlug(item.file);
    });
    return published ? {
      ...item,
      published: true,
      publishedAt: published.time || item.publishedAt || "",
      instagramId: published.instagramId || item.instagramId || "",
    } : item;
  });
  snapshot.log = log.slice(0, 50);
  return snapshot;
}

async function status(env, request) {
  const response = await serveAsset(env, "/data/status.json", request);
  if (!response.ok) return json({ error: "Status snapshot not found" }, 404);
  const snapshot = await response.json();
  snapshot.customers = await customers(env, request);
  return json(applyPublishedLog(snapshot, await activityLog(env, request)));
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
      font: String(input.font || brandInput.font || "Plus Jakarta Sans").trim(),
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

function graphConfig(env) {
  const igUserId = env.IG_USER_ID;
  const accessToken = env.IG_ACCESS_TOKEN;
  if (!igUserId || !accessToken) throw new Error("Instagram Cloud Secrets fehlen: IG_USER_ID / IG_ACCESS_TOKEN");
  return {
    igUserId,
    accessToken,
    version: env.GRAPH_API_VERSION || "v25.0",
    graphHost: env.IG_GRAPH_HOST || "graph.instagram.com",
  };
}

async function graphPost(env, path, params) {
  const config = graphConfig(env);
  const body = new URLSearchParams({ ...params, access_token: config.accessToken });
  const response = await fetch(`https://${config.graphHost}/${config.version}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(JSON.stringify(data.error || data));
  return data;
}

async function graphGet(env, path, params = {}) {
  const config = graphConfig(env);
  const url = new URL(`https://${config.graphHost}/${config.version}${path}`);
  url.search = new URLSearchParams({ ...params, access_token: config.accessToken }).toString();
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(JSON.stringify(data.error || data));
  return data;
}

async function waitForContainer(env, containerId, attempts = 24) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const status = await graphGet(env, `/${containerId}`, { fields: "status_code,status" });
    if (status.status_code === "FINISHED") return;
    if (status.status_code === "ERROR") throw new Error(`Container ${containerId} failed: ${status.status || "unknown error"}`);
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`Container ${containerId} wurde nicht rechtzeitig fertig.`);
}

async function findManifest(env, request, file) {
  const response = await serveAsset(env, "/data/status.json", request);
  if (!response.ok) throw new Error("Status snapshot not found");
  const snapshot = await response.json();
  return (snapshot.manifests || []).find((item) => item.file === file);
}

async function verifyPublishItem(item) {
  if (!item || !Array.isArray(item.urls) || item.urls.length === 0) throw new Error("Manifest nicht gefunden oder ohne URLs.");
  const checks = await Promise.all(item.urls.map(async (url) => {
    const response = await fetch(url, { method: "HEAD" });
    return { ok: response.ok, status: response.status, type: response.headers.get("content-type") || "" };
  }));
  if (item.type === "carousel" && !checks.every((check) => check.ok && contentTypeOk(check.type, "image/png"))) {
    throw new Error("Karussell ist nicht publish-ready: Bild-URLs liefern nicht alle image/png.");
  }
  if (item.type === "reel" && !checks.every((check) => check.ok && contentTypeOk(check.type, "video/mp4"))) {
    throw new Error("Reel ist nicht publish-ready: Video-URL liefert kein video/mp4.");
  }
}

async function publishCarousel(env, item) {
  if (item.urls.length < 2 || item.urls.length > 10) throw new Error("Instagram Karussell braucht 2 bis 10 Bilder.");
  const children = [];
  for (const imageUrl of item.urls) {
    const child = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
      image_url: imageUrl,
      is_carousel_item: "true",
    });
    await waitForContainer(env, child.id, 20);
    children.push(child.id);
  }
  const parent = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
    media_type: "CAROUSEL",
    children: children.join(","),
    caption: item.caption || "",
  });
  await waitForContainer(env, parent.id, 20);
  return graphPost(env, `/${graphConfig(env).igUserId}/media_publish`, { creation_id: parent.id });
}

async function publishReel(env, item) {
  const container = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
    media_type: "REELS",
    video_url: item.urls[0],
    caption: item.caption || "",
    share_to_feed: "true",
  });
  await waitForContainer(env, container.id, 60);
  return graphPost(env, `/${graphConfig(env).igUserId}/media_publish`, { creation_id: container.id });
}

async function publishFromCloud(request, env, type, file) {
  if (!["carousel", "reel"].includes(type)) {
    return json({ ok: false, error: "Cloud Publish v1 erlaubt nur Karussell und Reel. Story bleibt publish-ready." }, 403);
  }
  const safeFile = safePublishFile(file);
  const item = await findManifest(env, request, safeFile);
  if (!item || item.type !== type) return json({ ok: false, error: "Manifest nicht gefunden oder falscher Typ." }, 404);

  const log = await activityLog(env, request);
  const already = log.find((entry) => (entry.status === "published" || entry.instagramId) && (entry.manifest === safeFile || entry.slug === item.slug));
  if (already) {
    return json({ ok: true, skipped: true, instagramId: already.instagramId || "", message: "Schon veröffentlicht." });
  }

  try {
    await verifyPublishItem(item);
    const published = type === "carousel" ? await publishCarousel(env, item) : await publishReel(env, item);
    const entry = {
      time: new Date().toISOString(),
      action: `publish-${type}`,
      status: "published",
      type,
      topic: item.slug || manifestSlug(safeFile),
      slug: item.slug || manifestSlug(safeFile),
      manifest: safeFile,
      instagramId: published.id || "",
      note: "Cloud Publish v1 über Hasi Social Media.",
    };
    await appendActivityLog(env, request, entry);
    return json({ ok: true, instagramId: published.id || "", entry });
  } catch (error) {
    await appendActivityLog(env, request, {
      time: new Date().toISOString(),
      action: `publish-${type}`,
      status: "failed",
      type,
      topic: item.slug || manifestSlug(safeFile),
      slug: item.slug || manifestSlug(safeFile),
      manifest: safeFile,
      instagramId: "",
      note: String(error.message || error).slice(0, 500),
    }).catch(() => {});
    return json({ ok: false, error: String(error.message || error) }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/home") {
      return new Response(HOME_HTML, {
        headers: noStoreHeaders({
          "Content-Type": "text/html; charset=utf-8",
        }),
      });
    }
    if (url.pathname === "/demo" || url.pathname === "/demo.html") {
      return new Response(DEMO_HTML, {
        headers: noStoreHeaders({
          "Content-Type": "text/html; charset=utf-8",
        }),
      });
    }
    if (url.pathname === "/login" || url.pathname === "/login.html") {
      if (await verifySession(request, env)) {
        return Response.redirect(`${url.origin}${safeRedirectTarget(url.searchParams.get("next"), "/app")}`, 302);
      }
      return new Response(LOGIN_HTML, {
        headers: noStoreHeaders({
          "Content-Type": "text/html; charset=utf-8",
        }),
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
        headers: noStoreHeaders({
          Location: "/login",
          "Set-Cookie": clearSessionCookie(),
        }),
      });
    }

    if (!(await verifySession(request, env))) {
      if (url.pathname.startsWith("/api/")) return json({ error: "Unauthorized" }, 401);
      const next = safeRedirectTarget(`${url.pathname}${url.search}`, "/app");
      return Response.redirect(`${url.origin}/login?next=${encodeURIComponent(next)}`, 302);
    }

    if (url.pathname === "/admin" || url.pathname === "/admin.html") {
      return new Response(ADMIN_HTML, {
        headers: noStoreHeaders({ "Content-Type": "text/html; charset=utf-8" }),
      });
    }
    if (url.pathname === "/app" || url.pathname === "/app.html" || url.pathname.startsWith("/kunde/")) {
      return new Response(APP_HTML, {
        headers: noStoreHeaders({
          "Content-Type": "text/html; charset=utf-8",
        }),
      });
    }
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
    if (url.pathname.startsWith("/api/publish/") && request.method === "POST") {
      const [, , , type, ...fileParts] = url.pathname.split("/");
      return publishFromCloud(request, env, type, decodeURIComponent(fileParts.join("/") || ""));
    }
    return env.ASSETS.fetch(request);
  },
};
