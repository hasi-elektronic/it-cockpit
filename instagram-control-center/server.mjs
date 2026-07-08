import { createServer } from "node:http";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { extname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { homedir } from "node:os";

const root = "/Users/hguencavdi/Desktop/it-cockpit";
const appRoot = join(root, "instagram-control-center");
const publicRoot = join(appRoot, "public");
const toolsRoot = join(root, "instagram-karussells", "tools");
const mediaRoot = join(root, "instagram-karussells");
const envPath = join(toolsRoot, ".env");
const logPath = join(appRoot, "data", "activity-log.json");
const planPath = join(appRoot, "data", "content-plan.json");
const customersPath = join(appRoot, "data", "customers.json");

const port = Number(process.env.PORT || 8787);

const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".mp4": "video/mp4",
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function sendText(res, status, body, type = "text/plain; charset=utf-8") {
  res.writeHead(status, { "Content-Type": type });
  res.end(body);
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return fallback;
  }
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

function readRequestBody(req) {
  return new Promise((resolveBody, rejectBody) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
      if (body.length > 1024 * 1024) {
        req.destroy();
        rejectBody(new Error("Request body too large"));
      }
    });
    req.on("end", () => resolveBody(body));
    req.on("error", rejectBody);
  });
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

async function appendLog(entry) {
  const log = await readJson(logPath, []);
  log.unshift({
    time: new Date().toISOString(),
    ...entry,
  });
  await writeFile(logPath, `${JSON.stringify(log.slice(0, 100), null, 2)}\n`);
}

async function customers() {
  const rows = await readJson(customersPath, []);
  return Array.isArray(rows) ? rows : [];
}

async function addCustomer(req) {
  const body = await readRequestBody(req);
  const input = body ? JSON.parse(body) : {};
  const customer = normalizeCustomer(input);
  const rows = await customers();
  if (rows.some((row) => row.id === customer.id)) {
    throw new Error("Kunde existiert bereits");
  }
  const nextRows = [customer, ...rows];
  await writeFile(customersPath, `${JSON.stringify(nextRows, null, 2)}\n`);
  await appendLog({
    action: "customer-created",
    status: "ok",
    customerId: customer.id,
    customerName: customer.company,
  });
  return customer;
}

async function readEnv() {
  const text = await readFile(envPath, "utf8");
  const env = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.trim().startsWith("#")) continue;
    const index = line.indexOf("=");
    if (index === -1) continue;
    env[line.slice(0, index)] = line.slice(index + 1);
  }
  return env;
}

function sanitizeOutput(output) {
  return output
    .replace(/IGAA[A-Za-z0-9_.-]+/g, "IGAA***")
    .replace(/access_token=[^&\s]+/g, "access_token=***");
}

function runNodeScript(script, args = []) {
  return new Promise(async (resolveRun) => {
    const env = { ...process.env, ...(await readEnv()) };
    const child = spawn(process.execPath, [script, ...args], {
      cwd: root,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      resolveRun({
        code,
        ok: code === 0,
        stdout: sanitizeOutput(stdout),
        stderr: sanitizeOutput(stderr),
      });
    });
  });
}

async function listManifestFiles() {
  const files = await readdir(toolsRoot);
  return files
    .filter((file) => file.endsWith(".manifest.json"))
    .sort((a, b) => a.localeCompare(b));
}

function classifyManifest(file, manifest) {
  if (file.includes("story") || manifest.imageUrl) return "story";
  if (file.includes("reel") || manifest.videoUrl) return "reel";
  return "carousel";
}

async function checkUrl(url) {
  if (!url) return { ok: false, status: 0, type: "" };
  try {
    const response = await fetch(url, { method: "HEAD" });
    return {
      ok: response.ok,
      status: response.status,
      type: response.headers.get("content-type") || "",
      length: response.headers.get("content-length") || "",
    };
  } catch (error) {
    return { ok: false, status: 0, type: "", error: error.message };
  }
}

async function manifests() {
  const files = await listManifestFiles();
  const log = await readJson(logPath, []);
  const items = [];
  for (const file of files) {
    const fullPath = join(toolsRoot, file);
    const manifest = await readJson(fullPath, {});
    const type = classifyManifest(file, manifest);
    const urls = manifest.imageUrls || [manifest.videoUrl || manifest.imageUrl].filter(Boolean);
    const checks = await Promise.all(urls.map(checkUrl));
    const published = log.find((entry) => {
      if (entry.status !== "published" && !entry.instagramId) return false;
      return entry.manifest === file || entry.slug === file.replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, "");
    });
    items.push({
      file,
      type,
      path: fullPath,
      slug: file.replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, ""),
      caption: manifest.caption || "",
      urlCount: urls.length,
      urls,
      checks,
      ready: checks.length > 0 && checks.every((check) => check.ok),
      published: Boolean(published),
      publishedAt: published?.time || "",
      instagramId: published?.instagramId || "",
      preview: type === "carousel" ? urls[0] : manifest.videoUrl || manifest.imageUrl || "",
    });
  }
  return items;
}

async function automations() {
  const dir = join(homedir(), ".codex", "automations");
  if (!(await exists(dir))) return [];
  const ids = await readdir(dir);
  const rows = [];
  for (const id of ids) {
    const file = join(dir, id, "automation.toml");
    if (!(await exists(file))) continue;
    const text = await readFile(file, "utf8");
    if (!/Instagram|instagram|Hasi/.test(text)) continue;
    rows.push({
      id,
      name: (text.match(/name\s*=\s*"([^"]+)"/) || [])[1] || id,
      status: (text.match(/status\s*=\s*"([^"]+)"/) || [])[1] || "",
      schedule: (text.match(/rrule\s*=\s*"""([\s\S]*?)"""/) || text.match(/rrule\s*=\s*"([^"]+)"/) || [])[1] || "",
    });
  }
  return rows;
}

function nextPlan(plan) {
  const now = new Date();
  const topics = plan.topics || [];
  return Array.from({ length: 14 }).map((_, index) => {
    const date = new Date(now);
    date.setDate(now.getDate() + index);
    const topic = topics[index % topics.length] || "IT-Tipp";
    return {
      date: date.toISOString().slice(0, 10),
      topic,
      carousel: plan.cadence?.carousel || "08:00",
      reel: plan.cadence?.reel || "08:30",
      story: plan.cadence?.story || "09:00",
    };
  });
}

async function status() {
  const [check, items, autos, plan, log] = await Promise.all([
    runNodeScript(join(toolsRoot, "instagram-check.mjs")),
    manifests(),
    automations(),
    readJson(planPath, {}),
    readJson(logPath, []),
  ]);

  return {
    instagram: {
      ok: check.ok,
      output: check.stdout.trim() || check.stderr.trim(),
    },
    manifests: items,
    automations: autos,
    customers: await customers(),
    plan: nextPlan(plan),
    log: log.slice(0, 20),
  };
}

async function publish(type, file) {
  const safeFile = file.replace(/[^a-zA-Z0-9._-]/g, "");
  const manifestPath = join(toolsRoot, safeFile);
  if (!(await exists(manifestPath))) {
    return { ok: false, error: "Manifest not found" };
  }

  const scriptByType = {
    carousel: "publish-carousel.mjs",
    reel: "publish-reel.mjs",
    story: "publish-story.mjs",
  };
  const script = scriptByType[type];
  if (!script) return { ok: false, error: "Unknown publish type" };

  const result = await runNodeScript(join(toolsRoot, script), [manifestPath]);
  const output = result.stdout.trim() || result.stderr.trim();
  const idMatch =
    output.match(/Published Instagram media:\s*(\d+)/) ||
    output.match(/Published Instagram reel:\s*(\d+)/) ||
    output.match(/Published Instagram story:\s*(\d+)/);
  await appendLog({
    action: `publish-${type}`,
    status: result.ok ? "published" : "failed",
    type,
    manifest: safeFile,
    slug: safeFile.replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, ""),
    instagramId: idMatch?.[1] || "",
    ok: result.ok,
    output,
  });
  return result;
}

async function serveStatic(req, res, pathname) {
  const file = pathname === "/" || pathname.startsWith("/kunde/")
    ? "index.html"
    : pathname === "/admin"
      ? "admin.html"
      : pathname.slice(1);
  const target = resolve(publicRoot, file);
  if (!target.startsWith(publicRoot) || !(await exists(target))) {
    sendText(res, 404, "Not found");
    return;
  }
  res.writeHead(200, { "Content-Type": mime[extname(target)] || "application/octet-stream" });
  createReadStream(target).pipe(res);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://localhost:${port}`);
  try {
    if (url.pathname === "/api/status") {
      send(res, 200, await status());
      return;
    }
    if (url.pathname === "/api/customers" && req.method === "GET") {
      send(res, 200, { customers: await customers() });
      return;
    }
    if (url.pathname === "/api/customers" && req.method === "POST") {
      send(res, 201, { customer: await addCustomer(req) });
      return;
    }
    if (url.pathname.startsWith("/api/publish/") && req.method === "POST") {
      const [, , , type, file] = url.pathname.split("/");
      send(res, 200, await publish(type, decodeURIComponent(file || "")));
      return;
    }
    if (url.pathname.startsWith("/media/")) {
      const target = resolve(mediaRoot, decodeURIComponent(url.pathname.replace("/media/", "")));
      if (!target.startsWith(mediaRoot) || !(await exists(target))) {
        sendText(res, 404, "Not found");
        return;
      }
      res.writeHead(200, { "Content-Type": mime[extname(target)] || "application/octet-stream" });
      createReadStream(target).pipe(res);
      return;
    }
    await serveStatic(req, res, url.pathname);
  } catch (error) {
    send(res, 500, { error: error.message });
  }
});

server.listen(port, () => {
  console.log(`Hasi Instagram Control Center: http://localhost:${port}`);
});
