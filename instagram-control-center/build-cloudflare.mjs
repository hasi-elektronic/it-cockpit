import { mkdir, readFile, readdir, rm, stat, writeFile, copyFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = "/Users/hguencavdi/Desktop/it-cockpit";
const appRoot = join(root, "instagram-control-center");
const publicRoot = join(appRoot, "public");
const toolsRoot = join(root, "instagram-karussells", "tools");
const outDir = join(appRoot, "dist");

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

async function copyDir(src, dest) {
  await mkdir(dest, { recursive: true });
  for (const entry of await readdir(src, { withFileTypes: true })) {
    const source = join(src, entry.name);
    const target = join(dest, entry.name);
    if (entry.isDirectory()) await copyDir(source, target);
    else await copyFile(source, target);
  }
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

async function manifests(log) {
  const files = (await readdir(toolsRoot))
    .filter((file) => file.endsWith(".manifest.json"))
    .sort((a, b) => a.localeCompare(b));
  const items = [];
  for (const file of files) {
    const fullPath = join(toolsRoot, file);
    const fileStat = await stat(fullPath);
    const manifest = await readJson(fullPath, {});
    const type = classifyManifest(file, manifest);
    const urls = manifest.imageUrls || [manifest.videoUrl || manifest.imageUrl].filter(Boolean);
    const checks = await Promise.all(urls.map(checkUrl));
    const slug = file.replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, "");
    const published = log.find((entry) => {
      if (entry.status !== "published" && !entry.instagramId) return false;
      return entry.manifest === file || entry.slug === slug;
    });
    items.push({
      file,
      type,
      path: fullPath,
      slug,
      caption: manifest.caption || "",
      urlCount: urls.length,
      urls,
      checks,
      ready: checks.length > 0 && checks.every((check) => check.ok),
      published: Boolean(published),
      publishedAt: published?.time || "",
      instagramId: published?.instagramId || "",
      updatedAt: fileStat.mtime.toISOString(),
      sortAt: published?.time || fileStat.mtime.toISOString(),
      preview: type === "carousel" ? urls[0] : manifest.videoUrl || manifest.imageUrl || "",
    });
  }
  return items.sort((a, b) => new Date(b.sortAt).getTime() - new Date(a.sortAt).getTime());
}

function nextPlan(plan) {
  const now = new Date();
  const topics = plan.topics || [];
  return Array.from({ length: 14 }).map((_, index) => {
    const date = new Date(now);
    date.setDate(now.getDate() + index);
    return {
      date: date.toISOString().slice(0, 10),
      topic: topics[index % topics.length] || "Web-App für lokale Firmen",
      carousel: plan.cadence?.carousel || "08:00",
      reel: plan.cadence?.reel || "08:30",
      story: plan.cadence?.story || "09:00",
    };
  });
}

const log = await readJson(join(appRoot, "data", "activity-log.json"), []);
const plan = await readJson(join(appRoot, "data", "content-plan.json"), {});
const customer = await readJson(join(appRoot, "customer-profile.json"), {});
const customers = await readJson(join(appRoot, "data", "customers.json"), [customer].filter(Boolean));
const status = {
  cloud: true,
  customer,
  customers,
  instagram: {
    ok: true,
    output: "Cloud preview mode. Publishing is disabled in this protected build.",
  },
  manifests: await manifests(log),
  automations: [
    { id: "hasi-social-media-tagesproduktion", name: "Hasi Social Media Tagesproduktion", status: "ACTIVE", schedule: "08:00 Karussell + Reel + Story" },
    { id: "hasi-social-media-tageskontrolle", name: "Hasi Social Media Tageskontrolle", status: "ACTIVE", schedule: "09:15 Kontrolle / fehlende Inhalte nachholen" },
  ],
  plan: nextPlan(plan),
  log: log.slice(0, 50),
};

await rm(outDir, { recursive: true, force: true });
await mkdir(join(outDir, "data"), { recursive: true });
await copyDir(publicRoot, outDir);
await writeFile(join(outDir, "data", "status.json"), `${JSON.stringify(status, null, 2)}\n`);
await writeFile(join(outDir, "data", "customers.json"), `${JSON.stringify(customers, null, 2)}\n`);
const workerSource = await readFile(join(appRoot, "cloudflare-worker.js"), "utf8");
const loginHtml = await readFile(join(publicRoot, "login.html"), "utf8");
const adminHtml = await readFile(join(publicRoot, "admin.html"), "utf8");
const appHtml = await readFile(join(publicRoot, "index.html"), "utf8");
const homeHtml = await readFile(join(publicRoot, "home.html"), "utf8");
const demoHtml = await readFile(join(publicRoot, "demo.html"), "utf8");
await writeFile(
  join(outDir, "_worker.js"),
  workerSource
    .replace('"__LOGIN_HTML__"', JSON.stringify(loginHtml))
    .replace('"__ADMIN_HTML__"', JSON.stringify(adminHtml))
    .replace('"__APP_HTML__"', JSON.stringify(appHtml))
    .replace('"__HOME_HTML__"', JSON.stringify(homeHtml))
    .replace('"__DEMO_HTML__"', JSON.stringify(demoHtml)),
  "utf8"
);

if (!(await exists(join(outDir, "index.html")))) {
  throw new Error("index.html missing in Cloudflare build");
}
console.log(outDir);
