// Outage & Hack Map — zero-dependency Node server (Node 18+).
// Periodically scours news feeds and status pages, then serves the results
// as JSON plus a static map UI.
const http = require('http');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const { NEWS_FEEDS, STATUS_PAGES, fetchNews, fetchStatus } = require('./lib/sources');
const { collectServices } = require('./lib/services');
const { INTERNET_SOURCES, cloudflareDiagnostics } = require('./lib/internet');
const { collectVulns } = require('./lib/vulns');
const { clusterNews } = require('./lib/cluster');
const { collectHealthcare } = require('./lib/healthcare');

const pkg = require('./package.json');
const changelog = require('./lib/changelog');
const STARTED_AT = new Date().toISOString();

const PORT = +process.env.PORT || 3000;
const REFRESH_MIN = +process.env.REFRESH_MINUTES || 10;
const MAX_AGE_DAYS = +process.env.MAX_AGE_DAYS || 7;

let state = { updatedAt: null, refreshing: false, sources: [], items: [] };

let services = { updatedAt: null, refreshing: false, categories: [], services: [], feeds: {}, sources: [] };

async function refreshServices() {
  if (services.refreshing) return;
  services.refreshing = true;
  try {
    services = { ...(await collectServices()), updatedAt: new Date().toISOString(), refreshing: false };
    const bad = services.services.filter((s) => s.status !== 'ok').length;
    console.log(`[${services.updatedAt}] services: ${bad}/${services.services.length} with issues`);
  } catch (err) {
    services.refreshing = false;
    console.error('services refresh failed:', err);
  }
}

// Vulnerability data changes slowly (CISA updates about daily) and NVD rate-limits, so refresh hourly.
const VULN_REFRESH_MIN = +process.env.VULN_REFRESH_MINUTES || 60;
let vulns = { updatedAt: null, refreshing: false, exploited: [], newCritical: [], vendors: [], sources: [] };
async function refreshVulns() {
  if (vulns.refreshing) return;
  vulns.refreshing = true;
  try {
    vulns = { ...(await collectVulns()), updatedAt: new Date().toISOString(), refreshing: false };
    console.log(`[${vulns.updatedAt}] vulnerabilities: ${vulns.exploited.length} exploited, ${vulns.newCritical.length} new high/critical`);
  } catch (err) {
    vulns.refreshing = false;
    vulns.error = String(err.message || err);
    console.error('vulnerability refresh failed:', err);
  }
}

let health = { updatedAt: null, refreshing: false, ransomware: [], breaches: [], deviceAdvisories: [], fdaAlerts: [], recalls: [], sources: [] };
async function refreshHealthcare() {
  if (health.refreshing) return;
  health.refreshing = true;
  try {
    health = { ...(await collectHealthcare()), updatedAt: new Date().toISOString(), refreshing: false };
    const vendorHits = health.ransomware.filter((r) => r.vendor).length;
    console.log(`[${health.updatedAt}] healthcare: ${health.ransomware.length} ransomware posts (${vendorHits} vendor matches), ${health.breaches.length} HHS breaches, ${health.deviceAdvisories.length} device advisories, ${health.recalls.length} recalls`);
  } catch (err) {
    health.refreshing = false;
    health.error = String(err.message || err);
    console.error('healthcare refresh failed:', err);
  }
}

// Healthcare alerts per Services card: ransomware leak-site listings (30 days), device advisories,
// Class I recalls and HHS breach reports (90 days) that match the card's vendor.
function healthAlertsByService() {
  const out = {};
  const add = (vendor, kind, item) => {
    if (!vendor?.service) return;
    out[vendor.service] ||= { ransomware: [], advisories: 0, recalls: 0, breaches: 0 };
    if (kind === 'ransomware') out[vendor.service].ransomware.push(item);
    else out[vendor.service][kind]++;
  };
  const d30 = Date.now() - 30 * 864e5;
  for (const r of health.ransomware || []) if (Date.parse(r.discovered) > d30) add(r.vendor, 'ransomware', { victim: r.victim, group: r.group, discovered: r.discovered });
  for (const a of health.deviceAdvisories || []) if (Date.parse(a.updated) > Date.now() - 90 * 864e5) add(a.vendor, 'advisories');
  for (const r of health.recalls || []) add(r.vendor, 'recalls');
  for (const b of health.breaches || []) add(b.vendor, 'breaches');
  return out;
}

// Per-service counts of recently exploited vulnerabilities, for the Services cards.
function vulnCountsByService(days = 30) {
  const cutoff = new Date(Date.now() - days * 864e5).toISOString().slice(0, 10);
  const servicesFor = Object.fromEntries((vulns.vendors || []).map((v) => [v.key, v.services]));
  const counts = {};
  for (const v of vulns.exploited || []) {
    if (v.dateAdded < cutoff || !v.vendorKey) continue;
    for (const id of servicesFor[v.vendorKey] || []) {
      counts[id] ||= { count: 0, ransomware: 0, vendorKey: v.vendorKey };
      counts[id].count++;
      if (v.ransomware) counts[id].ransomware++;
    }
  }
  const critCutoff = new Date(Date.now() - 14 * 864e5).toISOString();
  for (const v of vulns.newCritical || []) {
    if (!v.vendorKey || (v.cvss?.score || 0) < 9 || v.published < critCutoff) continue;
    for (const id of servicesFor[v.vendorKey] || []) {
      counts[id] ||= { count: 0, ransomware: 0, vendorKey: v.vendorKey };
      counts[id].critical = (counts[id].critical || 0) + 1;
    }
  }
  return counts;
}

const refresh = () => Promise.all([refreshIncidents(), refreshServices()]);

async function refreshIncidents() {
  if (state.refreshing) return;
  state.refreshing = true;
  const started = Date.now();
  const jobs = [
    ...NEWS_FEEDS.map((f) => ({ name: f.name, kind: 'news', run: () => fetchNews(f) })),
    ...STATUS_PAGES.map((p) => ({ name: `${p.name} status`, kind: 'status', run: () => fetchStatus(p) })),
    ...INTERNET_SOURCES.map((src) => ({ name: src.name, kind: 'measured', run: src.run })),
  ];
  const results = await Promise.allSettled(jobs.map((j) => j.run()));

  const cutoff = Date.now() - MAX_AGE_DAYS * 864e5;
  const byId = new Map();
  const sources = [];
  results.forEach((r, i) => {
    const job = jobs[i];
    if (r.status === 'fulfilled') {
      sources.push({ name: job.name, kind: job.kind, ok: true, count: r.value.length });
      for (const it of r.value) {
        if (new Date(it.published).getTime() < cutoff) continue;
        const prev = byId.get(it.id);
        // Same headline from several feeds: keep the one with the most locations.
        if (!prev || it.locations.length > prev.locations.length) byId.set(it.id, it);
      }
    } else {
      sources.push({ name: job.name, kind: job.kind, ok: false, count: 0, error: String(r.reason?.message || r.reason), notConfigured: !!r.reason?.notConfigured });
    }
  });

  // Group headlines about the same event into one incident (status-page and measured items stay as-is).
  const all = [...byId.values()];
  const news = all.filter((it) => it.origin === 'news');
  let grouped = news;
  try { grouped = clusterNews(news); } catch (err) { console.error('news grouping failed:', err); }
  const items = [...grouped, ...all.filter((it) => it.origin !== 'news')]
    .sort((a, b) => (b.lastUpdate || b.published).localeCompare(a.lastUpdate || a.published));
  state = { updatedAt: new Date().toISOString(), refreshing: false, sources, items };
  const okCount = sources.filter((s) => s.ok).length;
  for (const s of sources) if (!s.ok && !s.notConfigured) console.warn(`  source failed: ${s.name}: ${s.error}`);
  console.log(`[${state.updatedAt}] ${items.length} incidents (${news.length} headlines grouped into ${grouped.length}) from ${okCount}/${sources.length} sources in ${Date.now() - started}ms`);
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };
const PUBLIC = path.join(__dirname, 'public');

// JSON responses, gzip-compressed when the browser accepts it (vulnerability data is ~2 MB raw).
function sendJson(req, res, obj, pretty = false) {
  const body = JSON.stringify(obj, null, pretty ? 2 : 0);
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store', vary: 'accept-encoding' };
  if (/\bgzip\b/.test(req.headers['accept-encoding'] || '') && body.length > 1024) {
    res.writeHead(200, { ...headers, 'content-encoding': 'gzip' });
    return res.end(zlib.gzipSync(body));
  }
  res.writeHead(200, headers);
  return res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/incidents') {
    if (!state.updatedAt) await refreshIncidents();
    return sendJson(req, res, state);
  }
  if (url.pathname === '/api/diagnostics') {
    // Configuration check. Shows whether settings are visible to the app, never their values.
    return sendJson(req, res, {
      version: pkg.version,
      startedAt: STARTED_AT,
      azureSiteName: process.env.WEBSITE_SITE_NAME || null,
      azureSlot: process.env.WEBSITE_SLOT_NAME || null,
      cloudflareRadar: cloudflareDiagnostics(),
      sources: state.sources.filter((s) => s.kind === 'measured'),
      vulnerabilitySources: vulns.sources,
      healthcareSources: health.sources,
    }, true);
  }
  if (url.pathname === '/api/version') {
    return sendJson(req, res, { version: pkg.version, releaseDate: pkg.releaseDate, startedAt: STARTED_AT, node: process.version, refreshMinutes: REFRESH_MIN, changelog });
  }
  if (url.pathname === '/api/services') {
    if (!services.updatedAt) await refreshServices();
    const vc = vulnCountsByService(30);
    const hc = healthAlertsByService();
    return sendJson(req, res, { ...services, services: services.services.map((s) => ({ ...s, ...(vc[s.id] ? { vulns: vc[s.id] } : {}), ...(hc[s.id] ? { health: hc[s.id] } : {}) })) });
  }
  if (url.pathname === '/api/healthcare') {
    if (!health.updatedAt && !health.refreshing) refreshHealthcare();
    return sendJson(req, res, health);
  }
  if (url.pathname === '/api/vulns') {
    if (!vulns.updatedAt && !vulns.refreshing) refreshVulns(); // first load: answer at once, page polls
    return sendJson(req, res, vulns);
  }
  if (url.pathname === '/api/refresh' && req.method === 'POST') {
    await refresh();
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, updatedAt: state.updatedAt }));
  }
  const file = path.normalize(path.join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
});

server.listen(PORT, () => {
  console.log(`Outage & Hack Map v${pkg.version} running at http://localhost:${PORT}`);
  refresh();
  refreshVulns();
  refreshHealthcare();
  setInterval(refresh, REFRESH_MIN * 60e3);
  setInterval(refreshVulns, VULN_REFRESH_MIN * 60e3);
  setInterval(refreshHealthcare, VULN_REFRESH_MIN * 60e3);
});
