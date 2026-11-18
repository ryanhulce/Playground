// Healthcare tab data:
//  - Ransomware leak-site posts (ransomware.live): healthcare victims, plus any victim matching your vendors
//  - HHS OCR breach reports (500+ individuals): https://ocrportal.hhs.gov/ocr/breach/
//  - CISA medical-device advisories (ICSMA), from CISA's official CSAF repository on GitHub
//  - FDA MedWatch safety alerts and Class I medical-device recalls (openFDA)
const { UA, parseFeed } = require('./sources');
const { CATALOG } = require('./services');
const { VENDORS } = require('./vulns');

const DAYS = +process.env.HEALTHCARE_DAYS || 90;
const TIMEOUT = 45000;

async function fetchText(url, opts = {}) {
  const res = await fetch(url, { ...opts, headers: { 'user-agent': UA, ...(opts.headers || {}) }, signal: AbortSignal.timeout(TIMEOUT) });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res;
}
const getJson = async (url) => (await fetchText(url, { headers: { accept: 'application/json' } })).json();
const since = (days) => new Date(Date.now() - days * 864e5);

// ---------- vendor matching ("one of your vendors was just listed") ----------
const WATCH_CATEGORIES = /^(Healthcare|Network & Security|Data Center & IT Ops|Cloud & Infrastructure)/;
const WATCHERS = [
  ...CATALOG.filter((s) => WATCH_CATEGORIES.test(s.category))
    .map((s) => ({ id: s.id, name: s.name.replace(/\s*\(.*\)$/, ''), re: s.match, exclude: s.exclude, service: s.id })),
  ...VENDORS.filter((v) => v.watch && !CATALOG.some((s) => s.id === v.key))
    .map((v) => ({ id: v.key, name: v.name, re: v.match, service: v.services[0] || null })),
];
function vendorMatch(...texts) {
  const text = texts.filter(Boolean).join(' ');
  for (const w of WATCHERS) {
    if (w.re.test(text) && !(w.exclude && w.exclude.test(text))) return { id: w.id, name: w.name, service: w.service };
  }
  return null;
}

// ---------- ransomware.live ----------
const isDomain = (s) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(s || '').trim());
function victimRow(v) {
  const desc = String(v.description || '').replace(/\s+/g, ' ').trim();
  return {
    victim: String(v.victim || v.post_title || 'Unknown').trim(),
    domain: isDomain(v.domain) ? v.domain.trim() : null,
    group: v.group || v.group_name || 'unknown',
    country: v.country || null,
    sector: v.activity || null,
    discovered: v.discovered,
    description: desc.slice(0, 280),
    link: v.url && /^https:\/\/www\.ransomware\.live\//.test(v.url) ? v.url : 'https://www.ransomware.live/',
    vendor: null,
  };
}
async function fetchRansomware() {
  const cutoff = since(DAYS).toISOString();
  const [hc, recent] = await Promise.all([
    getJson('https://api.ransomware.live/v2/sectorvictims/Healthcare'),
    getJson('https://api.ransomware.live/v2/recentvictims').catch(() => []),
  ]);
  if (!Array.isArray(hc)) throw new Error('Unexpected ransomware.live response');
  const seen = new Set();
  const out = [];
  for (const v of [...hc, ...(Array.isArray(recent) ? recent : [])]) {
    if (!v.discovered || v.discovered < cutoff) continue;
    const row = victimRow(v);
    const key = `${row.victim.toLowerCase()}|${row.group}`;
    if (seen.has(key)) continue;
    seen.add(key);
    row.vendor = vendorMatch(row.victim, row.domain);
    row.healthcare = /health/i.test(row.sector || '') || hc.includes(v);
    if (row.healthcare || row.vendor) out.push(row);
  }
  return out.sort((a, b) => b.discovered.localeCompare(a.discovered));
}

// ---------- HHS OCR breach portal ----------
// The portal is a JSF web app: open the front page (gets a session), then submit the
// "View HIPAA Breach Reports" link's form, exactly as a browser does when you click it.
const decodeHtml = (s) => String(s).replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
async function fetchHhs() {
  const base = 'https://ocrportal.hhs.gov/ocr/breach/';
  const cookies = new Map();
  const keep = (res) => {
    for (const c of res.headers.getSetCookie?.() || []) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies.set(kv.slice(0, i), kv.slice(i + 1)); }
  };
  const cookieHeader = () => [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const go = async (url, opts = {}) => {
    let res = await fetch(url, { ...opts, redirect: 'manual', headers: { 'user-agent': UA, cookie: cookieHeader(), ...(opts.headers || {}) }, signal: AbortSignal.timeout(TIMEOUT) });
    keep(res);
    for (let i = 0; i < 5 && res.status >= 300 && res.status < 400; i++) {
      res = await fetch(new URL(res.headers.get('location'), url).href, { redirect: 'manual', headers: { 'user-agent': UA, cookie: cookieHeader() }, signal: AbortSignal.timeout(TIMEOUT) });
      keep(res);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} from HHS breach portal`);
    return res.text();
  };

  const front = await go(`${base}breach_report.jsf`);
  const viewState = front.match(/name="javax\.faces\.ViewState"[^>]*value="([^"]+)"/)?.[1];
  const link = front.match(/\{'(ocrForm:[\w:]+)':'\1'\},''\);return false">View HIPAA Breach Reports/)?.[1];
  if (!viewState || !link) throw new Error('HHS portal layout changed (could not find the breach report link)');
  const body = new URLSearchParams({ ocrForm: 'ocrForm', [link]: link, 'javax.faces.ViewState': viewState });
  const page = await go(`${base}breach_frontpage.jsf`, { method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });

  const headers = [...page.matchAll(/<th[^>]*>([\s\S]*?)<\/th>/g)].map((m) => decodeHtml(m[1].replace(/<script[\s\S]*?<\/script>/g, '')));
  const col = (name) => headers.findIndex((h) => h.toLowerCase().startsWith(name));
  const idx = { name: col('name of covered'), state: col('state'), type: col('covered entity type'), people: col('individuals'), date: col('breach submission'), kind: col('type of breach'), where: col('location'), ba: col('business associate') };
  if (Object.values(idx).some((i) => i < 0)) throw new Error('HHS portal table layout changed');
  const rows = [...page.matchAll(/<tr[^>]*data-ri="\d+"[^>]*>([\s\S]*?)<\/tr>/g)]
    .map((m) => [...m[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((c) => decodeHtml(c[1])));
  if (!rows.length) throw new Error('No rows found on the HHS breach portal');
  return rows.map((r) => {
    const [mm, dd, yyyy] = (r[idx.date] || '').split('/');
    const entity = r[idx.name];
    return {
      entity,
      state: r[idx.state] || null,
      entityType: r[idx.type] || null,
      individuals: +String(r[idx.people] || '0').replace(/\D/g, '') || 0,
      date: yyyy ? `${yyyy}-${mm.padStart(2, '0')}-${dd.padStart(2, '0')}` : null,
      breachType: r[idx.kind] || null,
      location: r[idx.where] || null,
      businessAssociate: /^yes/i.test(r[idx.ba] || ''),
      vendor: vendorMatch(entity),
    };
  }).filter((r) => r.entity && r.date);
}

// ---------- CISA medical-device advisories (ICSMA) ----------
const CSAF = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/';
const csafCache = new Map(); // "file|date" -> parsed advisory
async function fetchCisaMedical() {
  const csv = await (await fetchText(`${CSAF}changes.csv`)).text();
  const cutoff = since(365).toISOString();
  const files = csv.split('\n')
    .map((l) => l.match(/^"([^"]*icsma[^"]*\.json)","([^"]+)"/i))
    .filter(Boolean)
    .map((m) => ({ file: m[1], changed: m[2] }))
    .filter((f) => f.changed >= cutoff)
    .sort((a, b) => b.changed.localeCompare(a.changed))
    .slice(0, 30);
  const out = [];
  for (let i = 0; i < files.length; i += 6) {
    const batch = await Promise.all(files.slice(i, i + 6).map(async (f) => {
      const key = `${f.file}|${f.changed}`;
      if (csafCache.has(key)) return csafCache.get(key);
      try {
        const d = await getJson(CSAF + f.file);
        const doc = d.document || {};
        const branches = d.product_tree?.branches || [];
        const vendorName = branches[0]?.name || '';
        const products = branches.flatMap((b) => (b.branches || []).map((p) => p.name)).filter(Boolean).slice(0, 5);
        const cves = (d.vulnerabilities || []).map((v) => {
          const s = (v.scores || [])[0] || {};
          return { cve: v.cve, score: s.cvss_v3?.baseScore ?? s.cvss_v4?.baseScore ?? null };
        });
        const scores = cves.map((c) => c.score).filter((x) => x != null);
        const pageLink = (doc.references || []).map((r) => r.url).find((u) => /cisa\.gov\/news-events\/ics-medical-advisories\//.test(u));
        const row = {
          id: doc.tracking?.id || f.file,
          title: doc.title || vendorName,
          vendorName,
          products,
          released: doc.tracking?.initial_release_date || f.changed,
          updated: doc.tracking?.current_release_date || f.changed,
          summary: ((doc.notes || []).find((n) => n.category === 'summary')?.text || '').slice(0, 400),
          cves: cves.slice(0, 8),
          cveCount: cves.length,
          maxCvss: scores.length ? Math.max(...scores) : null,
          link: pageLink || `https://www.cisa.gov/news-events/ics-medical-advisories/${String(doc.tracking?.id || '').toLowerCase()}`,
          vendor: vendorMatch(vendorName, doc.title),
        };
        csafCache.set(key, row);
        return row;
      } catch { return null; }
    }));
    out.push(...batch.filter(Boolean));
  }
  // Sort by latest update: CISA re-issues old advisories ("Update A") when there's news.
  return out.sort((a, b) => b.updated.localeCompare(a.updated));
}

// ---------- FDA ----------
async function fetchFdaAlerts() {
  const xml = await (await fetchText('https://www.fda.gov/about-fda/contact-fda/stay-informed/rss-feeds/medwatch/rss.xml')).text();
  const cutoff = since(DAYS);
  return parseFeed(xml)
    .map((i) => ({ title: i.title, summary: i.summary.slice(0, 300), link: i.link, date: new Date(i.date).toISOString(), vendor: vendorMatch(i.title, i.summary) }))
    .filter((i) => new Date(i.date) >= cutoff);
}
async function fetchFdaRecalls() {
  const ymd = (d) => d.toISOString().slice(0, 10).replace(/-/g, '');
  const url = `https://api.fda.gov/device/enforcement.json?search=classification:%22Class+I%22+AND+report_date:[${ymd(since(DAYS))}+TO+${ymd(new Date())}]&sort=report_date:desc&limit=500`;
  const d = await getJson(url);
  const byEvent = new Map();
  for (const r of d.results || []) {
    const e = byEvent.get(r.event_id) || {
      eventId: r.event_id,
      firm: r.recalling_firm,
      product: String(r.product_description || '').replace(/\s+/g, ' ').slice(0, 220),
      reason: String(r.reason_for_recall || '').replace(/\s+/g, ' ').slice(0, 300),
      date: r.report_date ? `${r.report_date.slice(0, 4)}-${r.report_date.slice(4, 6)}-${r.report_date.slice(6, 8)}` : null,
      status: r.status,
      products: 0,
      link: `https://www.accessdata.fda.gov/scripts/ires/index.cfm?Event=${encodeURIComponent(r.event_id)}`,
      vendor: vendorMatch(r.recalling_firm, r.product_description),
    };
    e.products++;
    byEvent.set(r.event_id, e);
  }
  return [...byEvent.values()].sort((a, b) => String(b.date).localeCompare(String(a.date)));
}

async function collectHealthcare() {
  const jobs = [
    ['ransomware', 'Ransomware leak sites (ransomware.live)', fetchRansomware],
    ['breaches', 'HHS breach reports (OCR portal)', fetchHhs],
    ['deviceAdvisories', 'CISA medical-device advisories', fetchCisaMedical],
    ['fdaAlerts', 'FDA MedWatch safety alerts', fetchFdaAlerts],
    ['recalls', 'FDA Class I device recalls (openFDA)', fetchFdaRecalls],
  ];
  const results = await Promise.allSettled(jobs.map(([, , fn]) => fn()));
  const out = { days: DAYS, sources: [] };
  results.forEach((r, i) => {
    const [key, name] = jobs[i];
    out[key] = r.status === 'fulfilled' ? r.value : [];
    out.sources.push(r.status === 'fulfilled' ? { name, ok: true, count: r.value.length } : { name, ok: false, count: 0, error: String(r.reason?.message || r.reason) });
  });
  return out;
}

module.exports = { collectHealthcare, vendorMatch };
