// Data sources: news RSS/Atom feeds and public service status pages.
const crypto = require('crypto');
const { classify, locate } = require('./extract');
const { cityByName, places } = require('./gazetteer');

const gnews = (q) =>
  `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en-US&gl=US&ceid=US:en`;

const NEWS_FEEDS = [
  { name: 'Google News: website down', url: gnews('"website down" OR "site down" OR "went down" when:3d') },
  { name: 'Google News: outage', url: gnews('outage (website OR app OR service OR internet) when:3d') },
  { name: 'Google News: cyberattack', url: gnews('cyberattack when:3d') },
  { name: 'Google News: data breach', url: gnews('"data breach" when:3d') },
  { name: 'Google News: ransomware', url: gnews('ransomware attack when:3d') },
  { name: 'Google News: DDoS', url: gnews('DDoS attack when:3d') },
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'The Record', url: 'https://therecord.media/feed' },
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
  { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' },
  { name: 'The Register (security)', url: 'https://www.theregister.com/security/headlines.atom' },
];

// Atlassian Statuspage-powered status pages (all expose /api/v2/summary.json).
const STATUS_PAGES = [
  { name: 'Cloudflare', base: 'https://www.cloudflarestatus.com', datacenters: true },
  { name: 'F5 Distributed Cloud', base: 'https://www.f5cloudstatus.com', datacenters: true },
  { name: 'Infoblox', base: 'https://status.infoblox.com', datacenters: true },
  { name: 'DigitalOcean', base: 'https://status.digitalocean.com' },
  { name: 'GitHub', base: 'https://www.githubstatus.com' },
  { name: 'Discord', base: 'https://discordstatus.com' },
  { name: 'Reddit', base: 'https://www.redditstatus.com' },
  { name: 'OpenAI', base: 'https://status.openai.com' },
  { name: 'Atlassian', base: 'https://status.atlassian.com' },
  { name: 'Zoom', base: 'https://status.zoom.us' },
  { name: 'Dropbox', base: 'https://status.dropbox.com' },
  { name: 'Twilio', base: 'https://status.twilio.com' },
  { name: 'Vercel', base: 'https://www.vercel-status.com' },
  { name: 'Linode', base: 'https://status.linode.com' },
];

const UA = 'Mozilla/5.0 (compatible; OutageMap/1.0)';

async function get(url, timeoutMs = 15000) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: '*/*' },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

const id = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 12);

// ---------- minimal RSS / Atom parsing ----------
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
function decode(s) {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&(\w+);/g, (m, n) => ENTITIES[n] ?? m);
}
const stripTags = (s) => s.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const clean = (s) => stripTags(decode(stripTags(decode(s || '')))); // handles double-encoded HTML

function tag(block, name) {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1] : '';
}
function attr(block, name, a) {
  const m = block.match(new RegExp(`<${name}\\s[^>]*${a}="([^"]*)"`, 'i'));
  return m ? decode(m[1]) : '';
}

function parseFeed(xml) {
  const items = [];
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [];
  for (const b of blocks) {
    const title = clean(tag(b, 'title'));
    const link = decode(stripTags(tag(b, 'link'))).trim() || attr(b, 'link', 'href');
    const summary = clean(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content'));
    const date = tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'updated') || tag(b, 'dc:date');
    const source = clean(tag(b, 'source'));
    if (title) items.push({ title, link, summary, date: clean(date), source });
  }
  return items;
}

async function fetchNews(feed) {
  const xml = await get(feed.url);
  const out = [];
  for (const it of parseFeed(xml)) {
    let title = it.title;
    let source = it.source || feed.name;
    // Google News titles look like "Headline - Publisher"
    if (it.source && title.endsWith(` - ${it.source}`)) title = title.slice(0, -(it.source.length + 3));
    let summary = it.summary;
    if (summary.startsWith(title)) summary = ''; // Google News repeats the headline
    const text = `${title}. ${summary}`;
    const cls = classify(text, title);
    if (!cls) continue;
    const published = new Date(it.date);
    out.push({
      id: id(title.toLowerCase()),
      type: cls.type,
      causedOutage: cls.alsoOutage,
      title,
      summary: summary.slice(0, 400),
      link: it.link,
      source,
      feed: feed.name,
      origin: 'news',
      published: isNaN(published) ? new Date().toISOString() : published.toISOString(),
      locations: locate(text),
    });
  }
  return out;
}

// ---------- status pages ----------
const DO_REGIONS = { NYC: 'New York', SFO: 'San Francisco', AMS: 'Amsterdam', SGP: 'Singapore', LON: 'London', FRA: 'Frankfurt', TOR: 'Toronto', BLR: 'Bengaluru', SYD: 'Sydney', ATL: 'Atlanta' };
const countryByName = new Map(places.filter((p) => p.kind === 'country').map((p) => [p.key.toLowerCase(), p]));

function placeForComponent(name) {
  // Cloudflare style: "Frankfurt, Germany - (FRA)"
  const cf = name.match(/^(.+?),\s*(.+?)\s*-\s*\(/);
  if (cf) {
    const city = cityByName[cf[1].toLowerCase()];
    if (city) return city;
    const country = countryByName.get(cf[2].toLowerCase());
    if (country) return { ...country, name: `${cf[1]}, ${country.name}` };
  }
  const dorg = name.match(/\b([A-Z]{3})\d\b/);
  if (dorg && DO_REGIONS[dorg[1]]) return cityByName[DO_REGIONS[dorg[1]].toLowerCase()];
  const hits = locate(name);
  return hits[0] || null;
}
const pick = (p) => p && { name: p.name, lat: p.lat, lon: p.lon, country: p.country, kind: p.kind };

const ADVISORY = /\b(security advisory|advisory:|CVE-\d{4}-\d+|vulnerabilit(y|ies)|scheduled maintenance)\b/i;

async function fetchStatus(page) {
  const data = JSON.parse(await get(`${page.base}/api/v2/summary.json`));
  const out = [];
  for (const inc of data.incidents || []) {
    // Planned maintenance and security advisories aren't outages, so don't pin them on the map.
    if (inc.impact === 'maintenance' || ADVISORY.test(inc.name || '')) continue;
    const latest = (inc.incident_updates || [])[0];
    const comps = (inc.components || []).map((c) => c.name).join(', ');
    const body = latest ? latest.body : '';
    const text = `${inc.name}. ${body} ${comps}`;
    const looksLikeAttack = /\b(DDoS|attack|malicious|security incident|unauthori[sz]ed)\b/i.test(text);
    let locations = locate(text);
    if (!locations.length && inc.components) {
      locations = inc.components.map((c) => pick(placeForComponent(c.name))).filter(Boolean).slice(0, 6);
    }
    out.push({
      id: id(`${page.name}:${inc.id}`),
      type: looksLikeAttack ? 'hack' : 'outage',
      causedOutage: true,
      title: `${page.name}: ${inc.name}`,
      summary: `[${inc.impact || 'unknown'} impact, ${inc.status}] ${body}`.slice(0, 400),
      link: inc.shortlink || page.base,
      source: `${page.name} status page`,
      feed: page.name,
      origin: 'status',
      published: inc.updated_at || inc.created_at,
      locations,
    });
  }

  if (page.datacenters) {
    for (const c of data.components || []) {
      if (c.group || ['operational', 'under_maintenance'].includes(c.status)) continue;
      const p = placeForComponent(c.name);
      if (!p) continue;
      out.push({
        id: id(`${page.name}:${c.id}`),
        type: 'outage',
        causedOutage: true,
        title: `${page.name} edge location ${c.name}: ${c.status.replace(/_/g, ' ')}`,
        summary: `${page.name} reports this location as ${c.status.replace(/_/g, ' ')}.`,
        link: page.base,
        source: `${page.name} status page`,
        feed: page.name,
        origin: 'status',
        published: c.updated_at || new Date().toISOString(),
        locations: [pick(p)],
      });
    }
  }
  return out;
}

module.exports = { NEWS_FEEDS, STATUS_PAGES, fetchNews, fetchStatus, parseFeed, get, UA, ADVISORY };
