// Measured internet outages (not news): IODA and Cloudflare Radar.
//  - IODA (Georgia Tech): free, no key. Detects country-level disruptions from BGP,
//    active probing and darknet traffic.  https://ioda.inetintel.cc.gatech.edu/
//  - Cloudflare Radar: free API token required (env CLOUDFLARE_API_TOKEN).
//    Curated outage annotations with cause and affected networks.  https://radar.cloudflare.com/outage-center
const crypto = require('crypto');
const { COUNTRY_BY_CODE } = require('./gazetteer');
const { UA } = require('./sources');

const LOOKBACK_HOURS = +process.env.INTERNET_LOOKBACK_HOURS || 72;
const id = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 12);

// Centroids for countries the text gazetteer leaves out (it skips names like Chad, Jordan,
// Georgia that are also common words). Matched here by ISO code, so there's no ambiguity.
const EXTRA_CENTROIDS = {
  TD: [15.5, 18.7], JO: [30.6, 36.2], GE: [42.3, 43.4], GN: [9.9, -9.7], HT: [18.97, -72.3], GA: [-0.8, 11.6],
  SL: [8.5, -11.8], LR: [6.4, -9.4], ML: [17.6, -4.0], NE: [17.6, 8.1], BF: [12.2, -1.6], SO: [5.2, 46.2],
  SS: [7.9, 30.0], ER: [15.2, 39.8], DJ: [11.8, 42.6], CD: [-4.0, 21.8], CG: [-0.2, 15.8], CF: [6.6, 20.9],
  BI: [-3.4, 29.9], MW: [-13.3, 34.3], TG: [8.6, 0.8], BJ: [9.3, 2.3], GM: [13.4, -15.3], GW: [11.8, -15.2],
  MR: [21.0, -10.9], AM: [40.1, 45.0], AZ: [40.1, 47.6], KG: [41.2, 74.8], TJ: [38.9, 71.3], TM: [38.97, 59.6],
  LA: [19.9, 102.5], BT: [27.5, 90.4], MV: [3.2, 73.2], BN: [4.5, 114.7], PG: [-6.3, 143.96], FJ: [-17.7, 178.1],
  BO: [-16.3, -63.6], PY: [-23.4, -58.4], GT: [15.8, -90.2], HN: [15.2, -86.2], NI: [12.9, -85.2], SV: [13.8, -88.9],
  DO: [18.7, -70.2], JM: [18.1, -77.3], TT: [10.7, -61.2], BS: [25.0, -77.4], BB: [13.2, -59.5], GY: [4.9, -58.9],
  SR: [3.9, -56.0], BZ: [17.2, -88.5], ME: [42.7, 19.4], MK: [41.6, 21.7], XK: [42.6, 20.9], LS: [-29.6, 28.2],
  SZ: [-26.5, 31.5], KM: [-11.9, 43.9], MU: [-20.3, 57.6], SC: [-4.7, 55.5], CV: [16.0, -24.0], GQ: [1.7, 10.3],
  TL: [-8.9, 125.7], NC: [-20.9, 165.6], PF: [-17.7, -149.4], GU: [13.4, 144.8], RE: [-21.1, 55.5], GL: [71.7, -42.6],
  LI: [47.2, 9.6], AD: [42.5, 1.5], MC: [43.7, 7.4], SM: [43.9, 12.5], VA: [41.9, 12.5], PW: [7.5, 134.6],
  WS: [-13.8, -172.1], TO: [-21.2, -175.2], VU: [-15.4, 166.96], SB: [-9.6, 160.2], KI: [1.9, -157.4], MH: [7.1, 171.2],
  FM: [7.4, 150.6], NR: [-0.5, 166.9], TV: [-7.1, 177.6], AG: [17.1, -61.8], DM: [15.4, -61.4], GD: [12.1, -61.7],
  KN: [17.3, -62.7], LC: [13.9, -60.98], VC: [12.98, -61.3], AW: [12.5, -69.97], CW: [12.2, -69.0], KY: [19.3, -81.3],
  BM: [32.3, -64.8], VG: [18.4, -64.6], VI: [18.3, -64.9], MO: [22.2, 113.5], SY: [34.8, 39.0], ZW: [-19.0, 29.2],
};
const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

function countryPlace(code, nameHint) {
  const cc = String(code || '').toUpperCase();
  const p = COUNTRY_BY_CODE[cc];
  if (p) return { name: p.name, lat: p.lat, lon: p.lon, country: cc, kind: 'country' };
  const c = EXTRA_CENTROIDS[cc];
  if (c) return { name: nameHint || safeName(cc), lat: c[0], lon: c[1], country: cc, kind: 'country' };
  return { unknown: true, name: nameHint || safeName(cc), country: cc };
}
function safeName(cc) { try { return regionNames.of(cc) || cc; } catch { return cc; } }

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(20000) });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}${text ? `: ${text.slice(0, 120)}` : ''}`);
  try { return JSON.parse(text); } catch { throw new Error('Response was not JSON'); }
}

const fmtDuration = (sec) => {
  if (!sec || sec < 0) return '';
  const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
  return h ? `${h}h${m ? ` ${m}m` : ''}` : `${m}m`;
};

// ---------- IODA ----------
const IODA_SIGNALS = { bgp: 'BGP routing', 'ping-slash24': 'active probing', 'merit-nt': 'darknet traffic', gtr: 'Google traffic' };

// Only keep significant IODA outages. IODA flags many tiny or artefactual blips: dozens of small
// countries with the same brief low-score BGP dip at once, single-signal traffic dips, or week-long
// low-level single-signal readings. Tuned on real data: ~97 flagged countries -> ~10 significant.
//   - two or more independent signals agree (e.g. routing AND traffic) with score >= 3,000, or
//   - one signal with score >= 20,000 lasting under 3 days, or
//   - score >= 50,000.
// Set IODA_SHOW_ALL=1 to show everything.
const IODA_SHOW_ALL = process.env.IODA_SHOW_ALL === '1';
function iodaSignificant(c, hours) {
  if (IODA_SHOW_ALL) return true;
  if (c.signals.size >= 2 && c.score >= 3000) return true;
  if (c.score >= 20000 && hours < 72) return true;
  return c.score >= 50000;
}

async function fetchIoda() {
  const until = Math.floor(Date.now() / 1000);
  const from = until - LOOKBACK_HOURS * 3600;
  const url = `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?entityType=country&from=${from}&until=${until}`;
  const body = await getJson(url);
  if (body.error) throw new Error(String(body.error.message || body.error));
  const events = Array.isArray(body.data) ? body.data : Array.isArray(body.data?.events) ? body.data.events : null;
  if (!events) throw new Error('Unexpected IODA response format');

  // Merge several events for the same country into one report.
  const byCountry = new Map();
  for (const e of events) {
    const loc = String(e.location || e.entity?.code || '');
    const code = loc.includes('/') ? loc.split('/').pop() : loc;
    if (!/^[A-Za-z]{2}$/.test(code)) continue;
    const start = +e.start || +e.from || 0;
    const duration = +e.duration || 0;
    const entry = byCountry.get(code) || { code, name: e.location_name || e.entity?.name, starts: [], ends: [], score: 0, signals: new Set(), n: 0 };
    entry.n++;
    entry.starts.push(start);
    entry.ends.push(start + duration);
    entry.score = Math.max(entry.score, +e.score || 0);
    if (e.datasource) entry.signals.add(IODA_SIGNALS[e.datasource] || e.datasource);
    byCountry.set(code, entry);
  }

  const now = Date.now() / 1000;
  const out = [];
  for (const c of byCountry.values()) {
    const place = countryPlace(c.code, c.name);
    const start = Math.min(...c.starts);
    const end = Math.max(...c.ends);
    if (!iodaSignificant(c, (end - start) / 3600)) continue;
    const ongoing = now - end < 3600;
    const signals = [...c.signals].join(', ');
    out.push({
      id: id(`ioda:${c.code}:${start}`),
      type: 'internet',
      title: `Internet disruption detected in ${place.name}${ongoing ? ' (ongoing)' : ''}`,
      summary: `IODA detected ${c.n} outage event${c.n > 1 ? 's' : ''}${signals ? ` in ${signals}` : ''}${c.signals.size >= 2 ? ` (confirmed by ${c.signals.size} independent measurements)` : ''}` +
        `${end > start ? `, lasting ${fmtDuration(end - start)}` : ''}${c.score ? ` (score ${Math.round(c.score).toLocaleString('en-US')})` : ''}.`,
      link: `https://ioda.inetintel.cc.gatech.edu/country/${c.code}?from=${start - 3600}&until=${Math.min(end + 3600, Math.floor(now))}`,
      source: 'IODA (Georgia Tech)',
      feed: 'IODA',
      origin: 'measured',
      ongoing,
      published: new Date(start * 1000).toISOString(),
      locations: place.unknown ? [] : [place],
      region: place.unknown ? place.name : undefined,
    });
  }
  return out;
}

// ---------- Cloudflare Radar ----------
const CAUSES = {
  POWER_OUTAGE: 'Power outage', GOVERNMENT_DIRECTED: 'Government-directed shutdown', CABLE_CUT: 'Cable cut',
  TECHNICAL_PROBLEM: 'Technical problem', WEATHER: 'Severe weather', MILITARY_ACTION: 'Military action',
  MAINTENANCE: 'Maintenance', FIRE: 'Fire', CYBERATTACK: 'Cyberattack', EARTHQUAKE: 'Earthquake', UNKNOWN: 'Unknown cause',
};
const nice = (s) => CAUSES[s] || String(s || '').toLowerCase().replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

async function fetchCloudflare() {
  const token = cloudflareToken();
  if (!token) {
    const err = new Error('Not configured: set CLOUDFLARE_API_TOKEN to enable');
    err.notConfigured = true;
    throw err;
  }
  const days = Math.max(1, Math.ceil(LOOKBACK_HOURS / 24));
  const body = await getJson(`https://api.cloudflare.com/client/v4/radar/annotations/outages?dateRange=${days}d&limit=100&format=json`,
    { authorization: `Bearer ${token}` });
  if (body.success === false) throw new Error((body.errors || []).map((e) => e.message).join('; ') || 'Cloudflare API error');
  const list = body.result?.annotations;
  if (!Array.isArray(list)) throw new Error('Unexpected Cloudflare Radar response format');

  const out = [];
  const now = Date.now();
  for (const a of list) {
    const entities = Array.isArray(a.entities) ? a.entities : [];
    const startMs = new Date(a.startDate || now).getTime();
    // Cloudflare sometimes never records an end time, so only call it ongoing for 48 hours.
    const noEnd = !a.endDate;
    const ongoing = noEnd && now - startMs < 48 * 3600e3;
    const endNote = noEnd && !ongoing ? ' Cloudflare has not recorded an end time.' : '';
    const cause = nice(a.outage?.outageCause);
    const scope = a.outage?.outageType ? nice(a.outage.outageType).toLowerCase() : '';
    const base = {
      source: 'Cloudflare Radar', feed: 'Cloudflare Radar', origin: 'measured', ongoing,
      link: a.linkedUrl || 'https://radar.cloudflare.com/outage-center',
      published: new Date(startMs).toISOString(),
    };

    // 1. Cloud platform outages (e.g. a global Microsoft 365 / Azure disruption): no country.
    const origins = entities.filter((e) => e.entityType === 'ORIGIN');
    if (a.dataSource === 'HTTP_ORIGINS' || a.outage?.outageType === 'PLATFORM' || origins.length) {
      const names = (origins.length ? origins.map((e) => e.entityName) : (a.originsDetails || []).map((o) => o.name || o.origin)).filter(Boolean);
      // "Microsoft Azure australiaeast" -> "Microsoft Azure"
      const providers = [...new Set(names.map((n) => String(n).replace(/\s+\S+$/, '').trim() || n))];
      const provider = providers.slice(0, 3).join(', ') || 'Cloud platform';
      const isGlobal = (a.origins || []).some((o) => /global/i.test(o)) || /\bglobal\b/i.test(a.description || '');
      out.push({
        ...base,
        id: id(`cfradar:${a.id || a.startDate + provider}`),
        type: 'outage',
        title: `${provider} disruption${isGlobal ? ' (global)' : ''}: ${cause}${ongoing ? ' (ongoing)' : ''}`,
        summary: `${a.description || ''}${names.length ? ` Affected ${names.length} cloud region${names.length > 1 ? 's' : ''}.` : ''}${endNote}`.trim().slice(0, 400),
        locations: [],
        region: isGlobal ? 'Global' : `${names.length} cloud regions`,
      });
      continue;
    }

    // 2. Country, sub-national region or single-network outages.
    const codes = new Set((a.locations || []).map(String));
    const nameByCode = {};
    for (const d of a.locationsDetails || []) nameByCode[d.code] = d.name;
    const areas = []; // sub-national areas like "Zhytomyr Oblast, Ukraine"
    for (const e of entities) {
      if (e.entityLocation) codes.add(String(e.entityLocation));
      if (e.entityType === 'GEOLOCATION' && e.entityName) areas.push(e.entityName);
    }
    for (const n of a.asnsDetails || []) if (n.location?.code) { codes.add(n.location.code); nameByCode[n.location.code] ||= n.location.name; }

    const places = [...codes].map((c) => countryPlace(c, nameByCode[c]));
    const located = places.filter((p) => !p.unknown);
    const networks = (a.asnsDetails || []).map((n) => n.name).filter(Boolean).slice(0, 4).join(', ');
    const where = areas.length ? areas.slice(0, 3).join('; ') : places.map((p) => p.name).join(', ') || networks || 'Unknown location';
    out.push({
      ...base,
      id: id(`cfradar:${a.id || a.startDate + where}`),
      type: 'internet',
      title: `Internet outage in ${where}: ${cause}${ongoing ? ' (ongoing)' : ''}`,
      summary: [a.description, scope && `Scope: ${scope}.`, networks && `Networks affected: ${networks}.`, endNote.trim()].filter(Boolean).join(' ').slice(0, 400),
      locations: located.slice(0, 6),
      region: located.length ? undefined : where,
    });
  }
  return out;
}

// Azure App Service normally exposes app settings as plain environment variables, but some
// setups use an APPSETTING_ prefix. Also trims stray spaces or line breaks from a pasted value.
function cloudflareToken() {
  return String(process.env.CLOUDFLARE_API_TOKEN || process.env.APPSETTING_CLOUDFLARE_API_TOKEN || '').trim();
}

// Safe diagnostics for /api/diagnostics: whether a token is visible, never its value.
function cloudflareDiagnostics() {
  const t = cloudflareToken();
  return {
    tokenFound: !!t,
    tokenLength: t.length,
    // Names only (no values) of any settings that look related, to catch typos.
    relatedSettingNames: Object.keys(process.env).filter((k) => /cloud|flare|radar/i.test(k)).sort(),
  };
}

const INTERNET_SOURCES = [
  { name: 'IODA internet outages', run: fetchIoda },
  { name: 'Cloudflare Radar outages', run: fetchCloudflare },
];

module.exports = { INTERNET_SOURCES, fetchIoda, fetchCloudflare, cloudflareDiagnostics };
