// Groups news headlines about the same event into one incident.
// Method: TF-IDF weighted word vectors (distinctive words like "NSA" or "iCloud" count far
// more than common ones like "down" or "outage"), compared by cosine similarity against each
// group's combined vector, within a time window.
const crypto = require('crypto');

const SIMILARITY = +process.env.CLUSTER_SIMILARITY || 0.3;  // 0..1, higher = stricter grouping
const WINDOW_HOURS = 72;
const MERGE_SIMILARITY = 0.15; // second pass, for groups about the same named organisation

// Different names for the same thing -> one token.
const ALIASES = [
  [/\bnational security agency\b/g, 'nsa'],
  [/\bamazon web services\b/g, 'aws'],
  [/\b(office|microsoft) 365\b/g, 'm365'],
  [/\bunited states\b|\bu\.s\.(a\.)?|\busa\b/g, 'us'],
  [/\bunited kingdom\b|\bu\.k\.|\bbritain\b/g, 'uk'],
  [/\bdistributed denial[- ]of[- ]service\b/g, 'ddos'],
  [/\bcyber[- ]attacks?\b/g, 'cyberattack'],
  [/\bdata breach(es)?\b/g, 'breach'],
  [/\bx \(formerly twitter\)|\btwitter\b/g, 'twitter'],
];

const STOP = new Set(`a an the and or but of to in on at for from by with as is are was were be been being it its this that these those
has have had do does did not no yes after before over under about into amid across against during says said say report reports reported
new latest update updates live today yesterday tuesday monday wednesday thursday friday saturday sunday week weeks day days hours hour
how why what who when where which here there than then also more most some many much thousands hundreds millions users customers people
just still now can could would should may might will according sources source exclusive breaking video watch read via per`.split(/\s+/));

function tokens(text) {
  let t = ` ${String(text).toLowerCase()} `;
  for (const [re, rep] of ALIASES) t = t.replace(re, ` ${rep} `);
  return t
    .replace(/['’]s\b/g, '')
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/[\s-]+/)
    .filter((w) => w.length > 1 && !STOP.has(w) && !/^\d+$/.test(w))
    .map((w) => (w.length > 4 && w.endsWith('s') && !w.endsWith('ss') ? w.slice(0, -1) : w)); // light plural stemming
}

// Headlines generated from templates, one per victim: never group these.
const NO_GROUP = /\b(ransomware attack by \S+\s*$|data breach (lawsuit )?investigation|lawsuit investigation|class action (lawsuit|investigation)|data breach alert by|attorneys investigate)\b/i;

// Capitalised words that aren't names.
const NOT_NAMES = new Set(`millions thousands hundreds first third party second exclusive breaking update report reports new
latest live watch major global massive widespread nearly over after amid how why what who the a an is are data breach hack hacked
cyberattack outage outages ransomware attack attacks security incident systems system service services network customers users
patients employees company group inc llc corp financial bank health county city state school university`.split(/\s+/));

const splitWords = (s) => String(s).split(/[\s,:;()\[\]"“”‘’'!?|–—/]+/).filter(Boolean);

// Likely names in a headline: capitalised words that never appear in lowercase anywhere in the
// news (so "Vendor" or "Banking" in a Title Case headline don't count, but "Infoblox" does).
function namesIn(title, lowerSeen) {
  const out = new Set();
  for (const w of splitWords(title)) {
    if (!/^[A-Z][A-Za-z0-9&.-]{1,}$/.test(w)) continue;
    const [t] = tokens(w);
    if (t && !NOT_NAMES.has(t) && !lowerSeen.has(t)) out.add(t);
  }
  return out;
}

function vector(toks, idf) {
  const v = new Map();
  for (const t of toks) v.set(t, (v.get(t) || 0) + (idf.get(t) || 0));
  let norm = 0;
  for (const x of v.values()) norm += x * x;
  norm = Math.sqrt(norm) || 1;
  for (const [k, x] of v) v.set(k, x / norm);
  return v;
}
function cosine(a, b) {
  let s = 0;
  const [small, big] = a.size < b.size ? [a, b] : [b, a];
  for (const [k, x] of small) { const y = big.get(k); if (y) s += x * y; }
  return s;
}
function addInto(sum, v) { for (const [k, x] of v) sum.set(k, (sum.get(k) || 0) + x); }
function normalized(sum) {
  let n = 0; for (const x of sum.values()) n += x * x; n = Math.sqrt(n) || 1;
  const out = new Map(); for (const [k, x] of sum) out.set(k, x / n); return out;
}

// items: map incidents from news ({ id, type, title, summary, link, source, published, locations, ... })
// Returns incidents; each grouped one gets `sources` (all headlines) and `sourceCount`.
function clusterNews(items) {
  if (items.length < 2) return items.map((it) => ({ ...it, sourceCount: 1 }));
  const docs = items.map((it) => ({ it, toks: tokens(`${it.title} ${it.title} ${it.summary || ''}`) })); // title counts double

  // IDF: words in many headlines (down, outage, hack…) get little weight.
  const df = new Map();
  for (const d of docs) for (const t of new Set(d.toks)) df.set(t, (df.get(t) || 0) + 1);
  const N = docs.length;
  const idf = new Map([...df].map(([t, n]) => [t, Math.log((N + 1) / (n + 0.5))]));
  for (const d of docs) d.vec = vector(d.toks, idf);

  // Oldest first, so each group's first item is the earliest report.
  docs.sort((a, b) => a.it.published.localeCompare(b.it.published));
  const lowerSeen = new Set();
  for (const { it } of docs) for (const w of splitWords(`${it.title} ${it.summary || ''}`)) {
    if (/^[a-z]/.test(w)) for (const t of tokens(w)) lowerSeen.add(t);
  }
  for (const d of docs) { d.set = new Set(d.toks); d.names = namesIn(d.it.title, lowerSeen); }

  // A group's main name: the word in the most of its headlines that is rare elsewhere
  // (e.g. "uber" rather than "driver" or "license"). Ties go to the rarer word.
  const defining = (g) => {
    const counts = new Map();
    for (const m of g.docs) for (const t of m.set) counts.set(t, (counts.get(t) || 0) + 1);
    const cands = [...counts].filter(([t, n]) => n * 2 >= g.docs.length && df.get(t) <= 2 * g.docs.length + 2);
    if (!cands.length) return [];
    const top = Math.max(...cands.map(([, n]) => n));
    const best = cands.filter(([, n]) => n === top).sort((a, b) => df.get(a[0]) - df.get(b[0]));
    return [best[0][0]];
  };
  // A headline conflicts with a group if it doesn't mention the group's main name and is about
  // a different place ("Florida DMV…" vs a group about "Uber").
  const conflicts = (d, g) => {
    const groupHas = (t) => g.docs.some((m) => m.set.has(t));
    // Shares an organisation name with the group: same story, however it's worded.
    if ([...d.names].some(groupHas)) return false;
    // Names organisations the group never mentions ("Infoblox…" vs a group about "Expedia").
    if (d.names.size > 0) return true;
    // No names: still separate if it lacks the group's main word and is about another place
    // ("Florida driver license systems…" vs a group about "Uber … driver's license").
    const main = defining(g);
    if (main.length && main.some((t) => d.set.has(t))) return false;
    const groupPlaces = new Set(g.docs.flatMap((m) => m.it.locations.map((l) => l.name)));
    return d.it.locations.some((l) => !groupPlaces.has(l.name));
  };

  const groups = [];
  for (const d of docs) {
    const t = Date.parse(d.it.published);
    let best = null, bestSim = 0;
    if (!NO_GROUP.test(d.it.title)) {
      for (const g of groups) {
        if (g.noGroup || t - g.last > WINDOW_HOURS * 3600e3) continue;
        const sim = cosine(d.vec, g.centroid);
        if (sim > bestSim && !conflicts(d, g)) { best = g; bestSim = sim; }
      }
    }
    if (best && bestSim >= SIMILARITY) {
      best.docs.push(d);
      addInto(best.sum, d.vec);
      best.centroid = normalized(best.sum);
      best.last = Math.max(best.last, t);
    } else {
      const sum = new Map(); addInto(sum, d.vec);
      groups.push({ docs: [d], sum, centroid: normalized(sum), last: t, noGroup: NO_GROUP.test(d.it.title) });
    }
  }

  // Second pass: merge follow-up coverage ("Apple restores services…") into the main story when
  // both groups are about the same named organisation, close in time, with overlapping wording.
  // The organisation name in the most headlines of the group (e.g. "apple"), if it's in at least half.
  const mainName = (g) => {
    const counts = new Map();
    for (const m of g.docs) for (const n of m.names) counts.set(n, (counts.get(n) || 0) + 1);
    const [best] = [...counts].sort((x, y) => y[1] - x[1]);
    return best && best[1] * 2 >= g.docs.length ? best[0] : null;
  };
  groups.sort((a, b) => b.docs.length - a.docs.length);
  for (let i = 0; i < groups.length; i++) {
    const a = groups[i];
    if (!a || a.noGroup) continue;
    const name = mainName(a);
    if (!name) continue;
    const aFirst = Date.parse(a.docs[0].it.published);
    for (let j = i + 1; j < groups.length; j++) {
      const b = groups[j];
      if (!b || b.noGroup || mainName(b) !== name) continue;
      const bFirst = Date.parse(b.docs[0].it.published);
      if (Math.abs(bFirst - aFirst) > WINDOW_HOURS * 3600e3 || cosine(a.centroid, b.centroid) < MERGE_SIMILARITY) continue;
      a.docs.push(...b.docs);
      addInto(a.sum, b.sum);
      a.centroid = normalized(a.sum);
      a.last = Math.max(a.last, b.last);
      groups[j] = null;
    }
    a.docs.sort((x, y) => x.it.published.localeCompare(y.it.published));
  }

  return groups.filter(Boolean).map((g) => {
    const members = g.docs.map((d) => d.it);
    if (members.length === 1) return { ...members[0], sourceCount: 1 };
    // Headline: the member closest to the group's centre (the most "typical" wording).
    const lead = g.docs.reduce((a, b) => (cosine(b.vec, g.centroid) > cosine(a.vec, g.centroid) ? b : a)).it;
    const hacks = members.filter((m) => m.type === 'hack').length;
    // Locations: those named by the most headlines (cap 4).
    const locCount = new Map();
    for (const m of members) for (const l of m.locations) {
      const e = locCount.get(l.name) || { l, n: 0 }; e.n++; locCount.set(l.name, e);
    }
    // Only keep places named by at least 20% of the headlines, so a single side story
    // ("Microsoft outage sends Japanese workers back to fax machines") doesn't pin a global outage on Japan.
    const minMentions = Math.max(1, Math.ceil(members.length * 0.2));
    const locations = [...locCount.values()].filter((e) => e.n >= minMentions).sort((a, b) => b.n - a.n).slice(0, 4).map((e) => e.l);
    const sorted = members.slice().sort((a, b) => b.published.localeCompare(a.published));
    return {
      ...lead,
      id: crypto.createHash('sha1').update(`cluster:${members[0].id}`).digest('hex').slice(0, 12),
      type: hacks * 2 >= members.length ? 'hack' : 'outage',
      published: members[0].published,                 // first report
      lastUpdate: sorted[0].published,                 // latest report
      locations,
      sourceCount: new Set(members.map((m) => m.source)).size,
      sources: sorted.map(({ title, link, source, published }) => ({ title, link, source, published })),
    };
  });
}

module.exports = { clusterNews, tokens };
