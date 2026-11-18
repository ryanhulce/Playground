// Classification (hack vs outage) and location extraction from free text.
const { places, CLOUD_REGIONS, cityByName } = require('./gazetteer');

// ---------- classification ----------
const HACK_TERMS = [
  /\bhack(ed|ers?|ing|s)?\b/i, /\bbreach(ed|es)?\b/i, /\bransomware\b/i,
  /\bcyber[- ]?attacks?\b/i, /\bcyber[- ]?incident\b/i, /\bDDoS\b/i,
  /\bdenial[- ]of[- ]service\b/i, /\bdata leak(ed|s)?\b/i, /\bleaked data\b/i,
  /\bcompromised?\b/i, /\bmalware\b/i, /\bexploit(ed|s|ation)?\b/i,
  /\bzero[- ]day\b/i, /\bextortion\b/i, /\bstolen (data|records|credentials)\b/i,
  /\bphishing\b/i, /\bdefaced?\b/i, /\bwiper\b/i, /\bbotnet\b/i,
  /\bunauthori[sz]ed access\b/i, /\bsecurity incident\b/i, /\bspyware\b/i,
  /\bAPT ?\d*\b/, /\bcyber[- ]?espionage\b/i,
];
const OUTAGE_TERMS = [
  /\boutages?\b/i, /\b(is|are|went|goes|go|was|were|been) down\b/i, /\bdown for\b/i,
  /\bdowntime\b/i, /\boffline\b/i, /\bdisruptions?\b/i, /\bdisrupted\b/i,
  /\bservice interruption\b/i, /\bnot working\b/i, /\bunavailable\b/i,
  /\bcrash(ed|es)?\b/i, /\bgoes dark\b/i, /\bblackout\b/i, /\bdegraded\b/i,
  /\bunreachable\b/i, /\bknocked offline\b/i, /\berrors? for users\b/i,
  /\bconnectivity issues\b/i, /\blogin issues\b/i, /\bshut ?down\b/i,
  /^(is|are)\b.{1,40}\bdown\b/i, /\b(can't|cannot|unable to) (log|sign) ?in\b/i,
];
// For outages, require some sign this is about the internet / an online service,
// so weather-driven power cuts don't flood the map.
const TECH_CONTEXT = /\b(web ?sites?|site|apps?|online|internet|web|servers?|cloud|network|platform|services?|DNS|API|e-?mail|login|log ?in|sign ?in|users|AWS|Amazon Web Services|Azure|Microsoft|Google|Cloudflare|Meta|Facebook|Instagram|WhatsApp|Twitter|YouTube|Gmail|Outlook|Teams|Office 365|Slack|Discord|Reddit|GitHub|Zoom|Netflix|Spotify|PlayStation|Xbox|Steam|iCloud|Apple|ChatGPT|OpenAI|banking|bank|telecom|broadband|mobile data|carrier|ISP|CDN|data ?cent(er|re))\b/i;
const HACK_STRONG = /\b(ransomware|cyber[- ]?attack|DDoS|hack(ed|ers)|breach(ed)?|data leak)\b/i;

// Headlines that discuss hacking/outages in general rather than report one.
const QUESTION_START = /^(can|could|would|should|will|is|are|was|were|do|does|did|how|why|who|when|where|which)\b/i;
const IS_IT_DOWN = /^(is|are)\b.*\b(down|not working|offline|having (problems|issues)|experiencing (an )?(outage|problems|issues))\b/i;
const GENERIC = /\b(explained|explainer|what you need to know|how to|tips|ways to|guide to|risks?|could|threat landscape|trends|predictions?|forecast|report (finds|says|shows)|survey|study|researchers? (find|say|warn)|podcast|webinar|opinion|op-ed|commentary|lessons|best practices|market|stocks?|funding|raises \$|acquires|acquisition|launches|unveils|partners? with|awards?|conference|summit|hearing|legislation|regulation|warns? of|warning about|advisory|prepare for|protect (yourself|your)|scams? to watch|in the age of|future of)\b/i;
const INCIDENT = /\b(hit by|struck by|suffer(s|ed)|confirm(s|ed)|disclos(es|ed)|reveals?|claims? (responsibility|attack)|took down|takes down|knock(s|ed)|(was|were|been|got|gets) hacked|breached|attack (on|at|against)|attacked|hits|crippl(es|ed)|disrupts?|disrupted|halts?|halted|shuts? down|stolen|stole|steals?|exposed|leaked|investigat(es|ing)|outage at|down for|after (a |the )?(data |cyber ?)?(breach|cyberattack|hack|ransomware attack|attack))\b/i;

function isGeneric(title) {
  const t = title.trim();
  const question = t.endsWith('?') || QUESTION_START.test(t);
  if (question && !IS_IT_DOWN.test(t) && !/^what we know/i.test(t)) return true;
  return GENERIC.test(t) && !INCIDENT.test(t);
}

function classify(text, title = text) {
  if (isGeneric(title)) return null;
  const hack = HACK_TERMS.filter((r) => r.test(text)).length;
  const outage = OUTAGE_TERMS.filter((r) => r.test(text)).length;
  if (!hack && !outage) return null;
  if (hack && (hack >= outage || HACK_STRONG.test(text))) {
    return { type: 'hack', alsoOutage: outage > 0 };
  }
  if (outage && TECH_CONTEXT.test(text)) return { type: 'outage', alsoOutage: true };
  return null;
}

// ---------- location extraction ----------
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const byKey = new Map();
for (const p of places) if (!byKey.has(p.key)) byKey.set(p.key, p);
const keys = [...byKey.keys()].sort((a, b) => b.length - a.length);
const PLACE_RE = new RegExp(`(?<![\\p{L}\\p{N}])(${keys.map(escape).join('|')})(?![\\p{L}\\p{N}])`, 'gu');
const REGION_RE = new RegExp(`\\b(${Object.keys(CLOUD_REGIONS).join('|')})\\b`, 'gi');
const DC_CODES = {
  NYC: 'New York', SFO: 'San Francisco', AMS: 'Amsterdam', SGP: 'Singapore', LON: 'London',
  FRA: 'Frankfurt', TOR: 'Toronto', BLR: 'Bengaluru', SYD: 'Sydney', ATL: 'Atlanta',
};
const DC_RE = new RegExp(`\\b(${Object.keys(DC_CODES).join('|')})\\d\\b`, 'g');

// A demonym followed by these words usually describes the attacker, not the victim.
// Checked against the next few words only ("Russian state-backed hackers", "Chinese APT").
const ATTACKER_HINT = /\b(linked|backed|sponsored|nexus|aligned|affiliated|based|hackers?|hacking|APT\d*|threat actors?|actors?|gangs?|cyber ?criminals?|hacktivists?|spies|operatives?|bots?|botnets?|trolls?|agents?|intelligence|military|cyber ?army|involvement|campaign|operation|attackers?|attacks?|cyber ?attacks?)\b/i;
// "China-linked", "Iran-backed", "North Korea's hackers", "Iran blamed for…"
const ATTACKER_AFTER = /^(\s*-\s*|\s+)(linked|backed|sponsored|based|aligned|nexus|affiliated|tied)\b|^'s\s+(state\s+)?(hackers|spies|intelligence|military|cyber ?army|APT)|^\s+(is |was |were )?(blamed|accused|suspected|behind)\b/i;
// "hackers from China", "linked to Russia", "attack by Iran", "blamed on North Korea"
const ATTACKER_BEFORE = /\b((hackers?|attackers?|actors?|gangs?|groups?|operatives?|spies|bots)\s+(based\s+)?(in|from)|(linked|tied|connected|attributed|traced|blamed)\s+(to|on)|(attacks?|attacked|hacked|breached|targeted|campaign|operation)\s+by|backed\s+by|blames?|accus(es|ed))\s+(the\s+)?$/i;
const nextWords = (s, n) => s.split(/\s+/).filter(Boolean).slice(0, n).join(' ');
const ATTACKER_PREFIX = /(pro|anti)-$/i;
const AMERICA_PREFIX = /(Latin|South|North|Central|of)\s+$/;

function locate(text) {
  const found = new Map(); // name -> place
  const add = (p) => { if (p && !found.has(p.name)) found.set(p.name, p); };

  for (const m of text.matchAll(REGION_RE)) add(cityByName[CLOUD_REGIONS[m[1].toLowerCase()].toLowerCase()]);
  for (const m of text.matchAll(DC_RE)) add(cityByName[DC_CODES[m[1]].toLowerCase()]);

  for (const m of text.matchAll(PLACE_RE)) {
    const key = m[1];
    const p = byKey.get(key);
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    const after = text.slice(m.index + key.length, m.index + key.length + 40);
    if (p.demonym && (ATTACKER_HINT.test(nextWords(after, 2)) || ATTACKER_PREFIX.test(before))) continue;
    if (p.kind !== 'city' && (ATTACKER_AFTER.test(after) || ATTACKER_BEFORE.test(before))) continue;
    if (key === 'America' && AMERICA_PREFIX.test(before)) continue;
    add(p);
  }

  // Drop a country if a more specific place in that same country was found.
  const list = [...found.values()];
  const specificCountries = new Set(list.filter((p) => p.kind !== 'country').map((p) => p.country));
  return list
    .filter((p) => !(p.kind === 'country' && specificCountries.has(p.country)))
    .slice(0, 4)
    .map(({ name, lat, lon, country, kind }) => ({ name, lat, lon, country, kind }));
}

module.exports = { classify, locate };
