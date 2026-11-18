// Vulnerabilities: confirmed-exploited (CISA KEV) and new critical CVEs (NVD), enriched with
// CVSS severity (NVD) and EPSS exploit likelihood (FIRST.org), and matched to your vendors.
//  - CISA KEV:  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//  - NVD API:   https://nvd.nist.gov/developers/vulnerabilities  (optional key: NVD_API_KEY)
//  - EPSS:      https://www.first.org/epss/
const { UA } = require('./sources');

const KEV_DAYS = Math.min(+process.env.KEV_DAYS || 90, 120);           // NVD allows up to 120 days per query
const CRITICAL_DAYS = Math.min(+process.env.NVD_CRITICAL_DAYS || 14, 120);
const FRESH_DAYS = Math.min(+process.env.NVD_FRESH_DAYS || 7, 14);          // full scan of brand-new CVEs (high & critical)

const KEV_URLS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json', // CISA's GitHub mirror
];

// Vendors we recognise. `match` is tested against CISA's vendor name, the NVD product (CPE)
// vendor, the reporter's email domain and the description. `services` links to Services cards.
// `watch: true` = in "Your vendors" by default (users can change this in the tab).
const VENDORS = [
  ['microsoft', 'Microsoft', /\bmicrosoft\b/i, ['microsoft365'], true],
  ['apple', 'Apple', /\bapple\b/i, ['apple'], true],
  ['google', 'Google (Chrome, Android)', /\b(google|chromium|android)\b/i, ['google'], true],
  ['cisco', 'Cisco', /\bcisco\b/i, ['cisco'], true],
  ['f5', 'F5', /\b(f5|f5networks|big-ip|nginx)\b/i, ['f5'], true],
  ['fortinet', 'Fortinet', /\b(fortinet|fortigate|fortios)\b/i, ['fortinet'], true],
  ['paloalto', 'Palo Alto Networks', /\b(palo ?alto ?networks|paloaltonetworks|pan-os|globalprotect)\b/i, ['paloalto'], true],
  ['ivanti', 'Ivanti', /\b(ivanti|pulse ?secure|mobileiron)\b/i, ['ivanti'], true],
  ['citrix', 'Citrix / NetScaler', /\b(citrix|netscaler)\b/i, ['citrix'], true],
  ['vmware', 'VMware (Broadcom)', /\b(vmware|broadcom|esxi|vcenter)\b/i, ['vmware'], true],
  ['infoblox', 'Infoblox', /\binfoblox\b/i, ['infoblox'], true],
  ['sonicwall', 'SonicWall', /\bsonicwall\b/i, ['sonicwall'], true],
  ['juniper', 'Juniper / HPE Aruba', /\b(juniper|junos|aruba ?networks|arubanetworks)\b/i, ['juniper'], true],
  ['zscaler', 'Zscaler', /\bzscaler\b/i, ['zscaler'], true],
  ['okta', 'Okta', /\bokta\b/i, ['okta'], true],
  ['akamai', 'Akamai', /\bakamai\b/i, ['akamai'], true],
  ['cyberark', 'CyberArk', /\bcyberark\b/i, ['cyberark'], true],
  ['sentinelone', 'SentinelOne', /\bsentinel ?one\b/i, ['sentinelone'], true],
  ['emailsec', 'Proofpoint / Mimecast', /\b(proofpoint|mimecast)\b/i, ['emailsec'], true],
  ['rubrik', 'Rubrik', /\brubrik\b/i, ['rubrik'], true],
  ['cohesity', 'Cohesity / Veritas', /\b(cohesity|veritas)\b/i, ['cohesity'], true],
  ['veeam', 'Veeam', /\bveeam\b/i, ['veeam'], true],
  ['commvault', 'Commvault', /\bcommvault\b/i, ['commvault'], true],
  ['nutanix', 'Nutanix', /\bnutanix\b/i, ['nutanix'], true],
  ['storage', 'Pure Storage / NetApp', /\b(pure ?storage|purestorage|netapp)\b/i, ['storage'], true],
  ['dellhpe', 'Dell / HPE', /\b(dell|hewlett ?packard ?enterprise|\bhpe\b)\b/i, ['dellhpe'], true],
  ['servicenow', 'ServiceNow', /\bservicenow\b/i, ['servicenow'], true],
  ['splunk', 'Splunk', /\bsplunk\b/i, ['splunk'], true],
  ['solarwinds', 'SolarWinds', /\bsolarwinds\b/i, ['solarwinds'], true],
  ['rmm', 'ConnectWise / Kaseya', /\b(connectwise|screenconnect|kaseya)\b/i, ['rmm'], true],
  ['atlassian', 'Atlassian', /\batlassian|confluence|jira\b/i, [], true],
  ['oracle', 'Oracle', /\boracle\b/i, [], true],
  ['adobe', 'Adobe', /\badobe\b/i, [], false],
  ['checkpoint', 'Check Point', /\bcheck ?point\b/i, [], true],
  ['barracuda', 'Barracuda', /\bbarracuda\b/i, [], true],
  ['progress', 'Progress (MOVEit)', /\b(progress ?software|moveit)\b|^progress$/i, [], true],
  ['sap', 'SAP', /\bsap\b/i, [], false],
  ['epic', 'Epic Systems', /\bepic ?systems\b/i, ['epic'], true],
  ['philips', 'Philips', /\bphilips\b/i, ['philips'], true],
  ['gehc', 'GE HealthCare', /\bge ?health ?care\b/i, ['gehc'], true],
  ['fujifilm', 'Fujifilm', /\bfujifilm\b/i, ['fujifilm'], true],
  ['linux', 'Linux kernel', /\blinux\b/i, [], false],
  ['mozilla', 'Mozilla (Firefox)', /\bmozilla|firefox\b/i, [], false],
  ['apache', 'Apache', /\bapache\b/i, [], false],
].map(([key, name, match, services, watch]) => ({ key, name, match, services, watch }));

function vendorFor(...texts) {
  for (const t of texts) {
    if (!t) continue;
    const v = VENDORS.find((x) => x.match.test(t));
    if (v) return v;
  }
  return null;
}

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res.json();
}

const nvdHeaders = () => (process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {});
const iso = (d) => d.toISOString().replace('Z', '').slice(0, 23) + 'Z';

// Best available CVSS score: v3.1 from NVD itself first, then the vendor's own score, then v4 / v3.0 / v2.
function bestCvss(metrics = {}, highest = false) {
  const all = [];
  for (const [key, ver] of [['cvssMetricV31', '3.1'], ['cvssMetricV40', '4.0'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']]) {
    for (const m of metrics[key] || []) {
      if (!m.cvssData) continue;
      all.push({ score: m.cvssData.baseScore, severity: (m.cvssData.baseSeverity || m.baseSeverity || '').toUpperCase(), version: ver, primary: m.type === 'Primary' });
    }
  }
  if (!all.length) return null;
  // Normally: NVD's own score first, else the vendor's, preferring v3.1. "highest": the top score of any.
  const pick = highest ? all.sort((a, b) => b.score - a.score)[0] : (all.find((m) => m.primary) || all[0]);
  return { score: pick.score, severity: pick.severity, version: pick.version, source: pick.primary ? 'NVD' : 'vendor' };
}

// CISA's SSVC assessment attached to many new CVEs: exploitation none | poc | active.
function ssvc(metrics = {}) {
  for (const [k, list] of Object.entries(metrics)) {
    if (!/^ssvc/i.test(k)) continue;
    for (const m of list || []) {
      const opts = Object.assign({}, ...(m.ssvcData?.options || []));
      if (opts.exploitation) return { exploitation: String(opts.exploitation).toLowerCase(), automatable: opts.automatable || null, impact: opts.technicalImpact || null };
    }
  }
  return null;
}

function cpeVendors(cve) {
  const out = new Set();
  for (const cfg of cve.configurations || []) for (const node of cfg.nodes || []) for (const m of node.cpeMatch || []) {
    const v = String(m.criteria || '').split(':')[3];
    if (v) out.add(v.replace(/_/g, ' '));
  }
  return [...out];
}
// For CVEs from unrecognised vendors, take the product name from the start of the description
// ("Craft CMS from 5.0.0 before 5.11.4 contains…" -> "Craft CMS").
function productFromDescription(desc) {
  const m = String(desc).match(/^(?:The |An? |In )?(.{2,60}?)(?=\s+(?:plugin|theme|extension|module|before|from|through|prior|versions?|v?\d|contains|is|are|allows|has|does|could|was|for|in|on|,))/i);
  return m ? m[1].replace(/^the\s+/i, '').trim() : '';
}
const sourceDomain = (s) => (String(s || '').includes('@') ? String(s).split('@')[1].split('.').slice(-2, -1)[0] : '');

async function nvdQuery(params) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`;
  return getJson(url, nvdHeaders());
}

async function fetchEpss(cves) {
  const out = {};
  for (let i = 0; i < cves.length; i += 100) {
    const batch = cves.slice(i, i + 100);
    const d = await getJson(`https://api.first.org/data/v1/epss?cve=${batch.join(',')}`);
    for (const r of d.data || []) out[r.cve] = { epss: +r.epss, percentile: +r.percentile };
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function collectVulns() {
  const sources = [];
  const note = (name, ok, count, error) => sources.push({ name, ok, count, ...(error ? { error } : {}) });
  const now = new Date();

  // 1. CISA KEV (with GitHub mirror as a fallback)
  let kev = null;
  for (const url of KEV_URLS) {
    try { kev = await getJson(url); break; } catch (e) { note(`CISA KEV (${new URL(url).host})`, false, 0, e.message); }
  }
  if (!kev) throw new Error('Could not load the CISA KEV catalog');
  const kevCutoff = new Date(now - KEV_DAYS * 864e5).toISOString().slice(0, 10);
  const recentKev = (kev.vulnerabilities || []).filter((v) => v.dateAdded >= kevCutoff);
  note('CISA Known Exploited Vulnerabilities', true, recentKev.length);

  // 2. NVD: CVSS for those KEV entries (one query), then recent critical CVEs.
  const nvdByCve = {};
  try {
    const d = await nvdQuery(`hasKev&kevStartDate=${iso(new Date(now - KEV_DAYS * 864e5))}&kevEndDate=${iso(now)}`);
    for (const v of d.vulnerabilities || []) nvdByCve[v.cve.id] = v.cve;
    note('NVD scores for exploited CVEs', true, Object.keys(nvdByCve).length);
  } catch (e) { note('NVD scores for exploited CVEs', false, 0, e.message); }

  // New critical CVEs, two ways:
  //  a) last CRITICAL_DAYS days that NVD itself has scored as critical (CVSS v3);
  //  b) EVERY CVE from the last FRESH_DAYS days, keeping those with any critical score (9.0+),
  //     including the vendor's own. NVD's severity filter only checks NVD's scores, and brand-new
  //     CVEs (e.g. F5's) often only have the vendor's score for the first days.
  const kevIds = new Set((kev.vulnerabilities || []).map((v) => v.cveID));
  const byId = new Map();
  const errors = [];
  const pause = () => sleep(process.env.NVD_API_KEY ? 700 : 6500); // stay inside NVD's public rate limit
  const pages = async (params, keep) => {
    for (let start = 0; start < 20000; start += 2000) {
      await pause();
      const d = await nvdQuery(`${params}&startIndex=${start}`);
      for (const x of d.vulnerabilities || []) if (keep(x.cve)) byId.set(x.cve.id, x.cve);
      if (start + 2000 >= (d.totalResults || 0)) break;
    }
  };
  try {
    await pages(`pubStartDate=${iso(new Date(now - CRITICAL_DAYS * 864e5))}&pubEndDate=${iso(now)}&cvssV3Severity=CRITICAL`, () => true);
  } catch (e) { errors.push(`NVD-scored: ${e.message}`); }
  try {
    await pages(`pubStartDate=${iso(new Date(now - FRESH_DAYS * 864e5))}&pubEndDate=${iso(now)}`, (c) => (bestCvss(c.metrics, true)?.score || 0) >= 7);
  } catch (e) { errors.push(`newest ${FRESH_DAYS} days: ${e.message}`); }
  const critical = [...byId.values()].filter((c) => !kevIds.has(c.id) && c.vulnStatus !== 'Rejected');
  if (errors.length === 2) note(`NVD new critical CVEs (${CRITICAL_DAYS}d)`, false, 0, errors.join('; '));
  else note(`NVD new critical CVEs (${CRITICAL_DAYS}d)`, true, critical.length, errors[0] ? `partly failed: ${errors[0]}` : undefined);

  // 3. EPSS for everything
  let epss = {};
  const allIds = [...recentKev.map((v) => v.cveID), ...critical.map((c) => c.id)];
  try { epss = await fetchEpss(allIds); note('EPSS exploit likelihood (FIRST.org)', true, Object.keys(epss).length); }
  catch (e) { note('EPSS exploit likelihood (FIRST.org)', false, 0, e.message); }

  const links = (notes) => String(notes || '').split(/\s*;\s*/).filter((u) => /^https?:\/\//.test(u)).slice(0, 4);

  const exploited = recentKev.map((v) => {
    const cve = nvdByCve[v.cveID];
    const vendor = vendorFor(v.vendorProject, ...(cve ? cpeVendors(cve) : []), v.product);
    return {
      cve: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      vendorKey: vendor?.key || null,
      name: v.vulnerabilityName,
      description: v.shortDescription,
      requiredAction: v.requiredAction,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      cvss: cve ? bestCvss(cve.metrics) : null,
      ssvc: cve ? ssvc(cve.metrics) : null,
      epss: epss[v.cveID] || null,
      published: cve?.published || null,
      advisories: links(v.notes),
    };
  }).sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || (b.cvss?.score || 0) - (a.cvss?.score || 0));

  const newCritical = critical.map((c) => {
    const desc = ((c.descriptions || []).find((d) => d.lang === 'en')?.value || '').replace(/^\s*Description:?\s*/i, '').replace(/\s+/g, ' ').trim();
    const cpes = cpeVendors(c);
    const vendor = vendorFor(...cpes, sourceDomain(c.sourceIdentifier), desc.slice(0, 160));
    return {
      cve: c.id,
      vendor: vendor?.name || productFromDescription(desc) || cpes[0] || 'Unknown vendor',
      vendorKey: vendor?.key || null,
      description: desc.slice(0, 320),
      published: c.published,
      cvss: bestCvss(c.metrics, true),
      ssvc: ssvc(c.metrics),
      status: c.vulnStatus,
      epss: epss[c.id] || null,
      advisories: (c.references || []).map((r) => r.url).slice(0, 2),
    };
  }).sort((a, b) => b.published.localeCompare(a.published));

  return {
    kevCatalogVersion: kev.catalogVersion,
    kevDays: KEV_DAYS,
    criticalDays: CRITICAL_DAYS,
    freshDays: FRESH_DAYS,
    vendors: VENDORS.map(({ key, name, services, watch }) => ({ key, name, services, watch })),
    exploited,
    newCritical,
    sources,
  };
}

module.exports = { collectVulns, VENDORS };
