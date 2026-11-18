// Vulnerabilities: confirmed-exploited (CISA KEV) and new critical CVEs (NVD), enriched with
// CVSS severity (NVD) and EPSS exploit likelihood (FIRST.org), and matched to your vendors.
//  - CISA KEV:  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//  - NVD API:   https://nvd.nist.gov/developers/vulnerabilities  (optional key: NVD_API_KEY)
//  - EPSS:      https://www.first.org/epss/
const { UA } = require('./sources');

const KEV_DAYS = Math.min(+process.env.KEV_DAYS || 90, 120);           // NVD allows up to 120 days per query
const CRITICAL_DAYS = Math.min(+process.env.NVD_CRITICAL_DAYS || 14, 120);

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
function bestCvss(metrics = {}) {
  const pick = (key) => {
    const list = metrics[key] || [];
    return list.find((m) => m.type === 'Primary') || list[0];
  };
  for (const [key, ver] of [['cvssMetricV31', '3.1'], ['cvssMetricV40', '4.0'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']]) {
    const m = pick(key);
    if (m) return { score: m.cvssData.baseScore, severity: (m.cvssData.baseSeverity || m.baseSeverity || '').toUpperCase(), version: ver };
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

  let critical = [];
  try {
    await sleep(process.env.NVD_API_KEY ? 700 : 6500); // stay inside NVD's public rate limit
    const d = await nvdQuery(`pubStartDate=${iso(new Date(now - CRITICAL_DAYS * 864e5))}&pubEndDate=${iso(now)}&cvssV3Severity=CRITICAL`);
    const kevIds = new Set((kev.vulnerabilities || []).map((v) => v.cveID));
    critical = (d.vulnerabilities || []).map((x) => x.cve).filter((c) => !kevIds.has(c.id) && c.vulnStatus !== 'Rejected');
    note(`NVD new critical CVEs (${CRITICAL_DAYS}d)`, true, critical.length);
  } catch (e) { note(`NVD new critical CVEs (${CRITICAL_DAYS}d)`, false, 0, e.message); }

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
      epss: epss[v.cveID] || null,
      published: cve?.published || null,
      advisories: links(v.notes),
    };
  }).sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || (b.cvss?.score || 0) - (a.cvss?.score || 0));

  const newCritical = critical.map((c) => {
    const desc = (c.descriptions || []).find((d) => d.lang === 'en')?.value || '';
    const cpes = cpeVendors(c);
    const vendor = vendorFor(...cpes, sourceDomain(c.sourceIdentifier), desc.slice(0, 160));
    return {
      cve: c.id,
      vendor: vendor?.name || productFromDescription(desc) || cpes[0] || 'Unknown vendor',
      vendorKey: vendor?.key || null,
      description: desc.slice(0, 500),
      published: c.published,
      cvss: bestCvss(c.metrics),
      epss: epss[c.id] || null,
      advisories: (c.references || []).map((r) => r.url).slice(0, 3),
    };
  }).sort((a, b) => b.published.localeCompare(a.published));

  return {
    kevCatalogVersion: kev.catalogVersion,
    kevDays: KEV_DAYS,
    criticalDays: CRITICAL_DAYS,
    vendors: VENDORS.map(({ key, name, services, watch }) => ({ key, name, services, watch })),
    exploited,
    newCritical,
    sources,
  };
}

module.exports = { collectVulns, VENDORS };
