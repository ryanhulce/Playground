// Version history shown in the site's "What's new" panel (click the version in the footer).
// Add new releases at the top, and keep package.json "version"/"releaseDate" in step.
module.exports = [
  { version: '2.0.0', date: '2026-11-18', changes: [
    'New Healthcare tab',
    'Ransomware leak-site posts (ransomware.live): healthcare organisations claimed by ransomware gangs, often days before the news, plus the most active groups',
    'HHS breach reports (500+ people), filterable by state, showing people affected, breach type and whether a vendor was involved',
    'CISA medical-device security advisories, and FDA Class I device recalls and MedWatch safety alerts',
    'Vendor alerts: your Services vendors are flagged when they appear in any of these sources (e.g. listed by a ransomware gang); "Your vendors only" filter',
    'Services cards show healthcare alerts (🚨 ransomware listing, 🩺 device advisories, recalls, HHS breach reports) linking to the Healthcare tab',
  ] },
  { version: '1.9.0', date: '2026-11-18', changes: [
    'Duplicate news grouped into incidents: headlines about the same event (e.g. 46 Apple outage stories) now appear once on the Map, with a "📰 N headlines · N outlets" tag that lists every source',
    'Incidents show when they were first and most recently reported; the time filter includes anything reported during the period',
    'Grouping keeps different organisations apart, including look-alike template headlines (law-firm breach notices, ransomware leak-site posts)',
    'A grouped incident is only pinned to places named by at least 20% of its headlines, so one side story doesn\'t mislocate a global outage',
  ] },
  { version: '1.8.0', date: '2026-11-18', changes: [
    'New Vulnerabilities tab: vulnerabilities confirmed as exploited (CISA KEV), with severity (CVSS), exploit likelihood (EPSS), ransomware use and CISA patch deadline',
    'Early warning: new critical (CVSS 9+) vulnerabilities from the last 14 days that are not yet known to be exploited (NVD)',
    '"Your vendors" filter based on the Services vendors, editable in the tab and saved in your browser; "By vendor" counts to drill in',
    'Services cards show "⚠ N exploited vulnerabilities (30d)" and link straight to that vendor in the Vulnerabilities tab',
    'Vulnerability data refreshes hourly; /api/diagnostics now also reports the vulnerability sources',
  ] },
  { version: '1.7.0', date: '2026-11-18', changes: [
    'Network & Security on the Services tab: Infoblox, F5, Cisco, Duo, Palo Alto Networks, Fortinet, Zscaler, Akamai, Okta, Citrix/NetScaler, Ivanti, SonicWall, Juniper/HPE Aruba, CyberArk, SentinelOne, Proofpoint/Mimecast',
    'Data Center & IT Ops: VMware, Rubrik, Cohesity/Veritas, Veeam, Commvault, Nutanix, Pure Storage/NetApp, Dell/HPE, ServiceNow, Datadog, Splunk, SolarWinds, ConnectWise/Kaseya',
    'Live official status for Infoblox, F5, Duo, Palo Alto Networks, Akamai and Rubrik (each checked against the real feed)',
    'F5 Distributed Cloud and Infoblox degraded locations shown on the map',
    'New 🛡 security news on service cards (vulnerabilities, exploits, breaches in the last 7 days); kept separate from outage status',
    'Status pages read more accurately: planned maintenance and security advisories no longer mark a service as degraded',
  ] },
  { version: '1.6.2', date: '2026-11-18', changes: [
    'New /api/diagnostics page that reports whether the Cloudflare token is visible to the app (never the token itself)',
    'Cloudflare token is also read from APPSETTING_CLOUDFLARE_API_TOKEN, and stray spaces in a pasted token are ignored',
  ] },
  { version: '1.6.1', date: '2026-11-18', changes: [
    'Cloudflare Radar checked against the live service and adjusted to match real data',
    'Regional outages now named precisely (e.g. "Zhytomyr Oblast, Ukraine") and single-network outages placed by their provider\'s country',
    'Cloud platform outages (e.g. a global Microsoft 365/Azure disruption) shown as service outages listed under "Global" instead of "Unknown location"',
    'Outages with no recorded end time are only marked "ongoing" for 48 hours',
  ] },
  { version: '1.6.0', date: '2026-11-18', changes: [
    'Measured internet outages on the map (purple pins), from IODA (Georgia Tech) and Cloudflare Radar, not just news headlines',
    'New "Internet" filter and counter; ongoing outages get a thick ring and an "ongoing" tag',
    'Covers every country, including ones the news matching skips (e.g. Chad, Jordan, Georgia)',
    'Cloudflare Radar is optional: it turns on when a free API token is set (CLOUDFLARE_API_TOKEN)',
  ] },
  { version: '1.5.0', date: '2026-11-18', changes: [
    'Healthcare on the Services tab: 30 vendors across EHR (Epic, Oracle Health/Cerner, MEDITECH…), PACS and imaging (Fujifilm Synapse, GE HealthCare, Philips, Sectra, Agfa), clinical systems (Imprivata, Vocera, BD Pyxis, Omnicell, Quest, Labcorp), and payers, pharmacy and claims (Change Healthcare/Optum, Availity, Surescripts, UnitedHealthcare, CVS/Aetna…)',
    'New "Hospitals & health systems" news feed for cyberattacks, EHR/IT outages and ambulance diversions',
    'Category picker on the Services tab (including "Healthcare (all)"), remembered between visits',
    'Ransomware attacks, cyberattacks and clinical downtime language now count as service problems',
  ] },
  { version: '1.4.1', date: '2026-11-18', changes: [
    'Clicking the version number in the footer opens this "What\'s new" panel',
  ] },
  { version: '1.4.0', date: '2026-11-18', changes: [
    'Footer showing the site version, release date and when the server last started',
  ] },
  { version: '1.3.0', date: '2026-11-18', changes: [
    'Map pins go on the victim, not the attacker ("Russian-linked hackers hit Danish utility" → Denmark)',
    'Opinion pieces, explainers, research reports and general warnings are no longer counted as incidents',
    '"Is X down?" headlines are recognised as outages',
  ] },
  { version: '1.2.0', date: '2026-11-17', changes: [
    'Services tab: about 60 services across Big Tech, cloud, banking, telecom, social, streaming and gaming',
    'Official status feeds (Apple, AWS, Azure, Google, Slack, Statuspage sites) combined with news, Downdetector and ThousandEyes signals',
  ] },
  { version: '1.1.0', date: '2026-11-17', changes: [
    'Map tiles switched to OpenStreetMap (no API key needed), with a Dark/Light switch',
    'Azure App Service deployment fixes',
  ] },
  { version: '1.0.0', date: '2026-11-17', changes: [
    'World map of hacks and website outages built from news feeds and status pages',
  ] },
];
