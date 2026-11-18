// Service health board: combines official status pages with outage reports
// in the news (including stories citing Downdetector and ThousandEyes).
const { parseFeed, get, UA, ADVISORY } = require('./sources');
const { classify } = require('./extract');

const gnews = (q) =>
  `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en-US&gl=US&ceid=US:en`;
const sp = (base) => ({ type: 'statuspage', url: `${base}/api/v2/summary.json`, page: base });

// id, display name, category, regex used to match news, Google News query term, official source / page
const CATALOG = [
  // Big Tech
  ['apple', 'Apple (iCloud, App Store, iMessage)', 'Big Tech', /\b(Apple|iCloud|App Store|iMessage|FaceTime|Apple Pay|Apple Music|Apple TV|Siri)\b/, 'iCloud OR "Apple Pay" OR iMessage OR "App Store"',
    { type: 'apple', url: 'https://www.apple.com/support/systemstatus/data/system_status_en_US.js', page: 'https://www.apple.com/support/systemstatus/' }],
  ['microsoft365', 'Microsoft 365 (Outlook, Teams)', 'Big Tech', /\b(Microsoft 365|Office 365|Outlook|Hotmail|Microsoft Teams|MS Teams|OneDrive|SharePoint|Exchange Online|Copilot)\b/, '"Microsoft 365" OR Outlook OR "Microsoft Teams"',
    { page: 'https://status.cloud.microsoft/' }],
  ['google', 'Google Workspace (Gmail, Drive, Meet)', 'Big Tech', /\b(Gmail|Google Drive|Google Docs|Google Meet|Google Workspace|Google Calendar|Google Search)\b/, 'Gmail OR "Google Drive" OR "Google Meet"',
    { type: 'gstatus', url: 'https://www.google.com/appsstatus/dashboard/incidents.json', page: 'https://www.google.com/appsstatus/dashboard/' }],
  ['amazon', 'Amazon (Shopping, Alexa, Prime Video)', 'Big Tech', /\b(Amazon(?! Web Services)|Alexa|Prime Video)\b/, 'Amazon OR Alexa OR "Prime Video"', null],
  ['meta', 'Meta (Facebook, Instagram, WhatsApp)', 'Big Tech', /\b(Meta|Facebook|Instagram|WhatsApp|Messenger|Threads)\b/, 'Facebook OR Instagram OR WhatsApp',
    { page: 'https://metastatus.com/' }],

  // Cloud & Internet infrastructure
  ['aws', 'Amazon Web Services', 'Cloud & Infrastructure', /\b(AWS|Amazon Web Services)\b/, 'AWS',
    { type: 'aws', url: 'https://health.aws.amazon.com/public/currentevents', page: 'https://health.aws.amazon.com/health/status' }],
  ['azure', 'Microsoft Azure', 'Cloud & Infrastructure', /\bAzure\b/, 'Azure',
    { type: 'rss', url: 'https://azure.status.microsoft/en-us/status/feed/', page: 'https://azure.status.microsoft/' }],
  ['gcloud', 'Google Cloud', 'Cloud & Infrastructure', /\b(Google Cloud|GCP)\b/, '"Google Cloud"',
    { type: 'gstatus', url: 'https://status.cloud.google.com/incidents.json', page: 'https://status.cloud.google.com/' }],
  ['cloudflare', 'Cloudflare', 'Cloud & Infrastructure', /\bCloudflare\b/, 'Cloudflare', sp('https://www.cloudflarestatus.com')],
  ['github', 'GitHub', 'Cloud & Infrastructure', /\bGitHub\b/, 'GitHub', sp('https://www.githubstatus.com')],
  ['openai', 'OpenAI / ChatGPT', 'Cloud & Infrastructure', /\b(ChatGPT|OpenAI)\b/, 'ChatGPT', sp('https://status.openai.com')],
  ['anthropic', 'Anthropic / Claude', 'Cloud & Infrastructure', /\b(Anthropic|Claude AI|Claude)\b/, 'Claude AI OR Anthropic', sp('https://status.anthropic.com')],
  ['crowdstrike', 'CrowdStrike', 'Cloud & Infrastructure', /\bCrowdStrike\b/, 'CrowdStrike', null],

  // Network & security vendors (official feeds verified to work: F5, Infoblox, Duo, Palo Alto, Akamai)
  ['infoblox', 'Infoblox (DNS, DHCP, IPAM)', 'Network & Security', /\b(Infoblox|BloxOne|NIOS-X)\b/, 'Infoblox', sp('https://status.infoblox.com')],
  ['f5', 'F5 (BIG-IP, Distributed Cloud, NGINX)', 'Network & Security', /\b(F5|BIG-IP|NGINX)\b/, '"F5 Networks" OR "BIG-IP" OR "F5 Inc" OR NGINX', sp('https://www.f5cloudstatus.com')],
  ['cisco', 'Cisco (Meraki, Webex, Umbrella)', 'Network & Security', /\b(Cisco|Meraki|Webex)\b/, 'Cisco OR Meraki OR Webex', { page: 'https://status.webex.com/' }],
  ['duo', 'Duo Security (Cisco MFA)', 'Network & Security', /\b(Cisco Duo|Duo Security|Duo (?:MFA|Push|Mobile|2FA|outage))\b/i, '"Duo Security" OR "Cisco Duo"', sp('https://status.duo.com')],
  ['paloalto', 'Palo Alto Networks (Prisma, GlobalProtect)', 'Network & Security', /\b(Palo Alto Networks|PAN-OS|GlobalProtect|Prisma Access|Prisma SASE|Cortex XDR|Cortex XSIAM)\b/, '"Palo Alto Networks" OR GlobalProtect OR "PAN-OS"', sp('https://status.paloaltonetworks.com')],
  ['fortinet', 'Fortinet (FortiGate)', 'Network & Security', /\b(Fortinet|FortiGate|FortiOS|FortiClient|FortiManager|FortiWeb|FortiSIEM)\b/, 'Fortinet OR FortiGate', null],
  ['zscaler', 'Zscaler', 'Network & Security', /\bZscaler\b/, 'Zscaler', { page: 'https://trust.zscaler.com/' }],
  ['akamai', 'Akamai', 'Network & Security', /\bAkamai\b/, 'Akamai', sp('https://www.akamaistatus.com')],
  ['okta', 'Okta', 'Network & Security', /\bOkta\b/, 'Okta', { page: 'https://status.okta.com/' }],
  ['citrix', 'Citrix / NetScaler', 'Network & Security', /\b(Citrix|NetScaler)\b/, 'Citrix OR NetScaler', { page: 'https://status.cloud.com/' }],
  ['ivanti', 'Ivanti (Connect Secure, EPMM)', 'Network & Security', /\bIvanti\b/, 'Ivanti', null],
  ['sonicwall', 'SonicWall', 'Network & Security', /\bSonicWall\b/i, 'SonicWall', null],
  ['juniper', 'Juniper / HPE Aruba', 'Network & Security', /\b(Juniper Networks|Juniper|Junos|HPE Aruba|Aruba Networks|Aruba Central)\b/, '"Juniper Networks" OR "HPE Aruba"', null],
  ['cyberark', 'CyberArk (privileged access)', 'Network & Security', /\bCyberArk\b/, 'CyberArk', null],
  ['sentinelone', 'SentinelOne', 'Network & Security', /\bSentinelOne\b/, 'SentinelOne', null],
  ['emailsec', 'Proofpoint / Mimecast (email security)', 'Network & Security', /\b(Proofpoint|Mimecast)\b/, 'Proofpoint OR Mimecast', null],

  // Data center, backup & IT operations
  ['vmware', 'VMware (Broadcom)', 'Data Center & IT Ops', /\b(VMware|vSphere|ESXi|vCenter|Broadcom)\b/, 'VMware OR ESXi OR vCenter', null],
  ['rubrik', 'Rubrik', 'Data Center & IT Ops', /\bRubrik\b/, 'Rubrik', sp('https://status.rubrik.com')],
  ['cohesity', 'Cohesity / Veritas', 'Data Center & IT Ops', /\b(Cohesity|Veritas)\b/, 'Cohesity OR Veritas', null],
  ['veeam', 'Veeam', 'Data Center & IT Ops', /\bVeeam\b/, 'Veeam', null],
  ['commvault', 'Commvault', 'Data Center & IT Ops', /\bCommvault\b/, 'Commvault', null],
  ['nutanix', 'Nutanix', 'Data Center & IT Ops', /\bNutanix\b/, 'Nutanix', null],
  ['storage', 'Pure Storage / NetApp', 'Data Center & IT Ops', /\b(Pure Storage|NetApp)\b/, '"Pure Storage" OR NetApp', null],
  ['dellhpe', 'Dell / HPE', 'Data Center & IT Ops', /\b(Dell Technologies|Dell EMC|Dell|Hewlett Packard Enterprise|HPE)\b/, '"Dell Technologies" OR "Hewlett Packard Enterprise"', null],
  ['servicenow', 'ServiceNow', 'Data Center & IT Ops', /\bServiceNow\b/, 'ServiceNow', null],
  ['datadog', 'Datadog', 'Data Center & IT Ops', /\bDatadog\b/, 'Datadog', { page: 'https://status.datadoghq.com/' }],
  ['splunk', 'Splunk', 'Data Center & IT Ops', /\bSplunk\b/, 'Splunk', null],
  ['solarwinds', 'SolarWinds', 'Data Center & IT Ops', /\bSolarWinds\b/, 'SolarWinds', null],
  ['rmm', 'ConnectWise / Kaseya (remote management)', 'Data Center & IT Ops', /\b(ConnectWise|ScreenConnect|Kaseya)\b/, 'ConnectWise OR ScreenConnect OR Kaseya', null],

  // Healthcare: clinical systems. Few vendors publish public status pages (most are behind
  // customer portals), so these rely on news coverage.
  ['epic', 'Epic (EHR, MyChart)', 'Healthcare: Clinical Systems', /\b(Epic Systems|MyChart|Epic (?:EHR|EMR|electronic (?:health|medical) records?|health records?|medical records?|Hosting|Hyperspace|Haiku|Rover))\b|\bEpic\b(?=.{0,60}\b(?:hospitals?|health|patients?|clinics?|medical|EHR|EMR|charts?|charting)\b)/, '"Epic Systems" OR MyChart OR "Epic EHR"', null, { exclude: /\b(Epic Games|Fortnite|Unreal Engine)\b/ }],
  ['oraclehealth', 'Oracle Health (Cerner)', 'Healthcare: Clinical Systems', /\b(Oracle Health|Oracle Cerner|Cerner|Millennium EHR|Oracle EHR)\b/, '"Oracle Health" OR Cerner', null],
  ['meditech', 'MEDITECH', 'Healthcare: Clinical Systems', /\bMEDITECH\b/i, 'Meditech', null],
  ['athena', 'athenahealth', 'Healthcare: Clinical Systems', /\bathena(?:health|One|Clinicals)\b/i, 'athenahealth', null],
  ['ecw', 'eClinicalWorks', 'Healthcare: Clinical Systems', /\beClinicalWorks\b/i, 'eClinicalWorks', null],
  ['nextgen', 'NextGen Healthcare', 'Healthcare: Clinical Systems', /\bNextGen (?:Healthcare|Office|Enterprise)\b/i, '"NextGen Healthcare"', null],
  ['veradigm', 'Veradigm (Allscripts)', 'Healthcare: Clinical Systems', /\b(Veradigm|Allscripts|Practice Fusion)\b/, 'Veradigm OR Allscripts', null],
  ['fujifilm', 'Fujifilm (Synapse PACS)', 'Healthcare: Clinical Systems', /\b(Fujifilm|FUJIFILM|Fuji PACS|Synapse PACS|Synapse 7x)\b/, 'Fujifilm OR "Synapse PACS"', null],
  ['gehc', 'GE HealthCare (Centricity)', 'Healthcare: Clinical Systems', /\b(GE HealthCare|GE Healthcare|Centricity)\b/, '"GE HealthCare" OR Centricity', null],
  ['philips', 'Philips Healthcare (IntelliSpace)', 'Healthcare: Clinical Systems', /\bPhilips\b/, 'Philips healthcare', null],
  ['sectra', 'Sectra PACS', 'Healthcare: Clinical Systems', /\bSectra\b/, 'Sectra', null],
  ['agfa', 'Agfa HealthCare', 'Healthcare: Clinical Systems', /\bAgfa\b/, '"Agfa HealthCare"', null],
  ['imprivata', 'Imprivata (SSO)', 'Healthcare: Clinical Systems', /\bImprivata\b/, 'Imprivata', null],
  ['clincomms', 'Clinical comms (Vocera, TigerConnect, Spok)', 'Healthcare: Clinical Systems', /\b(Vocera|TigerConnect|PerfectServe|Spok)\b/, 'Vocera OR TigerConnect OR Spok', null],
  ['bd', 'BD (Pyxis, Alaris)', 'Healthcare: Clinical Systems', /\b(Pyxis|BD Alaris|Alaris (?:pumps?|infusion)|Becton,? Dickinson)\b/, 'Pyxis OR "BD Alaris" OR "Becton Dickinson"', null],
  ['omnicell', 'Omnicell', 'Healthcare: Clinical Systems', /\bOmnicell\b/, 'Omnicell', null],
  ['quest', 'Quest Diagnostics', 'Healthcare: Clinical Systems', /\bQuest Diagnostics\b/, '"Quest Diagnostics"', null],
  ['labcorp', 'Labcorp', 'Healthcare: Clinical Systems', /\bLab[Cc]orp\b/, 'Labcorp', null],

  // Healthcare: payers, pharmacy, claims & telehealth
  ['changehc', 'Change Healthcare / Optum', 'Healthcare: Payers, Pharmacy & Claims', /\b(Change Healthcare|Optum)\b/, '"Change Healthcare" OR Optum', null],
  ['availity', 'Availity', 'Healthcare: Payers, Pharmacy & Claims', /\bAvaility\b/, 'Availity', null],
  ['waystar', 'Waystar', 'Healthcare: Payers, Pharmacy & Claims', /\bWaystar\b/, 'Waystar', null],
  ['surescripts', 'Surescripts (e-prescribing)', 'Healthcare: Payers, Pharmacy & Claims', /\bSurescripts\b/, 'Surescripts', null],
  ['uhc', 'UnitedHealthcare', 'Healthcare: Payers, Pharmacy & Claims', /\bUnitedHealth(?:care| Group)?\b/, 'UnitedHealthcare', null],
  ['cvs', 'CVS Health / Aetna', 'Healthcare: Payers, Pharmacy & Claims', /\b(CVS|Aetna)\b/, 'CVS OR Aetna', null],
  ['cigna', 'Cigna / Express Scripts', 'Healthcare: Payers, Pharmacy & Claims', /\b(Cigna|Evernorth|Express Scripts)\b/, 'Cigna OR "Express Scripts"', null],
  ['elevance', 'Elevance Health (Anthem)', 'Healthcare: Payers, Pharmacy & Claims', /\b(Elevance|Anthem|Carelon)\b/, 'Elevance OR Anthem', null],
  ['humana', 'Humana', 'Healthcare: Payers, Pharmacy & Claims', /\bHumana\b/, 'Humana', null],
  ['kaiser', 'Kaiser Permanente', 'Healthcare: Payers, Pharmacy & Claims', /\bKaiser(?: Permanente)?\b/, '"Kaiser Permanente"', null],
  ['walgreens', 'Walgreens', 'Healthcare: Payers, Pharmacy & Claims', /\bWalgreens\b/, 'Walgreens', null],
  ['telehealth', 'Telehealth (Teladoc, Amwell)', 'Healthcare: Payers, Pharmacy & Claims', /\b(Teladoc|Amwell|Doxy\.me)\b/, 'Teladoc OR Amwell', null],

  // Communication & social
  ['slack', 'Slack', 'Communication & Social', /\bSlack\b/, 'Slack', { type: 'slack', url: 'https://slack-status.com/api/v2.0.0/current', page: 'https://slack-status.com/' }],
  ['zoom', 'Zoom', 'Communication & Social', /\bZoom\b/, 'Zoom', sp('https://status.zoom.us')],
  ['discord', 'Discord', 'Communication & Social', /\bDiscord\b/, 'Discord', sp('https://discordstatus.com')],
  ['reddit', 'Reddit', 'Communication & Social', /\bReddit\b/, 'Reddit', sp('https://www.redditstatus.com')],
  ['x', 'X (Twitter)', 'Communication & Social', /\b(Twitter|X\.com|X \(formerly Twitter\))\b|\bX\b(?=,? (?:is |was |went )?(?:down|outage|not working))/, 'Twitter OR "X down"', null],
  ['tiktok', 'TikTok', 'Communication & Social', /\bTikTok\b/, 'TikTok', null],
  ['snapchat', 'Snapchat', 'Communication & Social', /\bSnapchat\b/, 'Snapchat', null],
  ['linkedin', 'LinkedIn', 'Communication & Social', /\bLinkedIn\b/, 'LinkedIn', null],

  // Banking & payments
  ['chase', 'Chase', 'Banking & Payments', /\b(JPMorgan Chase|Chase)\b/, '"Chase bank" OR "Chase app"', null],
  ['bofa', 'Bank of America', 'Banking & Payments', /\b(Bank of America|BofA)\b/, '"Bank of America"', null],
  ['wellsfargo', 'Wells Fargo', 'Banking & Payments', /\bWells Fargo\b/, '"Wells Fargo"', null],
  ['citi', 'Citi', 'Banking & Payments', /\b(Citibank|Citigroup|Citi)\b/, 'Citibank OR Citi', null],
  ['capitalone', 'Capital One', 'Banking & Payments', /\bCapital One\b/, '"Capital One"', null],
  ['usbank', 'U.S. Bank', 'Banking & Payments', /\bU\.?S\.? Bank\b/, '"US Bank"', null],
  ['pnc', 'PNC', 'Banking & Payments', /\bPNC\b/, 'PNC bank', null],
  ['tdbank', 'TD Bank', 'Banking & Payments', /\bTD Bank\b/, '"TD Bank"', null],
  ['navyfederal', 'Navy Federal', 'Banking & Payments', /\bNavy Federal\b/, '"Navy Federal"', null],
  ['schwab', 'Charles Schwab', 'Banking & Payments', /\bSchwab\b/, 'Schwab', null],
  ['fidelity', 'Fidelity', 'Banking & Payments', /\bFidelity (?:Investments|app|website|customers|NetBenefits)\b/i, '"Fidelity Investments"', null],
  ['paypal', 'PayPal', 'Banking & Payments', /\bPayPal\b/, 'PayPal', { page: 'https://www.paypal-status.com/' }],
  ['venmo', 'Venmo', 'Banking & Payments', /\bVenmo\b/, 'Venmo', null],
  ['cashapp', 'Cash App', 'Banking & Payments', /\bCash App\b/, '"Cash App"', null],
  ['zelle', 'Zelle', 'Banking & Payments', /\bZelle\b/, 'Zelle', null],
  ['stripe', 'Stripe', 'Banking & Payments', /\bStripe\b/, 'Stripe payments', { page: 'https://status.stripe.com/' }],
  ['square', 'Square', 'Banking & Payments', /\bSquare (?:payments|outage|sellers|POS)\b/i, 'Square payments', sp('https://www.issquareup.com')],
  ['visa', 'Visa', 'Banking & Payments', /\bVisa (?:card|network|payments|outage)\b/i, 'Visa card', null],
  ['mastercard', 'Mastercard', 'Banking & Payments', /\bMastercard\b/, 'Mastercard', null],
  ['amex', 'American Express', 'Banking & Payments', /\b(American Express|Amex)\b/, '"American Express"', null],
  ['coinbase', 'Coinbase', 'Banking & Payments', /\bCoinbase\b/, 'Coinbase', sp('https://status.coinbase.com')],
  ['robinhood', 'Robinhood', 'Banking & Payments', /\bRobinhood\b/, 'Robinhood', sp('https://status.robinhood.com')],

  // Telecom & ISPs
  ['verizon', 'Verizon', 'Telecom & ISPs', /\bVerizon\b/, 'Verizon', null],
  ['att', 'AT&T', 'Telecom & ISPs', /\bAT&T\b/, '"AT&T"', null],
  ['tmobile', 'T-Mobile', 'Telecom & ISPs', /\bT-Mobile\b/, '"T-Mobile"', null],
  ['xfinity', 'Comcast Xfinity', 'Telecom & ISPs', /\b(Xfinity|Comcast)\b/, 'Xfinity OR Comcast', null],
  ['spectrum', 'Spectrum', 'Telecom & ISPs', /\bSpectrum (?:internet|outage|customers|cable|TV|Mobile)\b|\bCharter Communications\b/i, 'Spectrum internet', null],
  ['starlink', 'Starlink', 'Telecom & ISPs', /\bStarlink\b/, 'Starlink', null],

  // Streaming & gaming
  ['netflix', 'Netflix', 'Streaming & Gaming', /\bNetflix\b/, 'Netflix', null],
  ['spotify', 'Spotify', 'Streaming & Gaming', /\bSpotify\b/, 'Spotify', null],
  ['disney', 'Disney+ / Hulu', 'Streaming & Gaming', /\b(Disney\+|Disney Plus|Hulu|ESPN\+)/, '"Disney+" OR Hulu', null],
  ['youtube', 'YouTube', 'Streaming & Gaming', /\bYouTube\b/, 'YouTube', null],
  ['psn', 'PlayStation Network', 'Streaming & Gaming', /\b(PlayStation Network|PSN|PlayStation)\b/, '"PlayStation Network" OR PSN', { page: 'https://status.playstation.com/' }],
  ['xbox', 'Xbox', 'Streaming & Gaming', /\bXbox\b/, 'Xbox', { page: 'https://support.xbox.com/xbox-live-status' }],
  ['steam', 'Steam', 'Streaming & Gaming', /\bSteam\b/, 'Steam', null],
  ['epicgames', 'Epic Games / Fortnite', 'Streaming & Gaming', /\b(Epic Games|Fortnite)\b/, '"Epic Games" OR Fortnite', sp('https://status.epicgames.com')],
  ['roblox', 'Roblox', 'Streaming & Gaming', /\bRoblox\b/, 'Roblox', sp('https://status.roblox.com')],
].map(([id, name, category, match, q, official, opts = {}]) => ({ id, name, category, match, q, official, exclude: opts.exclude }));

const CATEGORIES = [...new Set(CATALOG.map((s) => s.category))];

// ---------- official status sources ----------
const RANK = { ok: 0, maintenance: 0, minor: 1, major: 2 };
const worst = (a, b) => (RANK[b] > RANK[a] ? b : a);

async function getBody(url) {
  const res = await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  // AWS serves UTF-16 with a byte-order mark.
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return buf.subarray(3).toString('utf8');
  return buf.toString('utf8');
}
const parseJson = (s) => JSON.parse(s.trim().replace(/^[\w$.]+\(/, '').replace(/\);?\s*$/, ''));

const OFFICIAL = {
  async statuspage(src) {
    const d = parseJson(await getBody(src.url));
    // Work out the status ourselves instead of trusting the page's headline: a page often says
    // "Partially Degraded" only because of planned maintenance, and some list security
    // advisories as zero-impact "incidents".
    const IMPACT = { critical: 'major', major: 'major', minor: 'minor', none: 'ok', maintenance: 'maintenance' };
    const COMP = { major_outage: 'major', partial_outage: 'minor', degraded_performance: 'minor' };
    let status = 'ok';
    const incidents = [];
    const isAdvisory = (i) => i.impact === 'none' || ADVISORY.test(i.name || '');
    for (const i of d.incidents || []) {
      const advisory = isAdvisory(i);
      if (!advisory) status = worst(status, IMPACT[i.impact] || 'minor');
      incidents.push({ title: i.name, detail: i.incident_updates?.[0]?.body || '', impact: advisory ? 'advisory' : i.impact, since: i.created_at, link: i.shortlink || src.page });
    }
    // Degraded components (individual services or locations), ignoring group headers and maintenance.
    const degraded = (d.components || []).filter((c) => !c.group && COMP[c.status]);
    for (const c of degraded) status = worst(status, COMP[c.status]);
    for (const c of degraded.slice(0, 6)) {
      incidents.push({ title: `${c.name}: ${c.status.replace(/_/g, ' ')}`, detail: '', impact: COMP[c.status], since: c.updated_at, link: src.page });
    }
    if (degraded.length > 6) incidents.push({ title: `…and ${degraded.length - 6} more affected components`, detail: '', impact: 'minor', since: null, link: src.page });
    const inMaint = (d.scheduled_maintenances || []).filter((m) => m.status === 'in_progress').length +
      (d.components || []).filter((c) => !c.group && c.status === 'under_maintenance').length;
    const problems = (d.incidents || []).filter((i) => !isAdvisory(i) && i.impact !== 'maintenance').length;
    const label = status === 'ok'
      ? (inMaint ? 'Operational (maintenance in progress)' : 'All systems operational')
      : [problems && `${problems} active incident${problems > 1 ? 's' : ''}`, degraded.length && `${degraded.length} degraded component${degraded.length > 1 ? 's' : ''}`].filter(Boolean).join(', ');
    return { status, label, incidents };
  },

  async apple(src) {
    const d = parseJson(await getBody(src.url));
    const now = Date.now();
    const incidents = [];
    let status = 'ok';
    for (const svc of d.services || []) {
      for (const e of svc.events || []) {
        const ended = e.eventStatus === 'resolved' || e.eventStatus === 'completed' || (e.epochEndDate && e.epochEndDate < now);
        if (ended) continue;
        const type = String(e.statusType || '').toLowerCase();
        const sev = type.includes('maintenance') ? 'maintenance' : type.includes('outage') ? 'major' : 'minor';
        status = worst(status, sev);
        incidents.push({
          title: `${svc.serviceName}: ${e.statusType || 'Issue'}`, detail: e.message || '', impact: sev,
          since: e.epochStartDate ? new Date(e.epochStartDate).toISOString() : null, link: src.page,
        });
      }
    }
    return { status, label: incidents.length ? `${incidents.length} active issue(s)` : 'All services available', incidents };
  },

  async gstatus(src) { // Google Cloud & Google Workspace dashboards share a format
    const list = parseJson(await getBody(src.url));
    let status = 'ok';
    const incidents = [];
    for (const i of list) {
      if (i.end) continue;
      const sev = i.severity === 'high' ? 'major' : 'minor';
      status = worst(status, sev);
      incidents.push({
        title: i.external_desc || i.service_name || 'Incident', detail: i.most_recent_update?.text || '',
        impact: sev, since: i.begin, link: i.uri ? new URL(i.uri, src.page).href : src.page,
      });
    }
    return { status, label: incidents.length ? `${incidents.length} active incident(s)` : 'No active incidents', incidents };
  },

  async aws(src) {
    const body = (await getBody(src.url)).trim();
    const list = body ? parseJson(body) : [];
    let status = 'ok';
    const incidents = [];
    for (const e of Array.isArray(list) ? list : []) {
      const sev = String(e.status) === '3' ? 'major' : String(e.status) === '1' ? 'ok' : 'minor';
      status = worst(status, sev);
      const log = Array.isArray(e.event_log) ? e.event_log[e.event_log.length - 1] : null;
      incidents.push({
        title: `${e.service_name || e.service || 'AWS'}${e.region_name ? ` (${e.region_name})` : ''}: ${e.summary || 'Service event'}`,
        detail: log?.message || e.description || '', impact: sev,
        since: e.date ? new Date(+e.date * 1000 || e.date).toISOString() : null, link: src.page,
      });
    }
    return { status, label: incidents.length ? `${incidents.length} open event(s)` : 'No open events', incidents };
  },

  async rss(src) { // Azure's feed lists only currently active incidents
    const items = parseFeed(await get(src.url));
    const incidents = items.map((i) => ({ title: i.title, detail: i.summary, impact: 'minor', since: i.date, link: i.link || src.page }));
    return { status: incidents.length ? 'minor' : 'ok', label: incidents.length ? `${incidents.length} active incident(s)` : 'No active incidents', incidents };
  },

  async slack(src) {
    const d = parseJson(await getBody(src.url));
    let status = 'ok';
    const incidents = (d.active_incidents || []).map((i) => {
      const sev = i.type === 'outage' ? 'major' : i.type === 'notice' ? 'maintenance' : 'minor';
      status = worst(status, sev);
      return { title: i.title, detail: i.notes?.[0]?.body || '', impact: sev, since: i.date_created, link: i.url || src.page };
    });
    return { status, label: incidents.length ? `${incidents.length} active incident(s)` : 'No active incidents', incidents };
  },
};

// ---------- news signals (incl. Downdetector / ThousandEyes citations) ----------
const OUTAGE_WORDS = /\b(outage|outages|down|downtime|not working|offline|disruption|disrupted|glitch|issues|problems|errors|unavailable|can't (log|sign) in|login problems|Downdetector|ThousandEyes|cyber ?attack|ransomware|cybersecurity incident|security incident|downtime procedures|paper charts|diversion|diverting ambulances|systems? (are |were )?down)\b/i;
// Vulnerability / security-advisory news: shown on the card but does not mark the service down,
// unless the story also says the service itself is down.
const SECURITY_WORDS = /\b(vulnerabilit(y|ies)|zero-day|0-day|actively exploited|exploited|exploit|CVE-\d{4}-\d+|security (flaw|bug|advisory|update|patch)|critical (flaw|bug|patch)|patch(es)? (now|urgently)|backdoor|breach(ed)?|hacked|compromised|attackers?|hackers?|ransomware|cyber ?attacks?)\b/i;
const HARD_OUTAGE = /\b(outage|outages|is down|are down|went down|offline|not working|unavailable|disruption|disrupted|downtime)\b/i;
const SECURITY_CATEGORIES = new Set(['Network & Security', 'Data Center & IT Ops']);
const NOT_OUTAGE = /\b(shares (are )?down|stock (is )?down|down \d+(\.\d+)?%|price|earnings|layoffs?|steps down|stepping down|shut down (its|the) (division|unit|office))\b/i;

function downdetectorCount(text) {
  if (!/Downdetector/i.test(text)) return 0;
  let max = 0;
  const re = /([\d,.]+)\s*(k|thousand)?\s+(?:user\s+|outage\s+|problem\s+)?(?:reports|complaints|users reported)/gi;
  for (const m of text.matchAll(re)) {
    let n = parseFloat(m[1].replace(/,/g, ''));
    if (m[2]) n *= 1000;
    if (n > max && n < 5e6) max = n;
  }
  return Math.round(max);
}

async function fetchArticles(name, url) {
  const xml = await get(url);
  return parseFeed(xml).map((it) => {
    let title = it.title;
    if (it.source && title.endsWith(` - ${it.source}`)) title = title.slice(0, -(it.source.length + 3));
    const summary = it.summary.startsWith(title) ? '' : it.summary;
    const d = new Date(it.date);
    return { title, summary: summary.slice(0, 300), link: it.link, source: it.source || name, published: isNaN(d) ? new Date().toISOString() : d.toISOString() };
  });
}

function newsFeeds() {
  const feeds = [
    { name: 'Downdetector mentions', key: 'downdetector', url: gnews('Downdetector when:2d') },
    { name: 'ThousandEyes mentions', key: 'thousandeyes', url: gnews('ThousandEyes (outage OR disruption OR down) when:7d') },
  ];
  feeds.push({ name: 'Hospitals & health systems', key: 'hospitals', url: gnews('(hospital OR hospitals OR "health system") (cyberattack OR ransomware OR "EHR outage" OR "IT outage" OR "network outage" OR "system outage" OR downtime OR diversion) when:3d') });
  // Long OR-lists make Google News less reliable, so query each category in chunks of 8 services.
  for (const cat of CATEGORIES) {
    const list = CATALOG.filter((s) => s.category === cat);
    for (let i = 0; i < list.length; i += 8) {
      const terms = list.slice(i, i + 8).map((s) => `(${s.q})`).join(' OR ');
      const part = list.length > 8 ? ` (${i / 8 + 1})` : '';
      feeds.push({ name: `News: ${cat}${part}`, key: 'cat', url: gnews(`(${terms}) (outage OR down OR "not working" OR Downdetector OR cyberattack OR ransomware OR downtime) when:2d`) });
      // For infrastructure vendors, most important news is about vulnerabilities being exploited.
      if (SECURITY_CATEGORIES.has(cat)) {
        feeds.push({ name: `Security news: ${cat}${part}`, key: 'cat', url: gnews(`(${terms}) (vulnerability OR "zero-day" OR exploited OR CVE OR breach OR hacked OR "security advisory") when:7d`) });
      }
    }
  }
  return feeds;
}

// ---------- combine ----------
async function collectServices() {
  const sources = [];
  const feeds = newsFeeds();
  const officialJobs = CATALOG.filter((s) => s.official?.type);

  const [newsResults, officialResults] = await Promise.all([
    Promise.allSettled(feeds.map((f) => fetchArticles(f.name, f.url))),
    Promise.allSettled(officialJobs.map((s) => OFFICIAL[s.official.type](s.official))),
  ]);

  const articles = new Map();
  const special = { downdetector: [], thousandeyes: [], hospitals: [] };
  newsResults.forEach((r, i) => {
    const f = feeds[i];
    sources.push(r.status === 'fulfilled'
      ? { name: f.name, kind: 'news', ok: true, count: r.value.length }
      : { name: f.name, kind: 'news', ok: false, count: 0, error: String(r.reason?.message || r.reason) });
    if (r.status !== 'fulfilled') return;
    for (const a of r.value) {
      const key = a.title.toLowerCase();
      if (!articles.has(key)) articles.set(key, a);
      if (f.key === 'cat' || special[f.key].some((x) => x.title === a.title)) continue;
      // Hospital feed: skip explainers / opinion pieces using the map's incident rules.
      if (f.key === 'hospitals' && !classify(`${a.title}. ${a.summary}`, a.title)) continue;
      special[f.key].push(a);
    }
  });

  const official = {};
  officialResults.forEach((r, i) => {
    const s = officialJobs[i];
    sources.push(r.status === 'fulfilled'
      ? { name: `${s.name} official status`, kind: 'status', ok: true, count: r.value.incidents.length }
      : { name: `${s.name} official status`, kind: 'status', ok: false, count: 0, error: String(r.reason?.message || r.reason) });
    if (r.status === 'fulfilled') official[s.id] = r.value;
  });

  const now = Date.now();
  const H = 3600e3;
  const services = CATALOG.map((s) => {
    const related = [...articles.values()]
      .filter((a) => {
        const text = `${a.title} ${a.summary}`;
        if (!s.match.test(text) || (s.exclude && s.exclude.test(text))) return false;
        // A story about a vulnerability isn't an outage unless it also says the service is down.
        if (SECURITY_WORDS.test(text) && !HARD_OUTAGE.test(text) && !/\b(ransomware|cyber ?attack)\b/i.test(text)) return false;
        return OUTAGE_WORDS.test(text) && !NOT_OUTAGE.test(a.title) && now - new Date(a.published) < 48 * H;
      })
      .sort((a, b) => b.published.localeCompare(a.published));
    const security = [...articles.values()]
      .filter((a) => {
        const text = `${a.title} ${a.summary}`;
        return s.match.test(text) && !(s.exclude && s.exclude.test(text)) && SECURITY_WORDS.test(text) && !NOT_OUTAGE.test(a.title) && now - new Date(a.published) < 7 * 24 * H;
      })
      .sort((a, b) => b.published.localeCompare(a.published));
    const count6h = related.filter((a) => now - new Date(a.published) < 6 * H).length;
    const count24h = related.filter((a) => now - new Date(a.published) < 24 * H).length;
    const ddReports = Math.max(0, ...related.filter((a) => now - new Date(a.published) < 24 * H).map((a) => downdetectorCount(`${a.title} ${a.summary}`)));

    let newsStatus = 'ok';
    if (count6h >= 3 || ddReports >= 5000) newsStatus = 'major';
    else if (count6h >= 1 || count24h >= 2 || ddReports >= 500) newsStatus = 'minor';

    const off = official[s.id] || null;
    const offStatus = off ? (off.status === 'maintenance' ? 'ok' : off.status) : 'ok';
    return {
      id: s.id, name: s.name, category: s.category,
      status: worst(offStatus, newsStatus),
      official: off ? { ...off, page: s.official.page } : s.official?.page ? { status: 'unknown', label: 'Check official page', incidents: [], page: s.official.page } : null,
      officialError: s.official?.type && !off ? 'Could not load official status' : null,
      news: { status: newsStatus, count6h, count24h, ddReports, articles: related.slice(0, 8) },
      security: { count7d: security.length, articles: security.slice(0, 6) },
      links: {
        downdetector: `https://downdetector.com/search/?q=${encodeURIComponent(s.name.replace(/\s*\(.*\)/, '').split(' / ')[0])}`,
        thousandeyes: 'https://www.thousandeyes.com/outages/',
      },
    };
  });

  for (const k of Object.keys(special)) special[k].sort((a, b) => b.published.localeCompare(a.published)).splice(25);
  return { categories: CATEGORIES, services, feeds: special, sources };
}

module.exports = { collectServices, CATALOG, downdetectorCount, OFFICIAL };
