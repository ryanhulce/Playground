# Outage & Hack Map

A live world map of hacks and websites that are down, built from news reports and public status pages.

![](https://img.shields.io/badge/dependencies-none-brightgreen)

## Run it

Requires Node.js 18 or newer. There is nothing to install.

```bash
npm start
```

Then open http://localhost:3000. The first crawl takes about 10–20 seconds.

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `REFRESH_MINUTES` | `10` | How often the server re-crawls sources |
| `MAX_AGE_DAYS` | `7` | Drop reports older than this |

## How it works

1. **Collect** (`lib/sources.js`): every 10 minutes the server pulls
   - Google News RSS searches ("website down", outage, cyberattack, data breach, ransomware, DDoS)
   - security news feeds: BleepingComputer, The Record, The Hacker News, SecurityWeek, Dark Reading, The Register
   - Statuspage-powered status pages: Cloudflare, DigitalOcean, GitHub, Discord, Reddit, OpenAI, Atlassian, Zoom, Dropbox, Twilio, Vercel, Linode. Cloudflare's per-datacenter components are mapped straight to their city.
2. **Classify** (`lib/extract.js`): keyword rules tag each headline as a **hack** (breach, ransomware, DDoS, …) or an **outage** (down, offline, disruption, …). Outages must mention something online, so weather-related power cuts are skipped. Everything else is thrown away.
3. **Geolocate** (`lib/extract.js` and `lib/gazetteer.js`): place names, demonyms ("Danish", "Japanese"), US states, continents, cloud regions (`us-east-1` → Ashburn) and datacenter codes (`NYC3`) are matched against a built-in gazetteer. Demonyms that describe the *attacker* ("Russian-linked hackers", "pro-Iranian") are ignored, so the pin lands on the victim.
4. **Serve** (`server.js`): `GET /api/incidents` returns the deduplicated list; `POST /api/refresh` forces a re-crawl. The UI in `public/` uses Leaflet, which is bundled in `public/vendor/`, with OpenStreetMap tiles (no API key; darkened with a CSS filter, with a Dark/Light switch in the top-right).

Reports with no recognisable place are listed under "Global / location unknown" in the sidebar.

## Grouped news

Headlines about the same event are grouped into one incident on the Map, so one big outage doesn't fill the list 40 times. The incident shows a **📰 N headlines · N outlets** tag; click it to see every outlet's story. It also shows when the event was first and most recently reported.

How it works (`lib/cluster.js`):
- Headlines are compared by their distinctive words. "NSA", "iCloud" or "Equinor" count for much more than common words like "down" or "outage", and aliases such as "National Security Agency" → "NSA" are treated as the same.
- Headlines about different organisations or places are kept apart, even if they're worded alike.
- Template headlines with one per victim (law-firm breach notices, "X Ransomware Attack by Y" leak-site posts) are never grouped.
- Follow-up coverage about the same organisation within 3 days ("Apple restores services…") joins the main story.

`CLUSTER_SIMILARITY` (default 0.3) controls how similar headlines must be to group. Higher is stricter.

## Measured internet outages

Purple pins on the map are internet outages **measured** by network monitoring, not taken from headlines:

- **IODA** (Georgia Tech) detects country-level disruptions from internet routing (BGP), active probing and background "darknet" traffic. It needs no setup.
- **Cloudflare Radar** lists confirmed outages with a cause (power outage, cable cut, government shutdown, …) and the networks affected. It needs a free API token:
  1. Sign in at dash.cloudflare.com (a free account is fine) and go to **My Profile → API Tokens → Create Token → Create Custom Token**.
  2. Add the permission **Account → Radar → Read**, then create the token and copy it.
  3. In Azure, go to your Web App → **Settings → Environment variables**, add `CLOUDFLARE_API_TOKEN` with the token as its value, and save. The app restarts.

  To run locally instead:
  ```bash
  CLOUDFLARE_API_TOKEN=your-token npm start
  ```

Without a token, Cloudflare Radar shows as "off" in the map's Sources list and everything else works. `INTERNET_LOOKBACK_HOURS` (default 72) sets how far back to look.

## Healthcare tab

Open **🏥 Healthcare**, or go to `/#health`. It refreshes hourly:

- **Ransomware leak-site posts** (ransomware.live): healthcare organisations that ransomware gangs claim to have attacked, usually days before the news. Victims in any sector that match your vendors are included and flagged. The side panel shows the most active groups.
- **HHS breach reports**: the newest 100 breaches affecting 500+ people from the HHS Office for Civil Rights portal, filterable by state. HHS publishes them about 4–6 weeks after they're reported.
- **Medical-device security advisories**: CISA's ICSMA advisories, read from CISA's official CSAF repository on GitHub. Re-issued advisories show their update date.
- **FDA**: Class I medical-device recalls (openFDA) and MedWatch safety alerts.
- **⚠ Vendor alerts**: when a vendor on your Services board (Healthcare, Network & Security, Data Center & IT Ops or Cloud) appears in any of these sources. Those Services cards also show the alert.

`HEALTHCARE_DAYS` (default 90) sets the look-back. The HHS portal has no data feed, so the site opens its "View HIPAA Breach Reports" page the same way a browser does. If HHS changes the page, that source shows as failed under **Sources** and the rest keeps working.

## Vulnerabilities tab

Open **🛡 Vulnerabilities**, or go to `/#vulns`. It shows:

- **Confirmed exploited:** vulnerabilities on CISA's Known Exploited Vulnerabilities (KEV) list, added in the last 7, 30 or 90 days. Each shows its **CVSS** severity score and **EPSS** score (the estimated chance it will be exploited in the next 30 days), both from NVD and FIRST.org. It also shows whether the vulnerability is linked to ransomware, CISA's patch deadline for U.S. federal agencies, and links to the vendor advisories.
- **Not yet exploited:** newly published vulnerabilities at **Critical 9+** (last 14 days) or **High 7+** (last 7 days), as an early warning. Brand-new CVEs often only have the vendor's own score for the first days (marked *), so the newest 7 days are scanned in full rather than relying on NVD's severity filter. Each also shows CISA's early assessment of exploitation (none / proof-of-concept / exploited) and its EPSS score. Use **All / Exploited / Not yet** to choose what to show.
- **Your vendors:** a filter based on the vendors in the Services tab. Change it with **⚙ Edit list**; the list is saved in your browser. **By vendor** in the side panel shows counts; click one to filter.

Services cards show "⚠ N exploited vulnerabilities (30d)" for their vendor and link to this tab.

The data refreshes every hour (`VULN_REFRESH_MINUTES`). `KEV_DAYS` (default 90, max 120), `NVD_CRITICAL_DAYS` (default 14) and `NVD_FRESH_DAYS` (default 7) control the look-back. NVD limits requests without an API key. A free key from nvd.nist.gov/developers set as `NVD_API_KEY` is optional; the site works without one.

## Services tab

Open the **📊 Services** tab, or go to `/#services`, for a health board covering about 60 services: Apple, Microsoft 365, Google, Meta, AWS, Azure, Google Cloud, major US banks and payment apps, healthcare vendors (EHR, PACS and imaging, clinical systems, payers, pharmacy and claims), network and security vendors (Infoblox, F5, Cisco, Palo Alto, Fortinet, Zscaler, Okta…), data center and IT ops vendors (VMware, Rubrik, Veeam, Nutanix, ServiceNow…), carriers and ISPs, streaming and gaming services. Each service card combines:

- **Official status** where it can be read automatically: Apple System Status, the Azure status feed, AWS Health, Google Cloud and Workspace dashboards, Slack, and Statuspage sites (GitHub, Cloudflare, Zoom, Discord, OpenAI, Coinbase, Robinhood, Square, Epic Games, Roblox, …).
- **News signals**: recent outage stories that mention the service, and any Downdetector report counts quoted in them ("Downdetector shows 12,000 reports").
- Links to the official status page, Downdetector and the ThousandEyes outage map.

Cards also show a 🛡 count of **security news** from the last 7 days (vulnerabilities, exploits, breaches). It's listed when you open the card and doesn't change the outage status, unless the story says the service itself is down. Planned maintenance and security advisories on official status pages don't count as problems either.

A service turns **Major outage** when its official page says so, or when there are 3 or more outage stories in 6 hours or 5,000 or more Downdetector reports. It shows **Issues reported** for smaller signals. Services with no official feed and no news show **No reports**.

Most healthcare vendors (Epic, Oracle Health, Fujifilm, Change Healthcare, …) only publish status to customers behind a login, so their cards rely on news coverage. If your organization has access to a vendor's status feed or API, add it as an official source in `lib/services.js`. A **Hospitals & health systems** feed in the side panel tracks cyberattacks, EHR/IT outages and ambulance diversions.

Downdetector and ThousandEyes don't offer free public APIs, and Downdetector blocks scraping. So this tab uses news coverage that cites them, plus links to their live pages. If you have a paid Downdetector Enterprise or ThousandEyes API account, add it as an `OFFICIAL` source type in `lib/services.js`.

`GET /api/services` returns the board as JSON. To add a service, add a row to `CATALOG` in `lib/services.js`.

## Adding sources

- An RSS or Atom feed: add `{ name, url }` to `NEWS_FEEDS`.
- A Statuspage status page (any site with `/api/v2/summary.json`): add `{ name, base }` to `STATUS_PAGES`.
- More places: add rows to `lib/gazetteer.js`.

## Limitations

Location is inferred from headline text, so it's approximate. It is usually the country or city named in the story, which may be the company's home rather than where users were affected. Keyword classification will sometimes misfire.

## Versioning

The footer shows the version and release date from `package.json`, plus when the server last started. On Azure, that's your last deploy or restart. To release a new version, update `"version"` and `"releaseDate"` in `package.json` and add an entry to `lib/changelog.js` before deploying. `GET /api/version` returns the same information as JSON.

Click the version number in the footer to see the version history. It lives in `lib/changelog.js`: add each new release at the top of that file.
