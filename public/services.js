// "Services" tab: health board for major services (official status + news / Downdetector signals).
(() => {
  const LABEL = { ok: 'Operational', minor: 'Issues reported', major: 'Major outage' };
  const svc = {
    main: document.getElementById('svc-main'),
    summary: document.getElementById('svc-summary'),
    search: document.getElementById('svc-search'),
    cat: document.getElementById('svc-cat'),
    refresh: document.getElementById('svc-refresh'),
    sources: document.getElementById('svc-sources'),
  };
  let sdata = null;
  let onlyIssues = false;
  const open = new Set();

  const escH = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const agoS = (iso) => {
    if (!iso) return '';
    const s = (Date.now() - new Date(iso)) / 1000;
    if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };
  const fmt = (n) => (n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n));

  // Without an official feed, "ok" only means nobody is reporting problems.
  const hasOfficial = (s) => s.official && s.official.status !== 'unknown';
  const badge = (s) => (s.status === 'ok' && !hasOfficial(s) ? { cls: 'none', text: 'No reports' } : { cls: s.status, text: LABEL[s.status] });

  function subline(s) {
    const parts = [];
    if (s.official && s.official.status !== 'unknown') parts.push(`Official: ${s.official.label || LABEL[s.official.status] || s.official.status}`);
    else if (s.officialError) parts.push('Official status unavailable');
    else parts.push('No official status feed');
    if (s.news.count24h) parts.push(`${s.news.count24h} news report${s.news.count24h > 1 ? 's' : ''} (24h)`);
    if (s.news.ddReports) parts.push(`<span class="dd">~${fmt(s.news.ddReports)} Downdetector reports</span>`);
    if (s.vulns?.count) parts.push(`<a class="vuln-link" href="#vulns?vendor=${encodeURIComponent(s.vulns.vendorKey)}" title="Open in the Vulnerabilities tab">⚠ ${s.vulns.count} exploited vulnerabilit${s.vulns.count > 1 ? 'ies' : 'y'} (30d)${s.vulns.ransomware ? ', ransomware-linked' : ''}</a>`);
    if (s.vulns?.critical) parts.push(`<a class="crit-link" href="#vulns?vendor=${encodeURIComponent(s.vulns.vendorKey)}" title="Critical (CVSS 9+) vulnerabilities published in the last 14 days, not yet known to be exploited">🔴 ${s.vulns.critical} new critical vulnerabilit${s.vulns.critical > 1 ? 'ies' : 'y'}</a>`);
    if (s.health?.ransomware?.length) {
      const r = s.health.ransomware[0];
      parts.push(`<a class="vuln-link" href="#health" title="Open the Healthcare tab">🚨 Listed by ransomware gang ${escH(r.group)} (${new Date(r.discovered).toLocaleDateString([], { month: 'short', day: 'numeric' })})</a>`);
    }
    const hBits = [s.health?.advisories && `${s.health.advisories} device advisor${s.health.advisories > 1 ? 'ies' : 'y'}`, s.health?.recalls && `${s.health.recalls} Class I recall${s.health.recalls > 1 ? 's' : ''}`, s.health?.breaches && `${s.health.breaches} HHS breach report${s.health.breaches > 1 ? 's' : ''}`].filter(Boolean);
    if (hBits.length) parts.push(`<a class="health-link" href="#health" title="Open the Healthcare tab">🩺 ${hBits.join(', ')}</a>`);
    if (s.security?.count7d) parts.push(`<span class="sec">🛡 ${s.security.count7d} security stor${s.security.count7d > 1 ? 'ies' : 'y'} (7d)</span>`);
    return parts.join(' · ');
  }

  function detail(s) {
    const inc = s.official?.incidents || [];
    const arts = s.news.articles || [];
    return `<div class="card-detail">
      ${inc.length ? `<h4>Official incidents</h4><ul>${inc.map((i) => `<li><span class="badge ${i.impact === 'major' || i.impact === 'critical' ? 'major' : i.impact === 'advisory' || i.impact === 'maintenance' ? 'none' : 'minor'}">${escH(i.impact || 'issue')}</span>
        <a href="${escH(i.link)}" target="_blank" rel="noopener">${escH(i.title)}</a>
        ${i.since ? `<span class="muted"> · ${agoS(i.since)}</span>` : ''}
        ${i.detail ? `<div class="muted small">${escH(i.detail.slice(0, 240))}</div>` : ''}</li>`).join('')}</ul>` : ''}
      <h4>In the news (48h)</h4>
      ${arts.length ? `<ul>${arts.map((a) => `<li><a href="${escH(a.link)}" target="_blank" rel="noopener">${escH(a.title)}</a>
        <span class="muted"> · ${escH(a.source)} · ${agoS(a.published)}</span></li>`).join('')}</ul>` : '<p class="muted small">No outage reports in the news.</p>'}
      ${s.security?.articles?.length ? `<h4>Security news (7 days)</h4><ul>${s.security.articles.map((a) => `<li><a href="${escH(a.link)}" target="_blank" rel="noopener">${escH(a.title)}</a>
        <span class="muted"> · ${escH(a.source)} · ${agoS(a.published)}</span></li>`).join('')}</ul>` : ''}
      <div class="links">
        ${s.official?.page ? `<a href="${escH(s.official.page)}" target="_blank" rel="noopener">Official status page ↗</a>` : ''}
        ${s.links.downdetector ? `<a href="${escH(s.links.downdetector)}" target="_blank" rel="noopener" title="Find this service on Downdetector (opens a Google search limited to downdetector.com)">Downdetector ↗</a>` : ''}
        <a href="${escH(s.links.thousandeyes)}" target="_blank" rel="noopener">ThousandEyes ↗</a>
      </div>
    </div>`;
  }

  function renderServices() {
    if (!sdata) return;
    const q = svc.search.value.trim().toLowerCase();
    const cat = svc.cat.value;
    const inCat = (s) => !cat || (cat.endsWith(':') ? s.category.startsWith(cat) : s.category === cat);
    const list = sdata.services.filter((s) => inCat(s) && (!onlyIssues || s.status !== 'ok') && (!q || `${s.name} ${s.category}`.toLowerCase().includes(q)));
    const counts = { major: 0, minor: 0, ok: 0 };
    sdata.services.filter(inCat).forEach((s) => counts[s.status]++);
    svc.summary.innerHTML = `
      <span class="chip"><i class="dot hack"></i>${counts.major} major outage${counts.major === 1 ? '' : 's'}</span>
      <span class="chip"><i class="dot outage"></i>${counts.minor} with issues</span>
      <span class="chip"><i class="dot" style="background:var(--ok)"></i>${counts.ok} operational / no reports</span>
      <span class="chip muted">updated ${agoS(sdata.updatedAt)}</span>`;

    const order = { major: 0, minor: 1, ok: 2 };
    svc.main.innerHTML = sdata.categories.map((cat) => {
      const items = list.filter((s) => s.category === cat).sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name));
      if (!items.length) return '';
      return `<h3 class="cat-title">${escH(cat)}</h3><div class="grid">${items.map((s) => `
        <div class="card ${badge(s).cls}" data-id="${s.id}">
          <div class="card-head"><span class="card-name">${escH(s.name)}</span><span class="badge ${badge(s).cls}">${badge(s).text}</span></div>
          <div class="card-sub">${subline(s)}</div>
          ${open.has(s.id) ? detail(s) : ''}
        </div>`).join('')}</div>`;
    }).join('') || '<p class="muted pad">No services match.</p>';

    const feed = (items) => items.length
      ? items.map((a) => `<li><a href="${escH(a.link)}" target="_blank" rel="noopener">${escH(a.title)}</a><div class="meta">${escH(a.source)} · ${agoS(a.published)}</div></li>`).join('')
      : '<li class="muted">Nothing recent.</li>';
    document.getElementById('feed-hospitals').innerHTML = feed(sdata.feeds.hospitals || []);
    document.getElementById('feed-downdetector').innerHTML = feed(sdata.feeds.downdetector || []);
    document.getElementById('feed-thousandeyes').innerHTML = feed(sdata.feeds.thousandeyes || []);
    svc.sources.innerHTML = sdata.sources.slice().sort((a, b) => a.ok - b.ok || a.name.localeCompare(b.name))
      .map((s) => `<li><span>${escH(s.name)}</span><span class="${s.ok ? 'muted' : 'bad'}" title="${escH(s.error || '')}">${s.ok ? `${s.count}` : 'failed'}</span></li>`).join('');
  }

  async function loadServices() {
    try {
      const res = await fetch('/api/services');
      sdata = await res.json();
      if (!sdata.updatedAt) { setTimeout(loadServices, 3000); return; }
      if (svc.cat.options.length <= 2) {
        for (const c of sdata.categories) svc.cat.add(new Option(c, c));
        const saved = localStorage.getItem('svcCategory');
        if (saved && [...svc.cat.options].some((o) => o.value === saved)) svc.cat.value = saved;
      }
      renderServices();
    } catch (err) {
      svc.main.innerHTML = `<p class="pad">Could not reach server: ${escH(err.message)}</p>`;
    }
  }

  svc.main.addEventListener('click', (e) => {
    if (e.target.closest('a') || e.target.closest('.card-detail')) return;
    const card = e.target.closest('.card');
    if (!card) return;
    open.has(card.dataset.id) ? open.delete(card.dataset.id) : open.add(card.dataset.id);
    renderServices();
  });
  document.getElementById('svc-filter').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    onlyIssues = b.dataset.f === 'issues';
    document.querySelectorAll('#svc-filter button').forEach((x) => x.classList.toggle('on', x === b));
    renderServices();
  });
  svc.search.addEventListener('input', renderServices);
  svc.cat.addEventListener('change', () => { localStorage.setItem('svcCategory', svc.cat.value); renderServices(); });
  svc.refresh.addEventListener('click', async () => {
    svc.refresh.classList.add('spin');
    try { await fetch('/api/refresh', { method: 'POST' }); await loadServices(); }
    finally { svc.refresh.classList.remove('spin'); }
  });

  // ---- tab switching (#map / #services) ----
  let loaded = false;
  function showTab() {
    // #map, #services, #vulns (optionally #vulns?vendor=cisco)
    const tab = location.hash.startsWith('#services') ? 'services' : location.hash.startsWith('#vulns') ? 'vulns' : location.hash.startsWith('#health') ? 'health' : 'map';
    document.body.classList.toggle('tab-services', tab !== 'map'); // hides the map-only header controls
    document.getElementById('view-map').hidden = tab !== 'map';
    document.getElementById('view-services').hidden = tab !== 'services';
    document.getElementById('view-vulns').hidden = tab !== 'vulns';
    document.getElementById('view-health').hidden = tab !== 'health';
    document.querySelectorAll('.tabs a').forEach((a) => a.classList.toggle('on', a.dataset.tab === tab));
    if (tab === 'map') setTimeout(() => map.invalidateSize(), 0);
    if (tab === 'services' && !loaded) { loaded = true; loadServices(); }
    window.dispatchEvent(new CustomEvent('tabshown', { detail: tab }));
  }
  window.addEventListener('hashchange', showTab);
  showTab();
  setInterval(() => { if (loaded) loadServices(); }, 5 * 60 * 1000);
})();
