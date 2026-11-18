// "Vulnerabilities" tab: confirmed-exploited (CISA KEV) and new critical CVEs, filtered to your vendors.
(() => {
  const el = (id) => document.getElementById(id);
  const ui = {
    main: el('vuln-main'), summary: el('vuln-summary'), range: el('vuln-range'), ransom: el('vuln-ransom'),
    search: el('vuln-search'), byVendor: el('vuln-byvendor'), sources: el('vuln-sources'),
    panel: el('vuln-vendors'), vvList: el('vv-list'),
  };
  let vd = null;
  let scope = localStorage.getItem('vulnScope') || 'mine';
  let show = localStorage.getItem('vulnShow') || 'both';      // both | exploited | new
  const sevSel = el('vuln-sev');
  sevSel.value = localStorage.getItem('vulnSev') || '9';
  let vendorFilter = null; // from #vulns?vendor=key
  const open = new Set();
  const WL_KEY = 'vulnWatchlist';

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const daysAgo = (d) => Math.floor((Date.now() - new Date(d.length === 10 ? d + 'T12:00:00Z' : d)) / 864e5);
  const ago = (d) => { const n = daysAgo(d); return n <= 0 ? 'today' : n === 1 ? 'yesterday' : `${n}d ago`; };
  const fmtDate = (d) => new Date(d.length === 10 ? d + 'T12:00:00Z' : d).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });

  function watchlist() {
    try { const saved = JSON.parse(localStorage.getItem(WL_KEY)); if (Array.isArray(saved)) return new Set(saved); } catch {}
    return new Set((vd?.vendors || []).filter((v) => v.watch).map((v) => v.key));
  }
  const vendorName = (key) => vd?.vendors.find((v) => v.key === key)?.name || key;

  function cvssBadge(c) {
    if (!c) return '<span class="vb none" title="No CVSS score published yet">CVSS –</span>';
    const cls = c.score >= 9 ? 'crit' : c.score >= 7 ? 'high' : c.score >= 4 ? 'med' : 'low';
    const who = c.source === 'vendor' ? ' (vendor score: NVD has not analysed it yet)' : '';
    return `<span class="vb ${cls}" title="CVSS ${esc(c.version)} base score ${esc(c.severity || '')}${who}">CVSS ${c.score.toFixed(1)}${c.source === 'vendor' ? '*' : ''}</span>`;
  }
  function ssvcBadge(x) {
    if (!x) return '';
    const map = { active: ['crit', 'CISA: exploited'], poc: ['high', 'CISA: PoC'], none: ['low', 'CISA: none'] };
    const [cls, txt] = map[x.exploitation] || ['low', `CISA: ${x.exploitation}`];
    return `<span class="vb ${cls}" title="CISA's assessment: exploitation ${esc(x.exploitation)}${x.automatable ? `, automatable: ${esc(x.automatable)}` : ''}${x.impact ? `, technical impact: ${esc(x.impact)}` : ''}">${txt}</span>`;
  }
  function epssBadge(e) {
    if (!e) return '<span class="vb none" title="No EPSS score yet">EPSS –</span>';
    const pct = e.epss * 100;
    const cls = pct >= 10 ? 'crit' : pct >= 1 ? 'high' : 'low';
    const txt = pct >= 10 ? pct.toFixed(0) : pct >= 1 ? pct.toFixed(1) : pct.toFixed(2);
    return `<span class="vb ${cls}" title="EPSS: ${txt}% chance of exploitation in the next 30 days (higher than ${(e.percentile * 100).toFixed(0)}% of all CVEs)">EPSS ${txt}%</span>`;
  }

  function filtered() {
    const wl = watchlist();
    const days = +ui.range.value;
    const q = ui.search.value.trim().toLowerCase();
    const keep = (v) => (vendorFilter ? v.vendorKey === vendorFilter : scope === 'all' || wl.has(v.vendorKey)) &&
      (!q || `${v.cve} ${v.vendor} ${v.product || ''} ${v.name || ''} ${v.description}`.toLowerCase().includes(q));
    const exploited = vd.exploited.filter((v) => keep(v) && daysAgo(v.dateAdded) < days && (!ui.ransom.checked || v.ransomware));
    const minSev = +sevSel.value;
    const critical = ui.ransom.checked || show === 'exploited' ? [] : vd.newCritical.filter((v) => keep(v) && (v.cvss?.score || 0) >= minSev && daysAgo(v.published) < (minSev >= 9 ? vd.criticalDays : vd.freshDays || 7));
    return { exploited: show === 'new' ? [] : exploited, critical };
  }

  function row(v, kind) {
    const isOpen = open.has(v.cve);
    const isNew = kind === 'kev' && daysAgo(v.dateAdded) <= 3;
    const pastDue = kind === 'kev' && v.dueDate && daysAgo(v.dueDate) > 0;
    const title = kind === 'kev' ? v.name : v.description.split(/(?<=\.)\s/)[0].slice(0, 140);
    const meta = kind === 'kev'
      ? `${esc(v.vendor)} · ${esc(v.product)} · added ${ago(v.dateAdded)} · <span class="${pastDue ? 'due-past' : ''}" title="CISA's patch deadline for U.S. federal agencies">CISA deadline ${fmtDate(v.dueDate)}</span>`
      : `${esc(v.vendor)} · published ${ago(v.published)}`;
    return `<div class="vrow ${kind} ${isOpen ? 'open' : ''}" data-cve="${esc(v.cve)}">
      <div class="vrow-head">
        <div class="vrow-main">
          <div class="vrow-title"><span class="cve">${esc(v.cve)}</span>${isNew ? '<span class="vb new">NEW</span>' : ''} ${esc(title)}</div>
          <div class="vrow-meta">${meta}</div>
        </div>
        <div class="vrow-badges">${v.ransomware ? '<span class="vb ransom" title="Known to be used in ransomware campaigns">Ransomware</span>' : ''}${kind === 'crit' ? ssvcBadge(v.ssvc) : ''}${cvssBadge(v.cvss)}${epssBadge(v.epss)}</div>
      </div>
      ${isOpen ? `<div class="vrow-detail">
        <p>${esc(v.description)}</p>
        ${v.requiredAction ? `<p><b>Required action:</b> ${esc(v.requiredAction)}</p>` : ''}
        <div class="links">
          <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}" target="_blank" rel="noopener">NVD ↗</a>
          ${kind === 'kev' ? `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cve)}" target="_blank" rel="noopener">CISA KEV ↗</a>` : ''}
          ${(v.advisories || []).map((u, i) => `<a href="${esc(u)}" target="_blank" rel="noopener">${i === 0 ? 'Vendor advisory' : `Reference ${i + 1}`} ↗</a>`).join('')}
        </div>
      </div>` : ''}
    </div>`;
  }

  function render() {
    if (!vd) return;
    if (!vd.updatedAt) {
      ui.main.innerHTML = `<p class="muted pad">${vd.error ? `Could not load vulnerability data: ${esc(vd.error)}` : 'Loading vulnerability data… the first load can take about 15 seconds.'}</p>`;
      return;
    }
    const { exploited, critical } = filtered();
    const ransom = exploited.filter((v) => v.ransomware).length;
    const week = exploited.filter((v) => daysAgo(v.dateAdded) < 7).length;
    const days = +ui.range.value;
    ui.summary.innerHTML = `
      <span class="chip"><i class="dot hack"></i>${exploited.length} exploited</span>
      <span class="chip"><i class="dot outage"></i>${week} this week</span>
      <span class="chip"><i class="dot" style="background:#d2a8ff"></i>${ransom} ransomware</span>
      <span class="chip"><i class="dot" style="background:var(--accent)"></i>${critical.length} new ${+sevSel.value >= 9 ? 'critical' : 'high/critical'}</span>
      ${vendorFilter ? `<span class="chip vendor-chip">Vendor: ${esc(vendorName(vendorFilter))} <button id="vf-clear" title="Show all your vendors">×</button></span>` : ''}`;

    const scopeLabel = vendorFilter ? esc(vendorName(vendorFilter)) : scope === 'all' ? 'all vendors' : 'your vendors';
    const sevLabel = +sevSel.value >= 9 ? 'Critical' : 'High & critical';
    const newDays = +sevSel.value >= 9 ? vd.criticalDays : vd.freshDays || 7;
    ui.main.innerHTML = `
      ${show === 'new' ? '' : `<h3 class="cat-title">Confirmed exploited · CISA KEV · ${scopeLabel}</h3>
      ${exploited.length ? exploited.map((v) => row(v, 'kev')).join('') : `<p class="muted pad">No exploited vulnerabilities from ${scopeLabel} were added in the last ${days} days.</p>`}`}
      ${ui.ransom.checked || show === 'exploited' ? '' : `
      <h3 class="cat-title">${sevLabel}, not yet known to be exploited · last ${newDays} days · ${scopeLabel}</h3>
      <p class="muted small">Newly published vulnerabilities, including ones NVD hasn't analysed yet (score marked *, from the vendor). Watch EPSS and CISA's assessment: "PoC" or a rising EPSS means exploitation may be close.</p>
      ${critical.length ? critical.map((v) => row(v, 'crit')).join('') : `<p class="muted pad">No new ${sevLabel.toLowerCase()} vulnerabilities from ${scopeLabel}.</p>`}`}
      <p class="muted small pad">CISA catalog version ${esc(vd.kevCatalogVersion || '')} · checked ${ago(vd.updatedAt)}</p>`;

    // By-vendor counts (exploited, same period & ransomware filter, ignoring scope)
    const counts = {};
    for (const v of vd.exploited) {
      if (daysAgo(v.dateAdded) >= days || (ui.ransom.checked && !v.ransomware)) continue;
      const k = v.vendorKey || `other:${v.vendor}`;
      counts[k] = (counts[k] || 0) + 1;
    }
    const wl = watchlist();
    ui.byVendor.innerHTML = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 25).map(([k, n]) => {
      const known = !k.startsWith('other:');
      const name = known ? vendorName(k) : k.slice(6);
      return `<li class="${known ? 'clickable' : ''} ${vendorFilter === k ? 'on' : ''}" ${known ? `data-vendor="${esc(k)}"` : ''}>
        <span>${known && wl.has(k) ? '★ ' : ''}${esc(name)}</span><span class="muted">${n}</span></li>`;
    }).join('') || '<li class="muted">None in this period.</li>';
    ui.sources.innerHTML = vd.sources.map((s) => `<li><span>${esc(s.name)}</span><span class="${s.ok ? 'muted' : 'bad'}" title="${esc(s.error || '')}">${s.ok ? s.count : 'failed'}</span></li>`).join('');
  }

  function renderVendorPanel() {
    const wl = watchlist();
    ui.vvList.innerHTML = vd.vendors.slice().sort((a, b) => a.name.localeCompare(b.name)).map((v) =>
      `<label><input type="checkbox" value="${esc(v.key)}" ${wl.has(v.key) ? 'checked' : ''}/> ${esc(v.name)}</label>`).join('');
  }
  function saveWatchlist() {
    localStorage.setItem(WL_KEY, JSON.stringify([...ui.vvList.querySelectorAll('input:checked')].map((i) => i.value)));
    render();
  }

  async function load() {
    try {
      vd = await (await fetch('/api/vulns')).json();
      render();
      if (!vd.updatedAt && !vd.error) setTimeout(load, 4000);
    } catch (err) {
      ui.main.innerHTML = `<p class="pad">Could not reach server: ${esc(err.message)}</p>`;
    }
  }

  // ---- events ----
  ui.main.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    const r = e.target.closest('.vrow');
    if (!r) return;
    open.has(r.dataset.cve) ? open.delete(r.dataset.cve) : open.add(r.dataset.cve);
    render();
  });
  ui.summary.addEventListener('click', (e) => { if (e.target.id === 'vf-clear') location.hash = '#vulns'; });
  ui.byVendor.addEventListener('click', (e) => {
    const li = e.target.closest('li[data-vendor]');
    if (li) location.hash = vendorFilter === li.dataset.vendor ? '#vulns' : `#vulns?vendor=${encodeURIComponent(li.dataset.vendor)}`;
  });
  el('vuln-scope').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    scope = b.dataset.scope;
    localStorage.setItem('vulnScope', scope);
    document.querySelectorAll('#vuln-scope button').forEach((x) => x.classList.toggle('on', x === b));
    if (vendorFilter) location.hash = '#vulns'; else render();
  });
  document.querySelectorAll('#vuln-scope button').forEach((x) => x.classList.toggle('on', x.dataset.scope === scope));
  ui.range.addEventListener('change', render);
  el('vuln-show').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    show = b.dataset.show;
    localStorage.setItem('vulnShow', show);
    document.querySelectorAll('#vuln-show button').forEach((x) => x.classList.toggle('on', x === b));
    render();
  });
  document.querySelectorAll('#vuln-show button').forEach((x) => x.classList.toggle('on', x.dataset.show === show));
  sevSel.addEventListener('change', () => { localStorage.setItem('vulnSev', sevSel.value); render(); });
  ui.ransom.addEventListener('change', render);
  ui.search.addEventListener('input', render);
  el('vuln-edit').addEventListener('click', (e) => { e.stopPropagation(); if (!vd?.vendors?.length) return; renderVendorPanel(); ui.panel.hidden = !ui.panel.hidden; });
  el('vv-close').addEventListener('click', () => { ui.panel.hidden = true; });
  ui.vvList.addEventListener('change', saveWatchlist);
  el('vv-all').addEventListener('click', () => { ui.vvList.querySelectorAll('input').forEach((i) => { i.checked = true; }); saveWatchlist(); });
  el('vv-reset').addEventListener('click', () => { localStorage.removeItem(WL_KEY); renderVendorPanel(); render(); });
  document.addEventListener('click', (e) => { if (!ui.panel.hidden && !ui.panel.contains(e.target) && e.target.id !== 'vuln-edit') ui.panel.hidden = true; });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') ui.panel.hidden = true; });

  // ---- tab handling ----
  let loaded = false;
  function onTab(tab) {
    if (tab !== 'vulns') return;
    const m = location.hash.match(/vendor=([^&]+)/);
    vendorFilter = m ? decodeURIComponent(m[1]) : null;
    if (!loaded) { loaded = true; load(); } else render();
  }
  window.addEventListener('tabshown', (e) => onTab(e.detail));
  if (location.hash.startsWith('#vulns')) onTab('vulns'); // page opened directly on this tab
  setInterval(() => { if (loaded) load(); }, 15 * 60 * 1000);
})();
