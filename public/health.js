// "Healthcare" tab: ransomware leak-site posts, HHS breach reports, medical-device advisories, FDA.
(() => {
  const el = (id) => document.getElementById(id);
  const ui = { main: el('hc-main'), summary: el('hc-summary'), state: el('hc-state'), us: el('hc-us'), mine: el('hc-mine'), search: el('hc-search') };
  let hd = null;
  let rwDays = +(localStorage.getItem('hcRwDays') || 7);
  const showAll = new Set();

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toDate = (d) => new Date(String(d).length === 10 ? `${d}T12:00:00Z` : d);
  const daysAgo = (d) => Math.floor((Date.now() - toDate(d)) / 864e5);
  const ago = (d) => { const s = (Date.now() - toDate(d)) / 1000; return s < 3600 ? `${Math.max(1, Math.round(s / 60))}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`; };
  const fmtDate = (d) => toDate(d).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  const num = (n) => Number(n || 0).toLocaleString();
  const compact = (n) => Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(n || 0);
  const vendorBadge = (v) => (v ? `<span class="vb vendor" title="Matches a vendor on your Services board">⚠ Your vendor: ${esc(v.name)}</span>` : '');
  const cvss = (s) => (s == null ? '' : `<span class="vb ${s >= 9 ? 'crit' : s >= 7 ? 'high' : s >= 4 ? 'med' : 'low'}">CVSS ${Number(s).toFixed(1)}</span>`);

  function matches(text, vendor) {
    const q = ui.search.value.trim().toLowerCase();
    if (ui.mine.checked && !vendor) return false;
    return !q || text.toLowerCase().includes(q);
  }
  function limited(key, rows, n = 12) {
    if (showAll.has(key) || rows.length <= n) return { rows, more: '' };
    return { rows: rows.slice(0, n), more: `<button class="more" data-more="${key}">Show all ${rows.length}</button>` };
  }

  function render() {
    if (!hd) return;
    if (!hd.updatedAt) {
      ui.main.innerHTML = `<p class="muted pad">${hd.error ? `Could not load healthcare data: ${esc(hd.error)}` : 'Loading healthcare data… the first load can take about 15 seconds.'}</p>`;
      return;
    }
    const state = ui.state.value;

    // ---- data, filtered ----
    const rw = hd.ransomware.filter((r) => daysAgo(r.discovered) < rwDays && (!ui.us.checked || r.country === 'US') &&
      matches(`${r.victim} ${r.domain || ''} ${r.group} ${r.description}`, r.vendor));
    const br = hd.breaches.filter((b) => (!state || b.state === state) && matches(`${b.entity} ${b.state} ${b.breachType}`, b.vendor));
    const adv = hd.deviceAdvisories.filter((a) => matches(`${a.title} ${a.vendorName} ${a.products.join(' ')} ${a.summary} ${a.cves.map((c) => c.cve).join(' ')}`, a.vendor));
    const rc = hd.recalls.filter((r) => matches(`${r.firm} ${r.product} ${r.reason}`, r.vendor));
    const fa = hd.fdaAlerts.filter((a) => matches(`${a.title} ${a.summary}`, a.vendor));

    // ---- summary ----
    const vendorHits = [...hd.ransomware.filter((r) => r.vendor && daysAgo(r.discovered) < 30), ...hd.breaches.filter((b) => b.vendor), ...hd.deviceAdvisories.filter((a) => a.vendor && daysAgo(a.updated) < 90), ...hd.recalls.filter((r) => r.vendor)];
    const people = br.reduce((s, b) => s + b.individuals, 0);
    ui.summary.innerHTML = `
      <span class="chip" title="Ransomware leak-site posts in the last ${rwDays} days"><i class="dot hack"></i>${rw.length} ransomware</span>
      <span class="chip" title="${num(people)} people affected"><i class="dot outage"></i>${br.length} breaches · ${compact(people)} people</span>
      <span class="chip" title="CISA medical-device advisories released or updated in the last 90 days"><i class="dot" style="background:var(--accent)"></i>${adv.filter((a) => daysAgo(a.updated) < 90).length} device advisories</span>
      <span class="chip" title="FDA Class I device recalls"><i class="dot" style="background:#d2a8ff"></i>${rc.length} recalls</span>
      ${vendorHits.length ? `<span class="chip vendor-chip" title="Your vendors appearing in these sources">⚠ ${vendorHits.length} vendor alert${vendorHits.length > 1 ? 's' : ''}</span>` : ''}`;

    // ---- sections ----
    const rwL = limited('rw', rw, 15);
    const brL = limited('br', br, 15);
    const advL = limited('adv', adv, 8);
    const rcL = limited('rc', rc, 8);
    const faL = limited('fa', fa, 8);
    ui.main.innerHTML = `
      <div class="hc-head"><h3 class="cat-title">Ransomware leak-site posts · healthcare & your vendors</h3>
        <select id="hc-rwdays">${[7, 30, 90].map((d) => `<option value="${d}" ${d === rwDays ? 'selected' : ''}>Last ${d} days</option>`).join('')}</select></div>
      ${rwL.rows.map((r) => `<div class="vrow ${r.vendor ? 'vendor-row' : ''}">
        <div class="vrow-head"><div class="vrow-main">
          <div class="vrow-title">${esc(r.victim)} ${r.domain && !r.victim.includes(r.domain) ? `<span class="muted small">${esc(r.domain)}</span>` : ''}</div>
          <div class="vrow-meta">posted ${ago(r.discovered)} · ${esc(r.country || '??')} · ${esc(r.sector || 'sector unknown')} · <a href="${esc(r.link)}" target="_blank" rel="noopener">details ↗</a></div>
          ${r.description ? `<div class="vrow-desc">${esc(r.description)}</div>` : ''}
        </div><div class="vrow-badges">${vendorBadge(r.vendor)}<span class="vb ransom" title="Ransomware group">${esc(r.group)}</span></div></div>
      </div>`).join('') || '<p class="muted pad">No matching posts in this period.</p>'}${rwL.more}

      <h3 class="cat-title">HHS breach reports · 500+ people${state ? ` · ${esc(state)}` : ''}</h3>
      <p class="muted small">Newest ${hd.breaches.length} reports. HHS publishes them about 4–6 weeks after they're submitted (latest: ${hd.breaches[0] ? fmtDate(hd.breaches[0].date) : '–'}). <a href="https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf" target="_blank" rel="noopener">HHS portal ↗</a></p>
      ${br.length ? `<table class="hc-table"><thead><tr><th>Organisation</th><th>State</th><th>Type</th><th class="r">People</th><th>Submitted</th><th>Breach</th><th>Where</th><th title="Business associate (vendor) involved">Vendor</th></tr></thead><tbody>
        ${brL.rows.map((b) => `<tr class="${b.vendor ? 'vendor-row' : ''}"><td>${esc(b.entity)} ${vendorBadge(b.vendor)}</td><td>${esc(b.state || '')}</td><td>${esc((b.entityType || '').replace('Healthcare ', ''))}</td>
          <td class="r">${num(b.individuals)}</td><td>${fmtDate(b.date)}</td><td>${esc(b.breachType || '')}</td><td>${esc(b.location || '')}</td><td>${b.businessAssociate ? 'Yes' : ''}</td></tr>`).join('')}
      </tbody></table>` : '<p class="muted pad">No matching breach reports.</p>'}${brL.more}

      <h3 class="cat-title">Medical-device security advisories · CISA</h3>
      ${advL.rows.map((a) => `<div class="vrow crit ${a.vendor ? 'vendor-row' : ''}">
        <div class="vrow-head"><div class="vrow-main">
          <div class="vrow-title"><span class="cve">${esc(a.id)}</span>${daysAgo(a.released) <= 14 ? '<span class="vb new">NEW</span>' : daysAgo(a.updated) <= 14 ? '<span class="vb upd">UPDATED</span>' : ''} ${esc(a.title)}</div>
          <div class="vrow-meta">${daysAgo(a.released) - daysAgo(a.updated) > 7 ? `updated ${fmtDate(a.updated)} · first released ${fmtDate(a.released)}` : `released ${fmtDate(a.released)}`} · ${a.cveCount} CVE${a.cveCount === 1 ? '' : 's'}${a.cves.length ? ` (${a.cves.slice(0, 3).map((c) => esc(c.cve)).join(', ')}${a.cveCount > 3 ? '…' : ''})` : ''} · <a href="${esc(a.link)}" target="_blank" rel="noopener">CISA advisory ↗</a></div>
          ${a.summary ? `<div class="vrow-desc">${esc(a.summary)}</div>` : ''}
        </div><div class="vrow-badges">${vendorBadge(a.vendor)}${cvss(a.maxCvss)}</div></div>
      </div>`).join('') || '<p class="muted pad">No matching advisories.</p>'}${advL.more}

      <h3 class="cat-title">FDA Class I device recalls · last ${hd.days} days</h3>
      ${rcL.rows.map((r) => `<div class="vrow fda ${r.vendor ? 'vendor-row' : ''}">
        <div class="vrow-head"><div class="vrow-main">
          <div class="vrow-title">${esc(r.firm)}: ${esc(r.product.split(/[,;.]/)[0].slice(0, 90))}</div>
          <div class="vrow-meta">reported ${fmtDate(r.date)} · ${r.products} product${r.products > 1 ? 's' : ''} · ${esc(r.status || '')} · <a href="${esc(r.link)}" target="_blank" rel="noopener">FDA enforcement report ↗</a></div>
          ${r.reason ? `<div class="vrow-desc">${esc(r.reason)}</div>` : ''}
        </div><div class="vrow-badges">${vendorBadge(r.vendor)}<span class="vb crit">Class I</span></div></div>
      </div>`).join('') || '<p class="muted pad">No matching recalls.</p>'}${rcL.more}

      <h3 class="cat-title">FDA MedWatch safety alerts</h3>
      <ul class="feed">${faL.rows.map((a) => `<li class="${a.vendor ? 'vendor-row' : ''}"><a href="${esc(a.link)}" target="_blank" rel="noopener">${esc(a.title)}</a> ${vendorBadge(a.vendor)}<div class="meta">${fmtDate(a.date)}</div></li>`).join('') || '<li class="muted">No matching alerts.</li>'}</ul>${faL.more}
      <p class="muted small pad">Checked ${ago(hd.updatedAt)}.</p>`;

    // ---- side panel ----
    const alerts = [
      ...hd.ransomware.filter((r) => r.vendor && daysAgo(r.discovered) < 30).map((r) => ({ date: r.discovered, v: r.vendor, text: `Listed by ransomware group ${r.group}: ${r.victim}`, link: r.link, icon: '🚨' })),
      ...hd.breaches.filter((b) => b.vendor).map((b) => ({ date: b.date, v: b.vendor, text: `HHS breach report: ${b.entity} (${num(b.individuals)} people)`, link: 'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf', icon: '📋' })),
      ...hd.deviceAdvisories.filter((a) => a.vendor && daysAgo(a.updated) < 90).map((a) => ({ date: a.updated, v: a.vendor, text: `CISA device advisory: ${a.title}`, link: a.link, icon: '🩺' })),
      ...hd.recalls.filter((r) => r.vendor).map((r) => ({ date: r.date, v: r.vendor, text: `FDA Class I recall: ${r.firm}`, link: r.link, icon: '⚠' })),
    ].sort((a, b) => toDate(b.date) - toDate(a.date));
    el('hc-vendors').innerHTML = alerts.map((a) => `<li><a href="${esc(a.link)}" target="_blank" rel="noopener">${a.icon} <b>${esc(a.v.name)}</b>: ${esc(a.text)}</a><div class="meta">${fmtDate(a.date)}</div></li>`).join('') ||
      '<li class="muted">None of your vendors appear right now.</li>';
    const groups = {};
    for (const r of hd.ransomware) if (r.healthcare && daysAgo(r.discovered) < 30) groups[r.group] = (groups[r.group] || 0) + 1;
    el('hc-groups').innerHTML = Object.entries(groups).sort((a, b) => b[1] - a[1]).slice(0, 10)
      .map(([g, n]) => `<li><span>${esc(g)}</span><span class="muted">${n}</span></li>`).join('') || '<li class="muted">None.</li>';
    el('hc-sources').innerHTML = hd.sources.map((s) => `<li><span>${esc(s.name)}</span><span class="${s.ok ? 'muted' : 'bad'}" title="${esc(s.error || '')}">${s.ok ? s.count : 'failed'}</span></li>`).join('');
  }

  function fillStates() {
    if (ui.state.options.length > 1) return;
    const states = [...new Set(hd.breaches.map((b) => b.state).filter(Boolean))].sort();
    for (const st of states) ui.state.add(new Option(st, st));
    const saved = localStorage.getItem('hcState');
    if (saved && states.includes(saved)) ui.state.value = saved;
  }

  async function load() {
    try {
      hd = await (await fetch('/api/healthcare')).json();
      if (hd.updatedAt) fillStates();
      render();
      if (!hd.updatedAt && !hd.error) setTimeout(load, 4000);
    } catch (err) {
      ui.main.innerHTML = `<p class="pad">Could not reach server: ${esc(err.message)}</p>`;
    }
  }

  // ---- events ----
  ui.us.checked = localStorage.getItem('hcUs') === '1';
  ui.state.addEventListener('change', () => { localStorage.setItem('hcState', ui.state.value); render(); });
  ui.us.addEventListener('change', () => { localStorage.setItem('hcUs', ui.us.checked ? '1' : '0'); render(); });
  ui.mine.addEventListener('change', render);
  ui.search.addEventListener('input', render);
  ui.main.addEventListener('change', (e) => {
    if (e.target.id === 'hc-rwdays') { rwDays = +e.target.value; localStorage.setItem('hcRwDays', rwDays); render(); }
  });
  ui.main.addEventListener('click', (e) => {
    const b = e.target.closest('[data-more]');
    if (b) { showAll.add(b.dataset.more); render(); }
  });

  // ---- tab handling ----
  let loaded = false;
  const onTab = (tab) => { if (tab === 'health') { if (!loaded) { loaded = true; load(); } else render(); } };
  window.addEventListener('tabshown', (e) => onTab(e.detail));
  if (location.hash.startsWith('#health')) onTab('health');
  setInterval(() => { if (loaded) load(); }, 15 * 60 * 1000);
})();
