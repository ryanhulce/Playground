// Front end: loads /api/incidents and plots them on a Leaflet map.
const COLORS = { hack: '#f0506e', outage: '#f5a524', internet: '#a371f7' };
const TYPE_LABEL = { hack: 'hack', outage: 'outage', internet: 'internet' };
const AUTO_REFRESH_MS = 5 * 60 * 1000;

const map = L.map('map', { worldCopyJump: true, minZoom: 2 }).setView([25, 10], 2);
// Keyless OpenStreetMap tiles. "Dark" is the same tiles inverted via CSS (see .dark-tiles).
const OSM_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const OSM_ATTR = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';
const basemaps = {
  Dark: L.tileLayer(OSM_URL, { attribution: OSM_ATTR, maxZoom: 19, className: 'dark-tiles' }),
  Light: L.tileLayer(OSM_URL, { attribution: OSM_ATTR, maxZoom: 19 }),
};
const savedBase = localStorage.getItem('basemap');
(basemaps[savedBase] || basemaps.Dark).addTo(map);
L.control.layers(basemaps, null, { position: 'topright' }).addTo(map);
map.on('baselayerchange', (e) => localStorage.setItem('basemap', e.name));
const layer = L.layerGroup().addTo(map);

const ui = {
  list: document.getElementById('list'),
  listCount: document.getElementById('list-count'),
  updated: document.getElementById('updated'),
  sources: document.getElementById('sources'),
  range: document.getElementById('range'),
  search: document.getElementById('search'),
  refresh: document.getElementById('refresh'),
};
let data = { items: [], sources: [] };
let typeFilter = 'all';
const expanded = new Set(); // incidents whose source list is open
const markersByPlace = new Map();

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function ago(iso) {
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function filtered() {
  const hours = +ui.range.value;
  const cutoff = Date.now() - hours * 3600e3;
  const q = ui.search.value.trim().toLowerCase();
  return data.items.filter((it) =>
    (typeFilter === 'all' || it.type === typeFilter) &&
    new Date(it.lastUpdate || it.published) >= cutoff && // any report within the period
    (!q || `${it.title} ${it.summary} ${it.source} ${it.locations.map((l) => l.name).join(' ')} ${(it.sources || []).map((s) => `${s.title} ${s.source}`).join(' ')}`.toLowerCase().includes(q)));
}

// ---- map view filter: when zoomed in, the list and counts only include what's in view ----
function viewState() {
  const b = map.getBounds();
  const active = b.getEast() - b.getWest() < 340; // the whole world isn't visible
  // Pins can sit on a wrapped copy of the world, so also test longitude ±360.
  const inView = (l) => [0, 360, -360].some((k) => b.contains([l.lat, l.lon + k]));
  return { active, inView };
}

function render() {
  const items = filtered();

  // ---- group by place ----
  const groups = new Map();
  for (const it of items) for (const loc of it.locations) {
    const key = `${loc.name}|${loc.lat}|${loc.lon}`;
    if (!groups.has(key)) groups.set(key, { loc, items: [] });
    groups.get(key).items.push(it);
  }

  layer.clearLayers();
  markersByPlace.clear();
  const sorted = [...groups.values()].sort((a, b) => b.items.length - a.items.length);
  for (const g of sorted.reverse()) { // biggest drawn last = on top
    // Colour by the most common report type at this place (ties: hack > internet > outage).
    const n = (t) => g.items.filter((i) => i.type === t).length;
    const dominant = ['hack', 'internet', 'outage'].reduce((best, t) => (n(t) > n(best) ? t : best), 'hack');
    const color = COLORS[dominant];
    const ongoing = g.items.some((i) => i.ongoing);
    const r = 6 + Math.sqrt(g.items.length) * 5;
    const opts = { radius: r, color, weight: ongoing ? 4 : 2, fillColor: color, fillOpacity: ongoing ? 0.5 : 0.35 };
    const popup = `<h3>${esc(g.loc.name)} · ${g.items.length} incident${g.items.length > 1 ? 's' : ''}</h3><ul>${
      g.items.map((i) => `<li><span class="tag ${i.type}">${TYPE_LABEL[i.type] || i.type}</span>${i.ongoing ? ' <span class="tag ongoing">ongoing</span>' : ''}${i.sources ? ` <span class="tag status">📰 ${i.sources.length}</span>` : ''} <a href="${esc(i.link)}" target="_blank" rel="noopener">${esc(i.title)}</a>
        ${i.origin === 'measured' && i.summary ? `<div class="item-meta">${esc(i.summary)}</div>` : ''}
        <div class="item-meta">${i.sources ? `${i.sourceCount} outlets · first ${ago(i.published)} · latest ${ago(i.lastUpdate)}` : `${esc(i.source)} · ${ago(i.published)}`}</div></li>`).join('')}</ul>`;
    const marker = L.circleMarker([g.loc.lat, g.loc.lon], opts).bindPopup(popup, { maxWidth: 360 }).addTo(layer);
    marker.bindTooltip(`${g.loc.name}: ${g.items.length}`, { direction: 'top' });
    markersByPlace.set(g.loc.name, marker);
  }

  renderList(items);
}

// Sidebar list + header counts. Called on every map move, so it doesn't touch the pins.
function renderList(items = filtered()) {
  const view = viewState();
  const inView = (it) => it.locations.some(view.inView);
  const visible = view.active ? items.filter(inView) : items;
  const hiddenGlobal = view.active ? items.filter((i) => !i.locations.length).length : 0;

  // ---- stats (for the current view) ----
  const places = new Set(visible.flatMap((i) => i.locations.filter((l) => !view.active || view.inView(l)).map((l) => l.name)));
  document.getElementById('stat-hack').textContent = visible.filter((i) => i.type === 'hack').length;
  document.getElementById('stat-outage').textContent = visible.filter((i) => i.type === 'outage').length;
  document.getElementById('stat-internet').textContent = visible.filter((i) => i.type === 'internet').length;
  document.getElementById('stat-places').textContent = places.size;

  // ---- list ----
  const located = visible.filter((i) => i.locations.length);
  const unlocated = visible.filter((i) => !i.locations.length);
  ui.listCount.innerHTML = view.active
    ? `Showing ${visible.length} in map view <button id="reset-view" class="reset-view" title="Zoom out to the whole world">🌍 Reset</button>`
    : `${items.length} reports · ${located.length} mapped`;
  const row = (it) => `<li class="${it.type}" data-id="${it.id}">
      <div class="item-title">${esc(it.title)}</div>
      <div class="item-meta">
        <span class="tag ${it.type}">${TYPE_LABEL[it.type] || it.type}</span>
        ${it.ongoing ? '<span class="tag ongoing">ongoing</span>' : ''}
        ${it.origin === 'status' ? '<span class="tag status">status page</span>' : ''}
        ${it.origin === 'measured' ? '<span class="tag status">measured</span>' : ''}
        ${it.sources ? `<button class="tag srcs" data-toggle="${it.id}" title="Show all ${it.sources.length} headlines">📰 ${it.sources.length} headlines · ${it.sourceCount} outlets ${expanded.has(it.id) ? '▴' : '▾'}</button>
          <span>first ${ago(it.published)} · latest ${ago(it.lastUpdate)}</span>` : `<span>${esc(it.source)}</span><span>${ago(it.published)}</span>`}
        ${it.locations.length ? `<span>📍 ${esc(it.locations.map((l) => l.name).join(', '))}</span>` : it.region ? `<span>📍 ${esc(it.region)}</span>` : ''}
      </div>
      ${it.sources && expanded.has(it.id) ? `<ul class="src-headlines">${it.sources.map((s) => `<li><a href="${esc(s.link)}" target="_blank" rel="noopener">${esc(s.title)}</a> <span class="muted">· ${esc(s.source)} · ${ago(s.published)}</span></li>`).join('')}</ul>` : ''}
    </li>`;
  const scroll = ui.list.scrollTop;
  ui.list.innerHTML =
    ((located.length ? `<li class="section">${view.active ? 'In this area' : 'On the map'}</li>${located.map(row).join('')}` : '') +
    (unlocated.length ? `<li class="section">Global / location unknown</li>${unlocated.map(row).join('')}` : '') ||
    `<li class="section">${!data.updatedAt ? 'Fetching sources… first load can take ~15s' : view.active ? 'Nothing reported in this area. Zoom out or pan to see more.' : 'Nothing matches these filters'}</li>`) +
    (hiddenGlobal ? `<li class="section note">${hiddenGlobal} stor${hiddenGlobal === 1 ? 'y' : 'ies'} without a location hidden while zoomed in</li>` : '');
  ui.list.scrollTop = scroll;

  ui.sources.innerHTML = data.sources
    .slice().sort((a, b) => a.ok - b.ok || a.name.localeCompare(b.name))
    .map((s) => `<li><span>${esc(s.name)}</span><span class="${s.ok || s.notConfigured ? 'muted' : 'bad'}" title="${esc(s.error || '')}">${s.ok ? `${s.count} hits` : s.notConfigured ? 'off (no API token)' : 'failed'}</span></li>`)
    .join('');
  ui.updated.textContent = data.updatedAt ? `updated ${ago(data.updatedAt)}` : '';
}

ui.list.addEventListener('click', (e) => {
  const tog = e.target.closest('[data-toggle]');
  if (tog) { expanded.has(tog.dataset.toggle) ? expanded.delete(tog.dataset.toggle) : expanded.add(tog.dataset.toggle); renderList(); return; }
  if (e.target.closest('.src-headlines a')) return; // let headline links open normally
  const li = e.target.closest('li[data-id]');
  if (!li) return;
  const it = data.items.find((i) => i.id === li.dataset.id);
  if (!it) return;
  if (!it.locations.length) return window.open(it.link, '_blank', 'noopener');
  const loc = it.locations[0];
  map.flyTo([loc.lat, loc.lon], Math.max(map.getZoom(), loc.kind === 'city' ? 6 : 4), { duration: 0.8 });
  setTimeout(() => markersByPlace.get(loc.name)?.openPopup(), 850);
});

document.getElementById('type-filter').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  typeFilter = b.dataset.type;
  document.querySelectorAll('#type-filter button').forEach((x) => x.classList.toggle('on', x === b));
  render();
});
ui.range.addEventListener('change', render);
map.on('moveend', () => renderList());
const WORLD_VIEW = { center: [25, 10], zoom: 2 };
document.querySelector('.list-head').addEventListener('click', (e) => {
  if (e.target.closest('#reset-view')) map.flyTo(WORLD_VIEW.center, WORLD_VIEW.zoom, { duration: 0.6 });
});
ui.search.addEventListener('input', render);

async function load() {
  try {
    const res = await fetch('/api/incidents');
    data = await res.json();
    render();
    if (!data.updatedAt) setTimeout(load, 3000); // server still doing first crawl
  } catch (err) {
    ui.listCount.textContent = `Could not reach server: ${err.message}`;
  }
}
ui.refresh.addEventListener('click', async () => {
  ui.refresh.classList.add('spin');
  try { await fetch('/api/refresh', { method: 'POST' }); await load(); }
  finally { ui.refresh.classList.remove('spin'); }
});

load();
setInterval(load, AUTO_REFRESH_MS);
setInterval(() => { if (data.updatedAt) ui.updated.textContent = `updated ${ago(data.updatedAt)}`; }, 30e3);
