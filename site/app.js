/**
 * Robot Security Radar — frontend logic.
 * Pure helpers exported for tests; DOM render for the browser.
 */

// ── Pure helpers (exported for bun tests) ───────────────────────────

export function computePatchLag(firstSeen, today) {
  var d = new Date(today);
  var fs = new Date(firstSeen);
  var ms = d - fs;
  var days = Math.floor(ms / 86400000);
  return days < 0 ? 0 : days;
}

export function isOpen(incident) {
  return incident.open === true;
}

export function filterByCategory(incidents, category) {
  return incidents.filter(function (i) {
    return i.category === category;
  });
}

export function severityLabel(sev) {
  if (!sev) return "";
  if (sev.source === "cvss") return sev.value;
  return sev.value + " (estimated)";
}

export function statusLabel(state) {
  var map = {
    disclosed: "Disclosed",
    unpatched: "Unpatched",
    patched: "Patched",
    exploited_in_wild: "Exploited in Wild",
    resolved: "Resolved",
  };
  return map[state] || state;
}

export function statusClass(state) {
  var map = {
    disclosed: "status-disclosed",
    unpatched: "status-unpatched",
    patched: "status-patched",
    exploited_in_wild: "status-exploited",
    resolved: "status-resolved",
  };
  return map[state] || "";
}

export function buildItemMap(items) {
  var m = {};
  for (var i = 0; i < items.length; i++) {
    m[items[i].id] = items[i];
  }
  return m;
}

// ── New pure helpers (issue #10) ────────────────────────────────────

/**
 * Sort severity score for ordering.
 * Returns a numeric key: positive CVSS floats, or estimated bands as coarser values.
 * Used internally by sortIncidents.
 */
function severitySortKey(sev) {
  if (!sev) return 0;
  if (sev.source === "cvss") {
    var n = parseFloat(sev.value);
    return isNaN(n) ? 0 : n;
  }
  var bandMap = { critical: 10, high: 8, medium: 5, low: 2 };
  return bandMap[sev.value] || 0;
}

/**
 * Whether severity is from CVSS (numeric, higher rank) vs estimated (band).
 * Used internally by sortIncidents.
 */
function isCvss(sev) {
  return sev && sev.source === "cvss";
}

/**
 * Sort incidents by the given mode.
 * Modes: "newest" (default), "severity", "patch-lag".
 * Severity: CVSS scores first (desc), then estimated bands (critical>high>medium>low),
 *   ties broken by most recent first_seen.
 * Patch lag: longest lag first.
 * Newest: most recent first_seen first.
 * Returns a new array (does not mutate).
 */
export function sortIncidents(incidents, mode) {
  var arr = incidents.slice();
  if (mode === "severity") {
    arr.sort(function (a, b) {
      var aCvss = isCvss(a.severity);
      var bCvss = isCvss(b.severity);
      if (aCvss && !bCvss) return -1;
      if (!aCvss && bCvss) return 1;
      var aKey = severitySortKey(a.severity);
      var bKey = severitySortKey(b.severity);
      if (aKey !== bKey) return bKey - aKey;
      return (b.first_seen > a.first_seen ? 1 : b.first_seen < a.first_seen ? -1 : 0);
    });
  } else if (mode === "patch-lag") {
    arr.sort(function (a, b) {
      return computePatchLag(b.first_seen, TODAY) - computePatchLag(a.first_seen, TODAY);
    });
  } else {
    arr.sort(function (a, b) {
      return (b.first_seen > a.first_seen ? 1 : b.first_seen < a.first_seen ? -1 : 0);
    });
  }
  return arr;
}

/**
 * Filter incidents by chip selection.
 * opts: { robot_classes: string[], statuses: string[], vendors: string[] }
 * Empty array for a group means "no filter on that group".
 * AND across groups, OR within group.
 * Returns a new array.
 */
export function filterIncidents(incidents, opts) {
  var classes = opts.robot_classes || [];
  var statuses = opts.statuses || [];
  var vendors = opts.vendors || [];

  return incidents.filter(function (inc) {
    if (classes.length > 0 && classes.indexOf(inc.robot_class) === -1) return false;
    if (statuses.length > 0 && statuses.indexOf(inc.status.state) === -1) return false;
    if (vendors.length > 0 && vendors.indexOf(inc.vendor) === -1) return false;
    return true;
  });
}

/**
 * Case-insensitive substring search across title, vendor, ai_summary, and item titles.
 * Returns matching incidents.
 * Returns a new array.
 */
export function searchIncidents(incidents, query, itemMap) {
  if (!query || !query.trim()) return incidents;
  var q = query.toLowerCase();
  return incidents.filter(function (inc) {
    if (inc.title && inc.title.toLowerCase().indexOf(q) !== -1) return true;
    if (inc.vendor && inc.vendor.toLowerCase().indexOf(q) !== -1) return true;
    if (inc.ai_summary && inc.ai_summary.toLowerCase().indexOf(q) !== -1) return true;
    var ids = inc.item_ids || [];
    for (var i = 0; i < ids.length; i++) {
      var item = itemMap[ids[i]];
      if (item && item.title && item.title.toLowerCase().indexOf(q) !== -1) return true;
    }
    return false;
  });
}

// ── DOM rendering ────────────────────────────────────────────────────

var DATA_URL = "data/radar.json";
var TODAY = new Date().toISOString().slice(0, 10);

function $(sel) {
  return document.querySelector(sel);
}

function esc(s) {
  var d = document.createElement("div");
  d.appendChild(document.createTextNode(s));
  return d.innerHTML;
}

function renderCounts(counts) {
  $("#count-incidents").textContent = counts.incidents;
  $("#count-unpatched").textContent = counts.unpatched;
  $("#count-lag").textContent = counts.max_patch_lag_days;
}

function renderAxisCards(counts, incidents) {
  var cats = { vuln: "VULNERABILITIES", attack: "ATTACKS IN THE WILD", safety: "PHYSICAL SAFETY" };
  var cls = { vuln: "cat-vuln", attack: "cat-attack", safety: "cat-safety" };
  var grid = $("#axis-cards");
  grid.innerHTML = "";
  var keys = ["vuln", "attack", "safety"];
  for (var k = 0; k < keys.length; k++) {
    var cat = keys[k];
    var n = incidents.filter(function (i) { return i.category === cat; }).length;
    var card = document.createElement("div");
    card.className = "axis-card " + cls[cat];
    card.innerHTML =
      '<h3 class="axis-label">' + esc(cats[cat]) + '</h3>' +
      '<div class="axis-count">' + n + '</div>' +
      '<div class="axis-meta">' + cat.toUpperCase() + ' · ' + n + ' incident' + (n !== 1 ? 's' : '') + '</div>';
    grid.appendChild(card);
  }
}

/**
 * Build status line text for a card based on status and open state.
 * Caveat semantics: unpatched/exploited → "UNPATCHED FOR N DAYS";
 *   patched/resolved → "FIXED · AS OF {as_of}"; disclosed → "DISCLOSED {first_seen}".
 */
function buildStatusLine(inc) {
  var state = inc.status.state;
  if (state === "unpatched" || state === "exploited_in_wild") {
    var lag = computePatchLag(inc.first_seen, TODAY);
    return '<div class="patch-lag">UNPATCHED FOR ' + lag + ' DAYS</div>';
  }
  if (state === "patched" || state === "resolved") {
    var asOf = inc.status.as_of || "";
    return '<div class="patch-lag patch-fixed">FIXED · AS OF ' + esc(asOf) + '</div>';
  }
  if (state === "disclosed") {
    return '<div class="patch-lag patch-disclosed">DISCLOSED ' + esc(inc.first_seen) + '</div>';
  }
  return '';
}

function renderGrid(incidents, itemMap) {
  var grid = $("#incident-grid");
  grid.innerHTML = "";
  if (incidents.length === 0) {
    grid.innerHTML = '<p class="empty-msg">No incidents found.</p>';
    return;
  }
  for (var i = 0; i < incidents.length; i++) {
    var inc = incidents[i];
    var card = document.createElement("div");
    card.className = "incident-card";
    card.setAttribute("data-id", inc.id);

    var severity = severityLabel(inc.severity);
    var statusCls = statusClass(inc.status.state);
    var statusLine = buildStatusLine(inc);

    var aiBlock = inc.ai_summary
      ? '<div class="ai-note"><span class="ai-label">AI-GENERATED — verify with the linked source</span><p>' + esc(inc.ai_summary) + '</p></div>'
      : '';

    // Build detail link preserving active filters
    var detailHref = '?inc=' + encodeURIComponent(inc.id);
    var filterQs = buildFilterQueryString();
    if (filterQs) detailHref += '&' + filterQs;

    card.innerHTML =
      '<div class="card-header">' +
        '<a href="' + detailHref + '" class="card-id">' + esc(inc.id) + '</a>' +
        '<div class="card-badges">' +
          '<span class="badge badge-sev">' + esc(severity) + '</span>' +
          '<span class="badge ' + statusCls + '">' + esc(statusLabel(inc.status.state)) + '</span>' +
        '</div>' +
      '</div>' +
      '<h3 class="card-title"><a href="' + detailHref + '">' + esc(inc.title) + '</a></h3>' +
      '<div class="card-meta">' +
        '<span class="meta-vendor">' + esc(inc.vendor) + (inc.model ? ' · ' + esc(inc.model) : '') + '</span>' +
        '<span class="meta-class">' + esc(inc.robot_class) + '</span>' +
      '</div>' +
      statusLine +
      aiBlock;

    grid.appendChild(card);
  }
}

function renderDetail(inc, itemMap) {
  var html = '<div class="detail-view">';

  // Back link: preserve active filters
  var backHref = '?';
  var filterQs = buildFilterQueryString();
  if (filterQs) backHref += filterQs;
  html += '<a href="' + backHref + '" class="back-link">&larr; Back to all incidents</a>';
  html += '<h2 class="detail-title">' + esc(inc.title) + '</h2>';

  html += '<div class="detail-meta">';
  html += '<div class="detail-meta-item"><span class="meta-label">ID</span> ' + esc(inc.id) + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">Vendor</span> ' + esc(inc.vendor) + (inc.model ? ' · ' + esc(inc.model) : '') + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">Class</span> ' + esc(inc.robot_class) + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">Category</span> ' + esc(inc.category) + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">Severity</span> ' + esc(severityLabel(inc.severity)) + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">First seen</span> ' + esc(inc.first_seen) + '</div>';
  html += '<div class="detail-meta-item"><span class="meta-label">Last checked</span> ' + esc(inc.last_checked) + '</div>';
  html += '</div>';

  // Status block
  html += '<div class="detail-status">';
  html += '<span class="badge ' + statusClass(inc.status.state) + '">' + esc(statusLabel(inc.status.state)) + '</span>';
  if (inc.status.evidence_url) {
    html += ' <a href="' + esc(inc.status.evidence_url) + '" target="_blank" rel="noopener">Evidence &rarr;</a>';
  }
  if (inc.status.as_of) {
    html += ' <span class="meta-label">as of</span> ' + esc(inc.status.as_of);
  }
  if (inc.status.state === "unpatched") {
    html += '<div class="detail-caveat">No fix disclosed as of ' + esc(inc.status.as_of) + '</div>';
  }
  html += '</div>';

  // AI summary
  if (inc.ai_summary) {
    html += '<div class="ai-note"><span class="ai-label">AI-GENERATED — verify with the linked source</span><p>' + esc(inc.ai_summary) + '</p></div>';
  }

  // Item timeline
  html += '<h3 class="timeline-title">Items</h3>';
  html += '<ul class="timeline">';
  var ids = inc.item_ids || [];
  for (var j = 0; j < ids.length; j++) {
    var item = itemMap[ids[j]];
    if (!item) continue;
    html += '<li class="timeline-item">';
    html += '<a href="' + esc(item.url) + '" target="_blank" rel="noopener">' + esc(item.title) + '</a>';
    html += '<div class="timeline-meta">';
    html += '<span class="meta-label">Source:</span> ' + esc(item.source);
    html += ' · <span class="meta-label">Published:</span> ' + esc(item.published);
    html += '</div>';
    html += '</li>';
  }
  html += '</ul>';
  html += '</div>';

  return html;
}

function renderWire(wire) {
  var el = $("#wire-section");
  if (!wire || wire.length === 0) {
    el.style.display = "none";
    return;
  }
  el.style.display = "";
  var list = $("#wire-list");
  list.innerHTML = "";
  for (var i = 0; i < wire.length; i++) {
    var w = wire[i];
    var aiBlock = w.ai_summary
      ? '<div class="ai-note"><span class="ai-label">AI-GENERATED — verify with the linked source</span><p>' + esc(w.ai_summary) + '</p></div>'
      : '';
    var li = document.createElement("li");
    li.className = "wire-item";
    li.innerHTML =
      '<a href="' + esc(w.url) + '" target="_blank" rel="noopener">' + esc(w.title) + '</a>' +
      '<div class="wire-meta">' +
        '<span class="meta-label">Source:</span> ' + esc(w.source) +
        ' · <span class="meta-label">Published:</span> ' + esc(w.published) +
      '</div>' +
      aiBlock;
    list.appendChild(li);
  }
}

// ── Filter bar / sort / search state ────────────────────────────────

var _activeFilters = { robot_classes: [], statuses: [], vendors: [] };
var _activeSort = "newest";
var _searchQuery = "";

/**
 * Build a query string fragment from the current active filters and sort.
 * Used for URL persistence and back-link preservation.
 */
function buildFilterQueryString() {
  var parts = [];
  if (_activeFilters.robot_classes.length > 0) {
    parts.push('class=' + _activeFilters.robot_classes.map(encodeURIComponent).join(','));
  }
  if (_activeFilters.statuses.length > 0) {
    parts.push('status=' + _activeFilters.statuses.map(encodeURIComponent).join(','));
  }
  if (_activeFilters.vendors.length > 0) {
    parts.push('vendor=' + _activeFilters.vendors.map(encodeURIComponent).join(','));
  }
  if (_activeSort && _activeSort !== "newest") {
    parts.push('sort=' + encodeURIComponent(_activeSort));
  }
  if (_searchQuery) {
    parts.push('q=' + encodeURIComponent(_searchQuery));
  }
  return parts.join('&');
}

/**
 * Read filter/sort/search state from URL query params.
 */
function readQueryParams() {
  var params = new URLSearchParams(window.location.search);
  var cls = params.get("class");
  var st = params.get("status");
  var vr = params.get("vendor");
  var sort = params.get("sort");
  var q = params.get("q");

  if (cls) _activeFilters.robot_classes = cls.split(",").filter(Boolean);
  if (st) _activeFilters.statuses = st.split(",").filter(Boolean);
  if (vr) _activeFilters.vendors = decodeURIComponent(vr).split(",").filter(Boolean);
  if (sort === "newest" || sort === "severity" || sort === "patch-lag") {
    _activeSort = sort;
  }
  if (q) _searchQuery = decodeURIComponent(q);
}

/**
 * Push current filter/sort/search state to the URL without reload.
 */
function pushFilterState() {
  var qs = buildFilterQueryString();
  var base = window.location.pathname;
  window.history.replaceState(null, "", base + (qs ? '?' + qs : ''));
}

/**
 * Render the filter bar: chips for robot_class, status, vendor; sort buttons; search input.
 */
function renderFilterBar(incidents) {
  // Derive unique values from data
  var classSet = {};
  var statusSet = {};
  var vendorSet = {};
  for (var i = 0; i < incidents.length; i++) {
    var inc = incidents[i];
    if (inc.robot_class) classSet[inc.robot_class] = true;
    if (inc.status && inc.status.state) statusSet[inc.status.state] = true;
    if (inc.vendor) vendorSet[inc.vendor] = true;
  }
  var classes = Object.keys(classSet).sort();
  var statuses = Object.keys(statusSet).sort();
  var vendors = Object.keys(vendorSet).sort();

  // Robot class chips
  var classChips = $("#filter-chips-class");
  classChips.innerHTML = "";
  for (var c = 0; c < classes.length; c++) {
    var chip = document.createElement("button");
    chip.className = "filter-chip" + (_activeFilters.robot_classes.indexOf(classes[c]) !== -1 ? " active" : "");
    chip.setAttribute("data-group", "class");
    chip.setAttribute("data-value", classes[c]);
    chip.textContent = classes[c].toUpperCase();
    classChips.appendChild(chip);
  }

  // Status chips
  var statusChips = $("#filter-chips-status");
  statusChips.innerHTML = "";
  for (var s = 0; s < statuses.length; s++) {
    var chip = document.createElement("button");
    chip.className = "filter-chip" + (_activeFilters.statuses.indexOf(statuses[s]) !== -1 ? " active" : "");
    chip.setAttribute("data-group", "status");
    chip.setAttribute("data-value", statuses[s]);
    chip.textContent = statusLabel(statuses[s]).toUpperCase();
    statusChips.appendChild(chip);
  }

  // Vendor chips
  var vendorChips = $("#filter-chips-vendor");
  vendorChips.innerHTML = "";
  for (var v = 0; v < vendors.length; v++) {
    var chip = document.createElement("button");
    chip.className = "filter-chip" + (_activeFilters.vendors.indexOf(vendors[v]) !== -1 ? " active" : "");
    chip.setAttribute("data-group", "vendor");
    chip.setAttribute("data-value", vendors[v]);
    chip.textContent = vendors[v];
    vendorChips.appendChild(chip);
  }

  // Sort buttons
  var sortBtns = document.querySelectorAll(".sort-btn");
  for (var b = 0; b < sortBtns.length; b++) {
    if (sortBtns[b].getAttribute("data-sort") === _activeSort) {
      sortBtns[b].classList.add("active");
    } else {
      sortBtns[b].classList.remove("active");
    }
  }

  // Search input
  var searchInput = $("#search-input");
  if (searchInput) searchInput.value = _searchQuery;
}

/**
 * Apply current filters + sort + search and re-render the grid.
 */
function applyFiltersAndRender(itemMap) {
  var filtered = filterIncidents(_data.incidents, _activeFilters);
  if (_searchQuery) {
    filtered = searchIncidents(filtered, _searchQuery, itemMap);
  }
  var sorted = sortIncidents(filtered, _activeSort);
  renderGrid(sorted, itemMap);
}

// ── Init ─────────────────────────────────────────────────────────────

var _data = null;

async function init() {
  var resp = await fetch(DATA_URL);
  _data = await resp.json();
  var itemMap = buildItemMap(_data.items);

  var params = new URLSearchParams(window.location.search);
  var incId = params.get("inc");

  if (incId) {
    // Detail view
    $("#grid-section").style.display = "none";
    $("#axis-cards").style.display = "none";
    $("#filter-bar").style.display = "none";
    var found = null;
    for (var i = 0; i < _data.incidents.length; i++) {
      if (_data.incidents[i].id === incId) { found = _data.incidents[i]; break; }
    }
    if (found) {
      // Read filters for back-link preservation
      readQueryParams();
      $("#detail-section").innerHTML = renderDetail(found, itemMap);
      $("#detail-section").style.display = "";
    } else {
      $("#detail-section").innerHTML = '<p class="empty-msg">Incident not found. <a href="?">Back to all incidents</a></p>';
      $("#detail-section").style.display = "";
    }
  } else {
    // Grid view
    readQueryParams();
    renderCounts(_data.meta.counts);
    renderAxisCards(_data.meta.counts, _data.incidents);
    renderFilterBar(_data.incidents);
    applyFiltersAndRender(itemMap);
    renderWire(_data.wire);
    $("#detail-section").style.display = "none";

    // ── Event listeners ──────────────────────────────────────────────

    // Chip toggle (delegated on filter bar)
    var filterBar = $("#filter-bar");
    filterBar.addEventListener("click", function (e) {
      var chip = e.target.closest(".filter-chip");
      if (!chip) return;
      var group = chip.getAttribute("data-group");
      var value = chip.getAttribute("data-value");
      var arr;
      if (group === "class") arr = _activeFilters.robot_classes;
      else if (group === "status") arr = _activeFilters.statuses;
      else if (group === "vendor") arr = _activeFilters.vendors;
      else return;

      var idx = arr.indexOf(value);
      if (idx === -1) arr.push(value);
      else arr.splice(idx, 1);

      chip.classList.toggle("active");
      pushFilterState();
      applyFiltersAndRender(itemMap);
    });

    // Sort buttons (delegated on sort control)
    var sortControl = $("#sort-control");
    sortControl.addEventListener("click", function (e) {
      var btn = e.target.closest(".sort-btn");
      if (!btn) return;
      _activeSort = btn.getAttribute("data-sort");
      var allBtns = sortControl.querySelectorAll(".sort-btn");
      for (var b = 0; b < allBtns.length; b++) {
        allBtns[b].classList.toggle("active", allBtns[b] === btn);
      }
      pushFilterState();
      applyFiltersAndRender(itemMap);
    });

    // Search input with debounce
    var searchInput = $("#search-input");
    var debounceTimer = null;
    searchInput.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        _searchQuery = searchInput.value;
        pushFilterState();
        applyFiltersAndRender(itemMap);
      }, 150);
    });
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", init);
}
