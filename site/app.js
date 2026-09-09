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

function renderGrid(incidents, itemMap) {
  var grid = $("#incident-grid");
  grid.innerHTML = "";
  if (incidents.length === 0) {
    grid.innerHTML = '<p class="empty-msg">No incidents found.</p>';
    return;
  }
  for (var i = 0; i < incidents.length; i++) {
    var inc = incidents[i];
    var lag = computePatchLag(inc.first_seen, TODAY);
    var card = document.createElement("div");
    card.className = "incident-card";
    card.setAttribute("data-id", inc.id);

    var severity = severityLabel(inc.severity);
    var statusCls = statusClass(inc.status.state);
    var patchLine = inc.open
      ? '<div class="patch-lag">UNPATCHED FOR ' + lag + ' DAYS</div>'
      : '';

    var aiBlock = inc.ai_summary
      ? '<div class="ai-note"><span class="ai-label">AI-GENERATED — verify with the linked source</span><p>' + esc(inc.ai_summary) + '</p></div>'
      : '';

    card.innerHTML =
      '<div class="card-header">' +
        '<a href="?inc=' + encodeURIComponent(inc.id) + '" class="card-id">' + esc(inc.id) + '</a>' +
        '<div class="card-badges">' +
          '<span class="badge badge-sev">' + esc(severity) + '</span>' +
          '<span class="badge ' + statusCls + '">' + esc(statusLabel(inc.status.state)) + '</span>' +
        '</div>' +
      '</div>' +
      '<h3 class="card-title"><a href="?inc=' + encodeURIComponent(inc.id) + '">' + esc(inc.title) + '</a></h3>' +
      '<div class="card-meta">' +
        '<span class="meta-vendor">' + esc(inc.vendor) + (inc.model ? ' · ' + esc(inc.model) : '') + '</span>' +
        '<span class="meta-class">' + esc(inc.robot_class) + '</span>' +
      '</div>' +
      patchLine +
      aiBlock;

    grid.appendChild(card);
  }
}

function renderDetail(inc, itemMap) {
  var html = '<div class="detail-view">';

  html += '<a href="?" class="back-link">&larr; Back to all incidents</a>';
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
    var found = null;
    for (var i = 0; i < _data.incidents.length; i++) {
      if (_data.incidents[i].id === incId) { found = _data.incidents[i]; break; }
    }
    if (found) {
      $("#detail-section").innerHTML = renderDetail(found, itemMap);
      $("#detail-section").style.display = "";
    } else {
      $("#detail-section").innerHTML = '<p class="empty-msg">Incident not found. <a href="?">Back to all incidents</a></p>';
      $("#detail-section").style.display = "";
    }
  } else {
    // Grid view
    renderCounts(_data.meta.counts);
    renderAxisCards(_data.meta.counts, _data.incidents);
    renderGrid(_data.incidents, itemMap);
    renderWire(_data.wire);
    $("#detail-section").style.display = "none";
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", init);
}
