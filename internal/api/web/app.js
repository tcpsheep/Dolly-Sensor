"use strict";

/*
 * Dolly Sensor dashboard core. All network data is treated as untrusted text:
 * views build DOM nodes and use textContent, never interpolated HTML.
 */
(function () {
  const state = {
    status: null,
    route: null,
    token: 0,
    tickCount: 0,
    lastAutoRefresh: 0,
    refreshTimer: null,
    viewHooks: null,
    seenAlerts: new Set(),
    seenActions: new Map(),
    inspector: null,
    chartData: [],
    eventSource: null,
    liveState: "connecting",
    headerFailure: false,
    loaders: {},
  };

  const TITLES = {
    overview: ["Overview", "Traffic, evidence, and decisions at a glance"],
    protected: ["Protected IPs", "The only destinations this sensor defends"],
    destination: ["Destination", "Deep investigation of one protected IP"],
    intelligence: ["Intelligence", "Durable baselines, reputations, and trust evidence"],
    inspector: ["Inspector", "Recent sampled observations and decoded application context"],
    blocklist: ["Blocklist", "Deterministic source blocking with protected-space guardrails"],
    rules: ["Rules", "Standing and conditional policies evaluated on sampled traffic"],
    detection: ["Detection", "Live tuning of every rate, asymmetry, and signal weight"],
    mitigation: ["Mitigation", "Automated containment state and BGP action history"],
    settings: ["Settings", "Effective configuration and safety posture (read-only)"],
  };

  const ALERT_TYPES = {
    volumetric: "Volumetric attack",
    syn_flood: "Probable SYN flood",
    sweep: "Carpet bomb / subnet sweep",
    ttl_anomaly: "TTL anomaly",
    blocklist: "Blocklisted source",
    rule_trigger: "Rule triggered",
    test: "Delivery test",
  };

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key === "dataset") Object.assign(node.dataset, value);
        else if (key.startsWith("on") && typeof value === "function") {
          node.addEventListener(key.slice(2).toLowerCase(), value);
        } else if (key === "value") node.value = value;
        else if (key === "checked" || key === "disabled" || key === "selected") {
          node[key] = Boolean(value);
        } else {
          node.setAttribute(key, value === true ? "" : String(value));
        }
      }
    }
    append(node, children);
    return node;
  }

  function append(parent, children) {
    for (const child of children) {
      if (child === undefined || child === null || child === false) continue;
      if (Array.isArray(child)) append(parent, child);
      else if (child instanceof Node) parent.appendChild(child);
      else parent.appendChild(document.createTextNode(String(child)));
    }
  }

  function frag(...children) {
    const fragment = document.createDocumentFragment();
    append(fragment, children);
    return fragment;
  }

  function badge(label, variant) {
    return el("span", { class: "badge badge-" + (variant || "muted"), text: label == null || label === "" ? "—" : label });
  }

  function pill(label, variant) {
    return el("span", { class: "pill pill-" + (variant || "muted"), text: label });
  }

  function card(title, subtitle, body, actions) {
    const head = el("div", { class: "card-head" },
      el("div", {},
        el("div", { class: "card-title", text: title }),
        subtitle ? el("div", { class: "card-sub", text: subtitle }) : null,
      ),
      actions ? el("div", { class: "card-actions" }, actions) : null,
    );
    return el("section", { class: "card" }, head, el("div", { class: "card-body" }, body));
  }

  function kpi(label, value, sub, options) {
    const opts = options || {};
    const node = el("div", { class: "kpi" + (opts.variant ? " kpi-" + opts.variant : ""), id: opts.id },
      el("div", { class: "kpi-label", text: label }),
      el("div", { class: "kpi-value", id: opts.valueId, text: value == null ? "—" : value }),
      el("div", { class: "kpi-sub", id: opts.subId, text: sub || "" }),
    );
    return node;
  }

  function viewTop(lede, actions) {
    return el("div", { class: "view-top" },
      el("div", { class: "view-lede", text: lede || "" }),
      actions ? el("div", { class: "view-actions" }, actions) : null,
    );
  }

  function table(columns, rows, options) {
    const opts = options || {};
    const table = el("table", { class: "table" + (opts.compact ? " small-table" : "") });
    const headRow = el("tr");
    for (const column of columns) {
      const definition = typeof column === "string" ? { label: column } : column;
      headRow.appendChild(el("th", { class: definition.class, text: definition.label }));
    }
    const thead = el("thead", {}, headRow);
    const tbody = el("tbody");
    table.appendChild(thead);
    table.appendChild(tbody);
    if (!rows || rows.length === 0) {
      tbody.appendChild(el("tr", {}, el("td", {
        colspan: columns.length,
        class: "table-empty",
        text: opts.empty || "No data yet.",
      })));
    } else {
      for (const row of rows) {
        const definition = Array.isArray(row) ? { cells: row } : row;
        const tr = el("tr", {
          class: definition.onClick ? "clickable" : definition.class,
          title: definition.title,
          dataset: definition.dataset,
        });
        if (definition.draggable) tr.draggable = true;
        for (let i = 0; i < definition.cells.length; i++) {
          const cell = definition.cells[i];
          const column = typeof columns[i] === "string" ? {} : (columns[i] || {});
          const td = el("td", { class: column.class });
          if (cell instanceof Node) td.appendChild(cell);
          else td.textContent = cell === undefined || cell === null || cell === "" ? "—" : String(cell);
          tr.appendChild(td);
        }
        if (definition.onClick) {
          tr.tabIndex = 0;
          tr.addEventListener("click", definition.onClick);
          tr.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              definition.onClick(event);
            }
          });
        }
        tbody.appendChild(tr);
      }
    }
    return { table, tbody, thead };
  }

  function tableWrap(tableNode, extraClass) {
    return el("div", { class: "table-wrap" + (extraClass ? " " + extraClass : "") }, tableNode);
  }

  function kvList(pairs) {
    const grid = el("div", { class: "detail-grid" });
    for (const pair of pairs) {
      if (!pair) continue;
      const value = pair[1];
      const valueNode = el("div", { class: "kv-value" + (pair[2] === "plain" ? " plain" : "") });
      if (value instanceof Node) valueNode.appendChild(value);
      else valueNode.textContent = value === undefined || value === null || value === "" ? "—" : String(value);
      grid.appendChild(el("div", { class: "kv" },
        el("div", { class: "kv-label", text: pair[0] }),
        valueNode,
      ));
    }
    return grid;
  }

  function listRow(title, sub, side) {
    return el("li", { class: "list-row" },
      el("div", { class: "list-main" },
        el("div", { class: "list-title", text: title }),
        sub ? el("div", { class: "list-sub" }, sub) : null,
      ),
      side ? el("div", { class: "list-side" }, side) : null,
    );
  }

  function chips(values) {
    return el("div", { class: "chips" }, (values || []).map((value) => el("span", { class: "chip", text: value })));
  }

  function meterRows(items, maximum) {
    const max = maximum || Math.max(1, ...(items || []).map((item) => Number(item.count) || 0));
    const wrap = el("div");
    if (!items || items.length === 0) {
      wrap.appendChild(el("div", { class: "empty-state", text: "No distribution data yet." }));
      return wrap;
    }
    for (const item of items.slice(0, 10)) {
      const value = Number(item.count) || 0;
      wrap.appendChild(el("div", { class: "meter-row" },
        el("div", { class: "meter-label", text: item.name === undefined ? item.label : String(item.name), title: item.name === undefined ? item.label : String(item.name) }),
        el("progress", { class: "meter-progress", value: String(Math.max(0, value)), max: String(Math.max(1, max)), "aria-label": item.name === undefined ? item.label : String(item.name) }),
        el("div", { class: "meter-value", text: fmtInt(value) }),
      ));
    }
    return wrap;
  }

  function severityKind(severity) {
    if (severity === "critical") return "danger";
    if (severity === "warning") return "warn";
    return "info";
  }

  function threatKind(threat) {
    switch (threat) {
      case "under_attack": return "danger";
      case "anomalous": return "warn";
      case "learning": return "blue";
      case "clean": return "good";
      default: return "muted";
    }
  }

  function threatLabel(threat) {
    switch (threat) {
      case "under_attack": return "under attack";
      case "anomalous": return "anomalous";
      case "learning": return "learning";
      case "clean": return "clean";
      case "idle": return "idle";
      default: return threat || "unknown";
    }
  }

  function statusKind(status) {
    switch (status) {
      case "active": return "good";
      case "simulated": return "blue";
      case "announcing":
      case "withdrawing": return "warn";
      case "failed": return "danger";
      case "expired":
      case "withdrawn": return "muted";
      default: return "muted";
    }
  }

  function actionKind(kind) {
    return kind === "rtbh" ? "danger" : "blue";
  }

  function ruleStateKind(state) {
    switch (state) {
      case "enforcing": return "good";
      case "simulated": return "blue";
      case "bypassing": return "accent";
      case "pending":
      case "cooldown":
      case "watching": return "warn";
      case "error": return "danger";
      case "disabled": return "muted";
      default: return "muted";
    }
  }

  function ruleActionKind(type) {
    if (type === "discard") return "danger";
    if (type === "rate-limit") return "warn";
    return "accent";
  }

  function typeLabel(type) {
    return ALERT_TYPES[type] || String(type || "alert").replaceAll("_", " ");
  }

  function alertItem(alert, addActions) {
    const meta = [timeNode(alert.updated_at || alert.time), alert.layer ? "layer " + alert.layer : null];
    if (alert.occurrences > 1) meta.push("seen " + fmtInt(alert.occurrences) + "×");
    if (alert.score) meta.push("score " + fmtNumber(alert.score, 1));
    const item = el("div", { class: "alert-item" },
      el("div", { class: "alert-line" },
        el("div", { class: "flex wrap" },
          badge(alert.severity, severityKind(alert.severity)),
          alert.destination
            ? el("a", { class: "alert-dest", href: "#/destination/" + encodeURIComponent(alert.destination), text: alert.destination })
            : el("span", { class: "alert-dest", text: typeLabel(alert.type) }),
        ),
        el("div", { class: "small muted nowrap", text: typeLabel(alert.type) }),
      ),
      el("div", { class: "alert-reason", text: alert.reason || "No reason recorded." }),
      el("div", { class: "alert-meta" }, meta.filter(Boolean).map((part) => part instanceof Node ? part : el("span", { text: part }))),
      alert.action_summary ? el("div", { class: "alert-action", text: alert.action_summary }) : null,
      addActions ? el("div", { class: "inline-actions margin-top" }, addActions) : null,
    );
    return item;
  }

  function timeNode(value) {
    const full = formatDateTime(value);
    return el("span", { text: relativeTime(value), title: full });
  }

  async function apiGet(path) {
    const response = await fetch(path, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      credentials: "same-origin",
    });
    let body = null;
    try { body = await response.json(); } catch (_) { /* no body */ }
    if (!response.ok) {
      throw new Error((body && body.error) || ("request failed: HTTP " + response.status));
    }
    return body;
  }

  async function mutate(path, method, body) {
    const response = await fetch(path, {
      method: method || "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Dolly-Request": "1",
      },
      cache: "no-store",
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let payload = null;
    try { payload = await response.json(); } catch (_) { /* no body */ }
    if (!response.ok) {
      throw new Error((payload && payload.error) || ("request failed: HTTP " + response.status));
    }
    return payload;
  }

  function fmtNumber(value, digits) {
    if (value === undefined || value === null || !Number.isFinite(Number(value))) return "—";
    return Number(value).toLocaleString("en-US", {
      maximumFractionDigits: digits === undefined ? 1 : digits,
      minimumFractionDigits: 0,
    });
  }

  function fmtInt(value) {
    return fmtNumber(value, 0);
  }

  function fmtPercent(value, digits) {
    if (value === undefined || value === null || !Number.isFinite(Number(value))) return "—";
    return fmtNumber(value * 100, digits === undefined ? 1 : digits) + "%";
  }

  function fmtPPS(value) {
    const number = Number(value) || 0;
    if (number >= 1e9) return fmtNumber(number / 1e9, 2) + " Gpps";
    if (number >= 1e6) return fmtNumber(number / 1e6, 2) + " Mpps";
    if (number >= 1e3) return fmtNumber(number / 1e3, 1) + " kpps";
    return fmtNumber(number, 0) + " pps";
  }

  function fmtBPS(value) {
    const number = Number(value) || 0;
    if (number >= 1e12) return fmtNumber(number / 1e12, 2) + " Tbps";
    if (number >= 1e9) return fmtNumber(number / 1e9, 2) + " Gbps";
    if (number >= 1e6) return fmtNumber(number / 1e6, 2) + " Mbps";
    if (number >= 1e3) return fmtNumber(number / 1e3, 1) + " kbps";
    return fmtNumber(number, 0) + " bps";
  }

  function fmtBytes(value) {
    const number = Number(value) || 0;
    if (number >= 1e12) return fmtNumber(number / 1e12, 2) + " TB";
    if (number >= 1e9) return fmtNumber(number / 1e9, 2) + " GB";
    if (number >= 1e6) return fmtNumber(number / 1e6, 2) + " MB";
    if (number >= 1e3) return fmtNumber(number / 1e3, 1) + " KB";
    return fmtNumber(number, 0) + " B";
  }

  function fmtDuration(seconds) {
    const number = Number(seconds);
    if (!Number.isFinite(number) || number < 0) return "—";
    if (number < 1) return "<1s";
    if (number < 60) return fmtNumber(number, 0) + "s";
    if (number < 3600) return Math.floor(number / 60) + "m " + Math.floor(number % 60) + "s";
    if (number < 86400) return Math.floor(number / 3600) + "h " + Math.floor((number % 3600) / 60) + "m";
    return Math.floor(number / 86400) + "d " + Math.floor((number % 86400) / 3600) + "h";
  }

  function fmtClock(value) {
    const date = parseTimestamp(value);
    if (!date) return "—";
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function parseTimestamp(value) {
    if (!value) return null;
    const date = new Date(value);
    const time = date.getTime();
    if (!Number.isFinite(time) || time <= 0 || date.getUTCFullYear() < 2000) return null;
    return date;
  }

  function formatDateTime(value) {
    const date = parseTimestamp(value);
    return date ? date.toLocaleString() : "—";
  }

  function relativeTime(value) {
    const date = parseTimestamp(value);
    if (!date) return "never";
    const seconds = (Date.now() - date.getTime()) / 1000;
    if (Math.abs(seconds) < 5) return "just now";
    if (seconds >= 0) {
      if (seconds < 60) return Math.floor(seconds) + "s ago";
      if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
      if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
      return Math.floor(seconds / 86400) + "d ago";
    }
    const future = -seconds;
    if (future < 60) return "in " + Math.floor(future) + "s";
    if (future < 3600) return "in " + Math.floor(future / 60) + "m";
    return "in " + Math.floor(future / 3600) + "h";
  }

  function fmtWindow(from, to) {
    if (!from || !to) return "—";
    return relativeTime(from) + " → " + relativeTime(to);
  }

  function protocolLabel(protocol, fallback) {
    return fallback || protocol || "—";
  }

  function directionKind(direction) {
    if (direction === "inbound") return "blue";
    if (direction === "internal") return "purple";
    if (direction === "outbound") return "muted";
    return "muted";
  }

  function simBanner(status) {
    if (!status) return null;
    if (status.simulated) {
      return el("div", { class: "banner banner-warn" },
        el("strong", { text: "Simulation mode. " }),
        "BGP is disabled, so no network commands can leave this sensor. Mitigations are recorded as ",
        el("span", { class: "mono", text: "simulated" }),
        " with the same validation, expiry, and withdrawal lifecycle as real actions.",
      );
    }
    return el("div", { class: "banner banner-danger" },
      el("strong", { text: "BGP armed. " }),
      "This sensor can announce RTBH and Flowspec actions to its configured peer. Protected CIDRs and default-route guardrails still apply.",
    );
  }

  function button(label, options) {
    const opts = options || {};
    return el("button", {
      class: "button" + (opts.variant ? " button-" + opts.variant : "") + (opts.small ? " button-small" : ""),
      type: opts.type || "button",
      text: label,
      disabled: opts.disabled,
      onClick: opts.onClick,
      title: opts.title,
    });
  }

  function linkButton(label, onClick) {
    return el("button", { class: "link-button", type: "button", text: label, onClick });
  }

  function openDrawer(title, subtitle, body) {
    closeDrawer();
    const root = document.getElementById("drawer-root");
    const close = el("button", { class: "drawer-close", type: "button", "aria-label": "Close detail", text: "×", onClick: closeDrawer });
    const backdrop = el("div", { class: "drawer-backdrop", onClick: (event) => { if (event.target === backdrop) closeDrawer(); } },
      el("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": title },
        el("div", { class: "drawer-head" },
          el("div", { class: "grow" },
            el("div", { class: "drawer-title", text: title }),
            subtitle ? el("div", { class: "drawer-sub", text: subtitle }) : null,
          ),
          close,
        ),
        el("div", { class: "drawer-body" }, body),
      ),
    );
    root.replaceChildren(backdrop);
    document.body.classList.add("drawer-open");
    close.focus();
  }

  function closeDrawer() {
    const root = document.getElementById("drawer-root");
    if (!root) return;
    root.replaceChildren();
    document.body.classList.remove("drawer-open");
  }

  function drawerOpen() {
    const root = document.getElementById("drawer-root");
    return Boolean(root && root.childElementCount);
  }

  function toast(title, message, kind, timeout) {
    const container = document.getElementById("toasts");
    if (!container) return;
    while (container.childElementCount >= 4) container.firstElementChild.remove();
    const node = el("div", { class: "toast toast-" + (kind || "info"), role: "status" },
      el("div", { class: "toast-title", text: title }),
      message ? el("div", { class: "toast-message", text: message }) : null,
    );
    container.appendChild(node);
    const remove = () => {
      node.classList.add("toast-leaving");
      setTimeout(() => node.remove(), 170);
    };
    node.addEventListener("click", remove);
    setTimeout(remove, timeout || 6500);
  }

  function drawSeries(canvas, series, key, color, formatter) {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 5 || rect.height < 5) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(rect.width * dpr));
    canvas.height = Math.max(1, Math.floor(rect.height * dpr));
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);
    const points = (series || []).filter((point) => point && Number.isFinite(Number(point[key])));
    ctx.font = "10px " + getComputedStyle(document.documentElement).getPropertyValue("--mono");
    ctx.fillStyle = "#557385";
    if (points.length === 0) {
      ctx.fillText("No samples yet", 10, rect.height / 2);
      return;
    }
    const left = 2;
    const right = rect.width - 2;
    const top = 9;
    const bottom = rect.height - 17;
    const values = points.map((point) => Math.max(0, Number(point[key]) || 0));
    const max = Math.max(1, ...values);
    ctx.strokeStyle = "rgba(94, 143, 162, .16)";
    ctx.lineWidth = 1;
    for (let i = 0; i < 4; i++) {
      const y = top + (bottom - top) * i / 3;
      ctx.beginPath();
      ctx.moveTo(left, y + .5);
      ctx.lineTo(right, y + .5);
      ctx.stroke();
    }
    const step = points.length > 1 ? (right - left) / (points.length - 1) : 0;
    ctx.beginPath();
    for (let i = 0; i < values.length; i++) {
      const x = left + (values.length > 1 ? i * step : (right - left) / 2);
      const y = bottom - (values[i] / max) * (bottom - top);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.6;
    ctx.lineJoin = "round";
    ctx.stroke();
    ctx.lineTo(right, bottom);
    ctx.lineTo(left, bottom);
    ctx.closePath();
    ctx.globalAlpha = .10;
    ctx.fillStyle = color;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.fillStyle = "#6f8e9e";
    ctx.fillText(formatter ? formatter(max) : fmtInt(max), 5, 11);
    const start = points[0] && (points[0].at || points[0].At);
    const end = points[points.length - 1] && (points[points.length - 1].at || points[points.length - 1].At);
    if (start) ctx.fillText(formatDateTime(start), 5, rect.height - 4);
    if (end) {
      const label = formatDateTime(end);
      const width = ctx.measureText(label).width;
      ctx.fillText(label, Math.max(5, rect.width - width - 5), rect.height - 4);
    }
  }

  function chartPair(ppsId, bpsId, ppsColor, bpsColor) {
    return el("div", { class: "chart-wrap" },
      el("canvas", { id: ppsId, class: "chart" }),
      el("canvas", { id: bpsId, class: "chart" }),
    );
  }

  function drawPair(ppsCanvas, bpsCanvas, series) {
    drawSeries(ppsCanvas, series, series && series.length && series[0].PPS !== undefined ? "PPS" : "pps", "#4fd1b5", fmtPPS);
    drawSeries(bpsCanvas, series, series && series.length && series[0].BPS !== undefined ? "BPS" : "bps", "#65aef8", fmtBPS);
  }

  function parseHash() {
    let raw = location.hash.replace(/^#\/?/, "");
    let parts;
    try {
      parts = raw.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
    } catch (_) {
      return { name: "overview" };
    }
    if (parts.length === 0) return { name: "overview" };
    if (parts[0] === "destination") {
      return parts[1] ? { name: "destination", ip: parts[1] } : { name: "overview" };
    }
    if (TITLES[parts[0]] && parts[0] !== "destination") return { name: parts[0] };
    return { name: "overview" };
  }

  function setActiveNav(route) {
    const active = route.name === "destination" ? "protected" : route.name;
    for (const link of document.querySelectorAll(".nav-link")) {
      link.classList.toggle("active", link.dataset.route === active);
    }
  }

  function setPageHeading(route) {
    const title = TITLES[route.name] || TITLES.overview;
    const titleNode = document.getElementById("page-title");
    const subtitleNode = document.getElementById("page-subtitle");
    if (titleNode) titleNode.textContent = route.name === "destination" ? "Destination " + (route.ip || "") : title[0];
    if (subtitleNode) subtitleNode.textContent = title[1];
  }

  function renderPage(view) {
    const content = document.getElementById("content");
    content.replaceChildren(view);
  }

  function loadingView() {
    return el("div", { class: "loading-block" }, el("span", { class: "spinner" }), "Loading…");
  }

  function errorView(error) {
    return el("div", { class: "error-panel" },
      el("div", { class: "toast-title", text: "This view could not be loaded" }),
      el("div", { class: "toast-message", text: error && error.message ? error.message : String(error) }),
      el("div", { class: "margin-top" }, button("Retry", { variant: "primary", onClick: () => renderRoute({ silent: false }) })),
    );
  }

  function renderRoute(options) {
    const opts = options || {};
    const route = parseHash();
    state.route = route;
    state.viewHooks = null;
    state.lastAutoRefresh = 0;
    setActiveNav(route);
    setPageHeading(route);
    const token = ++state.token;
    if (!opts.silent) {
      renderPage(loadingView());
      window.scrollTo({ top: 0 });
    }
    const loader = state.loaders[route.name];
    if (!loader) {
      if (token === state.token) renderPage(errorView(new Error("view not implemented: " + route.name)));
      return;
    }
    Promise.resolve()
      .then(() => loader(route, token, Boolean(opts.silent)))
      .catch((error) => {
        if (token !== state.token) return;
        if (opts.silent) toast("Live refresh failed", error.message, "error");
        else renderPage(errorView(error));
      });
  }

  async function refreshCurrent() {
    if (!state.route) return;
    const route = parseHash();
    if (route.name !== state.route.name || route.ip !== state.route.ip) return;
    const token = ++state.token;
    const loader = state.loaders[route.name];
    if (!loader) return;
    try {
      await loader(route, token, true);
    } catch (error) {
      if (token === state.token) toast("Refresh failed", error.message, "error");
    }
  }

  function scheduleRefresh(delay) {
    if (state.refreshTimer) return;
    state.refreshTimer = setTimeout(() => {
      state.refreshTimer = null;
      if (!drawerOpen() && !document.hidden) refreshCurrent();
    }, delay || 700);
  }

  function applyHeader(status) {
    state.status = status;
    const simPill = document.getElementById("sim-pill");
    const bgpPill = document.getElementById("bgp-pill");
    const versionPill = document.getElementById("version-pill");
    if (simPill) {
      simPill.textContent = status.simulated ? "SIMULATION" : "BGP ARMED";
      simPill.className = "pill " + (status.simulated ? "pill-warn" : "pill-danger");
    }
    if (bgpPill) {
      if (!status.bgp) {
        bgpPill.textContent = "BGP disabled";
        bgpPill.className = "pill pill-muted";
      } else {
        const bgp = status.bgp;
        const stateText = bgp.state || (bgp.enabled ? "disconnected" : "disabled");
        bgpPill.textContent = "BGP " + stateText;
        let variant = "muted";
        if (bgp.state === "established") variant = "good";
        else if (bgp.enabled) variant = "warn";
        else if (bgp.state === "failed" || bgp.state === "error") variant = "danger";
        bgpPill.className = "pill pill-" + variant;
        bgpPill.title = bgp.last_error || ("peer " + (bgp.peer || "—"));
      }
    }
    if (versionPill) versionPill.textContent = "v" + (status.version || "—");
    if (state.route && state.route.name === "overview" && state.viewHooks && state.viewHooks.applyStatus) {
      state.viewHooks.applyStatus(status);
    }
  }

  async function refreshHeader() {
    try {
      const status = await apiGet("/api/status");
      state.headerFailure = false;
      applyHeader(status);
    } catch (error) {
      state.headerFailure = true;
      const bgpPill = document.getElementById("bgp-pill");
      if (bgpPill) {
        bgpPill.textContent = "sensor unreachable";
        bgpPill.className = "pill pill-danger";
      }
    }
  }

  function setLive(label, kind) {
    state.liveState = kind;
    const dot = document.getElementById("live-dot");
    const text = document.getElementById("live-label");
    if (dot) dot.className = "dot " + (kind === "live" ? "dot-live" : kind === "error" ? "dot-error" : "dot-idle");
    if (text) text.textContent = label;
  }

  function handleEvent(type, data) {
    if (type === "tick") {
      state.tickCount++;
      if (state.viewHooks && state.viewHooks.onTick) {
        try { state.viewHooks.onTick(data); } catch (_) { /* view hooks must never break the stream */ }
      }
      if (state.viewHooks && state.viewHooks.autoRefresh && !document.hidden && !drawerOpen()) {
        const interval = state.viewHooks.autoRefresh * 1000;
        if (Date.now() - state.lastAutoRefresh > interval) {
          state.lastAutoRefresh = Date.now();
          refreshCurrent();
        }
      }
      return;
    }
    if (type === "packet") {
      if (state.viewHooks && state.viewHooks.onPacket) {
        try { state.viewHooks.onPacket(data); } catch (_) { /* ignore */ }
      }
      return;
    }
    if (type === "alert") {
      if (state.viewHooks && state.viewHooks.onAlert) {
        try { state.viewHooks.onAlert(data); } catch (_) { /* ignore */ }
      }
      if (!state.seenAlerts.has(data.id)) {
        state.seenAlerts.add(data.id);
        if (state.seenAlerts.size > 600) state.seenAlerts.clear();
        toast(typeLabel(data.type), (data.destination || data.source || "") + (data.reason ? " — " + data.reason : ""), severityKind(data.severity), 8000);
        scheduleRefresh(700);
      }
      return;
    }
    if (type === "mitigation") {
      if (state.viewHooks && state.viewHooks.onMitigation) {
        try { state.viewHooks.onMitigation(data); } catch (_) { /* ignore */ }
      }
      const key = data.id + "|" + data.status;
      if (!state.seenActions.has(key)) {
        state.seenActions.set(key, Date.now());
        if (state.seenActions.size > 500) state.seenActions.clear();
        const kind = data.status === "failed" ? "error" : (data.status === "active" || data.status === "simulated") ? "good" : "info";
        toast("Mitigation " + data.status, summarizeAction(data), kind, 7000);
      }
      scheduleRefresh(700);
      return;
    }
    if (type === "blocklist") {
      if (state.viewHooks && state.viewHooks.onBlocklist) {
        try { state.viewHooks.onBlocklist(data); } catch (_) { /* ignore */ }
      }
      scheduleRefresh(500);
      return;
    }
    if (type === "trust") {
      if (state.viewHooks && state.viewHooks.onTrust) {
        try { state.viewHooks.onTrust(data); } catch (_) { /* ignore */ }
      }
      scheduleRefresh(500);
      return;
    }
    if (type === "rule" || type === "rules") {
      if (state.viewHooks && state.viewHooks.onRule) {
        try { state.viewHooks.onRule(type, data); } catch (_) { /* ignore */ }
      }
      scheduleRefresh(400);
    }
  }

  function summarizeAction(action) {
    if (!action) return "No action.";
    let text = action.kind === "rtbh" ? "RTBH " + action.target : "Flowspec " + action.action;
    if (action.kind === "flowspec") {
      if (action.match && action.match.destination) text += " to " + action.match.destination;
      if (action.match && action.match.source) text += " from " + action.match.source;
      if (action.match && action.match.dst_port) text += " port " + action.match.dst_port;
    }
    if (action.simulated) text = "Simulated " + text;
    if (action.status === "failed" && action.error) text += " — " + action.error;
    return text;
  }

  function connectEvents() {
    setLive("connecting", "idle");
    let source;
    try {
      source = new EventSource("/api/events");
    } catch (_) {
      setLive("stream unavailable", "error");
      return;
    }
    state.eventSource = source;
    source.addEventListener("open", () => setLive("live", "live"));
    source.addEventListener("error", () => {
      if (source.readyState === EventSource.CLOSED) setLive("stream offline", "error");
      else setLive("reconnecting", "idle");
    });
    for (const type of ["tick", "packet", "alert", "mitigation", "blocklist", "trust", "rule", "rules"]) {
      source.addEventListener(type, (event) => {
        let data;
        try { data = JSON.parse(event.data); } catch (_) { return; }
        handleEvent(type, data);
      });
    }
  }

  function start() {
    if (!location.hash) {
      history.replaceState(null, "", "#/overview");
    }
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.addEventListener("click", () => {
        if (drawerOpen()) closeDrawer();
      });
    });
    window.addEventListener("hashchange", () => {
      if (drawerOpen()) closeDrawer();
      renderRoute({ silent: false });
    });
    window.addEventListener("resize", () => {
      if (state.viewHooks && state.viewHooks.redraw) {
        try { state.viewHooks.redraw(); } catch (_) { /* ignore */ }
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && drawerOpen()) closeDrawer();
    });
    refreshHeader();
    setInterval(() => { if (!document.hidden) refreshHeader(); }, 12000);
    connectEvents();
    renderRoute({ silent: false });
  }

  window.Dolly = {
    state,
    el,
    frag,
    badge,
    pill,
    card,
    kpi,
    viewTop,
    table,
    tableWrap,
    kvList,
    listRow,
    chips,
    meterRows,
    severityKind,
    threatKind,
    threatLabel,
    statusKind,
    actionKind,
    ruleStateKind,
    ruleActionKind,
    typeLabel,
    alertItem,
    timeNode,
    apiGet,
    mutate,
    fmtNumber,
    fmtInt,
    fmtPercent,
    fmtPPS,
    fmtBPS,
    fmtBytes,
    fmtDuration,
    fmtClock,
    formatDateTime,
    relativeTime,
    fmtWindow,
    protocolLabel,
    directionKind,
    simBanner,
    button,
    linkButton,
    openDrawer,
    closeDrawer,
    drawerOpen,
    toast,
    drawSeries,
    drawPair,
    chartPair,
    parseHash,
    renderRoute,
    refreshCurrent,
    applyHeader,
    setPageHeading,
    loaders: {},
    registerLoader(name, loader) {
      state.loaders[name] = loader;
    },
  };

  window.addEventListener("DOMContentLoaded", start);
})();
