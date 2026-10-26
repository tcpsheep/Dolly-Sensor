"use strict";

/* Dolly Sensor views. All dynamic values are inserted as text nodes. */
(function () {
  const D = window.Dolly;
  const {
    el, badge, card, kpi, table, tableWrap, kvList, listRow, chips, meterRows,
    alertItem, timeNode, apiGet, mutate, fmtInt, fmtNumber, fmtPercent, fmtPPS,
    fmtBPS, fmtBytes, fmtDuration, fmtClock, formatDateTime, relativeTime,
    threatKind, threatLabel, statusKind, actionKind, typeLabel, severityKind,
    ruleStateKind, ruleActionKind,
    directionKind, simBanner, button, openDrawer, toast,
  } = D;
  function contentNode() {
    return document.getElementById("content");
  }

  function mount(token, view) {
    if (token !== D.state.token) return false;
    contentNode().replaceChildren(view);
    if (D.state.route && D.state.route.name !== "position") {
      // Keep headings in sync after a silent refresh or direct API navigation.
      D.setPageHeading(D.state.route);
    }
    return true;
  }

  function refreshButton(label) {
    return button(label || "Refresh", { small: true, onClick: () => D.refreshCurrent() });
  }

  function destinationLink(ip, className) {
    return el("a", {
      class: className || "cell-mono",
      href: "#/destination/" + encodeURIComponent(ip),
      text: ip,
    });
  }

  function destinationCell(row) {
    return el("div", {},
      destinationLink(row.destination),
      el("div", { class: "cell-secondary", text: (row.top_protocols && row.top_protocols[0] ? row.top_protocols[0].name : "unknown") + " · " + (row.sources || 0) + " sources" }),
    );
  }

  function topSummary(row) {
    const protocols = (row.top_protocols || []).slice(0, 2).map((item) => item.name);
    const ports = (row.top_ports || []).slice(0, 2).map((item) => item.port);
    if (!protocols.length && !ports.length) return "—";
    return [...protocols, ports.length ? "port " + ports.join("/") : null].filter(Boolean).join(" · ");
  }

  function destinationRows(rows, limit) {
    return (rows || []).slice(0, limit || rows.length).map((row) => ({
      cells: [
        destinationCell(row),
        badge(threatLabel(row.threat), threatKind(row.threat)),
        fmtPPS(row.pps),
        fmtBPS(row.bps),
        fmtPPS(row.baseline_pps),
        fmtBPS(row.baseline_bps),
        el("div", {}, fmtInt(row.sources), el("div", { class: "cell-secondary", text: fmtInt(row.trusted_sources) + " trusted" })),
        topSummary(row),
        timeNode(row.last_seen),
      ],
      onClick: () => { location.hash = "#/destination/" + encodeURIComponent(row.destination); },
      title: "Open " + row.destination,
    }));
  }

  function destinationTable(rows, limit, compact) {
    const result = table([
      "Destination",
      "Threat",
      { label: "PPS", class: "numeric" },
      { label: "BPS", class: "numeric" },
      { label: "Avg PPS", class: "numeric" },
      { label: "Avg BPS", class: "numeric" },
      { label: "Sources", class: "numeric" },
      "Top traffic",
      "Last seen",
    ], destinationRows(rows, limit), { compact: compact, empty: "No protected destination has been observed yet." });
    return result;
  }

  function packetApp(packet) {
    const app = packet.app || {};
    if (app.detail) return app.detail;
    if (app.dns_query) return "DNS " + app.dns_query;
    if (app.http_host) return "HTTP " + app.http_host;
    if (app.ftp_command) return "FTP " + app.ftp_command;
    if (app.ssh_banner) return "SSH " + app.ssh_banner;
    if (app.protocol) return app.protocol;
    return packet.summary || "—";
  }

  function packetTarget(packet) {
    const destination = packet.dst_ip || "—";
    if (packet.dst_protected) return destinationLink(destination, "cell-mono");
    return el("span", { class: "cell-mono", text: destination });
  }

  function packetTable(packets, options) {
    const opts = options || {};
    const result = table([
      "Time",
      "Direction",
      "Source",
      "Destination",
      "Proto",
      { label: "Ports", class: "cell-mono" },
      { label: "Size", class: "numeric" },
      { label: "Flags", class: "cell-mono" },
      "Application / summary",
    ], (packets || []).slice(0, opts.limit || packets.length).map((packet) => ({
      cells: [
        timeNode(packet.received_at),
        badge(packet.direction || "other", directionKind(packet.direction)),
        el("span", { class: "cell-mono", text: packet.src_ip || "—" }),
        packetTarget(packet),
        packet.protocol_name || String(packet.protocol || "—"),
        (packet.src_port && packet.dst_port) ? packet.src_port + " → " + packet.dst_port : "—",
        packet.packet_size ? packet.packet_size + " B" : "—",
        packet.tcp_flags || "—",
        el("span", { text: packetApp(packet), title: packet.summary || "" }),
      ],
      onClick: () => openPacket(packet),
      title: "Inspect packet #" + packet.id,
    })), { compact: opts.compact, empty: opts.empty || "No observations match this view." });
    return result;
  }

  function openPacket(packet) {
    const appLabels = [
      ["protocol", "Protocol"],
      ["detail", "Detail"],
      ["dns_query", "DNS query"],
      ["dns_record", "DNS record"],
      ["http_method", "HTTP method"],
      ["http_host", "HTTP host"],
      ["http_path", "HTTP path"],
      ["ssh_banner", "SSH banner"],
      ["ftp_command", "FTP command"],
      ["ftp_argument", "FTP argument"],
      ["ftp_reply_code", "FTP reply code"],
    ];
    const appPairs = [];
    for (const [key, label] of appLabels) {
      if (packet.app && packet.app[key]) appPairs.push([label, packet.app[key]]);
    }
    const flowPairs = [
      ["Source", packet.src_ip + (packet.src_port ? ":" + packet.src_port : "")],
      ["Destination", packet.dst_ip + (packet.dst_port ? ":" + packet.dst_port : "")],
      ["Protocol", packet.protocol_name || String(packet.protocol || "")],
      ["TCP flags", packet.tcp_flags || "—"],
      ["Sequence / ACK", packet.seq || packet.ack ? String(packet.seq || 0) + " / " + String(packet.ack || 0) : "—"],
      ["TTL", packet.ttl || "—"],
      ["IP length / frame", (packet.ip_length || "—") + " / " + (packet.frame_length || "—")],
      ["Packet size", packet.packet_size ? packet.packet_size + " bytes" : "—"],
      ["Direction", badge(packet.direction || "other", directionKind(packet.direction))],
      ["Protection", el("span", {}, packet.src_protected ? badge("source protected", "info") : null, " ", packet.dst_protected ? badge("destination protected", "info") : null)],
      ["Fragmented", packet.fragmented ? (packet.non_initial_fragment ? "non-initial fragment" : "fragment") : "no"],
    ];
    const capturePairs = [
      ["Received", formatDateTime(packet.received_at)],
      ["Exporter", packet.exporter || "—"],
      ["Sub-agent / source", (packet.sub_agent_id || "0") + " / " + (packet.source_id || "—")],
      ["Sample sequence", packet.sample_sequence],
      ["Sampling rate", "1:" + (packet.sampling_rate || 1)],
      ["Estimated volume", fmtInt(packet.estimated_packets) + " packets / " + fmtBytes(packet.estimated_bytes)],
      ["Frame length", (packet.frame_length || "—") + " bytes (stripped " + (packet.stripped || 0) + ")"],
      ["Source / destination MAC", (packet.src_mac || "—") + " → " + (packet.dst_mac || "—")],
    ];
    const sessionPairs = [
      ["Session state", packet.session_state || "unknown"],
      ["Session key", packet.session_key || "—"],
      ["Handshake complete", packet.handshake_completed ? "yes" : "no"],
      ["Out of state", packet.out_of_state ? badge("out of state", "warn") : "no"],
    ];
    const stateful = !(D.state.status && D.state.status.detection && D.state.status.detection.stateful === false);
    const body = el("div", { class: "stack" },
      el("div", { class: "banner banner-info", text: packet.summary || "No summary available." }),
      section("Packet", kvList(flowPairs)),
      section("Capture and sampling", kvList(capturePairs)),
      stateful
        ? section("TCP state evidence", kvList(sessionPairs))
        : section("TCP state evidence", el("div", { class: "empty-state", text: "Stateful protection is disabled; this packet was not matched against a connection table." })),
      section("Application context", appPairs.length ? kvList(appPairs) : el("div", { class: "empty-state", text: "No application metadata matched this packet." })),
      packet.arp ? section("ARP", kvList([
        ["Operation", packet.arp.operation === 1 ? "request" : packet.arp.operation === 2 ? "reply" : packet.arp.operation],
        ["Sender", packet.arp.sender_ip + " / " + (packet.arp.sender_mac || "—")],
        ["Target", packet.arp.target_ip + " / " + (packet.arp.target_mac || "—")],
      ])) : null,
      section("Payload preview", el("div", { class: "payload", text: packet.payload_preview || "(no payload captured or decoded)" })),
      section("Payload hex", el("div", { class: "payload", text: packet.payload_hex || "(no payload captured or decoded)" })),
    );
    openDrawer("Packet #" + packet.id, (packet.src_ip || "?") + " → " + (packet.dst_ip || "?") + " · " + (packet.protocol_name || ""), body);
  }

  function section(title, body) {
    return el("section", {},
      el("div", { class: "drawer-section-title", text: title }),
      body,
    );
  }

  function matchText(action) {
    const match = action.match || {};
    const parts = [];
    if (match.source) parts.push("source " + match.source);
    if (match.destination) parts.push("destination " + match.destination);
    if (match.protocol) parts.push("proto " + (match.protocol === 6 ? "TCP" : match.protocol === 17 ? "UDP" : match.protocol === 1 ? "ICMP" : match.protocol));
    if (match.src_port) parts.push("sport " + match.src_port);
    if (match.dst_port) parts.push("dport " + match.dst_port);
    if (match.tcp_flags) parts.push("flags 0x" + Number(match.tcp_flags).toString(16).padStart(2, "0"));
    return parts.join(" · ") || (action.kind === "rtbh" ? "host route " + (action.target || "—") : "—");
  }

  function actionRows(actions, allowWithdraw) {
    return (actions || []).map((action) => ({
      cells: [
        el("div", {}, badge(action.kind.toUpperCase(), actionKind(action.kind)), el("div", { class: "cell-secondary", text: action.action || "discard" })),
        badge(action.status, statusKind(action.status)),
        el("div", {},
          action.kind === "rtbh" ? el("span", { class: "cell-mono", text: action.target || "—" }) : el("span", { class: "cell-mono", text: matchText(action) }),
          action.simulated ? el("div", { class: "cell-secondary", text: "simulated · no BGP update" }) : null,
        ),
        el("div", {},
          el("div", { text: action.reason || "—", title: action.reason || "" }),
          action.error ? el("div", { class: "cell-secondary", text: action.error }) : null,
        ),
        timeNode(action.created_at),
        action.expires_at ? timeNode(action.expires_at) : "—",
        el("div", { class: "inline-actions" },
          button("View", { small: true, onClick: () => openAction(action) }),
          allowWithdraw && (action.status === "active" || action.status === "simulated")
            ? button("Withdraw", { small: true, variant: "danger", onClick: (event) => { event.stopPropagation(); withdrawAction(action); } })
            : null,
        ),
      ],
      onClick: () => openAction(action),
    }));
  }

  function actionTable(actions, allowWithdraw) {
    const result = table([
      "Kind", "Status", "Match", "Reason", "Started", "Expires", { label: "Actions", class: "actions-cell" },
    ], actionRows(actions, allowWithdraw), { compact: true, empty: "No mitigation actions recorded." });
    return result;
  }

  function openAction(action) {
    const body = el("div", { class: "stack" },
      el("div", { class: "banner " + (action.status === "failed" ? "banner-danger" : action.simulated ? "banner-info" : "banner-good") },
        action.simulated ? "This action is simulated. No BGP update was sent." : "This action is/was announced over BGP.",
      ),
      section("Action", kvList([
        ["ID", action.id],
        ["Kind", action.kind],
        ["Status", badge(action.status, statusKind(action.status))],
        ["Mode", action.simulated ? "simulated" : "live BGP"],
        ["Operation", action.action || "—"],
        ["Rate limit", action.rate_limit_bps ? fmtBPS(action.rate_limit_bps) : "—"],
        ["Target", action.target || "—"],
        ["Community", action.community || "—"],
        ["Next hop", action.next_hop || "—"],
        ["Owner", action.owner || "—"],
        ["Alert", action.alert_id || "—"],
      ])),
      section("Match", kvList([
        ["Source", action.match && action.match.source || "—"],
        ["Destination", action.match && action.match.destination || "—"],
        ["Protocol", action.match && action.match.protocol || "—"],
        ["Source port", action.match && action.match.src_port || "—"],
        ["Destination port", action.match && action.match.dst_port || "—"],
        ["TCP flags", action.match && action.match.tcp_flags || "—"],
        ["Packet length", action.match && action.match.packet_length || "—"],
      ])),
      section("Reason", el("div", { class: "alert-reason", text: action.reason || "No reason recorded." })),
      section("Lifecycle", kvList([
        ["Created", formatDateTime(action.created_at)],
        ["Updated", formatDateTime(action.updated_at)],
        ["Expires", formatDateTime(action.expires_at)],
        ["Withdrawn", formatDateTime(action.withdrawn_at)],
        ["Error", action.error || "—"],
      ])),
    );
    if (action.status === "active" || action.status === "simulated") {
      body.appendChild(button("Withdraw this action", {
        variant: "danger",
        onClick: () => { D.closeDrawer(); withdrawAction(action); },
      }));
    }
    openDrawer("Mitigation " + (action.kind || "").toUpperCase(), action.target || matchText(action), body);
  }

  async function withdrawAction(action) {
    if (!window.confirm("Withdraw " + (action.kind || "mitigation") + " action " + action.id + "?")) return;
    try {
      await mutate("/api/mitigations/" + encodeURIComponent(action.id) + "/withdraw", "POST", { reason: "manual withdrawal from dashboard" });
      toast("Mitigation withdrawn", action.target || action.id, "good");
      D.refreshCurrent();
    } catch (error) {
      toast("Withdrawal failed", error.message, "error");
    }
  }

  function alertsCard(alerts, limit, total) {
    const body = el("div", { class: "alert-list" });
    if (!alerts || alerts.length === 0) {
      body.appendChild(el("div", { class: "empty-state", text: "No alerts retained. That can mean calm traffic — or no detection activity yet." }));
    } else {
      for (const alert of alerts.slice(0, limit || alerts.length)) body.appendChild(alertItem(alert));
    }
    return card("Alerts", total === undefined ? "Newest retained findings" : fmtInt(total) + " retained records", body, null);
  }

  function activeMitigationsCard(actions) {
    const list = el("ul", { class: "list" });
    if (!actions || actions.length === 0) {
      list.appendChild(listRow("No live mitigations", "Simulation and live actions appear here for their full lifecycle."));
    } else {
      for (const action of actions.slice(0, 8)) {
        list.appendChild(listRow(
          (action.kind || "").toUpperCase() + " · " + action.status,
          matchText(action) + (action.simulated ? " · simulated" : ""),
          button("View", { small: true, onClick: () => openAction(action) }),
        ));
      }
    }
    return card("Active mitigation", "Current containment state", list);
  }

  async function loadOverview(route, token) {
    const data = await apiGet("/api/overview");
    if (token !== D.state.token) return;
    D.applyHeader(data.status);
    const alerts = data.status.alerts || {};
    const attacks = (data.destinations || []).filter((row) => row.attack).length;
    const ppsCanvas = el("canvas", { id: "overview-pps", class: "chart" });
    const bpsCanvas = el("canvas", { id: "overview-bps", class: "chart" });
    const destTable = destinationTable(data.destinations, 15);
    const packetsTable = packetTable(data.recent_packets || [], { compact: true, limit: 8, empty: "No packets observed yet." });
    const chartBody = el("div", {},
      el("div", { class: "chart-legend" }, el("span", { class: "legend-item" }, el("span", { class: "legend-swatch legend-pps", title: "Packets per second" }), "Packets / second")),
      ppsCanvas,
      el("div", { class: "chart-legend" }, el("span", { class: "legend-item" }, el("span", { class: "legend-swatch legend-bps", title: "Bits per second" }), "Bits / second")),
      bpsCanvas,
    );
    const health = data.status;
    const healthPairs = [
      ["Collector", health.collector.listen + " · " + health.collector.workers + " workers"],
      ["Queue", fmtInt(health.collector.queue_depth) + " / " + fmtInt(health.collector.queue_capacity)],
      ["Datagrams", fmtInt(health.collector.datagrams) + " · " + fmtInt(health.collector.decode_errors) + " decode errors"],
      ["Dropped", fmtInt(health.collector.dropped_datagrams) + " datagrams / " + fmtInt(health.collector.dropped_findings) + " findings"],
      ["Protected destinations", fmtInt(health.profiles) + " profiles · " + fmtInt(health.destination_live) + " live"],
      ["TCP state", (health.detection && health.detection.stateful) ? fmtInt(health.tcp.established) + " established · " + fmtInt(health.tcp.out_of_state) + " out of state" : "disabled (stateless protection)"],
      ["BGP", health.bgp ? health.bgp.state + " · " + (health.bgp.peer || "peer") : "disabled (simulation)"],
      ["Last packet", timeNode(health.collector.last_packet)],
      ["Last evaluation", timeNode(health.collector.last_evaluation)],
      ["Persistence", health.persistence.last_save ? timeNode(health.persistence.last_save) : "not saved yet"],
    ];
    const detectionPairs = [
      ["Protection", data.detection.stateful ? "stateful" : "stateless"],
      ["Threat threshold", fmtNumber(data.detection.threshold, 1)],
      ["Persistence / warm-up", data.detection.persistence + " windows / " + data.detection.warmup_windows],
      ["Floor PPS / BPS", fmtPPS(data.detection.pps_floor) + " / " + fmtBPS(data.detection.bps_floor)],
      ["Cooldown", fmtDuration(data.detection.cooldown_seconds)],
      ["Rate window", data.detection.rate_window_seconds + " seconds"],
      ["FTP application checks", data.detection.ftp_enabled ? "enabled" : "disabled"],
    ];
    const view = el("div", {},
      simBanner(data.status),
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "A bounded, sampling-aware view of traffic toward " + health.protected_cidrs.length + " protected prefix" + (health.protected_cidrs.length === 1 ? "" : "es") + ". Detection evidence stays visible even when mitigation is simulated." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      el("div", { class: "grid-kpi" },
        kpi("Protected traffic", fmtPPS(data.global.pps), fmtBPS(data.global.bps) + " · " + fmtInt(data.global.destinations) + " destinations", { id: "kpi-traffic", valueId: "kpi-pps", subId: "kpi-throughput" }),
        kpi("Detections", fmtInt(attacks), "destinations currently under attack", { id: "kpi-attacks", valueId: "kpi-attack-value", variant: attacks ? "danger" : "" }),
        kpi("Live mitigations", fmtInt((data.active_mitigations || []).length), data.status.simulated ? "simulated containment" : "BGP containment", { id: "kpi-mitigations", valueId: "kpi-mit-value" }),
        kpi("Critical alerts", fmtInt(alerts.critical || 0), fmtInt(alerts.total || 0) + " total retained", { variant: alerts.critical ? "danger" : "good", valueId: "kpi-alert-value" }),
        kpi("Protected prefixes", fmtInt(health.protected_cidrs.length), fmtInt(health.profiles) + " destination profiles", { variant: "accent", valueId: "kpi-prefix-value" }),
        kpi("Ingestion", fmtInt(health.collector.accepted), fmtInt(health.collector.dropped_datagrams) + " dropped datagrams", { variant: health.collector.dropped_datagrams ? "warn" : "", valueId: "kpi-ingest-value" }),
      ),
      el("div", { class: "grid-main" },
        el("div", { class: "stack" },
          card("Protected traffic", "Sampling-corrected rates over the recent window; last five minutes on the chart", chartBody),
          card("Protected destinations", "Top destinations by live risk and volume", tableWrap(destTable.table)),
          card("Recent observations", "Newest samples in the bounded inspector ring", tableWrap(packetsTable.table, "table-scroll-short")),
        ),
        el("div", { class: "stack" },
          alertsCard(data.recent_alerts || [], 10, alerts.total),
          activeMitigationsCard(data.active_mitigations || []),
          card("Collector health", "Ingestion never waits for this dashboard", kvList(healthPairs)),
          card("Detection parameters", "Directly configured thresholds and floors", kvList(detectionPairs)),
        ),
      ),
    );
    if (!mount(token, view)) return;
    const chartData = (data.global.series || []).slice(-300);
    let livePolls = 0;
    const hooks = {
      autoRefresh: 0,
      redraw() {
        D.drawPair(ppsCanvas, bpsCanvas, chartData);
      },
      onTick(tick) {
        if (!ppsCanvas.isConnected) return;
        chartData.push({ at: tick.at, pps: tick.pps, bps: tick.bps });
        if (chartData.length > 300) chartData.splice(0, chartData.length - 300);
        D.drawPair(ppsCanvas, bpsCanvas, chartData);
        const pps = document.getElementById("kpi-pps");
        const throughput = document.getElementById("kpi-throughput");
        const attackValue = document.getElementById("kpi-attack-value");
        const mitValue = document.getElementById("kpi-mit-value");
        const alertValue = document.getElementById("kpi-alert-value");
        const ingestValue = document.getElementById("kpi-ingest-value");
        if (pps) pps.textContent = fmtPPS(tick.pps);
        if (throughput) throughput.textContent = fmtBPS(tick.bps) + " · " + fmtInt(tick.destinations) + " live destinations";
        if (attackValue) attackValue.textContent = fmtInt(tick.attacks);
        if (mitValue) mitValue.textContent = fmtInt(tick.mitigation ? tick.mitigation.live : 0);
        if (alertValue && tick.alerts) alertValue.textContent = fmtInt(tick.alerts.critical || 0);
        if (ingestValue && tick.accepted !== undefined) ingestValue.textContent = fmtInt(tick.accepted);
        livePolls += 1;
        if (livePolls % 5 === 0) refreshDestinationPreview();
      },
    };
    D.state.viewHooks = hooks;
    requestAnimationFrame(() => hooks.redraw());

    async function refreshDestinationPreview() {
      try {
        const fresh = await apiGet("/api/destinations?limit=200");
        if (!destTable.tbody.isConnected || !D.state.route || D.state.route.name !== "overview") return;
        const rebuilt = destinationTable(fresh.destinations || [], 15);
        destTable.tbody.replaceChildren(...Array.from(rebuilt.tbody.childNodes));
      } catch (_) { /* live preview refresh is best effort */ }
    }
  }

  D.registerLoader("overview", loadOverview);

  async function loadProtected(route, token) {
    const [status, trust, destinationData] = await Promise.all([
      apiGet("/api/status"),
      apiGet("/api/trust"),
      apiGet("/api/destinations?limit=500"),
    ]);
    if (token !== D.state.token) return;
    D.applyHeader(status);
    const rows = destinationData.destinations || [];
    const manual = trust.manual || [];
    const datalist = el("datalist", { id: "protected-destination-options" },
      rows.map((row) => el("option", { value: row.destination })),
    );
    const destinationInput = el("input", { class: "input", name: "destination", placeholder: "203.0.113.10", required: true, list: "protected-destination-options", autocomplete: "off" });
    const sourceInput = el("input", { class: "input", name: "source", placeholder: "198.51.100.7", required: true, autocomplete: "off" });
    const trustButton = button("Grant trust", { type: "submit", variant: "primary" });
    const trustForm = el("form", {
      class: "form",
      onSubmit: async (event) => {
        event.preventDefault();
        const destination = destinationInput.value.trim();
        const source = sourceInput.value.trim();
        if (!destination || !source) return;
        trustButton.disabled = true;
        trustButton.textContent = "Saving…";
        try {
          await mutate("/api/trust", "POST", { destination, source, trusted: true });
          toast("Trust granted", source + " → " + destination, "good");
          D.refreshCurrent();
        } catch (error) {
          toast("Could not grant trust", error.message, "error");
          trustButton.disabled = false;
          trustButton.textContent = "Grant trust";
        }
      },
    },
      el("div", { class: "form-row" },
        el("div", { class: "form-field" }, el("label", { text: "Protected destination" }), destinationInput),
        el("div", { class: "form-field" }, el("label", { text: "External source" }), sourceInput),
        trustButton,
      ),
      el("div", { class: "form-hint", text: "Trust is contextual: it lowers suspicion for this source only toward this destination. Blocklist matches still take precedence, and internal sources are never trusted as external clients." }),
      datalist,
    );
    const manualRows = manual.map((item) => ({
      cells: [
        destinationLink(item.destination),
        el("span", { class: "cell-mono", text: item.source }),
        fmtNumber(item.trust, 1) + " / 100",
        badge(item.manual ? "manual" : "earned", item.manual ? "info" : "muted"),
        timeNode(item.last_seen),
        el("div", { class: "inline-actions" },
          button("Revoke", {
            small: true,
            variant: "danger",
            onClick: async () => {
              if (!window.confirm("Revoke manual trust for " + item.source + " toward " + item.destination + "?")) return;
              try {
                await mutate("/api/trust", "POST", { destination: item.destination, source: item.source, trusted: false });
                toast("Trust revoked", item.source + " → " + item.destination, "info");
                D.refreshCurrent();
              } catch (error) {
                toast("Could not revoke trust", error.message, "error");
              }
            },
          }),
        ),
      ],
    }));
    const manualTable = table(["Destination", "Source", "Trust", "Mode", "Last seen", "Actions"], manualRows, { compact: true, empty: "No manual trust decisions yet." });
    const destinationTableNode = destinationTable(rows, 500);
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "The sensor measures and defends only traffic toward these prefixes. Explicit protected CIDRs are required at startup; outbound and unrelated traffic is outside scope." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      status.warnings && status.warnings.length
        ? el("div", { class: "banner banner-warn" }, el("ul", { class: "warn-list" }, status.warnings.map((warning) => el("li", { text: warning }))))
        : null,
      el("div", { class: "grid-kpi" },
        kpi("Protected prefixes", fmtInt((status.protected_cidrs || []).length), "explicit configuration", { variant: "accent" }),
        kpi("Protected destinations", fmtInt(rows.length), "observed destination profiles"),
        kpi("Global trusted", fmtInt((trust.global || []).length), "prefixes exempt from penalties"),
        kpi("Manual contexts", fmtInt(manual.length), "source + destination decisions"),
      ),
      el("div", { class: "grid-2 margin-bottom" },
        card("Protected ranges", "No default route is implied by an empty list", chips(status.protected_cidrs || [])),
        card("Globally trusted sources", "Trusted prefixes never contribute attack penalties", chips(trust.global || [])),
      ),
      el("div", { class: "stack" },
        card("Destinations", "Merge of live hot state and durable profiles", tableWrap(destinationTableNode.table)),
        card("Manual trust", "Contextual exemption for known external clients", trustForm),
        card("Trust decisions", "Revoke changes take effect immediately", tableWrap(manualTable.table)),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 0 };
  }

  D.registerLoader("protected", loadProtected);

  async function loadDestination(route, token) {
    if (!route.ip) {
      if (token === D.state.token) D.renderRoute({ silent: false });
      return;
    }
    const detail = await apiGet("/api/destinations/" + encodeURIComponent(route.ip));
    if (token !== D.state.token) return;
    const destination = detail.destination || route.ip;
    const profile = detail.profile || null;
    const live = detail.live || null;
    const detection = detail.detection || null;
    const stateful = !(D.state.status && D.state.status.detection && D.state.status.detection.stateful === false);
    const recentAlerts = detail.alerts || [];
    const actions = detail.actions || [];
    const recent = detail.recent || [];
    const ppsCanvas = el("canvas", { id: "destination-pps", class: "chart dest-chart" });
    const bpsCanvas = el("canvas", { id: "destination-bps", class: "chart dest-chart" });
    const history = live && live.history ? live.history : [];
    const currentThreat = detection ? detection.threat : (live ? "learning" : "idle");
    const alertCount = recentAlerts.length;
    const liveSources = live && live.recent ? live.recent.source_count : (profile ? profile.source_count : 0);
    const score = detection ? detection.score : 0;
    const smoothed = detection ? detection.smoothed_score : 0;
    const threshold = detection ? detection.threshold : 0;
    const sourceList = profile && profile.sources ? [...profile.sources].sort((a, b) => b.trust - a.trust) : [];
    const sourceRows = sourceList.map((source) => ({
      cells: [
        el("span", { class: "cell-mono", text: source.source }),
        fmtNumber(source.trust, 1),
        source.manual ? badge("manual", "info") : badge("earned", "muted"),
        fmtInt(source.syn) + " / " + fmtInt(source.ack) + " / " + fmtInt(source.handshakes),
        timeNode(source.last_seen),
        el("div", { class: "inline-actions" },
          button(source.manual ? "Revoke trust" : "Trust", {
            small: true,
            variant: source.manual ? "danger" : "primary",
            onClick: async () => {
              try {
                await mutate("/api/trust", "POST", { destination, source: source.source, trusted: !source.manual });
                toast(source.manual ? "Trust revoked" : "Trust granted", source.source, "info");
                D.refreshCurrent();
              } catch (error) {
                toast("Trust change failed", error.message, "error");
              }
            },
          }),
        ),
      ],
    }));
    const sourcesTable = table(["Source", "Trust", "Mode", { label: "SYN / ACK / handshakes", class: "numeric" }, "Last seen", "Actions"], sourceRows, { compact: true, empty: "No source reputations recorded for this destination." });
    const distribution = (live && live.recent) || null;
    const profileProtocols = distribution ? distribution.protocols : (profile ? profile.protocols : []);
    const profilePorts = distribution ? distribution.dest_ports : (profile ? profile.dest_ports : []);
    const profileFlags = distribution ? distribution.tcp_flags : (profile ? profile.tcp_flags : []);
    const profileTTLs = distribution ? distribution.ttls : (profile ? profile.ttls : []);
    const protocolItems = (profileProtocols || []).map((item) => ({ name: item.name, count: item.count }));
    const portItems = (profilePorts || []).map((item) => ({ name: "port " + item.port, count: item.count }));
    const flagItems = (profileFlags || []).map((item) => ({ name: item.name, count: item.count }));
    const ttlItems = (profileTTLs || []).map((item) => ({ name: "TTL " + item.ttl, count: item.count }));
    const profileBody = el("div", {},
      el("div", { class: "margin-bottom" }, kvList([
        ["First seen", formatDateTime((profile && profile.first_seen) || (live && live.first_seen))],
        ["Last updated", timeNode((profile && profile.last_updated) || (live && live.last_seen))],
        ["Total packets", fmtInt(profile && profile.total_packets)],
        ["Total bytes", fmtBytes(profile && profile.total_bytes)],
        ["Average packet", profile && profile.avg_packet_size ? fmtNumber(profile.avg_packet_size, 0) + " B" : "—"],
        ["Sources / trusted", fmtInt((profile && profile.source_count) || liveSources) + " / " + fmtInt(profile && profile.trusted_count)],
        ["Max PPS", fmtPPS(profile && profile.max_pps)],
        ["Max BPS", fmtBPS(profile && profile.max_bps)],
      ])),
      el("div", { class: "grid grid-2" },
        distributionBlock("Protocols", protocolItems),
        distributionBlock("Destination ports", portItems),
        distributionBlock("TCP flags", flagItems),
        distributionBlock("TTLs", ttlItems),
      ),
    );
    const detectionPairs = detection ? [
      ["Threat", badge(threatLabel(detection.threat), threatKind(detection.threat))],
      ["Score / smoothed", fmtNumber(score, 1) + " / " + fmtNumber(smoothed, 1)],
      ["Threshold", fmtNumber(threshold, 1)],
      ["Consecutive windows", fmtInt(detection.consecutive)],
      ["Warm-up", detection.warmup ? "yes" : "no"],
      ["Samples", fmtInt(detection.samples)],
      ["Baseline PPS / BPS", fmtPPS(detection.baseline_pps) + " / " + fmtBPS(detection.baseline_bps)],
      ["Z PPS / Z BPS", fmtNumber(detection.z_pps, 2) + " / " + fmtNumber(detection.z_bps, 2)],
      ["Out of state", stateful ? fmtPPS(detection.out_of_state_pps) : "not tracked (stateless)"],
      ["Last evaluation", timeNode(detection.last_evaluation)],
    ] : [["Detection", "No evaluation yet"]];
    const signals = detection && detection.signals ? detection.signals : [];
    const detectionBody = el("div", {},
      kvList(detectionPairs),
      signals.length ? el("div", { class: "margin-top" },
        el("div", { class: "drawer-section-title", text: "Signals" }),
        el("ul", { class: "signal-list" }, signals.map((signal) => el("li", { text: signal }))),
      ) : el("div", { class: "empty-state", text: "No detection signals are currently firing." }),
    );
    const alertsBody = el("div", { class: "alert-list" });
    if (recentAlerts.length === 0) alertsBody.appendChild(el("div", { class: "empty-state", text: "No alerts retained for this destination." }));
    for (const alert of recentAlerts) alertsBody.appendChild(alertItem(alert));
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", {},
          el("div", { class: "view-actions margin-bottom" }, el("a", { class: "button button-ghost", href: "#/protected", text: "← Protected IPs" }), refreshButton()),
          el("div", { class: "view-lede" }, "Destination ", el("span", { class: "mono", text: destination }), " · ", badge(threatLabel(currentThreat), threatKind(currentThreat)), " · ", fmtInt(alertCount), " retained alert", alertCount === 1 ? "" : "s"),
        ),
        el("div", { class: "stat-strip" },
          el("span", {}, "Profiles ", el("strong", { text: profile ? "durable" : "not yet written" })),
          el("span", {}, "Live ", el("strong", { text: live ? "tracked" : "no current bucket" })),
          el("span", {}, "Actions ", el("strong", { text: actions.length })),
        ),
      ),
      simBanner(D.state.status),
      currentThreat === "under_attack"
        ? el("div", { class: "banner banner-danger" }, el("strong", { text: "Under attack. " }), "Detection is above threshold for this destination. Review the signals and mitigation state below.")
        : currentThreat === "anomalous"
          ? el("div", { class: "banner banner-warn" }, el("strong", { text: "Anomalous traffic. " }), "Evidence is above normal but has not yet crossed the configured action threshold.")
          : null,
      el("div", { class: "grid-kpi" },
        kpi("Current traffic", fmtPPS(live && live.pps), fmtBPS(live && live.bps), { valueId: "dest-pps" }),
        kpi("Baseline", fmtPPS(detection && detection.baseline_pps), fmtBPS(detection && detection.baseline_bps)),
        kpi("Threat score", fmtNumber(score, 1), "smoothed " + fmtNumber(smoothed, 1), { variant: currentThreat === "under_attack" ? "danger" : currentThreat === "anomalous" ? "warn" : "accent" }),
        kpi("Out of state", stateful ? fmtPPS(detection && detection.out_of_state_pps) : "off", stateful ? "TCP evidence" : "stateless protection"),
        kpi("Sources", fmtInt(liveSources), fmtInt(profile && profile.trusted_count) + " trusted"),
        kpi("Alerts", fmtInt(alertCount), fmtInt(actions.length) + " mitigation actions"),
      ),
      card("Traffic history", "Evaluation points recorded by the detector", el("div", {},
        el("div", { class: "chart-legend" }, el("span", { class: "legend-item" }, el("span", { class: "legend-swatch legend-pps" }), "Packets / second")),
        ppsCanvas,
        el("div", { class: "chart-legend" }, el("span", { class: "legend-item" }, el("span", { class: "legend-swatch legend-bps" }), "Bits / second")),
        bpsCanvas,
      )),
      el("div", { class: "section-gap" }),
      el("div", { class: "grid-main" },
        el("div", { class: "stack" },
          card("Detection state", "A layered score with explicit signals", detectionBody),
          card("Source reputations", "Evidence is accumulated per destination/source pair", tableWrap(sourcesTable.table, "table-scroll-short")),
          card("Recent observations", "Newest sampled packets toward this destination", tableWrap(packetTable(recent, { compact: true, limit: 30 }).table)),
          card("Alerts", "Retained findings for this destination", alertsBody),
        ),
        el("div", { class: "stack" },
          card("Traffic profile", distribution ? "Current merged window; all-time totals in the header" : "Durable all-time profile", profileBody),
          card("Mitigation history", "Actions associated with this destination or its alerts", tableWrap(actionTable(actions, true).table, "table-scroll-short")),
        ),
      ),
    );
    if (!mount(token, view)) return;
    const hooks = {
      autoRefresh: 10,
      redraw() {
        D.drawPair(ppsCanvas, bpsCanvas, history);
      },
    };
    D.state.viewHooks = hooks;
    requestAnimationFrame(() => hooks.redraw());
    D.setPageHeading({ name: "destination", ip: destination });
  }

  function distributionBlock(title, items) {
    return el("div", {},
      el("div", { class: "drawer-section-title", text: title }),
      meterRows(items || []),
    );
  }

  D.registerLoader("destination", loadDestination);

  async function loadIntelligence(route, token) {
    const data = await apiGet("/api/intelligence");
    if (token !== D.state.token) return;
    const reputations = data.reputations || [];
    const destinations = data.destinations || [];
    const manual = data.manual_trust || [];
    const params = data.detection || {};
    const destinationRows = destinations.map((row) => ({
      cells: [
        destinationLink(row.destination),
        fmtPPS(row.max_pps),
        fmtBPS(row.max_bps),
        fmtInt(row.total_packets),
        fmtBytes(row.total_bytes),
        fmtInt(row.source_count) + " / " + fmtInt(row.trusted_count),
        timeNode(row.last_updated),
      ],
      onClick: () => { location.hash = "#/destination/" + encodeURIComponent(row.destination); },
    }));
    const destinationTable = table([
      "Destination", { label: "Max PPS", class: "numeric" }, { label: "Max BPS", class: "numeric" },
      { label: "Packets", class: "numeric" }, { label: "Bytes", class: "numeric" }, "Sources / trusted", "Last updated",
    ], destinationRows, { compact: true, empty: "No durable destination profiles yet." });
    const reputationRows = reputations.map((reputation) => ({
      cells: [
        destinationLink(reputation.destination),
        el("span", { class: "cell-mono", text: reputation.source }),
        fmtNumber(reputation.trust, 1),
        reputation.manual ? badge("manual", "info") : badge("earned", "muted"),
        fmtInt(reputation.syn) + " / " + fmtInt(reputation.ack),
        fmtInt(reputation.handshakes),
        timeNode(reputation.last_seen),
      ],
      onClick: () => { location.hash = "#/destination/" + encodeURIComponent(reputation.destination); },
    }));
    const reputationTable = table([
      "Destination", "Source", { label: "Trust", class: "numeric" }, "Mode",
      { label: "SYN / ACK", class: "numeric" }, { label: "Handshakes", class: "numeric" }, "Last seen",
    ], reputationRows, { compact: true, empty: "No source reputation records yet." });
    const manualRows = manual.map((item) => ({
      cells: [
        destinationLink(item.destination),
        el("span", { class: "cell-mono", text: item.source }),
        fmtNumber(item.trust, 1),
        fmtInt(item.active_days) + " active days",
        timeNode(item.last_seen),
      ],
    }));
    const manualTable = table(["Destination", "Source", "Trust", "Activity", "Last seen"], manualRows, { compact: true, empty: "No manual trust decisions." });
    const paramsPairs = [
      ["Protection", params.stateful ? "stateful" : "stateless"],
      ["Threshold", fmtNumber(params.threshold, 1)],
      ["Persistence", params.persistence + " windows"],
      ["PPS floor", fmtPPS(params.pps_floor)],
      ["BPS floor", fmtBPS(params.bps_floor)],
      ["Warm-up windows", params.warmup_windows],
      ["Rate window", params.rate_window_seconds + " seconds"],
      ["Cooldown", fmtDuration(params.cooldown_seconds)],
      ["FTP checks", params.ftp_enabled ? "enabled" : "disabled"],
    ];
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "Learning is durable. Source TrustScore is contextual to a destination, earned from plausible behavior and handshakes, and can be overridden by an operator. Hot distributions are bounded and expire; these facts persist." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      el("div", { class: "grid-kpi" },
        kpi("Destination profiles", fmtInt(data.profiles), "durable in memory store", { variant: "accent" }),
        kpi("Source reputations", fmtInt(reputations.length), "per destination/source context"),
        kpi("Manual trust", fmtInt(manual.length), "operator decisions"),
        kpi("Threshold", fmtNumber(params.threshold, 1), "effective threat score"),
      ),
      el("div", { class: "grid-2" },
        card("Detection parameters", "Explicit configuration values", kvList(paramsPairs)),
        card("Learning model", "Why a source is trusted", el("div", {},
          el("p", { class: "card-note", text: "Trust starts with a small initial credit, grows slowly for active days, completed handshakes, and long sessions, and decays when a source is absent. A manual decision is an explicit operator override. Trust lowers suspicion; it never bypasses the blocklist." }),
          chips(["initial credit", "active-day credit", "handshake credit", "long-session credit", "daily decay", "manual override"]),
        )),
      ),
      el("div", { class: "section-gap" }),
      el("div", { class: "stack" },
        card("Destination baselines", "Durable totals, peaks, and source counts", tableWrap(destinationTable.table, "table-scroll-short")),
        card("Source reputations", "Trust and sampled TCP evidence", tableWrap(reputationTable.table, "table-scroll-short")),
        card("Manual trust", "Contextual exceptions", tableWrap(manualTable.table)),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 0 };
  }

  D.registerLoader("intelligence", loadIntelligence);

  function defaultInspectorFilter() {
    return { destination: "", source: "", port: "", protocol: "", direction: "", q: "", limit: 100 };
  }

  function inspectorQuery(filter) {
    const params = new URLSearchParams();
    if (filter.destination) params.set("destination", filter.destination);
    if (filter.source) params.set("source", filter.source);
    if (filter.port) params.set("port", filter.port);
    if (filter.protocol) params.set("protocol", filter.protocol);
    if (filter.direction) params.set("direction", filter.direction);
    if (filter.q) params.set("q", filter.q);
    params.set("limit", String(filter.limit || 100));
    return "/api/packets?" + params.toString();
  }

  function packetMatchesFilter(packet, filter) {
    if (!filter) return true;
    const lower = (value) => String(value || "").toLowerCase();
    if (filter.destination && !lower(packet.dst_ip).includes(lower(filter.destination))) return false;
    if (filter.source && !lower(packet.src_ip).includes(lower(filter.source))) return false;
    if (filter.port) {
      const port = Number(filter.port);
      if (packet.src_port !== port && packet.dst_port !== port) return false;
    }
    if (filter.protocol && lower(packet.protocol_name) !== lower(filter.protocol) && String(packet.protocol) !== filter.protocol) return false;
    if (filter.direction && packet.direction !== filter.direction) return false;
    if (filter.q) {
      const haystack = lower([
        packet.summary, packet.src_ip, packet.dst_ip, packet.protocol_name,
        packet.app && packet.app.protocol, packet.app && packet.app.detail,
        packet.app && packet.app.dns_query, packet.app && packet.app.http_host,
      ].join(" "));
      if (!haystack.includes(lower(filter.q))) return false;
    }
    return true;
  }

  async function loadInspector(route, token) {
    const saved = D.state.inspector;
    const filter = saved ? Object.assign(defaultInspectorFilter(), saved.filter) : defaultInspectorFilter();
    const live = saved ? saved.live : true;
    const destinationInput = el("input", { class: "input", value: filter.destination, placeholder: "203.0.113.10", autocomplete: "off" });
    const sourceInput = el("input", { class: "input", value: filter.source, placeholder: "198.51.100.7", autocomplete: "off" });
    const portInput = el("input", { class: "input", value: filter.port, placeholder: "80", inputmode: "numeric", autocomplete: "off" });
    const protocolSelect = el("select", { class: "input" },
      el("option", { value: "", text: "Any protocol" }),
      el("option", { value: "tcp", text: "TCP" }),
      el("option", { value: "udp", text: "UDP" }),
      el("option", { value: "icmp", text: "ICMP" }),
      el("option", { value: "icmpv6", text: "ICMPv6" }),
    );
    protocolSelect.value = filter.protocol || "";
    const directionSelect = el("select", { class: "input" },
      el("option", { value: "", text: "Any direction" }),
      el("option", { value: "inbound", text: "Inbound" }),
      el("option", { value: "internal", text: "Internal" }),
      el("option", { value: "outbound", text: "Outbound" }),
    );
    directionSelect.value = filter.direction || "";
    const queryInput = el("input", { class: "input", value: filter.q, placeholder: "DNS name, HTTP host, FTP command, summary…", autocomplete: "off" });
    const limitSelect = el("select", { class: "input" },
      el("option", { value: "50", text: "50 packets" }),
      el("option", { value: "100", text: "100 packets" }),
      el("option", { value: "200", text: "200 packets" }),
      el("option", { value: "500", text: "500 packets" }),
    );
    limitSelect.value = String(filter.limit || 100);
    const liveCheckbox = el("input", { type: "checkbox", checked: live });
    const liveLabel = el("label", { class: "checkbox-line" }, liveCheckbox, "Prepend live packets");
    const searchButton = button("Search", { type: "submit", variant: "primary" });
    const resetButton = button("Reset", { type: "button", onClick: () => {
      destinationInput.value = "";
      sourceInput.value = "";
      portInput.value = "";
      protocolSelect.value = "";
      directionSelect.value = "";
      queryInput.value = "";
      limitSelect.value = "100";
      form.requestSubmit();
    } });
    const statusLine = el("div", { class: "stat-strip" }, el("span", { text: "Ready" }));
    const resultsHost = el("div", {});
    const form = el("form", {
      class: "form",
      onSubmit: (event) => {
        event.preventDefault();
        filter.destination = destinationInput.value.trim();
        filter.source = sourceInput.value.trim();
        filter.port = portInput.value.trim();
        filter.protocol = protocolSelect.value;
        filter.direction = directionSelect.value;
        filter.q = queryInput.value.trim();
        filter.limit = Number(limitSelect.value) || 100;
        runSearch(filter, liveCheckbox.checked);
      },
    },
      el("div", { class: "form-row" },
        el("div", { class: "form-field" }, el("label", { text: "Destination contains" }), destinationInput),
        el("div", { class: "form-field" }, el("label", { text: "Source contains" }), sourceInput),
        el("div", { class: "form-field" }, el("label", { text: "Port (either side)" }), portInput),
        el("div", { class: "form-field" }, el("label", { text: "Protocol" }), protocolSelect),
        el("div", { class: "form-field" }, el("label", { text: "Direction" }), directionSelect),
      ),
      el("div", { class: "form-row" },
        el("div", { class: "form-field" }, el("label", { text: "Search text" }), queryInput),
        el("div", { class: "form-field" }, el("label", { text: "Limit" }), limitSelect),
        searchButton,
        resetButton,
        liveLabel,
      ),
      el("div", { class: "form-hint", text: "Searches only the bounded in-memory ring. Sampling means the inspector is a sample, not a packet capture; no payload is ever persisted by the sensor." }),
    );
    const resultsCard = card("Observations", "Decoded sample fields, application context, and bounded payload previews", resultsHost);
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "Inspect recent samples without impacting ingestion. The ring is overwritten continuously; packet IDs are only valid while an observation remains buffered." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      card("Filters", "Search text matches addresses, summary, and decoded application fields", form),
      el("div", { class: "margin-bottom" }, statusLine),
      resultsCard,
    );
    if (!mount(token, view)) return;
    const inspector = {
      filter,
      live,
      rows: [],
      limit: filter.limit || 100,
      tbody: null,
      resultsHost,
      statusLine,
    };
    D.state.inspector = inspector;
    liveCheckbox.addEventListener("change", () => {
      inspector.live = liveCheckbox.checked;
    });
    D.state.viewHooks = {
      autoRefresh: 0,
      onPacket(packet) {
        if (!inspector.live || !resultsHost.isConnected) return;
        if (!packetMatchesFilter(packet, inspector.filter)) return;
        inspector.rows = inspector.rows.filter((item) => item.id !== packet.id);
        inspector.rows.unshift(packet);
        if (inspector.rows.length > inspector.limit) inspector.rows.length = inspector.limit;
        renderInspectorRows(inspector);
      },
    };

    async function runSearch(nextFilter, liveMode) {
      inspector.filter = nextFilter;
      inspector.live = liveMode;
      inspector.limit = nextFilter.limit || 100;
      searchButton.disabled = true;
      searchButton.textContent = "Searching…";
      statusLine.replaceChildren(el("span", { class: "spinner" }), el("span", { text: "Searching the bounded ring…" }));
      try {
        const data = await apiGet(inspectorQuery(nextFilter));
        if (!resultsHost.isConnected) return;
        inspector.rows = data.packets || [];
        renderInspectorRows(inspector);
      } catch (error) {
        if (resultsHost.isConnected) {
          statusLine.replaceChildren(el("span", { text: "Search failed: " + error.message }));
          toast("Inspector search failed", error.message, "error");
        }
      } finally {
        searchButton.disabled = false;
        searchButton.textContent = "Search";
      }
    }

    function renderInspectorRows(current) {
      const result = packetTable(current.rows, { compact: false, limit: current.limit, empty: "No observations match these filters." });
      current.tbody = result.tbody;
      current.resultsHost.replaceChildren(tableWrap(result.table));
      current.statusLine.replaceChildren(
        el("span", {}, fmtInt(current.rows.length), " observations"),
        el("span", {}, "newest first"),
        el("span", {}, current.live ? "live prepend: on" : "live prepend: off"),
        el("span", { text: "ring search: current filters" }),
      );
    }

    runSearch(filter, live);
  }

  D.registerLoader("inspector", loadInspector);

  async function loadConnections(route, token) {
    const data = await apiGet("/api/connections");
    if (token !== D.state.token) return;
    const stateful = data.stateful !== false;
    const stats = data.stats || {};
    const connections = stateful ? (data.connections || []) : [];
    const rows = connections.map((connection) => ({
      cells: [
        el("span", { class: "cell-mono", text: connection.source }),
        el("span", { class: "cell-mono", text: connection.destination }),
        badge("TCP", "blue"),
        connection.source_port + " → " + connection.dest_port,
        badge(connection.state || "unknown", connection.state === "established" ? "good" : "muted"),
        fmtNumber(connection.duration_seconds, 1) + "s",
        fmtInt(connection.packets),
        fmtBytes(connection.bytes),
        timeNode(connection.last_seen),
      ],
    }));
    const connTable = table([
      "Source", "Destination", "Protocol", "Ports", "State", { label: "Duration", class: "numeric" },
      { label: "Packets", class: "numeric" }, { label: "Bytes", class: "numeric" }, "Last seen",
    ], rows, { compact: true, empty: stateful ? "No established TCP sessions inferred from the current sample stream." : "Stateful protection is disabled; the sensor is not tracking connections." });
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "A best-effort view of plausible TCP conversations. Sampling frequently misses handshakes, so an empty table or an incomplete handshake is not proof of malicious traffic." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      stateful ? null : el("div", { class: "banner banner-warn" }, el("strong", { text: "Stateless protection. " }), "detection.stateful is false, so connection tracking, out-of-state TCP evidence, and handshake trust are disabled. Detection still uses sampled rates, protocol and SYN mixes, reputation, blocklists, and application rules."),
      el("div", { class: "grid-kpi" },
        kpi("Protection", stateful ? "stateful" : "stateless", stateful ? "TCP session tracking" : "no connection table", { variant: stateful ? "good" : "warn" }),
        kpi("Established", fmtInt(stats.established), "sessions", { variant: "good" }),
        kpi("Pending", fmtInt(stats.pending), "handshakes in progress"),
        kpi("Tracked", fmtInt(stats.tracked), "bounded session table"),
        kpi("Out of state", fmtInt(stats.out_of_state), "samples inconsistent with state"),
        kpi("Evicted", fmtInt(stats.evicted), "capacity pressure"),
        kpi("Total seen", fmtInt(stats.total_seen), "packets evaluated"),
      ),
      card("Established sessions", "Inferred from sampled TCP traffic; not a full connection table", tableWrap(connTable.table, "table-scroll-short")),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 6 };
  }

  D.registerLoader("connections", loadConnections);

  async function loadBlocklist(route, token) {
    const [info, trust] = await Promise.all([apiGet("/api/blocklist"), apiGet("/api/trust")]);
    if (token !== D.state.token) return;
    const files = info.files || [];
    const warnings = info.warnings || [];
    const manual = info.manual || [];
    const trusted = trust.manual || [];
    const trustedRows = trusted.map((item) => ({
      cells: [
        destinationLink(item.destination),
        el("span", { class: "cell-mono", text: item.source }),
        badge(item.manual ? "manual" : "earned", item.manual ? "info" : "muted"),
        fmtNumber(item.trust, 1),
        fmtInt(item.handshakes),
        timeNode(item.last_seen),
        el("div", { class: "inline-actions" },
          button("Revoke", {
            small: true,
            variant: "danger",
            onClick: async () => {
              if (!window.confirm("Revoke trust for " + item.source + " toward " + item.destination + "?")) return;
              try {
                await mutate("/api/trust", "POST", { destination: item.destination, source: item.source, trusted: false });
                toast("Manual trust revoked", item.source + " → " + item.destination, "info");
                D.refreshCurrent();
              } catch (error) {
                toast("Could not revoke trust", error.message, "error");
              }
            },
          }),
        ),
      ],
    }));
    const trustTable = table(["Destination", "Source", "Kind", { label: "Trust", class: "numeric" }, { label: "Handshakes", class: "numeric" }, "Last seen", "Actions"], trustedRows, {
      compact: true,
      empty: "No manual trust decisions. Earning trust through good behaviour is separate from a manual exemption.",
    });
    const fileRows = files.map((file) => ({
      cells: [
        el("span", { class: "cell-mono", text: file.name }),
        fmtInt(file.entries),
        file.manual ? badge("manual", "info") : badge("file", "muted"),
        timeNode(file.modified),
        file.error ? badge("error", "danger") : badge("loaded", "good"),
        file.error ? el("span", { class: "cell-secondary", text: file.error }) : "—",
      ],
    }));
    const filesTable = table(["File", { label: "Entries", class: "numeric" }, "Kind", "Modified", "Status", "Error"], fileRows, { compact: true, empty: "No blocklist directory or files configured/loaded." });
    const manualRows = manual.map((entry) => ({
      cells: [
        el("span", { class: "cell-mono", text: entry }),
        el("div", { class: "inline-actions" },
          button("Remove", {
            small: true,
            variant: "danger",
            onClick: async () => {
              if (!window.confirm("Remove " + entry + " from the manual blocklist?")) return;
              try {
                await mutate("/api/blocklist", "DELETE", { entry });
                toast("Blocklist entry removed", entry, "info");
                D.refreshCurrent();
              } catch (error) {
                toast("Could not remove entry", error.message, "error");
              }
            },
          }),
        ),
      ],
    }));
    const manualTable = table(["Manual entry", "Actions"], manualRows, { compact: true, empty: "No manual entries. Add a source IP or prefix below." });
    const entryInput = el("input", { class: "input", placeholder: "198.51.100.7 or 198.51.100.0/24", required: true, autocomplete: "off" });
    const addButton = button("Add entry", { type: "submit", variant: "primary" });
    const addForm = el("form", {
      class: "form",
      onSubmit: async (event) => {
        event.preventDefault();
        const entry = entryInput.value.trim();
        if (!entry) return;
        addButton.disabled = true;
        addButton.textContent = "Adding…";
        try {
          await mutate("/api/blocklist", "POST", { entry });
          entryInput.value = "";
          toast("Blocklist entry added", entry, "good");
          D.refreshCurrent();
        } catch (error) {
          toast("Could not add entry", error.message, "error");
          addButton.disabled = false;
          addButton.textContent = "Add entry";
        }
      },
    },
      el("div", { class: "form-row" },
        el("div", { class: "form-field" }, el("label", { text: "Source IP or prefix" }), entryInput),
        addButton,
      ),
      el("div", { class: "form-hint", text: "Entries are validated before they are written. Default routes and prefixes overlapping a protected range are refused. A match produces a critical alert and a source+destination+protocol discard." }),
    );
    const reloadButton = button("Reload from disk", {
      small: true,
      onClick: async () => {
        reloadButton.disabled = true;
        try {
          const result = await mutate("/api/blocklist/reload", "POST");
          const count = result.warnings ? result.warnings.length : 0;
          toast("Blocklist reloaded", count ? count + " warning(s); see the active list" : "All files parsed cleanly", count ? "warn" : "good");
          D.refreshCurrent();
        } catch (error) {
          toast("Blocklist reload failed", error.message, "error");
          reloadButton.disabled = false;
        }
      },
    });
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "The blocklist is deterministic: a matching external source is always treated as critical, regardless of its TrustScore. Protected sources are never blocked, and destination-only discards are refused." }),
        el("div", { class: "view-actions" }, reloadButton, refreshButton()),
      ),
      warnings.length ? el("div", { class: "banner banner-warn" }, el("strong", { text: "Blocklist warnings. " }), el("ul", { class: "warn-list" }, warnings.map((warning) => el("li", { text: warning })))) : null,
      el("div", { class: "grid-kpi" },
        kpi("Active entries", fmtInt(info.entries), "compiled prefixes", { variant: "accent" }),
        kpi("Source files", fmtInt(files.length), "plus manual file"),
        kpi("Manual entries", fmtInt(manual.length), "operator-managed"),
        kpi("Loaded", info.loaded_at ? relativeTime(info.loaded_at) : "never", info.manual_file || ""),
      ),
      el("div", { class: "stack" },
        card("Manual blocklist", "Atomic add/remove; writes the configured manual file", addForm),
        card("Manual entries", "These match exactly as compiled prefixes", tableWrap(manualTable.table)),
        card("Manual trust / whitelist", "Contextual exemptions; trust always belongs to one destination", tableWrap(trustTable.table)),
        card("Source files", "Reloads swap an immutable snapshot atomically", tableWrap(filesTable.table)),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 0 };
  }

  D.registerLoader("blocklist", loadBlocklist);

  async function loadMitigation(route, token) {
    const data = await apiGet("/api/mitigations");
    if (token !== D.state.token) return;
    const counts = data.counts || {};
    const active = data.active || [];
    const history = data.history || [];
    const bgp = data.bgp;
    let bgpBody;
    if (bgp) {
      bgpBody = kvList([
        ["State", badge(bgp.state || "unknown", bgp.state === "established" ? "good" : "warn")],
        ["Peer", bgp.peer || "—"],
        ["Local / peer AS", bgp.local_as + " / " + bgp.peer_as],
        ["Capabilities", (bgp.four_byte_as ? "AS4 " : "") + (bgp.peer_flowspec ? "Flowspec" : "") || "—"],
        ["Connected at", formatDateTime(bgp.connected_at)],
        ["Uptime", fmtDuration(bgp.uptime_seconds)],
        ["Updates / withdrawals", fmtInt(bgp.updates_sent) + " / " + fmtInt(bgp.withdrawals_sent)],
        ["Hold time", fmtNumber(bgp.hold_seconds, 0) + "s"],
        ["Last error", bgp.last_error || "—"],
      ]);
    } else {
      bgpBody = el("div", {},
        el("div", { class: "banner banner-info" }, el("strong", { text: "BGP is disabled. " }), "Every action below is simulated: it is validated, deduplicated, expired, and withdrawn exactly like a real action, but no network command is sent."),
        chips(["no peer", "no announcements", "simulated lifecycle", "safe default"]),
      );
    }
    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "Mitigation is deliberately conservative. Actions are deduplicated, bounded, expire automatically, and are withdrawn on shutdown. Source directionality and protected-space rules are enforced by the manager." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      simBanner({ simulated: data.simulated }),
      el("div", { class: "grid-kpi" },
        kpi("Live", fmtInt(counts.live), "active or simulated", { variant: "good" }),
        kpi("Simulated", fmtInt(counts.simulated), "no BGP update", { variant: "blue" }),
        kpi("Announced", fmtInt(counts.active), "live BGP actions"),
        kpi("Failed", fmtInt(counts.failed), "retain failure detail", { variant: counts.failed ? "danger" : "" }),
        kpi("History", fmtInt(counts.history), "bounded records"),
        kpi("Withdrawn / expired", fmtInt(counts.withdrawn) + " / " + fmtInt(counts.expired), "completed lifecycle"),
      ),
      el("div", { class: "grid-main" },
        el("div", { class: "stack" },
          card("Active mitigations", "Withdrawing an action is immediate and auditable", tableWrap(actionTable(active, true).table)),
          card("Action history", "Newest actions first, including failures and expirations", tableWrap(actionTable(history, true).table, "table-scroll-short")),
        ),
        el("div", { class: "stack" },
          card("BGP speaker", (data.simulated ? "Simulation mode" : "Peer and session state"), bgpBody),
          card("Guardrails", "These checks run before every action", el("ul", { class: "signal-list" },
            el("li", { text: "Destination must be inside an explicit protected prefix." }),
            el("li", { text: "Mitigation never targets a default route." }),
            el("li", { text: "RTBH targets only an external source; source directionality is enforced." }),
            el("li", { text: "Destination-only Flowspec discard is refused." }),
            el("li", { text: "Equivalent actions are deduplicated and active actions are capped." }),
            el("li", { text: "Shutdown withdraws actions before it exits." }),
          )),
        ),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 5 };
  }

  D.registerLoader("mitigation", loadMitigation);

  const RULE_TCP_FLAGS = [
    ["FIN", 1], ["SYN", 2], ["RST", 4], ["PSH", 8],
    ["ACK", 16], ["URG", 32], ["ECE", 64], ["CWR", 128],
  ];

  function ruleProtocolLabel(value) {
    switch (Number(value)) {
      case 0: return "any protocol";
      case 1: return "ICMP";
      case 6: return "TCP";
      case 17: return "UDP";
      case 47: return "GRE";
      case 50: return "ESP";
      case 51: return "AH";
      default: return "protocol " + value;
    }
  }

  function ruleFlagText(bits) {
    const value = Number(bits) || 0;
    return RULE_TCP_FLAGS.filter(([, bit]) => value & bit).map(([name]) => name).join("+");
  }

  function clampInt(value, min, max) {
    const number = Math.trunc(Number(value));
    if (!Number.isFinite(number)) return min || 0;
    if (min !== undefined && number < min) return min;
    if (max !== undefined && number > max) return max;
    return number;
  }

  function ruleNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number > 0 ? number : 0;
  }

  function rulePayloadText(payload) {
    if (!payload || !payload.mode || payload.mode === "none") return "";
    const pattern = payload.pattern ? "“" + payload.pattern + "”" : "";
    if (payload.mode === "absent_first_n") return pattern + " absent in first " + (payload.first_n || 0) + " sampled";
    if (payload.mode === "present_first_n") return pattern + " present in first " + (payload.first_n || 0) + " sampled";
    const kind = payload.kind && payload.kind !== "contains" ? payload.kind + " " : "";
    return "payload " + kind + pattern;
  }

  function ruleMatchSummaryNode(rule) {
    const match = rule.match || {};
    const secondary = [];
    if (match.source) secondary.push("from " + match.source);
    if (match.protocol) secondary.push(ruleProtocolLabel(match.protocol));
    const range = (min, max, unit) => {
      if (min && max) return min + "–" + max + " " + unit;
      if (min) return "≥ " + min + " " + unit;
      if (max) return "≤ " + max + " " + unit;
      return "";
    };
    if (match.src_port) secondary.push("sport " + match.src_port);
    else {
      const srcRange = range(match.src_port_min, match.src_port_max, "");
      if (srcRange) secondary.push("sport " + srcRange);
    }
    if (match.dst_port) secondary.push("dport " + match.dst_port);
    else {
      const dstRange = range(match.dst_port_min, match.dst_port_max, "");
      if (dstRange) secondary.push("dport " + dstRange);
    }
    if (match.tcp_flags) secondary.push("flags " + ruleFlagText(match.tcp_flags));
    if (match.packet_length) secondary.push("length " + match.packet_length);
    else {
      const lenRange = range(match.packet_length_min, match.packet_length_max, "B");
      if (lenRange) secondary.push(lenRange);
    }
    if (match.fragment) secondary.push("fragmented only");
    if (match.direction) secondary.push(match.direction);
    return el("div", {},
      el("span", { class: "cell-mono", text: match.destination || "—" }),
      el("div", { class: "cell-secondary", text: secondary.length ? secondary.join(" · ") : "any protocol, port, or direction" }),
    );
  }

  function ruleConditionSummaryNode(rule) {
    if (rule.mode === "standing") return el("span", { class: "muted", text: "always active" });
    const condition = rule.condition || {};
    const parts = [];
    if (condition.min_pps) parts.push("≥ " + fmtPPS(condition.min_pps));
    if (condition.min_bps) parts.push("≥ " + fmtBPS(condition.min_bps));
    if (condition.min_packets) parts.push("≥ " + fmtInt(condition.min_packets) + " sampled packets");
    if (condition.min_bytes) parts.push("≥ " + fmtBytes(condition.min_bytes));
    if (condition.min_sources) parts.push("≥ " + fmtInt(condition.min_sources) + " distinct sources");
    const payload = rulePayloadText(condition.payload);
    if (payload) parts.push(payload);
    const window = condition.window_seconds ? "in " + condition.window_seconds + "s" : "";
    const consecutive = condition.consecutive > 1 ? "for " + condition.consecutive + " windows" : "";
    return el("div", {},
      el("div", { text: parts.length ? parts.join(" and ") : "—" }),
      el("div", { class: "cell-secondary", text: [window, consecutive, condition.cooldown_seconds ? "cooldown " + fmtDuration(condition.cooldown_seconds) : ""].filter(Boolean).join(" · ") || "immediate on match" }),
    );
  }

  function ruleActionCell(rule) {
    const action = rule.action || {};
    const secondary = [];
    if (action.type === "rate-limit") secondary.push(fmtBPS(action.rate_limit_bps || 0) + " cap");
    if (action.type === "allow") secondary.push("local bypass only");
    if (action.duration_seconds) secondary.push(fmtDuration(action.duration_seconds));
    secondary.push(action.scope === "flow" ? "observed conversation" : "rule header");
    return el("div", {},
      el("div", {}, badge(action.type || "—", ruleActionKind(action.type))),
      el("div", { class: "cell-secondary", text: secondary.join(" · ") }),
    );
  }

  function ruleStateCell(rule) {
    const stats = rule.stats || {};
    const state = stats.state || (rule.enabled ? "idle" : "disabled");
    return el("div", {},
      el("div", {}, badge(state, ruleStateKind(state))),
      stats.action_status ? el("div", { class: "cell-secondary", text: stats.action_status }) : null,
      stats.last_error ? el("div", { class: "cell-secondary danger-text", text: stats.last_error }) : null,
    );
  }

  function ruleActivityCell(rule) {
    const stats = rule.stats || {};
    return el("div", {},
      el("div", { text: fmtInt(stats.hits) + " hits · " + fmtInt(stats.triggers) + " triggers" }),
      el("div", { class: "cell-secondary", text: fmtInt(stats.suppressed) + " suppressed · " + (stats.last_hit ? relativeTime(stats.last_hit) : "never fired") }),
    );
  }

  function ruleField(label, control, hint, extraClass) {
    return el("div", { class: "form-field" + (extraClass ? " " + extraClass : "") },
      el("label", { text: label }),
      control,
      hint ? el("div", { class: "form-hint", text: hint }) : null,
    );
  }

  function ruleText(value, placeholder) {
    return el("input", { class: "input", type: "text", value: value || "", placeholder: placeholder || "", autocomplete: "off", spellcheck: "false" });
  }

  function ruleNumberInput(value, step, placeholder, min, max) {
    return el("input", {
      class: "input",
      type: "number",
      min: min === undefined ? "0" : String(min),
      max: max === undefined ? null : String(max),
      step: step || "1",
      value: value === undefined || value === null || value === 0 ? "" : String(value),
      placeholder: placeholder || "",
    });
  }

  function ruleSelect(options, value) {
    const select = el("select", { class: "input" });
    for (const [optionValue, label] of options) {
      select.appendChild(el("option", { value: String(optionValue), text: label }));
    }
    select.value = String(value === undefined || value === null ? options[0][0] : value);
    return select;
  }

  function ruleSection(title, subtitle, ...body) {
    return el("section", { class: "form-section" },
      el("div", { class: "form-section-head" },
        el("div", { class: "form-section-title", text: title }),
        subtitle ? el("div", { class: "form-section-sub", text: subtitle }) : null,
      ),
      body,
    );
  }

  function renderRulePreview(container, preview) {
    const samples = preview.samples || [];
    const stat = (label, value, sub) => el("div", { class: "preview-stat" },
      el("div", { class: "preview-stat-label", text: label }),
      el("div", { class: "preview-stat-value", text: value }),
      el("div", { class: "preview-stat-sub", text: sub || "" }),
    );
    const sampleRows = samples.map((obs) => ({
      cells: [
        timeNode(obs.received_at),
        el("span", { class: "cell-mono", text: (obs.src_ip || "?") + (obs.src_port ? ":" + obs.src_port : "") }),
        el("span", { class: "cell-mono", text: (obs.dst_ip || "?") + (obs.dst_port ? ":" + obs.dst_port : "") }),
        ruleProtocolLabel(obs.protocol),
        obs.tcp_flags || "—",
        obs.payload_preview ? String(obs.payload_preview).slice(0, 80) : "—",
      ],
    }));
    const sampleTable = table(
      ["Time", "Source", "Destination", "Protocol", "Flags", "Payload preview"],
      sampleRows,
      { compact: true, empty: "No sampled observation in the ring matches this draft." },
    );
    container.replaceChildren(
      el("div", { class: "preview-head" },
        el("div", { class: "form-section-title", text: "Preview against recent samples" }),
        el("div", { class: "small muted", text: "Uses sampled observations only; this is not an inline packet replay." }),
      ),
      el("div", { class: "preview-stats" },
        stat("Matched samples", fmtInt(preview.matched), "in the bounded ring"),
        stat("Flows", fmtInt(preview.flows), "distinct conversations"),
        stat("Potential triggers", fmtInt(preview.potential_triggers), "first-N projections"),
        stat("Estimated packets", fmtInt(preview.estimated_packets), "sampled projection"),
        stat("Estimated bytes", fmtBytes(preview.estimated_bytes), "sampled projection"),
        stat("Equivalent rate", fmtPPS(preview.equivalent_pps) + " · " + fmtBPS(preview.equivalent_bps), "over observed span"),
      ),
      preview.warning ? el("div", { class: "banner banner-info", text: preview.warning }) : null,
      tableWrap(sampleTable.table, "table-scroll-short"),
    );
    container.classList.remove("hidden");
  }

  function openRuleEditor(rule, data) {
    const existing = Boolean(rule && rule.id);
    const candidate = rule ? JSON.parse(JSON.stringify(rule)) : {
      name: "",
      description: "",
      enabled: true,
      mode: "standing",
      match: {
        destination: "", source: "", protocol: 0,
        src_port: 0, dst_port: 0,
        src_port_min: 0, src_port_max: 0,
        dst_port_min: 0, dst_port_max: 0,
        tcp_flags: 0,
        packet_length: 0, packet_length_min: 0, packet_length_max: 0,
        fragment: false, direction: "",
      },
      condition: { window_seconds: 5, consecutive: 1, cooldown_seconds: 0, min_sources: 0, payload: { mode: "none", encoding: "text", kind: "contains" } },
      action: { type: "allow", scope: "rule", rate_limit_bps: 0, duration_seconds: 0 },
    };
    const defaults = (data && data.defaults) || {};
    const limits = (data && data.limits) || {};
    const match = candidate.match || {};
    const condition = candidate.condition || {};
    const payload = condition.payload || {};
    const action = candidate.action || {};

    const nameInput = el("input", {
      class: "input", type: "text", value: candidate.name || "",
      placeholder: "Block scanners to the web prefix", maxlength: "100", required: true, autocomplete: "off",
    });
    const descriptionInput = el("textarea", {
      class: "input", rows: "2", maxlength: "1000",
      placeholder: "Why this policy exists and what it is expected to protect.",
    });
    descriptionInput.value = candidate.description || "";
    const enabledInput = el("input", { type: "checkbox", checked: candidate.enabled !== false });
    const modeSelect = ruleSelect([["standing", "Standing (always active)"], ["conditional", "Conditional (volume or payload trigger)"]], candidate.mode || "standing");

    const destinationInput = ruleText(match.destination, "203.0.113.0/24");
    destinationInput.required = true;
    const sourceInput = ruleText(match.source, "198.51.100.0/24 (optional)");
    const protocolInput = ruleNumberInput(match.protocol, "1", "0 = any, 6 = TCP", 0, 255);
    const srcPortInput = ruleNumberInput(match.src_port, "1", "0 = any", 0, 65535);
    const dstPortInput = ruleNumberInput(match.dst_port, "1", "0 = any", 0, 65535);
    const srcPortMinInput = ruleNumberInput(match.src_port_min, "1", "min", 0, 65535);
    const srcPortMaxInput = ruleNumberInput(match.src_port_max, "1", "max", 0, 65535);
    const dstPortMinInput = ruleNumberInput(match.dst_port_min, "1", "min", 0, 65535);
    const dstPortMaxInput = ruleNumberInput(match.dst_port_max, "1", "max", 0, 65535);
    const packetLengthInput = ruleNumberInput(match.packet_length, "1", "0 = any", 0, 65535);
    const packetLengthMinInput = ruleNumberInput(match.packet_length_min, "1", "min", 0, 65535);
    const packetLengthMaxInput = ruleNumberInput(match.packet_length_max, "1", "max", 0, 65535);
    const fragmentInput = el("input", { type: "checkbox", checked: Boolean(match.fragment) });
    const directionSelect = ruleSelect([["", "Any direction"], ["inbound", "Inbound"], ["internal", "Internal"]], match.direction || "");

    const flags = new Map();
    const flagWrap = el("div", { class: "flag-grid" });
    for (const [flagName, bit] of RULE_TCP_FLAGS) {
      const checkbox = el("input", { type: "checkbox", checked: (Number(match.tcp_flags) || 0) & bit });
      flags.set(bit, checkbox);
      flagWrap.appendChild(el("label", { class: "checkbox-line flag-pill" }, checkbox, flagName));
    }

    const windowInput = ruleNumberInput(condition.window_seconds || 5, "1", "5", 1, 60);
    const minPPSInput = ruleNumberInput(condition.min_pps, "any", "0 = disabled");
    const minBPSInput = ruleNumberInput(condition.min_bps, "any", "bits per second");
    const minPacketsInput = ruleNumberInput(condition.min_packets, "1", "sampled observations");
    const minBytesInput = ruleNumberInput(condition.min_bytes, "1", "estimated bytes");
    const minSourcesInput = ruleNumberInput(condition.min_sources, "1", "distinct sources", 0, 65535);
    const consecutiveInput = ruleNumberInput(condition.consecutive || 1, "1", "1", 1, 60);
    const cooldownInput = ruleNumberInput(condition.cooldown_seconds, "1", "0 = none");
    const payloadModeSelect = ruleSelect([
      ["none", "No payload condition"],
      ["contains", "Payload contains pattern"],
      ["absent_first_n", "Pattern absent in first N sampled packets"],
      ["present_first_n", "Pattern present in first N sampled packets"],
    ], payload.mode || "none");
    const payloadPatternInput = ruleText(payload.pattern, "USER anonymous or \\x16\\x03");
    const payloadEncodingSelect = ruleSelect([["text", "Text"], ["hex", "Hex"]], payload.encoding || "text");
    const payloadKindSelect = ruleSelect([["contains", "Contains"], ["prefix", "Prefix"], ["suffix", "Suffix"], ["regex", "Regular expression"]], payload.kind || "contains");
    const payloadCaseInput = el("input", { type: "checkbox", checked: Boolean(payload.case_insensitive) });
    const payloadOffsetInput = ruleNumberInput(payload.offset, "1", "0", 0, 512);
    const payloadFirstNInput = ruleNumberInput(payload.first_n, "1", "5", 1, 1000);

    const actionTypeSelect = ruleSelect([
      ["allow", "Allow / local bypass"],
      ["discard", "Discard"],
      ["rate-limit", "Rate limit"],
    ], action.type || "allow");
    const rateLimitInput = ruleNumberInput(action.rate_limit_bps, "any", defaults.rate_limit_bps ? String(defaults.rate_limit_bps) + " (default)" : "bits per second");
    const durationInput = ruleNumberInput(action.duration_seconds, "1", defaults.duration_seconds ? String(defaults.duration_seconds) + " (default)" : "seconds");
    const scopeSelect = ruleSelect([["rule", "Rule header"], ["flow", "Observed conversation"]], action.scope || "rule");

    const conditionSection = ruleSection("Trigger conditions", "Evaluated only for conditional rules against sampled observations.",
      el("div", { class: "form-grid" },
        ruleField("Window (seconds)", windowInput, "Rolling window, 1–60 seconds."),
        ruleField("Minimum PPS", minPPSInput, "Sampled packets per second."),
        ruleField("Minimum BPS", minBPSInput, "Bits per second; 0 disables."),
        ruleField("Minimum packets", minPacketsInput, "Sampled observations in the window."),
        ruleField("Minimum bytes", minBytesInput, "Estimated bytes in the window."),
        ruleField("Minimum distinct sources", minSourcesInput, "Distributed-attack guard; requires an empty source prefix. Sampling bounds what can be counted."),
        ruleField("Consecutive windows", consecutiveInput, "Threshold must hold repeatedly."),
        ruleField("Cooldown (seconds)", cooldownInput, "Suppress repeat triggers after a fire."),
      ),
      el("div", { class: "form-grid form-grid-top" },
        ruleField("Payload condition", payloadModeSelect, "Payload is sampled and capped at the capture budget (512 bytes)."),
        ruleField("Pattern", payloadPatternInput, "Text or hexadecimal bytes; at most 256 bytes."),
        ruleField("Encoding", payloadEncodingSelect),
        ruleField("Match kind", payloadKindSelect, "Regular expressions require text encoding."),
        ruleField("Offset (bytes)", payloadOffsetInput, "Skip bytes before matching."),
        ruleField("First N sampled", payloadFirstNInput, "Counts sampled observations, not every packet."),
      ),
      el("label", { class: "checkbox-line" }, payloadCaseInput, "Case-insensitive text matching"),
      el("div", { class: "form-hint" }, "First-N rules cannot also use volume or distinct-source thresholds. Payload conditions apply to sampled packets only; enforcement remains a header match."),
    );

    const actionSection = ruleSection("Enforcement action", "Every action is subject to protected-prefix and default-route guardrails.",
      el("div", { class: "form-grid" },
        ruleField("Action", actionTypeSelect),
        ruleField("Rate limit (BPS)", rateLimitInput, "Only used by rate-limit; 0 uses the configured default."),
        ruleField("Duration (seconds)", durationInput, "0 uses the configured default."),
        ruleField("Scope", scopeSelect, "Flow scope narrows enforcement to the observed conversation."),
      ),
      el("div", { class: "form-hint", id: "rule-action-note" }),
      el("div", { class: "form-hint" }, "Allow is a local bypass of Dolly's automatic mitigation, not a BGP permit. Conditional allow is rejected because there is no meaningful enforcement."),
    );

    const previewBox = el("div", { class: "rule-preview hidden" });
    const formError = el("div", { class: "form-error hidden" });
    const saveButton = button(existing ? "Save changes" : "Create rule", { type: "submit", variant: "primary" });
    const previewButton = button("Preview samples", { onClick: () => runPreview() });

    function syncProtocol() {
      const protocol = clampInt(protocolInput.value, 0, 255);
      const tcp = protocol === 6;
      for (const checkbox of flags.values()) checkbox.disabled = !tcp;
      flagWrap.classList.toggle("form-disabled", !tcp);
      if (!tcp) {
        for (const checkbox of flags.values()) checkbox.checked = false;
      }
      const portOK = tcp || protocol === 17;
      for (const field of [srcPortInput, dstPortInput, srcPortMinInput, srcPortMaxInput, dstPortMinInput, dstPortMaxInput]) {
        field.disabled = !portOK;
        const wrapper = field.closest(".form-field");
        if (wrapper) wrapper.classList.toggle("form-disabled", !portOK);
      }
      if (!portOK) {
        for (const field of [srcPortInput, dstPortInput, srcPortMinInput, srcPortMaxInput, dstPortMinInput, dstPortMaxInput]) {
          field.value = "";
        }
      }
    }

    function syncMode() {
      const conditional = modeSelect.value === "conditional";
      for (const input of conditionSection.querySelectorAll("input, select, textarea")) {
        input.disabled = !conditional;
      }
      conditionSection.classList.toggle("form-disabled", !conditional);
      if (!conditional) scopeSelect.value = "rule";
      syncPayload();
      syncAction();
    }

    function syncAction() {
      const type = actionTypeSelect.value;
      const rate = type === "rate-limit";
      rateLimitInput.disabled = !rate;
      rateLimitInput.closest(".form-field").classList.toggle("form-disabled", !rate);
      durationInput.disabled = type === "allow";
      durationInput.closest(".form-field").classList.toggle("form-disabled", type === "allow");
      scopeSelect.disabled = modeSelect.value === "standing" || type === "allow";
      scopeSelect.closest(".form-field").classList.toggle("form-disabled", scopeSelect.disabled);
      const note = document.getElementById("rule-action-note");
      if (note) {
        note.textContent = type === "allow"
          ? "Allow never announces a BGP permit. It only suppresses Dolly's automatic mitigation for matching traffic."
          : type === "rate-limit"
            ? "Rate limiting is announced as a Flowspec action; the configured default applies when no explicit rate is set."
            : "Discard is announced as a Flowspec action. A rule-scoped discard needs a source prefix unless destination-only discard is enabled.";
      }
    }

    function syncPayload() {
      const conditional = modeSelect.value === "conditional";
      const mode = payloadModeSelect.value;
      const active = conditional && mode !== "none";
      const firstN = active && (mode === "absent_first_n" || mode === "present_first_n");
      for (const field of [payloadModeSelect, payloadPatternInput, payloadEncodingSelect, payloadKindSelect, payloadCaseInput, payloadOffsetInput]) {
        field.disabled = !conditional || (!active && field !== payloadModeSelect);
        const wrapper = field.closest(".form-field");
        if (wrapper) wrapper.classList.toggle("form-disabled", field.disabled);
      }
      payloadPatternInput.required = active;
      payloadFirstNInput.disabled = !firstN;
      const firstWrapper = payloadFirstNInput.closest(".form-field");
      if (firstWrapper) firstWrapper.classList.toggle("form-disabled", !firstN);
      if (!firstN) payloadFirstNInput.value = "";
    }

    function collectRule() {
      const mode = modeSelect.value;
      const protocol = clampInt(protocolInput.value, 0, 255);
      let tcpFlags = 0;
      if (protocol === 6) {
        for (const [bit, checkbox] of flags) {
          if (checkbox.checked) tcpFlags |= bit;
        }
      }
      const outPayload = { mode: "none" };
      if (mode === "conditional" && payloadModeSelect.value !== "none") {
        outPayload.mode = payloadModeSelect.value;
        outPayload.pattern = payloadPatternInput.value;
        outPayload.encoding = payloadEncodingSelect.value;
        outPayload.kind = payloadKindSelect.value;
        outPayload.case_insensitive = payloadCaseInput.checked;
        outPayload.offset = clampInt(payloadOffsetInput.value, 0, 512);
        if (outPayload.mode !== "contains") {
          outPayload.first_n = clampInt(payloadFirstNInput.value, 1, 1000);
        }
      }
      const outCondition = { payload: outPayload };
      if (mode === "conditional") {
        outCondition.window_seconds = clampInt(windowInput.value, 1, 60);
        outCondition.min_pps = ruleNumber(minPPSInput.value);
        outCondition.min_bps = ruleNumber(minBPSInput.value);
        outCondition.min_packets = clampInt(minPacketsInput.value, 0);
        outCondition.min_bytes = clampInt(minBytesInput.value, 0);
        outCondition.min_sources = clampInt(minSourcesInput.value, 0, 65535);
        outCondition.consecutive = clampInt(consecutiveInput.value, 1, 60);
        outCondition.cooldown_seconds = clampInt(cooldownInput.value, 0, 86400);
      }
      const outAction = { type: actionTypeSelect.value, scope: "rule" };
      if (outAction.type === "rate-limit") outAction.rate_limit_bps = Math.trunc(ruleNumber(rateLimitInput.value));
      if (outAction.type !== "allow") outAction.duration_seconds = clampInt(durationInput.value, 0, 86400);
      if (mode === "conditional" && outAction.type !== "allow") outAction.scope = scopeSelect.value;
      return {
        name: nameInput.value.trim(),
        description: descriptionInput.value.trim(),
        enabled: enabledInput.checked,
        mode: mode,
        match: {
          destination: destinationInput.value.trim(),
          source: sourceInput.value.trim(),
          protocol: protocol,
          src_port: clampInt(srcPortInput.value, 0, 65535),
          dst_port: clampInt(dstPortInput.value, 0, 65535),
          src_port_min: clampInt(srcPortMinInput.value, 0, 65535),
          src_port_max: clampInt(srcPortMaxInput.value, 0, 65535),
          dst_port_min: clampInt(dstPortMinInput.value, 0, 65535),
          dst_port_max: clampInt(dstPortMaxInput.value, 0, 65535),
          tcp_flags: tcpFlags,
          packet_length: clampInt(packetLengthInput.value, 0, 65535),
          packet_length_min: clampInt(packetLengthMinInput.value, 0, 65535),
          packet_length_max: clampInt(packetLengthMaxInput.value, 0, 65535),
          fragment: fragmentInput.checked,
          direction: directionSelect.value,
        },
        condition: outCondition,
        action: outAction,
      };
    }

    function showError(message) {
      formError.textContent = message;
      formError.classList.remove("hidden");
    }

    function clearError() {
      formError.classList.add("hidden");
      formError.textContent = "";
    }

    function validateLocal(candidateRule) {
      if (!candidateRule.name) return "A rule name is required.";
      if (!candidateRule.match.destination) return "A destination prefix is required.";
      if (candidateRule.mode === "conditional" && candidateRule.action.type === "allow") {
        return "Conditional allow is not supported. Use a standing allow rule or choose a different action.";
      }
      const m = candidateRule.match;
      if (m.src_port && (m.src_port_min || m.src_port_max)) {
        return "Source port cannot be both an exact value and a range.";
      }
      if (m.dst_port && (m.dst_port_min || m.dst_port_max)) {
        return "Destination port cannot be both an exact value and a range.";
      }
      if (m.packet_length && (m.packet_length_min || m.packet_length_max)) {
        return "Packet length cannot be both an exact value and a range.";
      }
      if (m.src_port_min > m.src_port_max || m.dst_port_min > m.dst_port_max || m.packet_length_min > m.packet_length_max) {
        return "Range minimum must not exceed its maximum.";
      }
      if ((m.src_port_min || m.dst_port_min) && m.protocol !== 6 && m.protocol !== 17) {
        return "Port ranges need protocol TCP or UDP.";
      }
      if (candidateRule.mode === "conditional" && candidateRule.condition.min_sources > 0 && candidateRule.match.source) {
        return "Minimum distinct sources requires an empty source prefix.";
      }
      return "";
    }

    async function runPreview() {
      clearError();
      const payloadRule = collectRule();
      let problem = validateLocal(payloadRule);
      if (!problem && payloadRule.mode === "conditional" && payloadRule.action.type === "discard" &&
          payloadRule.action.scope !== "flow" && !payloadRule.match.source) {
        // The server refuses rule-scoped destination-only discards; surface that
        // constraint before the round trip so the operator can fix it locally.
        payloadRule.match.source = "198.51.100.0/24";
      }
      if (problem) {
        showError(problem);
        return;
      }
      previewButton.disabled = true;
      previewButton.textContent = "Previewing…";
      try {
        const result = await mutate("/api/rules/preview", "POST", payloadRule);
        renderRulePreview(previewBox, result.preview || {});
      } catch (error) {
        showError(error.message);
      } finally {
        previewButton.disabled = false;
        previewButton.textContent = "Preview samples";
      }
    }

    async function saveRule() {
      clearError();
      const payloadRule = collectRule();
      const problem = validateLocal(payloadRule);
      if (problem) {
        showError(problem);
        return;
      }
      saveButton.disabled = true;
      saveButton.textContent = existing ? "Saving…" : "Creating…";
      try {
        const result = existing
          ? await mutate("/api/rules/" + encodeURIComponent(rule.id), "PUT", payloadRule)
          : await mutate("/api/rules", "POST", payloadRule);
        D.closeDrawer();
        toast(existing ? "Rule updated" : "Rule created", (result.rule && result.rule.name) || payloadRule.name, "good");
        D.refreshCurrent();
      } catch (error) {
        showError(error.message);
        saveButton.disabled = false;
        saveButton.textContent = existing ? "Save changes" : "Create rule";
      }
    }

    modeSelect.addEventListener("change", syncMode);
    actionTypeSelect.addEventListener("change", syncAction);
    payloadModeSelect.addEventListener("change", syncPayload);
    protocolInput.addEventListener("change", syncProtocol);
    protocolInput.addEventListener("input", syncProtocol);

    const form = el("form", {
      class: "rule-editor",
      onSubmit: (event) => {
        event.preventDefault();
        saveRule();
      },
    },
      ruleSection("Identity", "Names and explanations are stored with the rule and shown in alerts.",
        el("div", { class: "form-grid" },
          ruleField("Name", nameInput, "Required, 100 characters or fewer.", "span-2"),
          ruleField("Description", descriptionInput, "Optional operator context.", "span-2"),
          ruleField("Mode", modeSelect, "Standing rules apply immediately; conditional rules wait for their trigger."),
          el("div", { class: "form-field" },
            el("label", { text: "State" }),
            el("label", { class: "checkbox-line" }, enabledInput, "Enabled"),
            el("div", { class: "form-hint", text: "Disabling a rule withdraws its rule-owned actions." }),
          ),
        ),
      ),
      ruleSection("Header match", "Destination is required. Flowspec enforces these header fields; ranges are inclusive.",
        el("div", { class: "form-grid" },
          ruleField("Destination prefix", destinationInput, "Must be fully inside an explicitly protected prefix. Default routes are refused.", "span-2"),
          ruleField("Source prefix", sourceInput, "Optional. Refused if it overlaps protected space.", "span-2"),
          ruleField("Protocol", protocolInput, "0 = any · 6 TCP · 17 UDP · 1 ICMP."),
          ruleField("Direction", directionSelect),
          ruleField("Source port (exact)", srcPortInput, "0 = any. Use the range instead of an exact value, not both."),
          el("div", { class: "form-field" },
            el("label", { text: "Source port range" }),
            el("div", { class: "range-pair" }, srcPortMinInput, el("span", { class: "range-sep", text: "–" }), srcPortMaxInput),
            el("div", { class: "form-hint", text: "Inclusive min–max. One side can stay empty." }),
          ),
          ruleField("Destination port (exact)", dstPortInput, "0 = any."),
          el("div", { class: "form-field" },
            el("label", { text: "Destination port range" }),
            el("div", { class: "range-pair" }, dstPortMinInput, el("span", { class: "range-sep", text: "–" }), dstPortMaxInput),
            el("div", { class: "form-hint", text: "Inclusive min–max. One side can stay empty." }),
          ),
          ruleField("Packet length (exact)", packetLengthInput, "Exact IP packet length; 0 = any."),
          el("div", { class: "form-field" },
            el("label", { text: "Packet length range (bytes)" }),
            el("div", { class: "range-pair" }, packetLengthMinInput, el("span", { class: "range-sep", text: "–" }), packetLengthMaxInput),
            el("div", { class: "form-hint", text: "Inclusive min–max bytes; e.g. 64–128 to match small packets." }),
          ),
          el("div", { class: "form-field" },
            el("label", { text: "Fragmentation" }),
            el("label", { class: "checkbox-line" }, fragmentInput, "Match fragmented packets only"),
            el("div", { class: "form-hint", text: "Encoded as a Flowspec fragment-bit component." }),
          ),
        ),
        el("div", { class: "form-field" },
          el("label", { text: "TCP flags (all selected bits must match)" }),
          flagWrap,
          el("div", { class: "form-hint", text: "Available for TCP only. Selecting none matches every TCP flag combination." }),
        ),
      ),
      conditionSection,
      actionSection,
      previewBox,
      formError,
      el("div", { class: "rule-editor-footer" },
        el("div", { class: "form-hint" },
          existing
            ? "Updated " + relativeTime(rule.updated_at) + " · " + fmtInt(data && data.limits ? data.limits.max_rules : 0) + " rule capacity"
            : "New rules are validated against protected prefixes before they are persisted.",
        ),
        el("div", { class: "inline-actions" },
          previewButton,
          button("Cancel", { variant: "ghost", onClick: () => D.closeDrawer() }),
          saveButton,
        ),
      ),
    );

    openDrawer(existing ? "Edit rule" : "New rule", existing ? rule.name : "Standing or conditional policy", form);
    syncMode();
    syncProtocol();
    syncPayload();
    syncAction();
  }

  // moveRule calls the move endpoint and refreshes on success.
  async function moveRule(id, position, control) {
    if (control) control.disabled = true;
    try {
      await mutate("/api/rules/" + encodeURIComponent(id) + "/move", "POST", { position });
      D.refreshCurrent();
    } catch (error) {
      toast("Could not move rule", error.message, "error");
      if (control) control.disabled = false;
    }
  }

  // attachRuleDragWire wires HTML5 drag-and-drop reordering on a rendered rule
  // table. Rows carry their rule id and index; dropping a row onto another
  // moves it to that position through the persisted move endpoint.
  function attachRuleDragWire(tableNode, rules) {
    if (!tableNode || !rules || rules.length < 2) return;
    const tbody = tableNode.querySelector("tbody");
    if (!tbody) return;
    let dragging = null;

    tbody.addEventListener("dragstart", (event) => {
      const row = event.target.closest("tr[data-rule-id]");
      if (!row) return;
      dragging = row;
      row.classList.add("dragging");
      event.dataTransfer.effectAllowed = "move";
      try {
        event.dataTransfer.setData("text/plain", row.dataset.ruleId);
      } catch (_) { /* older browsers */ }
    });
    tbody.addEventListener("dragend", () => {
      if (!dragging) return;
      dragging.classList.remove("dragging");
      dragging = null;
      for (const row of tbody.querySelectorAll("tr")) {
        row.classList.remove("drag-over", "drag-over-above", "drag-over-below");
      }
    });
    tbody.addEventListener("dragover", (event) => {
      if (!dragging) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      const row = event.target.closest("tr[data-rule-id]");
      for (const existing of tbody.querySelectorAll("tr")) {
        if (existing !== row) existing.classList.remove("drag-over", "drag-over-above", "drag-over-below");
      }
      if (!row || row === dragging) return;
      const rect = row.getBoundingClientRect();
      const above = event.clientY < rect.top + rect.height / 2;
      row.classList.remove("drag-over", "drag-over-above", "drag-over-below");
      row.classList.add(above ? "drag-over-above" : "drag-over-below");
    });
    tbody.addEventListener("drop", (event) => {
      if (!dragging) return;
      event.preventDefault();
      const row = event.target.closest("tr[data-rule-id]");
      const fromIndex = Number(dragging.dataset.ruleIndex);
      let targetIndex = row && row !== dragging ? Number(row.dataset.ruleIndex) : -1;
      if (row && row !== dragging) {
        const rect = row.getBoundingClientRect();
        if (event.clientY >= rect.top + rect.height / 2) targetIndex += 1;
      }
      const ruleId = dragging.dataset.ruleId;
      dragging.classList.remove("dragging");
      dragging = null;
      for (const existing of tbody.querySelectorAll("tr")) {
        existing.classList.remove("drag-over", "drag-over-above", "drag-over-below");
      }
      if (targetIndex < 0 || !Number.isInteger(targetIndex)) return;
      // Removing the dragged rule first shifts the target when moving down.
      let finalIndex = targetIndex;
      if (fromIndex < targetIndex) finalIndex = targetIndex - 1;
      if (finalIndex === fromIndex) return;
      moveRule(ruleId, finalIndex);
    });
  }

  function ruleRows(rules, data) {
    const total = (rules || []).length;
    return (rules || []).map((rule, index) => {
      const toggle = button(rule.enabled ? "Disable" : "Enable", {
        small: true,
        onClick: async () => {
          toggle.disabled = true;
          try {
            await mutate("/api/rules/" + encodeURIComponent(rule.id) + "/enabled", "PATCH", { enabled: !rule.enabled });
            toast(rule.enabled ? "Rule disabled" : "Rule enabled", rule.name, rule.enabled ? "info" : "good");
            D.refreshCurrent();
          } catch (error) {
            toast("Could not change rule state", error.message, "error");
            toggle.disabled = false;
          }
        },
      });
      const remove = button("Delete", {
        small: true,
        variant: "danger",
        onClick: async () => {
          if (!window.confirm("Delete rule “" + rule.name + "”? Its rule-owned actions will be withdrawn.")) return;
          remove.disabled = true;
          try {
            await mutate("/api/rules/" + encodeURIComponent(rule.id), "DELETE");
            toast("Rule deleted", rule.name, "info");
            D.refreshCurrent();
          } catch (error) {
            toast("Could not delete rule", error.message, "error");
            remove.disabled = false;
          }
        },
      });
      const up = button("↑", {
        small: true,
        variant: "ghost",
        title: "Move rule up",
        disabled: index === 0,
        onClick: () => moveRule(rule.id, index - 1, up),
      });
      const down = button("↓", {
        small: true,
        variant: "ghost",
        title: "Move rule down",
        disabled: index === total - 1,
        onClick: () => moveRule(rule.id, index + 1, down),
      });
      const handle = el("span", { class: "drag-handle", title: "Drag to reorder", text: "⋮⋮" });
      return {
        class: "rule-row",
        dataset: { ruleId: rule.id, ruleIndex: String(index) },
        draggable: "true",
        cells: [
          el("div", { class: "rule-order-cell" },
            handle,
            el("div", {},
              el("div", { class: "cell-primary", text: rule.name }),
              rule.description ? el("div", { class: "cell-secondary", text: rule.description }) : el("div", { class: "cell-mono cell-secondary", text: rule.id }),
            ),
          ),
          el("div", {},
            badge(rule.mode, rule.mode === "standing" ? "accent" : "blue"),
            !rule.enabled ? el("div", { class: "cell-secondary", text: "disabled" }) : null,
          ),
          ruleMatchSummaryNode(rule),
          ruleConditionSummaryNode(rule),
          ruleActionCell(rule),
          ruleStateCell(rule),
          ruleActivityCell(rule),
          el("div", { class: "inline-actions" },
            up,
            down,
            button("Edit", { small: true, onClick: () => openRuleEditor(rule, data) }),
            toggle,
            remove,
          ),
        ],
      };
    });
  }

  async function loadRules(route, token) {
    const data = await apiGet("/api/rules");
    if (token !== D.state.token) return;
    const rules = data.rules || [];
    const summary = data.summary || {};
    const limits = data.limits || {};
    const save = data.save || {};
    const warnings = (data.warnings || []).slice();
    if (save.error) warnings.push("Rules could not be persisted: " + save.error);
    if (!data.enabled) warnings.push("The rules engine is disabled in configuration. Definitions are shown but not evaluated.");
    const rulesTable = table([
      "Rule", "Mode", "Header match", "Condition", "Action", "State", "Activity", "Actions",
    ], ruleRows(rules, data), { compact: true, empty: "No rules yet. Create a standing bypass or a conditional volume/payload policy." });
    attachRuleDragWire(rulesTable.table, rules);

    const summaryPairs = [
      ["Enabled", fmtInt(summary.enabled) + " / " + fmtInt(summary.total)],
      ["Mode split", fmtInt(summary.standing) + " standing · " + fmtInt(summary.conditional) + " conditional"],
      ["Allow rules", fmtInt(summary.allow) + " local bypass policies"],
      ["Errors", fmtInt(summary.errors)],
      ["Hits / triggers", fmtInt(summary.hits) + " / " + fmtInt(summary.triggers)],
      ["Suppressed", fmtInt(summary.suppressed) + " by allow rules"],
      ["Dropped samples", fmtInt(summary.dropped_observations)],
      ["Rule capacity", fmtInt(limits.max_rules) + " rules · " + fmtInt(limits.max_flows_per_rule) + " flows/rule"],
      ["Destination-only discard", limits.allow_destination_discard ? badge("enabled", "warn") : badge("refused", "good")],
    ];
    const savePairs = [
      ["Path", el("span", { class: "mono", text: save.path || "in-memory only" })],
      ["Last save", save.last_save ? timeNode(save.last_save) : "never"],
      ["Persisted rules", fmtInt(save.rules)],
      ["Save error", save.error ? badge(save.error, "danger") : badge("clean", "good")],
    ];

    const view = el("div", {},
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "Rules are evaluated top to bottom: drag rows (or use the arrows) to set the order — the sequence is persisted. Rules survive restarts and reconcile standing actions on startup, reconnect, and every maintenance tick. Conditions are evaluated on sampled sFlow observations; enforcement is a BGP Flowspec header match, not inline packet inspection." }),
        el("div", { class: "view-actions" },
          button("New rule", { variant: "primary", onClick: () => openRuleEditor(null, data) }),
          refreshButton(),
        ),
      ),
      data.enabled ? null : el("div", { class: "banner banner-warn" }, el("strong", { text: "Rules engine disabled. " }), "Definitions remain visible and editable, but no evaluation or standing enforcement occurs."),
      warnings.length ? el("div", { class: "banner banner-warn" }, el("strong", { text: "Rule warnings. " }), el("ul", { class: "warn-list" }, warnings.map((warning) => el("li", { text: warning })))) : null,
      el("div", { class: "grid-kpi" },
        kpi("Rules", fmtInt(summary.total), fmtInt(limits.max_rules) + " capacity", { variant: "accent" }),
        kpi("Enabled", fmtInt(summary.enabled), "evaluated by the sensor", { variant: "good" }),
        kpi("Standing", fmtInt(summary.standing), "persistent actions"),
        kpi("Conditional", fmtInt(summary.conditional), "trigger-driven actions"),
        kpi("Triggers", fmtInt(summary.triggers), fmtInt(summary.hits) + " total hits"),
        kpi("Suppressed", fmtInt(summary.suppressed), "allow-rule bypasses"),
      ),
      el("div", { class: "grid-main" },
        el("div", { class: "stack" },
          card("Rule catalog", "Newest first. Rule-owned actions are withdrawn when a rule is disabled or deleted.", tableWrap(rulesTable.table, "table-scroll-short")),
          card("Semantics and guardrails", "What a rule can and cannot do", el("ul", { class: "signal-list" },
            el("li", { text: "Standing rules apply their rule-header action until disabled or deleted, and are replayed after BGP reconnects." }),
            el("li", { text: "Conditional rules trigger temporary, rule-owned actions; volume conditions use rule scope by default." }),
            el("li", { text: "Payload and first-N conditions are evaluated on sampled packets only; the resulting enforcement is header-based." }),
            el("li", { text: "Allow is a local bypass of automatic mitigation, never a BGP permit or override of network policy." }),
            el("li", { text: "Destination must be inside a protected prefix; default routes and protected sources are refused." }),
            el("li", { text: "Destination-only discard requires explicit configuration; the default is refusal." }),
          )),
        ),
        el("div", { class: "stack" },
          card("Catalog summary", "Runtime counters and configured bounds", kvList(summaryPairs)),
          card("Persistence", "Atomic writes; statistics survive restarts", kvList(savePairs)),
        ),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 8 };
  }

  D.registerLoader("rules", loadRules);

  async function loadSettings(route, token) {
    const [settings, status] = await Promise.all([apiGet("/api/settings"), apiGet("/api/status")]);
    if (token !== D.state.token) return;
    D.applyHeader(status);
    const cfg = settings.config || {};
    const detection = cfg.detection || {};
    const stateful = detection.stateful !== false;
    const mitigation = cfg.mitigation || {};
    const collector = cfg.collector || {};
    const dashboard = cfg.dashboard || {};
    const bgp = cfg.bgp || {};
    const alerting = cfg.alerting || {};
    const persistence = cfg.persistence || {};
    const memory = cfg.memory || {};
    const ftp = (cfg.protocols || {}).ftp || {};
    const warnings = settings.warnings || [];
    const testButton = button("Send test notification", {
      variant: "primary",
      disabled: !settings.webhook_configured,
      onClick: async () => {
        testButton.disabled = true;
        testButton.textContent = "Sending…";
        try {
          await mutate("/api/settings/test-webhook", "POST");
          toast("Test notification delivered", "The configured webhook accepted the test.", "good");
        } catch (error) {
          toast("Test notification failed", error.message, "error");
        } finally {
          testButton.disabled = !settings.webhook_configured;
          testButton.textContent = "Send test notification";
        }
      },
    });
    const safetyPairs = [
      ["Dashboard", dashboard.listen || "—"],
      ["Collector", collector.listen || "—"],
      ["BGP", bgp.enabled ? "enabled — can announce" : "disabled — simulation only"],
      ["Protected prefixes", chips(cfg.protected_cidrs || [])],
      ["Global trusted", chips(cfg.trusted_sources || [])],
      ["Auto-block", mitigation.auto_block ? "enabled" : "disabled"],
    ];
    const detectionPairs = [
      ["Protection", detection.stateful ? "stateful" : "stateless"],
      ["Evaluation interval", detection.evaluation_interval || "—"],
      ["Rate window", (detection.rate_window_seconds || 0) + " seconds"],
      ["Cooldown", detection.cooldown || "—"],
      ["Warm-up windows", detection.warmup_windows],
      ["Trust exemption score", fmtNumber(detection.trust_exemption_score, 1)],
      ["Out-of-state minimum", detection.stateful ? fmtPPS(detection.out_of_state_min_pps) : "not used (stateless)"],
      ["Threat threshold", fmtNumber(detection.threshold, 1)],
      ["Persistence", (detection.persistence || 0) + " windows"],
      ["PPS floor", fmtPPS(detection.pps_floor)],
      ["BPS floor", fmtBPS(detection.bps_floor)],
    ];
    const mitigationPairs = [
      ["Blocklist directory", mitigation.blocklist_dir || "—"],
      ["Manual file", mitigation.manual_file || "—"],
      ["Duration", mitigation.duration || "—"],
      ["Dedup window", mitigation.dedup_window || "—"],
      ["Max active", mitigation.max_active],
      ["Rate limit", fmtBPS(Number(mitigation.rate_limit_mbps || 0) * 1e6)],
      ["History limit", mitigation.history_limit],
      ["FTP block duration", ftp.block_duration || "—"],
    ];
    const bgpPairs = [
      ["Enabled", bgp.enabled ? "yes" : "no"],
      ["Peer", bgp.peer_ip ? bgp.peer_ip + ":" + bgp.peer_port : "—"],
      ["Local / peer AS", (bgp.local_as || "—") + " / " + (bgp.peer_as || "—")],
      ["Local address", bgp.local_addr || "—"],
      ["Router ID", bgp.router_id || "—"],
      ["Next hop", bgp.next_hop || "—"],
      ["Community", bgp.community || "—"],
      ["Hold time", bgp.hold_time || "—"],
      ["Connect timeout", bgp.connect_timeout || "—"],
    ];
    const alertPairs = [
      ["Webhook", settings.webhook_configured ? badge("configured (hidden)", "good") : badge("not configured", "muted")],
      ["Format", alerting.format || "—"],
      ["Timeout", alerting.timeout || "—"],
      ["Retries", alerting.retries],
    ];
    const memoryPairs = [
      ["Packet buffer", fmtInt(memory.packet_buffer) + " observations"],
      ["Alert history", fmtInt(memory.alert_history) + " records"],
      ["Destination stats TTL", memory.destination_stats_ttl || "—"],
      ["Baseline TTL", memory.baseline_ttl || "—"],
      ["TCP session TTL", stateful ? (memory.tcp_session_ttl || "—") : "not used (stateless)"],
      ["TCP pending TTL", stateful ? (memory.tcp_pending_ttl || "—") : "not used (stateless)"],
      ["Max TCP sessions", stateful ? fmtInt(memory.max_tcp_sessions) : "not used (stateless)"],
      ["FTP state TTL", memory.ftp_state_ttl || "—"],
      ["Profile file", persistence.profile_file || "—"],
      ["Save interval", persistence.save_interval || "—"],
    ];
    const ftpPairs = [
      ["Enabled", ftp.enabled ? "yes" : "no"],
      ["Control rate", fmtPPS(ftp.control_rate_limit_pps)],
      ["Data rate", fmtPPS(ftp.data_rate_limit_pps)],
      ["Exempt trust", fmtNumber(ftp.exempt_trust_score, 1)],
      ["Max command bytes", fmtInt(ftp.max_command_bytes)],
      ["Block duration", ftp.block_duration || "—"],
    ];
    const view = el("div", {},
      simBanner(status),
      el("div", { class: "view-top" },
        el("div", { class: "view-lede", text: "This page is a read-only view of the effective configuration. Edit the JSON file and restart the service to change settings. Secrets are never returned to the dashboard." }),
        el("div", { class: "view-actions" }, refreshButton()),
      ),
      warnings.length ? el("div", { class: "banner banner-warn" }, el("strong", { text: "Configuration warnings. " }), el("ul", { class: "warn-list" }, warnings.map((warning) => el("li", { text: warning })))) : null,
      el("div", { class: "grid-kpi" },
        kpi("Version", settings.version || "—", "Dolly Sensor", { variant: "accent" }),
        kpi("Simulation", status.simulated ? "ON" : "OFF", status.simulated ? "safe default; no BGP updates" : "armed; live BGP possible", { variant: status.simulated ? "warn" : "danger" }),
        kpi("Protected", fmtInt((cfg.protected_cidrs || []).length), "explicit prefixes"),
        kpi("Webhook", settings.webhook_configured ? "configured" : "off", "URL never exposed"),
      ),
      el("div", { class: "grid-2" },
        card("Test alerting", "Deliver one explicit test notification", el("div", { class: "stack" },
          testButton,
          el("div", { class: "form-hint", text: settings.webhook_configured ? "The test is recorded as an info alert. It does not request mitigation." : "Set alerting.webhook_url in the configuration file and restart to enable delivery." }),
        )),
        card("Safety posture", "Understanding the defaults", el("div", {},
          kvList(safetyPairs),
          el("div", { class: "form-hint margin-top", text: "Defaults are intentionally conservative: BGP disabled, dashboard loopback-only, explicit protected CIDRs required, default-route mitigation refused, and simulated actions first-class." }),
        )),
      ),
      el("div", { class: "section-gap" }),
      el("div", { class: "grid-2" },
        card("Detection", "Every value is explicit in the configuration file", kvList(detectionPairs)),
        card("Mitigation", "Bounds and lifecycle", kvList(mitigationPairs)),
        card("BGP", "No password is used; for local lab peers only unless protected by network policy", kvList(bgpPairs)),
        card("Alerting", "Webhook URL is redacted", kvList(alertPairs)),
        card("FTP inspection", "Application-layer checks", kvList(ftpPairs)),
        card("Memory & persistence", "Bounded, atomic, restart-safe", kvList(memoryPairs)),
      ),
    );
    if (!mount(token, view)) return;
    D.state.viewHooks = { autoRefresh: 0 };
  }

  D.registerLoader("settings", loadSettings);

  window.__dollyViewsLoaded = true;
})();
