"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const ROLE_LABELS = {
  SYSTEM_ADMIN: "Administrator",
  SECURITY_ANALYST: "Analyst",
  SECURITY_MANAGER: "Manager",
  VIEWER: "Viewer",
};

const STATUS_ORDER = ["NEW", "ASSIGNED", "INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"];
const STATUS_LABELS = {
  NEW: "New",
  ASSIGNED: "Assigned",
  INVESTIGATING: "Investigating",
  ESCALATED: "Escalated",
  RESOLVED: "Resolved",
  CLOSED: "Closed",
};
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SCENARIOS = [
  ["brute_force", "Brute-force login"],
  ["port_scan", "Port scan"],
  ["request_flood", "Request flood"],
  ["new_country", "Login from new country"],
  ["admin_access", "Non-admin opens /admin"],
  ["bad_ip", "Known malicious IP"],
  ["config_change", "Unauthorized config change"],
  ["normal", "Normal traffic"],
  ["all", "All scenarios"],
];

const state = {
  token: sessionStorage.getItem("sw_token"),
  user: safeJson(sessionStorage.getItem("sw_user")),
  health: null,
  currentTab: "dashboard",
  selectedIncident: null,
  assignees: [],
  pollTimer: null,
  lastUpdated: null,
};

function safeJson(value) {
  try {
    return value ? JSON.parse(value) : null;
  } catch (_error) {
    return null;
  }
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function truncate(value, length = 90) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function parseDate(value) {
  if (typeof value === "number") return new Date(value * 1000);
  const text = String(value ?? "").trim();
  const naive = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text);
  return new Date(naive ? `${text.replace(" ", "T")}Z` : text);
}

function fmtDate(value) {
  if (!value) return "—";
  const date = parseDate(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

function fmtTime(value) {
  if (!value) return "—";
  const date = parseDate(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString();
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function severityTag(severity) {
  const key = String(severity || "").toLowerCase();
  return `<span class="tag sev-${esc(key)}">${esc(severity || "—")}</span>`;
}

function statusTag(status) {
  return `<span class="status">${esc(STATUS_LABELS[status] || status || "—")}</span>`;
}

function isAdmin() {
  return state.user?.role === "SYSTEM_ADMIN";
}

function canWrite() {
  return ["SYSTEM_ADMIN", "SECURITY_ANALYST", "SECURITY_MANAGER"].includes(state.user?.role);
}

function canClose() {
  return ["SYSTEM_ADMIN", "SECURITY_MANAGER"].includes(state.user?.role);
}

function toast(title, message = "", type = "ok") {
  const element = document.createElement("div");
  element.className = `toast ${type === "error" ? "error" : ""}`;
  element.innerHTML = `<b>${esc(title)}</b>${message ? `<span>${esc(message)}</span>` : ""}`;
  $("#toasts").append(element);
  setTimeout(() => element.remove(), 5000);
}

async function api(path, options = {}) {
  const { method = "GET", body, auth = true, raw = false } = options;
  const headers = {};
  if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && auth && state.token) {
    logout(true);
    throw new Error("Your session expired. Please sign in again.");
  }

  if (raw) {
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response;
  }

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    let detail = payload?.detail || payload || `Request failed (${response.status})`;
    if (Array.isArray(detail)) {
      detail = detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
    }
    throw new Error(String(detail));
  }
  return payload;
}

function setLive(online) {
  const dot = $("#live-dot");
  const label = $("#live-label");
  if (!dot || !label) return;
  dot.classList.toggle("off", !online);
  label.textContent = online ? "Live" : "Reconnecting";
}

function markUpdated() {
  state.lastUpdated = new Date();
  const target = $("#last-updated");
  if (target) target.textContent = `Updated ${state.lastUpdated.toLocaleTimeString()}`;
}

function updateUserChip() {
  const chip = $("#current-user");
  if (!chip || !state.user) return;
  chip.innerHTML = `<b>${esc(state.user.username)}</b><span>${esc(ROLE_LABELS[state.user.role] || state.user.role)}</span>`;
}

function showLogin() {
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#login-error").textContent = "";
  $("#login-form").reset();
}

function showApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  updateUserChip();
  buildNav();
  switchTab("dashboard");
  startPolling();
}

async function boot() {
  bindEvents();
  populateScenarios();

  try {
    state.health = await api("/health", { auth: false });
  } catch (_error) {
    state.health = null;
  }

  const hint = $("#login-hint");
  if (state.health) {
    hint.textContent = state.health.environment === "production"
      ? "Use the account created by your administrator."
      : "Local development accounts: admin/admin123, analyst/analyst123, manager/manager123, viewer/viewer123.";
  } else {
    hint.textContent = "The API cannot be reached. Start the backend and refresh this page.";
  }

  if (state.token) {
    try {
      state.user = await api("/auth/me");
      sessionStorage.setItem("sw_user", JSON.stringify(state.user));
      await loadAssignees();
      showApp();
      return;
    } catch (_error) {
      logout(false);
      return;
    }
  }
  showLogin();
}

async function login(event) {
  event.preventDefault();
  const button = $("#login-btn");
  const errorBox = $("#login-error");
  errorBox.textContent = "";
  button.disabled = true;
  button.textContent = "Signing in…";

  try {
    const result = await api("/auth/login", {
      method: "POST",
      auth: false,
      body: {
        username: $("#username").value.trim(),
        password: $("#password").value,
      },
    });
    state.token = result.token;
    state.user = { username: result.username, role: result.role };
    sessionStorage.setItem("sw_token", state.token);
    sessionStorage.setItem("sw_user", JSON.stringify(state.user));
    await loadAssignees();
    showApp();
    toast("Signed in", `Welcome back, ${result.username}.`);
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Sign in";
  }
}

function logout(expired = false) {
  state.token = null;
  state.user = null;
  state.selectedIncident = null;
  state.assignees = [];
  sessionStorage.removeItem("sw_token");
  sessionStorage.removeItem("sw_user");
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  showLogin();
  if (expired) toast("Session expired", "Please sign in again.", "error");
}

function navItems() {
  const items = [
    ["dashboard", "Dashboard"],
    ["events", "Events"],
    ["incidents", "Incidents"],
    ["rules", "Rules"],
  ];
  if (["SYSTEM_ADMIN", "SECURITY_ANALYST", "SECURITY_MANAGER"].includes(state.user?.role)) {
    items.push(["sources", "Log sources"]);
  }
  if (isAdmin()) {
    items.push(["users", "Users"]);
    items.push(["audit", "Audit"]);
  }
  return items;
}

function buildNav() {
  $("#nav").innerHTML = navItems()
    .map(([id, label]) => `<button data-tab="${id}">${label}</button>`)
    .join("");
}

function switchTab(tab) {
  state.currentTab = tab;
  $$(".tab").forEach((section) => {
    section.classList.toggle("hidden", section.id !== `tab-${tab}`);
  });
  $$("#nav button").forEach((button) => {
    button.classList.toggle("on", button.dataset.tab === tab);
  });
  loadTab(tab);
}

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(() => {
    if (document.hidden) return;
    if (["dashboard", "events", "incidents"].includes(state.currentTab)) {
      refreshCurrentTab(true);
    }
  }, 4000);
}

function refreshCurrentTab(quiet = false) {
  loadTab(state.currentTab, quiet);
}

function loadTab(tab, quiet = false) {
  if (tab === "dashboard") loadDashboard(quiet);
  else if (tab === "events") loadEvents(quiet);
  else if (tab === "incidents") loadIncidents(quiet);
  else if (tab === "rules") loadRules();
  else if (tab === "sources") loadSources();
  else if (tab === "users") loadUsers();
  else if (tab === "audit") loadAudit();
}

async function loadDashboard(quiet = false) {
  try {
    const [stats, incidents, events, notifications] = await Promise.all([
      api("/stats/dashboard"),
      api("/incidents?limit=8"),
      api("/events?limit=12"),
      api("/notifications?limit=8"),
    ]);
    renderStats(stats);
    renderSeverity(stats);
    renderTopIps(stats);
    renderRecentIncidents(incidents);
    renderRecentEvents(events);
    renderNotifications(notifications);
    const panel = $("#test-panel");
    const allowed = isAdmin() && state.health?.test_endpoints;
    panel.classList.toggle("hidden", !allowed);
    markUpdated();
    setLive(true);
  } catch (error) {
    setLive(false);
    if (!quiet) toast("Could not load dashboard", error.message, "error");
  }
}

function renderStats(stats) {
  const cards = [
    ["Total events", stats.total_events, `${stats.events_last_24h} in the last 24h`],
    ["Open incidents", stats.open_incidents, `${stats.unassigned_incidents} unassigned`],
    ["Critical / High", stats.critical_high_incidents, "Open right now"],
    ["Mean time to resolve", fmtDuration(stats.mttr_seconds), `Detection: ${fmtDuration(stats.mttd_seconds)}`],
  ];
  $("#stats").innerHTML = cards
    .map(
      ([label, value, sub]) => `
      <div class="card stat">
        <b>${esc(value)}</b>
        <span>${esc(label)}</span>
        <div class="sub">${esc(sub)}</div>
      </div>`
    )
    .join("");
}

function severityCounts(stats) {
  const counts = {};
  const raw = stats.open_by_severity || {};
  Object.entries(raw).forEach(([key, value]) => {
    counts[String(key).toUpperCase()] = value;
  });
  return counts;
}

function renderSeverity(stats) {
  const counts = severityCounts(stats);
  const max = Math.max(1, ...SEVERITY_ORDER.map((severity) => counts[severity] || 0));
  const colors = {
    CRITICAL: "var(--red)",
    HIGH: "var(--orange)",
    MEDIUM: "#fbbf24",
    LOW: "var(--blue)",
  };
  $("#severity-bars").innerHTML = SEVERITY_ORDER.map((severity) => {
    const count = counts[severity] || 0;
    return `
      <div class="bar-row">
        <span>${esc(severity)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(count / max) * 100}%;background:${colors[severity]}"></div></div>
        <span class="bar-count">${count}</span>
      </div>`;
  }).join("");
}

function renderTopIps(stats) {
  const ips = stats.top_ips || [];
  if (!ips.length) {
    $("#top-ips").innerHTML = `<p class="muted">No events ingested yet.</p>`;
    return;
  }
  const max = Math.max(1, ...ips.map((item) => item.count));
  $("#top-ips").innerHTML = ips
    .map(
      (item) => `
      <div class="bar-row">
        <span title="${esc(item.ip)}">${esc(item.ip)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(item.count / max) * 100}%"></div></div>
        <span class="bar-count">${esc(item.count)}</span>
      </div>`
    )
    .join("");
}

function renderRecentIncidents(incidents) {
  if (!incidents.length) {
    $("#recent-incidents").innerHTML = `<p class="muted">No incidents yet. Ingest events or run a test scenario.</p>`;
    return;
  }
  $("#recent-incidents").innerHTML = `
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Incident</th><th>Status</th></tr></thead>
      <tbody>
        ${incidents
          .map(
            (incident) => `
          <tr class="click" data-open-incident="${incident.id}">
            <td>${esc(fmtTime(incident.created_at))}</td>
            <td>${severityTag(incident.severity)}</td>
            <td>${esc(truncate(incident.title, 48))}</td>
            <td>${statusTag(incident.status)}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;
}

function renderRecentEvents(events) {
  if (!events.length) {
    $("#recent-events").innerHTML = `<p class="muted">No events ingested yet.</p>`;
    return;
  }
  $("#recent-events").innerHTML = `
    <table>
      <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead>
      <tbody>
        ${events
          .map(
            (event) => `
          <tr>
            <td>${esc(fmtTime(event.ts))}</td>
            <td>${esc(event.source_id)}</td>
            <td>${esc(event.event_type)}${event.hit ? ' <span class="hit">detected</span>' : ""}</td>
            <td>${esc(event.ip)}</td>
            <td>${esc(truncate(event.detail, 40))}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;
}

function renderNotifications(notifications) {
  if (!notifications.length) {
    $("#notifications").innerHTML = `<p class="muted">No notifications.</p>`;
    return;
  }
  $("#notifications").innerHTML = notifications
    .map(
      (item) => `
      <div class="notif">
        <b>${esc(item.subject || item.message)}</b>
        <time>${esc(fmtDate(item.created_at))} · ${esc(item.status)} · ${esc(item.channel)}</time>
      </div>`
    )
    .join("");
}

function eventQuery() {
  const params = new URLSearchParams();
  const ip = $("#ev-ip").value.trim();
  const user = $("#ev-user").value.trim();
  const type = $("#ev-type").value.trim();
  const limit = $("#ev-limit").value || "200";
  if (ip) params.set("ip", ip);
  if (user) params.set("user", user);
  if (type) params.set("event_type", type);
  if ($("#ev-hit").checked) params.set("hit_only", "true");
  params.set("limit", limit);
  return params.toString();
}

async function loadEvents(quiet = false) {
  try {
    const events = await api(`/events?${eventQuery()}`);
    $("#ev-count").textContent = `${events.length} event${events.length === 1 ? "" : "s"} shown`;
    if (!events.length) {
      $("#event-rows").innerHTML = `<tr><td colspan="8" class="empty">No events match these filters.</td></tr>`;
    } else {
      $("#event-rows").innerHTML = events
        .map(
          (event) => `
        <tr>
          <td>${esc(fmtTime(event.ts))}</td>
          <td>${esc(event.source_id)}</td>
          <td>${esc(event.ip)}</td>
          <td>${esc(event.user)}</td>
          <td>${esc(event.event_type)}</td>
          <td>${esc(event.country)}</td>
          <td>${esc(truncate(event.detail, 70))}</td>
          <td>${event.hit ? "Yes" : "No"}</td>
        </tr>`
        )
        .join("");
    }
    markUpdated();
    setLive(true);
  } catch (error) {
    setLive(false);
    if (!quiet) toast("Could not load events", error.message, "error");
  }
}

function incidentQuery() {
  const params = new URLSearchParams({ limit: "200" });
  if ($("#inc-status").value) params.set("status", $("#inc-status").value);
  if ($("#inc-severity").value) params.set("severity", $("#inc-severity").value);
  return params.toString();
}

async function loadIncidents(quiet = false) {
  try {
    const incidents = await api(`/incidents?${incidentQuery()}`);
    const selectedBefore = state.selectedIncident;
    const selectedExists = incidents.some((incident) => incident.id === state.selectedIncident);
    if (!selectedExists) state.selectedIncident = incidents.length ? incidents[0].id : null;

    if (!incidents.length) {
      $("#incident-rows").innerHTML = `<tr><td colspan="6" class="empty">No incidents match these filters.</td></tr>`;
    } else {
      $("#incident-rows").innerHTML = incidents
        .map(
          (incident) => `
        <tr class="click ${incident.id === state.selectedIncident ? "sel" : ""}" data-incident="${incident.id}">
          <td>${esc(incident.id)}</td>
          <td>${severityTag(incident.severity)}</td>
          <td>${esc(truncate(incident.title, 50))}${incident.count > 1 ? ` <span class="muted">+${incident.count - 1}</span>` : ""}</td>
          <td>${statusTag(incident.status)}</td>
          <td>${esc(incident.owner || "Unassigned")}</td>
          <td>${esc(fmtTime(incident.created_at))}</td>
        </tr>`
        )
        .join("");
    }

    if (state.selectedIncident) {
      const selectionChanged = selectedBefore !== state.selectedIncident;
      if (!quiet || selectionChanged) await loadIncidentDetail();
      else if (!document.activeElement || !$("#incident-detail").contains(document.activeElement)) {
        await loadIncidentDetail();
      }
    } else {
      $("#incident-detail").innerHTML = `<p class="muted">Select an incident to investigate it.</p>`;
    }
    markUpdated();
    setLive(true);
  } catch (error) {
    setLive(false);
    if (!quiet) toast("Could not load incidents", error.message, "error");
  }
}

function actionButtons(incident) {
  if (!canWrite()) return "";
  const status = incident.status;
  const buttons = [];
  if (status === "NEW") {
    buttons.push(`<button class="btn small" data-action="assign-me">Assign to me</button>`);
    buttons.push(`<button class="btn small alt" data-action="start">Start investigating</button>`);
    buttons.push(`<button class="btn small alt" data-action="escalate">Escalate</button>`);
  } else if (status === "ASSIGNED") {
    buttons.push(`<button class="btn small" data-action="start">Start investigating</button>`);
    buttons.push(`<button class="btn small alt" data-action="escalate">Escalate</button>`);
  } else if (status === "INVESTIGATING") {
    buttons.push(`<button class="btn small" data-action="escalate">Escalate</button>`);
    buttons.push(`<button class="btn small" data-action="resolve">Resolve</button>`);
  } else if (status === "ESCALATED") {
    buttons.push(`<button class="btn small alt" data-action="resume">Resume investigating</button>`);
    buttons.push(`<button class="btn small" data-action="resolve">Resolve</button>`);
  } else if (status === "RESOLVED" && canClose()) {
    buttons.push(`<button class="btn small" data-action="close">Close incident</button>`);
  }
  return buttons.join("");
}

async function loadIncidentDetail() {
  try {
    const incident = await api(`/incidents/${state.selectedIncident}`);
    const ownerOptions = state.assignees
      .map((user) => `<option value="${esc(user.username)}" ${user.username === incident.owner ? "selected" : ""}>${esc(user.username)} (${esc(ROLE_LABELS[user.role] || user.role)})</option>`)
      .join("");
    const assigneeMissing = incident.owner && !state.assignees.some((user) => user.username === incident.owner);
    const ownerSelect = canWrite()
      ? `<label>Owner
           <select id="detail-owner">
             <option value="">Unassigned</option>
             ${assigneeMissing ? `<option value="${esc(incident.owner)}" selected>${esc(incident.owner)} (inactive)</option>` : ""}
             ${ownerOptions}
           </select>
         </label>`
      : `<div><span class="muted">Owner</span><br>${esc(incident.owner || "Unassigned")}</div>`;
    const severitySelect = canWrite()
      ? `<label>Severity
           <select id="detail-severity">
             ${SEVERITY_ORDER.map((severity) => `<option value="${severity}" ${incident.severity === severity ? "selected" : ""}>${severity}</option>`).join("")}
           </select>
         </label>`
      : `<div><span class="muted">Severity</span><br>${severityTag(incident.severity)}</div>`;

    const timeline = (incident.timeline || [])
      .map(
        (entry) => `
        <div class="item">
          <time>${esc(fmtDate(entry.timestamp))} · ${esc(entry.author)} · ${esc(entry.kind)}</time>
          ${esc(entry.text)}
        </div>`
      )
      .join("") || `<p class="muted">No timeline entries.</p>`;

    const related = (incident.related_events || [])
      .slice(0, 25)
      .map(
        (event) => `
        <tr>
          <td>${esc(fmtTime(event.ts))}</td>
          <td>${esc(event.event_type)}</td>
          <td>${esc(event.ip)}</td>
          <td>${esc(truncate(event.detail, 46))}</td>
        </tr>`
      )
      .join("");

    $("#incident-detail").innerHTML = `
      <div class="detail">
        <h3>${esc(incident.title)}</h3>
        <div class="row">${severityTag(incident.severity)} ${statusTag(incident.status)} <span class="muted">#${esc(incident.id)} · ${esc(incident.count)} event${incident.count === 1 ? "" : "s"} · IP ${esc(incident.ip || "—")}</span></div>
        <p class="desc">${esc(incident.description || "No description")}</p>
        <div class="controls">${ownerSelect}${severitySelect}</div>
        <div class="actions">${actionButtons(incident)}</div>
        <h4>Timeline</h4>
        <div class="timeline">${timeline}</div>
        ${
          canWrite()
            ? `<div class="note-form">
                 <textarea id="detail-note" placeholder="Add investigation note…"></textarea>
                 <button class="btn small" data-action="note">Add note</button>
               </div>`
            : ""
        }
        <h4>Related events</h4>
        ${
          related
            ? `<div class="table-wrap" style="max-height:220px"><table><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>${related}</tbody></table></div>`
            : `<p class="muted">No linked events.</p>`
        }
      </div>`;

    if (canWrite()) {
      $("#detail-owner").addEventListener("change", (event) => {
        patchIncident({ owner: event.target.value || null }, "Owner updated");
      });
      $("#detail-severity").addEventListener("change", (event) => {
        patchIncident({ severity: event.target.value }, "Severity updated");
      });
    }
  } catch (error) {
    $("#incident-detail").innerHTML = `<p class="error">${esc(error.message)}</p>`;
  }
}

async function patchIncident(payload, successMessage) {
  try {
    await api(`/incidents/${state.selectedIncident}`, { method: "PATCH", body: payload });
    toast(successMessage);
    await loadIncidents(true);
  } catch (error) {
    toast("Update failed", error.message, "error");
  }
}

async function incidentAction(action) {
  const id = state.selectedIncident;
  if (!id) return;
  try {
    if (action === "assign-me") {
      await api(`/incidents/${id}`, { method: "PATCH", body: { owner: state.user.username } });
      toast("Incident assigned to you");
    } else if (action === "start") {
      await api(`/incidents/${id}`, { method: "PATCH", body: { status: "INVESTIGATING" } });
      toast("Investigation started");
    } else if (action === "resume") {
      await api(`/incidents/${id}`, { method: "PATCH", body: { status: "INVESTIGATING" } });
      toast("Incident moved back to investigation");
    } else if (action === "escalate") {
      await api(`/incidents/${id}/escalate`, { method: "POST" });
      toast("Incident escalated");
    } else if (action === "resolve") {
      const summary = window.prompt("Resolution summary");
      if (!summary) return;
      await api(`/incidents/${id}/resolve`, {
        method: "POST",
        body: { resolution_summary: summary },
      });
      toast("Incident resolved");
    } else if (action === "close") {
      if (!window.confirm("Close this incident?")) return;
      await api(`/incidents/${id}/close`, { method: "POST" });
      toast("Incident closed");
    } else if (action === "note") {
      const text = $("#detail-note").value.trim();
      if (!text) return;
      await api(`/incidents/${id}/notes`, { method: "POST", body: { text } });
      toast("Note added");
    }
    await loadIncidents(true);
  } catch (error) {
    toast("Action failed", error.message, "error");
  }
}

async function loadRules() {
  try {
    const rules = await api("/rules");
    $("#rule-rows").innerHTML = rules
      .map(
        (rule) => `
      <tr>
        <td><input type="checkbox" data-rule="${esc(rule.id)}" ${rule.enabled ? "checked" : ""} ${isAdmin() ? "" : "disabled"}></td>
        <td><b>${esc(rule.id)}</b> · ${esc(rule.name)}</td>
        <td>${esc(rule.condition)}</td>
        <td>${severityTag(rule.severity)}</td>
        <td>${esc(rule.threshold ?? "—")}${rule.time_window_seconds ? ` / ${esc(rule.time_window_seconds)}s` : ""}</td>
      </tr>`
      )
      .join("");
    $("#rules-note").textContent = isAdmin()
      ? "Changes are saved immediately and audited."
      : "Only administrators can enable or disable rules.";
  } catch (error) {
    toast("Could not load rules", error.message, "error");
  }
}

async function loadSources() {
  try {
    const sources = await api("/log-sources");
    $("#source-count").textContent = `${sources.length} source${sources.length === 1 ? "" : "s"}`;
    $("#source-rows").innerHTML = sources
      .map(
        (source) => `
      <tr>
        <td><b>${esc(source.id)}</b></td>
        <td>${esc(source.name)}</td>
        <td>${esc(source.source_type)}</td>
        <td>
          ${
            isAdmin()
              ? `<input type="checkbox" data-source-active="${esc(source.id)}" ${source.is_active ? "checked" : ""}>`
              : source.is_active
                ? "Active"
                : "Inactive"
          }
        </td>
        <td>${esc(fmtDate(source.created_at))}</td>
        <td>${isAdmin() ? `<button class="btn danger small" data-source-delete="${esc(source.id)}">Delete</button>` : ""}</td>
      </tr>`
      )
      .join("") || `<tr><td colspan="6" class="empty">No log sources.</td></tr>`;
    $("#source-form-wrap").classList.toggle("hidden", !isAdmin());
  } catch (error) {
    toast("Could not load log sources", error.message, "error");
  }
}

async function loadUsers() {
  if (!isAdmin()) return;
  try {
    const users = await api("/auth/users");
    $("#user-rows").innerHTML = users
      .map(
        (user) => `
      <tr>
        <td><b>${esc(user.username)}</b></td>
        <td>${esc(user.email || "—")}</td>
        <td>
          <select data-user-role="${esc(user.username)}">
            ${Object.entries(ROLE_LABELS).map(([value, label]) => `<option value="${value}" ${user.role === value ? "selected" : ""}>${label}</option>`).join("")}
          </select>
        </td>
        <td><input type="checkbox" data-user-active="${esc(user.username)}" ${user.is_active ? "checked" : ""}></td>
        <td>${esc(fmtDate(user.created_at))}</td>
        <td class="row">
          <button class="btn alt small" data-user-password="${esc(user.username)}">Reset password</button>
          <button class="btn danger small" data-user-delete="${esc(user.username)}">Delete</button>
        </td>
      </tr>`
      )
      .join("");
    $("#user-form-wrap").classList.remove("hidden");
  } catch (error) {
    toast("Could not load users", error.message, "error");
  }
}

async function loadAudit() {
  try {
    const entries = await api("/audit?limit=500");
    $("#audit-rows").innerHTML = entries
      .map(
        (entry) => `
      <tr>
        <td>${esc(fmtDate(entry.timestamp))}</td>
        <td>${esc(entry.user)}</td>
        <td>${esc(entry.action)}</td>
        <td>${esc(entry.ip_address || "—")}</td>
      </tr>`
      )
      .join("") || `<tr><td colspan="4" class="empty">No audit entries.</td></tr>`;
  } catch (error) {
    toast("Could not load audit trail", error.message, "error");
  }
}

async function loadAssignees() {
  if (!canWrite()) return;
  try {
    state.assignees = await api("/auth/assignees");
  } catch (_error) {
    state.assignees = [];
  }
}

function populateScenarios() {
  $("#scenario").innerHTML = SCENARIOS.map(
    ([value, label]) => `<option value="${value}">${label}</option>`
  ).join("");
}

async function runScenario() {
  const scenario = $("#scenario").value;
  const button = $("#run-scenario");
  button.disabled = true;
  try {
    const result = await api(`/events/simulate/${encodeURIComponent(scenario)}`, { method: "POST" });
    toast(
      "Test events ingested",
      `${result.accepted} events, ${result.alerts} alerts, ${result.new_incidents} new incidents.`
    );
    await loadDashboard(true);
  } catch (error) {
    toast("Test failed", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function exportCsv() {
  try {
    const response = await api("/stats/reports/export/csv", { raw: true });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "incident-report.csv";
    link.click();
    URL.revokeObjectURL(url);
    toast("Report exported");
  } catch (error) {
    toast("Export failed", error.message, "error");
  }
}

function bindEvents() {
  $("#login-form").addEventListener("submit", login);
  $("#logout").addEventListener("click", () => logout(false));

  $("#nav").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-tab]");
    if (button) switchTab(button.dataset.tab);
  });

  $("#recent-incidents").addEventListener("click", (event) => {
    const row = event.target.closest("[data-open-incident]");
    if (!row) return;
    state.selectedIncident = Number(row.dataset.openIncident);
    switchTab("incidents");
  });

  $("#event-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    loadEvents();
  });
  $("#ev-refresh").addEventListener("click", () => loadEvents());

  $("#inc-filters").addEventListener("change", () => loadIncidents());
  $("#inc-refresh").addEventListener("click", () => loadIncidents());
  $("#export-csv").addEventListener("click", exportCsv);

  $("#incident-rows").addEventListener("click", (event) => {
    const row = event.target.closest("[data-incident]");
    if (!row) return;
    state.selectedIncident = Number(row.dataset.incident);
    loadIncidents();
  });
  $("#incident-detail").addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (button) incidentAction(button.dataset.action);
  });

  $("#rule-rows").addEventListener("change", async (event) => {
    const checkbox = event.target.closest("[data-rule]");
    if (!checkbox || !isAdmin()) return;
    try {
      await api(`/rules/${encodeURIComponent(checkbox.dataset.rule)}`, {
        method: "PATCH",
        body: { enabled: checkbox.checked },
      });
      toast("Rule updated");
    } catch (error) {
      checkbox.checked = !checkbox.checked;
      toast("Rule update failed", error.message, "error");
    }
  });

  $("#run-scenario").addEventListener("click", runScenario);

  $("#source-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/log-sources", {
        method: "POST",
        body: {
          id: $("#src-id").value.trim(),
          name: $("#src-name").value.trim(),
          source_type: $("#src-type").value,
        },
      });
      $("#source-form").reset();
      toast("Log source created");
      loadSources();
    } catch (error) {
      toast("Could not create log source", error.message, "error");
    }
  });
  $("#source-rows").addEventListener("change", async (event) => {
    const checkbox = event.target.closest("[data-source-active]");
    if (!checkbox) return;
    try {
      await api(`/log-sources/${encodeURIComponent(checkbox.dataset.sourceActive)}`, {
        method: "PATCH",
        body: { is_active: checkbox.checked },
      });
      toast("Log source updated");
    } catch (error) {
      checkbox.checked = !checkbox.checked;
      toast("Update failed", error.message, "error");
    }
  });
  $("#source-rows").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-source-delete]");
    if (!button) return;
    if (!window.confirm("Delete this log source?")) return;
    try {
      await api(`/log-sources/${encodeURIComponent(button.dataset.sourceDelete)}`, { method: "DELETE" });
      toast("Log source deleted");
      loadSources();
    } catch (error) {
      toast("Delete failed", error.message, "error");
    }
  });

  $("#user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/auth/users", {
        method: "POST",
        body: {
          username: $("#usr-username").value.trim(),
          email: $("#usr-email").value.trim() || null,
          password: $("#usr-password").value,
          role: $("#usr-role").value,
        },
      });
      $("#user-form").reset();
      toast("User created");
      loadUsers();
      await loadAssignees();
    } catch (error) {
      toast("Could not create user", error.message, "error");
    }
  });
  $("#user-rows").addEventListener("change", async (event) => {
    const roleSelect = event.target.closest("[data-user-role]");
    const activeBox = event.target.closest("[data-user-active]");
    try {
      if (roleSelect) {
        await api(`/auth/users/${encodeURIComponent(roleSelect.dataset.userRole)}`, {
          method: "PATCH",
          body: { role: roleSelect.value },
        });
        toast("User role updated");
        await loadAssignees();
      } else if (activeBox) {
        await api(`/auth/users/${encodeURIComponent(activeBox.dataset.userActive)}`, {
          method: "PATCH",
          body: { is_active: activeBox.checked },
        });
        toast("User status updated");
        await loadAssignees();
      }
    } catch (error) {
      toast("Update failed", error.message, "error");
      loadUsers();
    }
  });
  $("#user-rows").addEventListener("click", async (event) => {
    const passwordButton = event.target.closest("[data-user-password]");
    const deleteButton = event.target.closest("[data-user-delete]");
    try {
      if (passwordButton) {
        const username = passwordButton.dataset.userPassword;
        const password = window.prompt(`New password for ${username} (minimum 8 characters)`);
        if (!password) return;
        await api(`/auth/users/${encodeURIComponent(username)}`, {
          method: "PATCH",
          body: { password },
        });
        toast("Password reset");
      } else if (deleteButton) {
        const username = deleteButton.dataset.userDelete;
        if (!window.confirm(`Delete user ${username}?`)) return;
        await api(`/auth/users/${encodeURIComponent(username)}`, { method: "DELETE" });
        toast("User deleted");
        loadUsers();
        await loadAssignees();
      }
    } catch (error) {
      toast("Action failed", error.message, "error");
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.token) refreshCurrentTab(true);
  });
}

boot();
