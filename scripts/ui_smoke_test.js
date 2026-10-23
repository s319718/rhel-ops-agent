"use strict";

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const BASE_URL = process.env.RHEL_AGENT_URL || "http://127.0.0.1:8880";
const EDGE =
  process.env.EDGE_PATH ||
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const DEBUG_PORT = 9333;
const OUT_DIR = path.resolve(__dirname, "..", "docs", "screenshots");
const PROFILE_DIR = path.resolve(
  __dirname,
  "..",
  ".ui-test-profile",
  String(Date.now())
);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForDebugger() {
  const endpoint = `http://127.0.0.1:${DEBUG_PORT}/json/list`;
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(endpoint);
      if (response.ok) {
        const targets = await response.json();
        const page = targets.find((target) => target.type === "page");
        if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
      }
    } catch {
      // Edge is still starting.
    }
    await sleep(100);
  }
  throw new Error("Edge DevTools endpoint did not become ready");
}

class CdpClient {
  constructor(wsUrl) {
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.ws = new WebSocket(wsUrl);
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
        return;
      }
      this.events.push(message);
    };
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    this.ws.close();
  }
}

async function evaluate(client, expression) {
  const result = await client.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.text || "Runtime evaluation failed");
  }
  return result.result?.value;
}

async function waitFor(client, expression, label, timeoutMs = 12000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await evaluate(client, expression)) return;
    await sleep(120);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function capture(client, name) {
  const screenshot = await client.send("Page.captureScreenshot", {
    format: "png",
    fromSurface: true,
    captureBeyondViewport: false,
  });
  fs.writeFileSync(path.join(OUT_DIR, name), Buffer.from(screenshot.data, "base64"));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function setViewport(client, width, height, mobile = false) {
  await client.send("Emulation.setDeviceMetricsOverride", {
    width,
    height,
    deviceScaleFactor: 1,
    mobile,
  });
}

async function navigate(client, url) {
  await client.send("Page.navigate", { url });
  await waitFor(
    client,
    "document.readyState === 'complete' && !!document.querySelector('#app-shell:not(.hidden)')",
    "application shell"
  );
  await sleep(400);
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.mkdirSync(PROFILE_DIR, { recursive: true });
  const edge = spawn(
    EDGE,
    [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--disable-software-rasterizer",
      "--no-first-run",
      `--remote-debugging-port=${DEBUG_PORT}`,
      `--user-data-dir=${PROFILE_DIR}`,
      "about:blank",
    ],
    { stdio: "ignore" }
  );

  let client;
  try {
    const wsUrl = await waitForDebugger();
    client = new CdpClient(wsUrl);
    await client.connect();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await setViewport(client, 1440, 1000);
    await navigate(client, BASE_URL);

    const runtimeErrors = client.events.filter(
      (event) => event.method === "Runtime.exceptionThrown"
    );
    assert(runtimeErrors.length === 0, "JavaScript exception on initial load");
    assert(
      Number(await evaluate(client, "document.querySelector('#risk-score').textContent")) > 0,
      "risk score was not rendered"
    );
    assert(
      (await evaluate(client, "document.querySelectorAll('.nav-item').length")) === 5,
      "primary navigation missing"
    );
    await capture(client, "dashboard.png");

    await evaluate(
      client,
      "document.querySelector('[data-view=\"assistant\"]').click(); true"
    );
    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('#chat-input');
        input.value = '把系统语言改成中文';
        input.dispatchEvent(new Event('input', { bubbles: true }));
        document.querySelector('#chat-send').click();
        return true;
      })()`
    );
    await waitFor(client, "!!document.querySelector('.plan-wrap')", "language plan");
    const planText = await evaluate(client, "document.querySelector('.plan-wrap').innerText");
    assert(
      planText.includes("需要重新登录") || planText.includes("建议重启"),
      "restart advice missing from plan"
    );
    await capture(client, "assistant-plan.png");

    await evaluate(client, "document.querySelector('.execute-plan-btn').click(); true");
    await waitFor(
      client,
      "!document.querySelector('#confirm-modal').classList.contains('hidden')",
      "confirmation modal"
    );
    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('#confirm-phrase');
        input.value = '确认修改语言';
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`
    );
    assert(
      !(await evaluate(client, "document.querySelector('#confirm-submit').disabled")),
      "confirm button stayed disabled"
    );
    await evaluate(client, "document.querySelector('#confirm-submit').click(); true");
    await waitFor(
      client,
      "document.querySelector('#chat-log').innerText.includes('操作已完成')",
      "execution result"
    );
    const resultText = await evaluate(client, "document.querySelector('#chat-log').innerText");
    assert(resultText.includes("创建重启计划"), "restart follow-up missing");
    await capture(client, "assistant-result.png");

    await evaluate(
      client,
      "document.querySelector('[data-view=\"vulnerabilities\"]').click(); true"
    );
    await waitFor(client, "document.querySelectorAll('.finding').length > 0", "findings");
    await capture(client, "vulnerabilities.png");

    await evaluate(client, "document.querySelector('[data-view=\"audit\"]').click(); true");
    await waitFor(
      client,
      "document.querySelectorAll('#audit-table-body tr').length > 0",
      "audit events"
    );
    await capture(client, "audit.png");

    await setViewport(client, 390, 844, true);
    await navigate(client, `${BASE_URL}/#overview`);
    const overflow = await evaluate(
      client,
      "document.documentElement.scrollWidth - window.innerWidth"
    );
    assert(overflow <= 1, `mobile horizontal overflow: ${overflow}px`);
    assert(
      await evaluate(client, "getComputedStyle(document.querySelector('#mobile-menu')).display !== 'none'"),
      "mobile navigation trigger missing"
    );
    await capture(client, "mobile-overview.png");

    console.log(`UI smoke test passed. Screenshots: ${OUT_DIR}`);
  } finally {
    if (client) {
      try {
        await client.send("Browser.close");
      } catch {
        client.close();
      }
    }
    if (!edge.killed) edge.kill();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
