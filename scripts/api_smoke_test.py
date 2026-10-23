#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any


class ApiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar())
        )

    def request(
        self, path: str, method: str = "GET", payload: Any = None
    ) -> tuple[int, dict[str, str], Any]:
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                body = response.read().decode("utf-8")
                return response.status, dict(response.headers), json.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError("HTTP %s: %s" % (exc.code, body)) from exc

    def login(self, password: str) -> None:
        self.request("/api/auth/login", "POST", {"password": password})


def assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError("%s: expected %r, got %r" % (label, expected, actual))


def main() -> int:
    parser = argparse.ArgumentParser(description="RHEL Ops Agent API smoke test")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--password", help="管理员密码；不传则按无登录测试")
    args = parser.parse_args()

    client = ApiClient(args.base_url)
    if args.password:
        client.login(args.password)

    status, _, overview = client.request("/api/overview")
    assert_equal(status, 200, "overview status")
    print("overview:", overview["agent"]["mode"], "score", overview["risk"]["score"])

    status, _, rules = client.request("/api/rules")
    assert_equal(status, 200, "rules status")
    print(
        "rules:",
        rules["count"],
        "actions,",
        rules["vulnerability_checks"],
        "checks,",
        rules["audit_patterns"],
        "audit patterns",
    )

    status, _, planned = client.request(
        "/api/plan", "POST", {"message": "把系统语言改成中文"}
    )
    assert_equal(status, 200, "plan status")
    plan = planned["plan"]
    assert_equal(plan["status"], "ready", "language plan")
    assert_equal(plan["requires_restart"], True, "language restart advice")
    print("plan:", plan["status"], plan["overall_risk"], plan["confirmation_phrase"])

    selected = [step["action_id"] for step in plan["steps"]]
    status, _, executed = client.request(
        "/api/execute",
        "POST",
        {
            "proposal_id": planned["proposal_id"],
            "selected_action_ids": selected,
            "confirmation": plan["confirmation_phrase"],
        },
    )
    assert_equal(status, 200, "execute status")
    assert_equal(executed["result"]["status"], "completed", "execute result")
    assert_equal(executed["result"]["requires_restart"], True, "restart result")
    print("execute:", executed["result"]["status"], "restart", executed["result"]["requires_restart"])

    status, _, started = client.request("/api/scan", "POST", {})
    assert_equal(status, 202, "scan start")
    scan_id = started["scan_id"]
    scan = None
    for _ in range(40):
        status, _, payload = client.request("/api/scans/" + scan_id)
        scan = payload["scan"]
        if scan["status"] != "running":
            break
        time.sleep(0.25)
    if scan is None or scan["status"] == "running":
        raise AssertionError("scan did not finish")
    assert_equal(scan["status"], "completed", "scan completion")
    print(
        "scan:",
        scan["status"],
        "findings",
        scan["summary"]["total"],
        "checked",
        scan["summary"]["checked"],
    )

    status, _, blocked = client.request("/api/plan", "POST", {"message": "rm -rf /"})
    assert_equal(status, 200, "blocked plan status")
    assert_equal(blocked["plan"]["status"], "blocked", "root deletion")
    print("blocked:", blocked["plan"]["blocked"]["id"])

    status, _, simulated = client.request(
        "/api/lab/simulate", "POST", {"command": "systemctl stop sshd"}
    )
    assert_equal(status, 200, "simulation status")
    print("simulation detected:", simulated["detected"])

    status, _, audit = client.request("/api/audit?limit=20")
    assert_equal(status, 200, "audit status")
    print("audit events:", len(audit["events"]))
    print("API smoke test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("API smoke test failed: %s" % exc, file=sys.stderr)
        raise
