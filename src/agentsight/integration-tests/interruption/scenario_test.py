#!/usr/bin/env python3
"""
AgentSight Interruption Scenario Test Tool

Constructs controlled error scenarios against an LLM API endpoint,
captured by AgentSight eBPF probes, for verifying interruption
detection, classification, and logtail export.

Prerequisites:
    - AgentSight service running with eBPF probes attached
    - python3 cmdline rule in agentsight config (agent_name: "TestAgent")
    - SLS_LOGTAIL_FILE environment variable set for agentsight service

Usage:
    python3 scenario_test.py <scenario> --api-key <KEY> [--base-url URL]

    API key can also be set via DASHSCOPE_API_KEY environment variable.

Scenarios:
    auth_single    1x auth error (invalid key)
    auth_storm     5x auth error rapid-fire (retry storm, same root cause)
    mixed_light    8 normal + 2 auth errors
    mixed_heavy    5 normal + 5 auth errors (alternating)
    multi_type     1x auth + 1x model_not_found(404) + 3 normal
    healthy        10 normal calls (zero interruptions baseline)
    all            Run all scenarios sequentially
"""
import json
import time
import urllib.request
import urllib.error
import ssl
import sqlite3
import argparse

DEFAULT_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
INVALID_KEY = "sk-INVALID_SCENARIO_TEST_{}"
DB_INT = "/var/log/sysak/.agentsight/interruption_events.db"
LOGTAIL = "/var/sysom/ilog/agentsight"

CALL_INTERVAL = 2


def send_request(api_key, base_url, model="qwen-max", content="hello", max_tokens=5):
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "max_tokens": max_tokens,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {}".format(api_key),
    }
    req = urllib.request.Request(base_url, data=payload, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except Exception as e:
        return -1, str(e)


def get_baseline():
    b = {"int_count": 0, "logtail_lines": 0}
    try:
        conn = sqlite3.connect(DB_INT)
        b["int_count"] = conn.execute("SELECT COUNT(*) FROM interruption_events").fetchone()[0]
        conn.close()
    except Exception:
        pass
    try:
        with open(LOGTAIL) as f:
            b["logtail_lines"] = sum(1 for _ in f)
    except Exception:
        pass
    return b


def check_results(baseline, wait=10):
    print("\n  Waiting {}s for AgentSight processing...".format(wait))
    time.sleep(wait)

    results = {"logtail_chats": [], "logtail_interruptions": [], "new_interruptions": []}
    try:
        conn = sqlite3.connect(DB_INT)
        total = conn.execute("SELECT COUNT(*) FROM interruption_events").fetchone()[0]
        new_count = total - baseline["int_count"]
        if new_count > 0:
            rows = conn.execute(
                "SELECT interruption_type, severity, agent_name, substr(detail, 1, 200) "
                "FROM interruption_events ORDER BY id DESC LIMIT ?",
                (new_count,)
            ).fetchall()
            results["new_interruptions"] = [
                {"type": r[0], "severity": r[1], "agent": r[2], "detail": r[3][:100]}
                for r in reversed(rows)
            ]
        conn.close()
    except Exception:
        pass

    try:
        with open(LOGTAIL) as f:
            lines = f.readlines()
        new_lines = lines[baseline["logtail_lines"]:]
        for line in new_lines:
            try:
                d = json.loads(line.strip())
                if d.get("gen_ai.operation.name") == "interruption":
                    results["logtail_interruptions"].append({
                        "type": d.get("agentsight.interruption.type"),
                        "severity": d.get("agentsight.interruption.severity"),
                        "agent": d.get("agentsight.agent.name"),
                    })
                else:
                    results["logtail_chats"].append({
                        "model": d.get("gen_ai.request.model"),
                        "status": d.get("agentsight.http.status_code"),
                    })
            except Exception:
                pass
    except Exception:
        pass

    return results


def print_results(name, calls, results):
    print("\n  === Results for '{}' ===".format(name))
    print("  Calls made: {}".format(len(calls)))
    for c in calls:
        print("    {} {} -> {}".format(c["type"], c["model"], c["status"]))

    ints = results.get("logtail_interruptions", [])
    chats = results.get("logtail_chats", [])
    print("  Logtail: {} chat records, {} interruption records".format(len(chats), len(ints)))
    for i in ints:
        print("    INT: type={} severity={} agent={}".format(i["type"], i["severity"], i["agent"]))

    db_ints = results.get("new_interruptions", [])
    if db_ints:
        print("  DB interruption_events: {} new".format(len(db_ints)))
        for d in db_ints:
            print("    type={} severity={} agent={}".format(d["type"], d["severity"], d["agent"]))


# ==================== Scenarios ====================

def scenario_auth_single(api_key, base_url):
    """1x auth error"""
    baseline = get_baseline()
    calls = []
    print("  Sending 1 request with invalid API key...")
    status, _ = send_request(INVALID_KEY.format("auth_single"), base_url)
    calls.append({"type": "auth_error", "model": "qwen-max", "status": status})
    results = check_results(baseline)
    print_results("auth_single", calls, results)
    return calls, results


def scenario_auth_storm(api_key, base_url):
    """5x auth error (retry storm, same root cause)"""
    baseline = get_baseline()
    calls = []
    bad_key = INVALID_KEY.format("auth_storm")
    print("  Sending 5 rapid requests with same invalid key (retry storm)...")
    for i in range(5):
        status, _ = send_request(bad_key, base_url, content="retry {}".format(i))
        calls.append({"type": "auth_error", "model": "qwen-max", "status": status})
        time.sleep(0.5)
    results = check_results(baseline)
    print_results("auth_storm", calls, results)
    return calls, results


def scenario_mixed_light(api_key, base_url):
    """8 normal + 2 auth errors"""
    baseline = get_baseline()
    calls = []
    plan = ["ok"] * 4 + ["auth"] + ["ok"] * 4 + ["auth"]
    print("  Sending 10 requests (8 normal + 2 auth errors)...")
    for i, typ in enumerate(plan):
        if typ == "ok":
            status, _ = send_request(api_key, base_url, content="normal {}".format(i), max_tokens=5)
            calls.append({"type": "normal", "model": "qwen-max", "status": status})
        else:
            status, _ = send_request(INVALID_KEY.format("mixed_light"), base_url, content="error {}".format(i))
            calls.append({"type": "auth_error", "model": "qwen-max", "status": status})
        time.sleep(CALL_INTERVAL)
    results = check_results(baseline, wait=15)
    print_results("mixed_light", calls, results)
    return calls, results


def scenario_mixed_heavy(api_key, base_url):
    """5 normal + 5 auth errors (alternating)"""
    baseline = get_baseline()
    calls = []
    print("  Sending 10 requests (5 normal + 5 auth errors, alternating)...")
    for i in range(10):
        if i % 2 == 0:
            status, _ = send_request(api_key, base_url, content="normal {}".format(i), max_tokens=5)
            calls.append({"type": "normal", "model": "qwen-max", "status": status})
        else:
            status, _ = send_request(INVALID_KEY.format("mixed_heavy"), base_url, content="error {}".format(i))
            calls.append({"type": "auth_error", "model": "qwen-max", "status": status})
        time.sleep(CALL_INTERVAL)
    results = check_results(baseline, wait=15)
    print_results("mixed_heavy", calls, results)
    return calls, results


def scenario_multi_type(api_key, base_url):
    """1x auth + 1x model_not_found (404) + 3 normal"""
    baseline = get_baseline()
    calls = []
    print("  Sending 5 requests (1 auth + 1 bad model + 3 normal)...")

    status, _ = send_request(api_key, base_url, content="normal 1", max_tokens=5)
    calls.append({"type": "normal", "model": "qwen-max", "status": status})
    time.sleep(CALL_INTERVAL)

    status, _ = send_request(INVALID_KEY.format("multi_type"), base_url, content="auth error")
    calls.append({"type": "auth_error", "model": "qwen-max", "status": status})
    time.sleep(CALL_INTERVAL)

    status, _ = send_request(api_key, base_url, content="normal 2", max_tokens=5)
    calls.append({"type": "normal", "model": "qwen-max", "status": status})
    time.sleep(CALL_INTERVAL)

    status, _ = send_request(api_key, base_url, model="nonexistent-model-xyz-999", content="bad model")
    calls.append({"type": "model_not_found", "model": "nonexistent-model-xyz-999", "status": status})
    time.sleep(CALL_INTERVAL)

    status, _ = send_request(api_key, base_url, content="normal 3", max_tokens=5)
    calls.append({"type": "normal", "model": "qwen-max", "status": status})

    results = check_results(baseline, wait=15)
    print_results("multi_type", calls, results)
    return calls, results


def scenario_healthy(api_key, base_url):
    """10 normal calls (baseline)"""
    baseline = get_baseline()
    calls = []
    print("  Sending 10 normal requests...")
    for i in range(10):
        status, _ = send_request(api_key, base_url, content="healthy {}".format(i), max_tokens=5)
        calls.append({"type": "normal", "model": "qwen-max", "status": status})
        time.sleep(CALL_INTERVAL)
    results = check_results(baseline, wait=15)
    print_results("healthy", calls, results)
    return calls, results


SCENARIOS = {
    "auth_single": scenario_auth_single,
    "auth_storm":  scenario_auth_storm,
    "mixed_light": scenario_mixed_light,
    "mixed_heavy": scenario_mixed_heavy,
    "multi_type":  scenario_multi_type,
    "healthy":     scenario_healthy,
}


def main():
    import os
    parser = argparse.ArgumentParser(
        description="AgentSight Interruption Scenario Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("scenario", choices=list(SCENARIOS.keys()) + ["all"])
    parser.add_argument("--api-key", default=os.environ.get("DASHSCOPE_API_KEY", ""),
                        help="Valid dashscope API key (or set DASHSCOPE_API_KEY env)")
    parser.add_argument("--base-url", default=DEFAULT_URL)
    args = parser.parse_args()

    if not args.api_key:
        parser.error("API key required: use --api-key or set DASHSCOPE_API_KEY env var")

    print("=" * 60)
    print("AgentSight Scenario Test")
    print("=" * 60)
    print("Base URL: {}".format(args.base_url))
    print("Scenario: {}".format(args.scenario))

    if args.scenario == "all":
        for name in ["healthy", "auth_single", "auth_storm", "mixed_light", "multi_type"]:
            print("\n>>> Running scenario: {} <<<".format(name))
            SCENARIOS[name](args.api_key, args.base_url)
            print()
            time.sleep(5)
    else:
        SCENARIOS[args.scenario](args.api_key, args.base_url)

    print("\nDone.")


if __name__ == "__main__":
    main()
