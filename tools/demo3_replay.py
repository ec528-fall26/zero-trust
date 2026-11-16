#!/usr/bin/env python3
"""Build docs/demo3-replay.html: a page that replays the recorded Demo 3 runs.

Every value on the page is read from results/*.json, so the page cannot drift
from the evidence.  Nothing on it runs live.

    python3 tools/demo3_replay.py            # or: make demo3-replay
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
TEMPLATE = Path(__file__).resolve().parent / "demo3_replay_template.html"
OUTPUT = ROOT / "docs" / "demo3-replay.html"


def load(name: str) -> dict:
    path = RESULTS / name
    if not path.is_file():
        raise SystemExit(f"demo3-replay: missing {path.relative_to(ROOT)}; run its experiment first")
    return json.loads(path.read_text(encoding="utf-8"))


def observed(scenario: dict, key: str):
    value = scenario.get("observed")
    if isinstance(value, dict):
        return value.get(key)
    return value if key == "status" else None


def chain(result: dict) -> dict:
    agent = result.get("model_agent") if isinstance(result.get("model_agent"), dict) else {}
    return {
        "status": result["status"],
        "generated_at": result["generated_at"],
        "tpm_type": result.get("tpm_type"),
        "agent_mode": result.get("agent_mode"),
        "approver_mode": result.get("approver_mode"),
        "model": agent.get("model"),
        "timeline": result.get("timeline", []),
        "human_approvals": result.get("human_approvals"),
        "scenarios": [
            {
                "name": entry["name"],
                "passed": entry["passed"],
                "status": observed(entry, "status"),
                "reason": observed(entry, "reason"),
                "verdict": observed(entry, "attestation_verdict"),
                "executed": observed(entry, "workload_executed"),
            }
            for entry in result["scenarios"]
        ],
    }


def build() -> dict:
    end_to_end = load("demo3-end-to-end-human.json")
    nitro = load("demo3-nitrotpm-end-to-end.json")
    human = load("demo3-human-approval.json")
    trials = load("demo3-trials.json")
    return {
        "e2e": chain(end_to_end),
        "nitro": chain(nitro),
        "tool_input": (end_to_end.get("model_agent") or {}).get("tool_input"),
        "human": {
            "status": human["status"],
            "generated_at": human["generated_at"],
            "approvers": [{"name": a.get("name"), "role": a.get("role")} for a in human.get("approvers", [])],
            "wait": human.get("human_wait_seconds"),
            "scenarios": [
                {"name": s["name"], "passed": s["passed"], "expected": s.get("expected"), "launches": s.get("launches")}
                for s in human["scenarios"]
            ],
        },
        "trials": {
            "totals": trials["totals"],
            "latency": trials["latency"],
            "sizes": trials["workload_scaling"]["sizes"],
            "over": trials["workload_scaling"]["over_limit"],
        },
    }


def main() -> int:
    data = json.dumps(build(), ensure_ascii=True, separators=(",", ":"))
    # The data sits inside a <script>; never let it close the element.
    data = data.replace("</", "<\\/")
    page = TEMPLATE.read_text(encoding="utf-8").replace("__DATA__", data, 1)
    OUTPUT.write_text(page, encoding="utf-8")
    print(OUTPUT.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
