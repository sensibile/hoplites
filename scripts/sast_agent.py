#!/usr/bin/env python3
"""Turn agent hypotheses and PoC outcomes into findings with inferred/confirmed status.

Every hypothesis starts as `inferred`. It becomes `confirmed` only when the PoC test mapped
to it asserts the exploit and passed. A failed, erroring or missing PoC keeps it `inferred`;
nothing here marks code safe. `reviewed_not_vulnerable` entries are coverage records only.
"""

import argparse
import hashlib
import json
from pathlib import Path

FINDINGS_SCHEMA = "hoplites-sast-findings/1"


def status(hypothesis_id, confirmations, outcomes):
    """Return (status, evidence) for one hypothesis."""
    poc = confirmations.get(hypothesis_id)
    if poc is None:
        return "inferred", {"poc": None, "outcome": "not_run"}
    outcome = outcomes.get(poc, "not_run")
    return ("confirmed" if outcome == "pass" else "inferred"), {"poc": poc, "outcome": outcome}


def findings(doc, confirmations, outcomes, run):
    """Pure core: hypotheses doc -> (inferred findings, confirmed findings, coverage records)."""
    inferred, confirmed = [], []
    for h in doc["hypotheses"]:
        state, evidence = status(h["id"], confirmations, outcomes)
        line = h["sink"]["line"]
        item = {
            "engine": "agent",
            "engine_version": doc.get("model"),
            "rule_id": h["id"],
            "cwe": [h["cwe"]],
            "path": h["sink"]["path"],
            "start_line": line,
            "end_line": line,
            "flow": [{"path": s["path"], "line": s["line"]} for s in h.get("steps", [])],
            "message": h.get("rationale", "")[:300],
            "confidence": h.get("confidence"),
            "status": state,
            "evidence": evidence,
            "run": run,
        }
        inferred.append({**item, "config": "agent-inferred"})
        if state == "confirmed":
            confirmed.append({**item, "config": "agent-confirmed"})
    coverage = [
        {**r, "status": "coverage_only", "run": run} for r in doc.get("reviewed_not_vulnerable", [])
    ]
    return inferred, confirmed, coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hypotheses", type=Path)
    parser.add_argument("--confirmations", type=Path, help="{hypothesis id: PoC test id}")
    parser.add_argument("--poc-outcomes", type=Path, help="sast_poc_run.py output")
    parser.add_argument("--prompt", type=Path, required=True, help="Prompt file used for the run")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Use a new output directory")
    raw = args.hypotheses.read_bytes()
    doc = json.loads(raw)
    confirmations = json.loads(args.confirmations.read_text()) if args.confirmations else {}
    outcomes = json.loads(args.poc_outcomes.read_text())["outcomes"] if args.poc_outcomes else {}
    run = {
        "prompt_id": doc.get("prompt"),
        "prompt_sha256": hashlib.sha256(args.prompt.read_bytes()).hexdigest(),
        "model": doc.get("model"),
        "hypotheses_sha256": hashlib.sha256(raw).hexdigest(),
    }
    inferred, confirmed, coverage = findings(doc, confirmations, outcomes, run)
    args.output_dir.mkdir(parents=True)
    for name, items in (("agent-inferred", inferred), ("agent-confirmed", confirmed)):
        (args.output_dir / f"{name}.json").write_text(
            json.dumps(
                {"schema": FINDINGS_SCHEMA, "config": name, "run": run, "findings": items},
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
    (args.output_dir / "coverage.json").write_text(
        json.dumps({"run": run, "records": coverage}, ensure_ascii=False, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
