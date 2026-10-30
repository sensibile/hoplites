#!/usr/bin/env python3
"""Promotion gate for synthesized SAST rules (judgment only; inputs come from sast_measure.py).

A rule is promoted only if all three hold on the development set:
  1. it detects every confirmed case it claims (`hoplites-regression-cases`),
  2. it does not fire on the fixed pair of any of those cases,
  3. adding the candidate rule set does not regress the engine config: paired precision does
     not drop, fixed-case false alarms do not grow, and no new in-scope finding appears
     outside the truth set (an unlabeled finding is unknown, not a true positive).
"""

import argparse
import json
from pathlib import Path

GATE_VERSION = "1"


def rule_hits(matrix, rule_id):
    return {cid for cid, c in matrix["cases"].items() if rule_id in c["rules"]}


def unlabeled_keys(matrix):
    return {(f["rule_id"], f["path"], f["start_line"]) for f in matrix["unlabeled_in_scope"]}


def judge(rules, truth, confirmed_cases, baseline, candidate, rule_only):
    """Pure core: rule metadata + matrices -> per-rule and set-level verdicts."""
    pairs = {c["id"]: c.get("pair") for c in truth["cases"]}
    polarity = {c["id"]: c["polarity"] for c in truth["cases"]}
    verdicts = []
    for rule in rules:
        targets = rule["regression_cases"]
        hits = rule_hits(rule_only, rule["id"])
        problems = []
        for case in targets:
            if polarity.get(case) != "vulnerable":
                problems.append(f"{case}: not a vulnerable truth case")
            elif case not in confirmed_cases:
                problems.append(f"{case}: not confirmed by PoC")
            elif case not in hits:
                problems.append(f"{case}: not detected")
            pair = pairs.get(case)
            if pair and pair in hits:
                problems.append(f"{pair}: fires on fixed pair")
        fixed_hits = sorted(c for c in hits if polarity[c] == "fixed")
        if fixed_hits:
            problems.append(f"fires on fixed cases {fixed_hits}")
        if not targets:
            problems.append("no regression cases")
        verdicts.append({"rule": rule["id"], "pass": not problems, "problems": problems})
    b, c = baseline["total"], candidate["total"]
    new_unlabeled = sorted(unlabeled_keys(candidate) - unlabeled_keys(baseline))
    bp, cp = b["precision_paired"]["value"], c["precision_paired"]["value"]
    set_problems = []
    if cp == "UNKNOWN" or (bp != "UNKNOWN" and cp < bp):
        set_problems.append(f"paired precision {bp} -> {cp}")
    if c["false_alarms"]["num"] > b["false_alarms"]["num"]:
        set_problems.append(
            f"fixed-case false alarms {b['false_alarms']['num']} -> {c['false_alarms']['num']}"
        )
    if new_unlabeled:
        set_problems.append(f"{len(new_unlabeled)} new in-scope findings outside truth")
    return {
        "gate_version": GATE_VERSION,
        "rules": verdicts,
        "set": {
            "pass": not set_problems,
            "problems": set_problems,
            "baseline": {
                "recall": b["recall"],
                "false_alarms": b["false_alarms"],
                "precision_paired": b["precision_paired"],
            },
            "candidate": {
                "recall": c["recall"],
                "false_alarms": c["false_alarms"],
                "precision_paired": c["precision_paired"],
            },
            "new_unlabeled": [list(k) for k in new_unlabeled],
        },
        "promote": [v["rule"] for v in verdicts if v["pass"]] if not set_problems else [],
    }


def load_rules(paths):
    """Read rule metadata from opengrep YAML (top-level `rules:` list) or Joern model JSON."""
    out = []
    for p in paths:
        if p.suffix == ".json":
            model = json.loads(p.read_text())
            for s in model["sinks"]:
                out.append({"id": s["id"], "regression_cases": s.get("regression_cases", [])})
            continue
        import yaml

        for r in yaml.safe_load(p.read_text())["rules"]:
            meta = r.get("metadata", {})
            out.append(
                {"id": r["id"], "regression_cases": meta.get("hoplites-regression-cases", [])}
            )
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, nargs="+", required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument(
        "--confirmed-measure", type=Path, required=True, help="measure.json holding agent-confirmed"
    )
    parser.add_argument("--measure", type=Path, required=True)
    parser.add_argument("--baseline", required=True, help="Config label before adding rules")
    parser.add_argument("--candidate", required=True, help="Config label with rules added")
    parser.add_argument(
        "--rule-only", required=True, help="Config label of the candidate rules alone"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    truth = json.loads(args.truth.read_text())
    m = json.loads(args.measure.read_text())["matrices"]
    conf = json.loads(args.confirmed_measure.read_text())["matrices"]["agent-confirmed"]["cases"]
    confirmed = {cid for cid, c in conf.items() if c["strict"]}
    result = judge(
        load_rules(args.rules),
        truth,
        confirmed,
        m[args.baseline],
        m[args.candidate],
        m[args.rule_only],
    )
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {"promote": result["promote"], "set": result["set"]["problems"]}, ensure_ascii=False
        )
    )


if __name__ == "__main__":
    main()
