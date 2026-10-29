#!/usr/bin/env python3
"""Calculate the detection/precision matrix of SAST configs against a resolved truth set.

Calculation only: collection lives in the engine runner and normalizer, judgment in the
rule gate. Definitions are fixed in docs/sast-python-engine-loop.md (measurement v1).
"""

import argparse
import hashlib
import json
from pathlib import Path

MEASURE_VERSION = "1"
# Pre-registered CWE equivalence: a finding counts for a case only with one of these CWEs.
ACCEPTED = {
    "CWE-89": {"CWE-89"},
    "CWE-78": {"CWE-78", "CWE-77"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "CWE-918": {"CWE-918"},
    "CWE-502": {"CWE-502"},
}
IN_SCOPE = set().union(*ACCEPTED.values())


def overlaps(finding, sink):
    start = finding.get("start_line")
    if start is None or finding.get("path") != sink["path"]:
        return False
    end = finding.get("end_line") or start
    return start <= sink["end_line"] and end >= sink["start_line"]


def in_function(finding, case):
    """Post-hoc secondary match (added after the first Bandit output): same enclosing function."""
    start = finding.get("start_line")
    lo, hi = case["function_range"]
    return start is not None and finding.get("path") == case["sink"]["path"] and lo <= start <= hi


def case_hits(case, findings):
    """Findings on the case sink: strict (accepted CWE) and location-only (any CWE)."""
    on_sink = [f for f in findings if overlaps(f, case["sink"])]
    strict = [f for f in on_sink if set(f["cwe"]) & ACCEPTED[case["cwe"]]]
    return strict, on_sink


def ratio(num, den):
    return {"num": num, "den": den, "value": round(num / den, 4) if den else "UNKNOWN"}


def config_matrix(truth, findings):
    """Per CWE and per flow kind: recall over vulnerable cases, false alarms on fixed cases."""
    rows, per_case = {}, {}
    for case in truth["cases"]:
        strict, loc = case_hits(case, findings)
        per_case[case["id"]] = {
            "strict": bool(strict),
            "location_only": bool(loc),
            "function_scope": any(
                in_function(f, case) and set(f["cwe"]) & ACCEPTED[case["cwe"]] for f in findings
            ),
            "rules": sorted({f["rule_id"] for f in strict}),
            "other_cwe": sorted(
                {c for f in loc if f not in strict for c in f["cwe"] or ["(none)"]}
            ),
        }
    for scope_key, key_of in (("by_cwe", lambda c: c["cwe"]), ("by_flow", lambda c: c["flow"])):
        groups = {}
        for case in truth["cases"]:
            g = groups.setdefault(
                key_of(case),
                {"vuln": 0, "tp": 0, "tp_loc": 0, "tp_fn": 0, "fixed": 0, "fa": 0, "fa_fn": 0},
            )
            hit = per_case[case["id"]]
            if case["polarity"] == "vulnerable":
                g["vuln"] += 1
                g["tp"] += hit["strict"]
                g["tp_loc"] += hit["location_only"]
                g["tp_fn"] += hit["function_scope"]
            else:
                g["fixed"] += 1
                g["fa"] += hit["strict"]
                g["fa_fn"] += hit["function_scope"]
        rows[scope_key] = {
            k: {
                "recall": ratio(g["tp"], g["vuln"]),
                "recall_location_only": ratio(g["tp_loc"], g["vuln"]),
                "false_alarms": ratio(g["fa"], g["fixed"]),
                "precision_paired": ratio(g["tp"], g["tp"] + g["fa"]),
                "posthoc_function_scope": {
                    "recall": ratio(g["tp_fn"], g["vuln"]),
                    "false_alarms": ratio(g["fa_fn"], g["fixed"]),
                },
            }
            for k, g in sorted(groups.items())
        }
    tp = sum(per_case[c["id"]]["strict"] for c in truth["cases"] if c["polarity"] == "vulnerable")
    vuln = sum(c["polarity"] == "vulnerable" for c in truth["cases"])
    fa = sum(per_case[c["id"]]["strict"] for c in truth["cases"] if c["polarity"] == "fixed")
    fixed = len(truth["cases"]) - vuln
    labeled = [f for f in findings if any(overlaps(f, c["sink"]) for c in truth["cases"])]
    unlabeled = [f for f in findings if f not in labeled]
    unlabeled_in_scope = [f for f in unlabeled if set(f["cwe"]) & IN_SCOPE]
    rows["total"] = {
        "recall": ratio(tp, vuln),
        "false_alarms": ratio(fa, fixed),
        "precision_paired": ratio(tp, tp + fa),
        "findings": len(findings),
        "unlabeled_in_scope": len(unlabeled_in_scope),
        "unlabeled_other": len(unlabeled) - len(unlabeled_in_scope),
    }
    rows["unlabeled_in_scope"] = [
        {k: f.get(k) for k in ("rule_id", "cwe", "path", "start_line")} for f in unlabeled_in_scope
    ]
    rows["cases"] = per_case
    return rows


def disagreements(truth, matrices):
    """Cases where configs differ in strict detection; each is an investigation item."""
    out = []
    for case in truth["cases"]:
        hits = {name: m["cases"][case["id"]]["strict"] for name, m in matrices.items()}
        if len(set(hits.values())) > 1:
            out.append(
                {
                    "case": case["id"],
                    "polarity": case["polarity"],
                    "flow": case["flow"],
                    "detected_by": sorted(k for k, v in hits.items() if v),
                    "missed_by": sorted(k for k, v in hits.items() if not v),
                }
            )
    return out


def union(findings_by_config, names):
    return [f for n in names for f in findings_by_config[n]]


def measure(truth, findings_by_config, unions=None):
    matrices = {name: config_matrix(truth, fs) for name, fs in findings_by_config.items()}
    for label, names in (unions or {}).items():
        matrices[label] = config_matrix(truth, union(findings_by_config, names))
    singles = {k: v for k, v in matrices.items() if k in findings_by_config}
    return {
        "measure_version": MEASURE_VERSION,
        "truth": {"set": truth["set"], "source": truth.get("source"), "cases": len(truth["cases"])},
        "accepted_cwe": {k: sorted(v) for k, v in ACCEPTED.items()},
        "unions": unions or {},
        "matrices": matrices,
        "disagreements": disagreements(truth, singles),
    }


def load_findings(path):
    doc = json.loads(path.read_text())
    return doc["config"], doc["findings"], hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--findings", type=Path, nargs="+", required=True)
    parser.add_argument(
        "--union", action="append", default=[], help="label=configA,configB (union of findings)"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    truth = json.loads(args.truth.read_text())
    by_config, inputs = {}, {}
    for p in args.findings:
        name, fs, digest = load_findings(p)
        if name in by_config:
            parser.error(f"duplicate config {name}")
        by_config[name], inputs[name] = fs, {"path": str(p), "sha256": digest}
    unions = {}
    for spec in args.union:
        label, names = spec.split("=", 1)
        unions[label] = names.split(",")
    result = measure(truth, by_config, unions)
    result["inputs"] = inputs
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
