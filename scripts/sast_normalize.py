#!/usr/bin/env python3
"""Normalize engine SARIF into hoplites SAST findings (CWE, location, flow path).

The raw SARIF stays untouched next to the output. CWE comes only from what the engine
reported (rule tags/properties/taxa); nothing is inferred from rule names.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlparse

FINDINGS_SCHEMA = "hoplites-sast-findings/1"
NORMALIZER_VERSION = "1"
CWE = re.compile(r"\bCWE[-_ ]?(\d+)\b", re.I)


def cwe_list(values):
    found = set()
    for v in values:
        found.update(f"CWE-{int(m)}" for m in CWE.findall(str(v)))
    return sorted(found, key=lambda c: int(c[4:]))


def rule_cwes(rule):
    props = rule.get("properties", {})
    values = list(props.get("tags", []))
    for key in ("cwe", "CWE", "cwe_id"):
        if key in props:
            values += props[key] if isinstance(props[key], list) else [props[key]]
    values += [r.get("target", {}).get("id", "") for r in rule.get("relationships", [])]
    return cwe_list(values)


def relative_uri(uri, base_ids, uri_base_id, target_root):
    """Resolve a SARIF artifact URI to a path relative to the scanned target root."""
    if uri_base_id and uri_base_id in base_ids:
        uri = base_ids[uri_base_id].rstrip("/") + "/" + uri
    parsed = urlparse(uri)
    path = unquote(parsed.path) if parsed.scheme == "file" else unquote(uri)
    root = str(target_root).rstrip("/") + "/"
    for prefix in (root, "/private" + root):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path.removeprefix("./")


def physical(loc, base_ids, target_root):
    phys = loc.get("physicalLocation", {})
    art = phys.get("artifactLocation", {})
    region = phys.get("region", {})
    start = region.get("startLine")
    return {
        "path": relative_uri(art.get("uri", ""), base_ids, art.get("uriBaseId"), target_root),
        "start_line": start,
        "end_line": region.get("endLine", start),
    }


def normalize(sarif, config, target_root):
    """Pure core: SARIF dict -> list of normalized findings for one engine config."""
    out = []
    for run_index, run in enumerate(sarif.get("runs", [])):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])
        by_id = {r.get("id"): r for r in rules}
        base_ids = {k: v.get("uri", "") for k, v in run.get("originalUriBaseIds", {}).items()}
        for index, res in enumerate(run.get("results", [])):
            rule = by_id.get(res.get("ruleId"))
            if (
                rule is None
                and isinstance(res.get("ruleIndex"), int)
                and res["ruleIndex"] < len(rules)
            ):
                rule = rules[res["ruleIndex"]]
            rule = rule or {}
            cwes = cwe_list(
                rule_cwes(rule)
                + res.get("properties", {}).get("tags", [])
                + [res.get("properties", {}).get("cwe", "")]
                + [t.get("id", "") for t in res.get("taxa", [])]
            )
            locs = res.get("locations") or [{}]
            primary = physical(locs[0], base_ids, target_root)
            flow = []
            for cf in res.get("codeFlows", [])[:1]:
                for tf in cf.get("threadFlows", [])[:1]:
                    flow = [
                        physical(s.get("location", {}), base_ids, target_root)
                        for s in tf.get("locations", [])
                    ]
            out.append(
                {
                    "config": config,
                    "engine": driver.get("name"),
                    "engine_version": driver.get("semanticVersion") or driver.get("version"),
                    "rule_id": res.get("ruleId") or rule.get("id"),
                    "cwe": cwes,
                    **primary,
                    "flow": [{"path": f["path"], "line": f["start_line"]} for f in flow],
                    "message": (res.get("message") or {}).get("text", "")[:300],
                    "raw_ref": {"run": run_index, "result": index},
                }
            )
    return sorted(out, key=lambda f: (f["path"], f["start_line"] or 0, f["rule_id"] or ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--config", required=True, help="Engine configuration label")
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    raw = args.sarif.read_bytes()
    findings = normalize(json.loads(raw), args.config, args.target_root.resolve())
    doc = {
        "schema": FINDINGS_SCHEMA,
        "normalizer_version": NORMALIZER_VERSION,
        "config": args.config,
        "sarif": {"path": str(args.sarif), "sha256": hashlib.sha256(raw).hexdigest()},
        "findings": findings,
    }
    args.output.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
