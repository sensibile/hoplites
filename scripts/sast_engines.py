#!/usr/bin/env python3
"""Run one SAST engine configuration on a Python source tree and keep its raw output.

Shell only: it records the exact command, engine/binary/rule digests and the target tree
digest in manifest.json, and never edits raw output. Normalization is sast_normalize.py.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))
from sast_truth import read_tree, tree_digest  # noqa: E402

JOERN_SCRIPT = Path(__file__).parent / "sast_joern_taint.sc"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dir_digest(root, patterns):
    root = Path(root)
    files = {
        str(p.relative_to(root)): p.read_bytes()
        for pattern in patterns
        for p in sorted(root.rglob(pattern))
        if p.is_file()
    }
    return {"path": str(root.resolve()), "files": len(files), "sha256": tree_digest(files)}


def run(command, cwd):
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    return done.returncode, done.stdout[-4000:], done.stderr[-4000:]


def bandit(args, out):
    sarif, raw = out / "bandit.sarif", out / "bandit.json"
    base = [args.bandit, "-r", "app", "-q"]
    code, _, err = run(base + ["-f", "sarif", "-o", str(sarif)], args.target)
    run(base + ["-f", "json", "-o", str(raw)], args.target)
    version = subprocess.check_output([args.bandit, "--version"], text=True).splitlines()[0]
    return {
        "engine": {"name": "bandit", "version": version, "plugins": "default (all)"},
        "command": base + ["-f", "sarif", "-o", str(sarif)],
        "exit_code": code,
        "stderr_tail": err,
        "sarif": sarif,
        "raw": [raw],
    }


def opengrep(args, out):
    sarif, raw = out / "opengrep.sarif", out / "opengrep.json"
    command = [args.opengrep, "scan", "--disable-version-check", "--no-rewrite-rule-ids", "--quiet"]
    for rules in args.rules:
        command += ["--config", str(Path(rules).resolve())]
    if args.taint_intrafile:
        command.append("--taint-intrafile")
    command += ["--json-output", str(raw), "--sarif-output", str(sarif), "app"]
    code, _, err = run(command, args.target)
    version = subprocess.check_output([args.opengrep, "--version"], text=True).strip()
    return {
        "engine": {
            "name": "opengrep",
            "version": version,
            "binary_sha256": sha256(Path(args.opengrep).resolve()),
        },
        "rules": [dir_digest(r, ["*.yaml", "*.yml"]) for r in args.rules],
        "command": command,
        "exit_code": code,
        "stderr_tail": err,
        "sarif": sarif,
        "raw": [raw],
    }


def joern(args, out):
    sarif, raw = out / "joern.sarif", out / "joern-flows.json"
    cpg = out / "cpg.bin"
    parse = [
        str(Path(args.joern_home) / "joern-parse"),
        str(Path(args.target) / "app"),
        "--language",
        "pythonsrc",
        "-o",
        str(cpg),
    ]
    code, _, err = run(parse, args.target)
    if code != 0:
        raise SystemExit(f"joern-parse failed: {err}")
    command = [
        str(Path(args.joern_home) / "joern"),
        "--script",
        str(JOERN_SCRIPT),
        "--param",
        f"cpgFile={cpg}",
        "--param",
        f"modelFile={Path(args.model).resolve()}",
        "--param",
        f"outFile={raw}",
    ]
    code, stdout, err = run(command, args.target)
    if not raw.exists():
        raise SystemExit(f"joern script produced no output: {err or stdout}")
    sarif.write_text(json.dumps(flows_to_sarif(json.loads(raw.read_text()), args), indent=2) + "\n")
    version = (
        (Path(args.joern_home) / "VERSION").read_text().strip()
        if (Path(args.joern_home) / "VERSION").exists()
        else args.joern_version
    )
    return {
        "engine": {"name": "joern", "version": version},
        "model": {"path": str(Path(args.model).resolve()), "sha256": sha256(args.model)},
        "script_sha256": sha256(JOERN_SCRIPT),
        "command": [parse, command],
        "exit_code": code,
        "stderr_tail": err,
        "sarif": sarif,
        "raw": [raw],
    }


def flows_to_sarif(doc, args):
    """Convert the Joern taint script's flow list to SARIF 2.1.0 (raw JSON is kept as-is)."""
    rules = {}
    results = []
    for f in doc["flows"]:
        rules.setdefault(f["rule"], {"id": f["rule"], "properties": {"tags": [f["cwe"]]}})
        steps = [s for s in f["path"] if s.get("file") and s.get("line")]
        sink = steps[-1] if steps else {"file": f.get("sinkFile"), "line": f.get("sinkLine")}
        loc = lambda s: {
            "physicalLocation": {
                "artifactLocation": {"uri": "app/" + s["file"]},
                "region": {"startLine": s["line"]},
            }
        }  # noqa: E731
        results.append(
            {
                "ruleId": f["rule"],
                "message": {"text": f"{f['cwe']} flow from {f['source']} to {f['sink']}"},
                "locations": [loc(sink)],
                "codeFlows": [
                    {"threadFlows": [{"locations": [{"location": loc(s)} for s in steps]}]}
                ],
            }
        )
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "joern",
                        "version": args.joern_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=["bandit", "opengrep", "joern"])
    parser.add_argument("--target", type=Path, required=True, help="Seed set root containing app/")
    parser.add_argument("--config", required=True, help="Configuration label")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bandit", default="bandit")
    parser.add_argument("--opengrep", default="opengrep")
    parser.add_argument("--rules", action="append", default=[])
    parser.add_argument("--taint-intrafile", action="store_true")
    parser.add_argument("--joern-home", type=Path)
    parser.add_argument("--joern-version", default="unknown")
    parser.add_argument("--model", type=Path, help="Joern source/sink model JSON")
    args = parser.parse_args()
    out = (args.output_dir / args.config).resolve()
    if out.exists():
        parser.error("Use a new output directory")
    out.mkdir(parents=True)
    result = {"bandit": bandit, "opengrep": opengrep, "joern": joern}[args.engine](args, out)
    if not result["sarif"].exists():
        raise SystemExit(
            f"{args.engine} produced no SARIF (exit {result['exit_code']}): {result['stderr_tail']}"
        )
    files = read_tree(args.target / "app")
    manifest = {
        "config": args.config,
        **{k: v for k, v in result.items() if k not in ("sarif", "raw")},
        "target": {
            "path": str(args.target.resolve()),
            "app_tree_sha256": tree_digest(files),
            "files": len(files),
        },
        "outputs": {p.name: sha256(p) for p in [result["sarif"], *result["raw"]]},
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=str) + "\n"
    )
    print(out / result["sarif"].name)


if __name__ == "__main__":
    main()
