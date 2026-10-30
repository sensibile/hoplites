#!/usr/bin/env python3
"""Run one SAST engine configuration on a Python source tree and keep its raw output.

Shell only: it records the exact command, engine/binary/rule digests and the target tree
digest in manifest.json, and never edits raw output. Normalization is sast_normalize.py.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))
from sast_truth import read_tree, tree_digest  # noqa: E402

JOERN_SCRIPT = Path(__file__).parent / "sast_joern_taint.sc"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable(name):
    """Absolute path of an engine binary given as a path or a PATH command name."""
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"executable not found: {name}")
    return str(Path(found).resolve())


def dir_digest(root, patterns):
    root = Path(root)
    files = {
        str(p.relative_to(root)): p.read_bytes()
        for pattern in patterns
        for p in sorted(root.rglob(pattern))
        if p.is_file()
    }
    return {"path": str(root.resolve()), "files": len(files), "sha256": tree_digest(files)}


def run(command, cwd, env=None):
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True, env=env)
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
            "binary_sha256": sha256(args.opengrep),
        },
        "rules": [dir_digest(r, ["*.yaml", "*.yml"]) for r in args.rules],
        "command": command,
        "exit_code": code,
        "stderr_tail": err,
        "sarif": sarif,
        "raw": [raw],
    }


def joern_env(args):
    env = dict(os.environ)
    if args.java_home:
        env["JAVA_HOME"] = str(args.java_home)
        env["PATH"] = f"{args.java_home}/bin:{env['PATH']}"
    return env


def joern(args, out):
    """Call the launchers in bin/ directly; the top-level wrappers need GNU readlink on macOS."""
    sarif, raw = out / "joern.sarif", out / "joern-flows.json"
    cpg = out / "cpg.bin"
    home = Path(args.joern_home)
    jvm = ["-J-XX:+UseG1GC", f"-Dlog4j.configurationFile={home / 'conf/log4j2.xml'}"]
    parse = [str(home / "bin/joern-parse"), *jvm, str(Path(args.target) / "app")]
    parse += ["--language", "pythonsrc", "-o", str(cpg)]
    env = joern_env(args)
    code, _, err = run(parse, home, env)
    if code != 0:
        raise SystemExit(f"joern-parse failed: {err}")
    command = [str(home / "bin/repl-bridge"), *jvm, "--script", str(JOERN_SCRIPT)]
    command += ["--param", f"cpgFile={cpg}", "--param", f"modelFile={Path(args.model).resolve()}"]
    command += ["--param", f"outFile={raw}"]
    code, stdout, err = run(command, home, env)
    if not raw.exists():
        raise SystemExit(f"joern script produced no output: {err or stdout}")
    sarif.write_text(json.dumps(flows_to_sarif(json.loads(raw.read_text()), args), indent=2) + "\n")
    java = subprocess.run(["java", "-version"], capture_output=True, text=True, env=env).stderr
    return {
        "engine": {
            "name": "joern",
            "version": args.joern_version,
            "java": java.splitlines()[0] if java else None,
        },
        "model": {"path": str(Path(args.model).resolve()), "sha256": sha256(args.model)},
        "script_sha256": sha256(JOERN_SCRIPT),
        "command": [parse, command],
        "exit_code": code,
        "stderr_tail": err,
        "sarif": sarif,
        "raw": [raw],
    }


def location(step):
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": "app/" + step["file"]},
            "region": {"startLine": step["line"]},
        }
    }


def scan_problems(sarif_doc, raw_docs):
    """Engine-reported errors and notifications, so a partial scan is not read as complete."""
    notes = [
        n.get("message", {}).get("text", "")
        for run in sarif_doc.get("runs", [])
        for inv in run.get("invocations", [])
        for n in inv.get("toolExecutionNotifications", [])
    ]
    errors = [e for doc in raw_docs if isinstance(doc, dict) for e in doc.get("errors", [])]
    return {
        "errors": len(errors),
        "error_samples": [str(e)[:300] for e in errors[:5]],
        "sarif_notifications": len(notes),
        "notification_samples": [n[:300] for n in notes[:5]],
    }


def flows_to_sarif(doc, args):
    """Convert Joern flows to SARIF 2.1.0: one result per (rule, sink line), shortest path kept.

    The raw flow JSON keeps every path.
    """
    rules, best = {}, {}
    for f in doc["flows"]:
        rules.setdefault(f["rule"], {"id": f["rule"], "properties": {"tags": [f["cwe"]]}})
        steps = [s for s in f["path"] if s.get("file") and s.get("line")]
        if not steps:
            continue
        key = (f["rule"], steps[-1]["file"], steps[-1]["line"])
        if key not in best or len(steps) < len(best[key][1]):
            best[key] = (f, steps)
    results = [
        {
            "ruleId": f["rule"],
            "message": {"text": f"{f['cwe']} flow from {f['source']} to {f['sink']}"},
            "locations": [location(steps[-1])],
            "codeFlows": [
                {"threadFlows": [{"locations": [{"location": location(s)} for s in steps]}]}
            ],
        }
        for key, (f, steps) in sorted(best.items())
    ]
    driver = {"name": "joern", "version": args.joern_version, "rules": list(rules.values())}
    return {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}


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
    parser.add_argument("--java-home", type=Path)
    parser.add_argument("--model", type=Path, help="Joern source/sink model JSON")
    args = parser.parse_args()
    # Engines run with other working directories, so every input path is made absolute first.
    args.target = args.target.resolve()
    args.rules = [str(Path(r).resolve()) for r in args.rules]
    args.model = args.model.resolve() if args.model else None
    args.joern_home = args.joern_home.resolve() if args.joern_home else None
    if args.engine in ("bandit", "opengrep"):
        setattr(args, args.engine, executable(getattr(args, args.engine)))
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
        "scan_problems": scan_problems(
            json.loads(result["sarif"].read_text()),
            [json.loads(p.read_text()) for p in result["raw"] if p.exists()],
        ),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=str) + "\n"
    )
    print(out / result["sarif"].name)


if __name__ == "__main__":
    main()
