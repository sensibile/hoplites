#!/usr/bin/env python3
"""Resolve a SAST truth spec (function + call name per case) to sink line ranges.

The spec names sinks by enclosing function and call name instead of line numbers so the
seed code carries no markers an agent could read. Resolution fails unless each sink is
exactly one call in its function.
"""

import argparse
import ast
import hashlib
import json
from pathlib import Path

TRUTH_SCHEMA = "hoplites-sast-truth/1"
SPEC_SCHEMA = "hoplites-sast-truth-spec/1"
POLARITIES = {"vulnerable", "fixed"}


def call_matches(node, call):
    """A bare name matches the called attribute/name; a dotted name matches the call's suffix."""
    func = node.func
    if "." in call:
        dotted = ast.unparse(func)
        return dotted == call or dotted.endswith("." + call)
    if isinstance(func, ast.Attribute):
        return func.attr == call
    return isinstance(func, ast.Name) and func.id == call


def sink_range(source, function, call):
    """Return (start, end) of the single `call` inside `function`, then the function's (start, end)."""
    tree = ast.parse(source)
    defs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function
    ]
    if len(defs) != 1:
        raise ValueError(f"function {function!r}: expected 1 definition, found {len(defs)}")
    calls = [n for n in ast.walk(defs[0]) if isinstance(n, ast.Call) and call_matches(n, call)]
    if len(calls) != 1:
        raise ValueError(f"{function}: expected 1 call to {call!r}, found {len(calls)}")
    return calls[0].lineno, calls[0].end_lineno, defs[0].lineno, defs[0].end_lineno


def tree_digest(files):
    """SHA-256 over sorted (path, content sha256) pairs; files maps relative path to bytes."""
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(f"{path}\0{hashlib.sha256(files[path]).hexdigest()}\n".encode())
    return h.hexdigest()


def resolve(spec, sources):
    """Pure core: spec dict + {relative path: source text} -> truth dict."""
    if spec.get("schema") != SPEC_SCHEMA:
        raise ValueError(f"unsupported spec schema {spec.get('schema')!r}")
    ids = [c["id"] for c in spec["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    by_id = {c["id"]: c for c in spec["cases"]}
    cases, seen_sinks = [], {}
    for case in spec["cases"]:
        if case["polarity"] not in POLARITIES:
            raise ValueError(f"{case['id']}: polarity {case['polarity']!r}")
        pair = case.get("pair")
        if pair is not None and by_id.get(pair, {}).get("pair") != case["id"]:
            raise ValueError(f"{case['id']}: pair {pair!r} is not reciprocal")
        if pair is not None and by_id[pair]["polarity"] == case["polarity"]:
            raise ValueError(f"{case['id']}: pair {pair!r} has the same polarity")
        sink = case["sink"]
        if sink["path"] not in sources:
            raise ValueError(f"{case['id']}: missing file {sink['path']}")
        start, end, fn_start, fn_end = sink_range(
            sources[sink["path"]], sink["function"], sink["call"]
        )
        key = (sink["path"], start)
        if key in seen_sinks:
            raise ValueError(f"{case['id']}: sink shared with {seen_sinks[key]}")
        seen_sinks[key] = case["id"]
        cases.append(
            {
                **case,
                "sink": {**sink, "start_line": start, "end_line": end},
                "function_range": [fn_start, fn_end],
            }
        )
    return {
        "schema": TRUTH_SCHEMA,
        "set": spec["set"],
        "language": spec["language"],
        "author": spec.get("author"),
        "cases": cases,
    }


def read_tree(root):
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*.py"))
        if "__pycache__" not in p.parts
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--root", type=Path, help="Seed set root (default: spec directory)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    root = args.root or args.spec.parent
    files = read_tree(root)
    truth = resolve(json.loads(args.spec.read_text()), {k: v.decode() for k, v in files.items()})
    truth["source"] = {
        "spec_sha256": hashlib.sha256(args.spec.read_bytes()).hexdigest(),
        "tree_sha256": tree_digest(files),
        "files": len(files),
    }
    args.output.write_text(json.dumps(truth, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
