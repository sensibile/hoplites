#!/usr/bin/env python3
"""Compare image packages at ecosystem/name/version/architecture grain."""

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, unquote


def identity(c):
    purl = c.get("purl", "")
    if not purl:
        return (c.get("type"), c["name"], c.get("version"), None)
    ecosystem = purl.split("/")[0]
    arch = parse_qs(urlsplit(purl).query).get("arch", [None])[0]
    package_path = unquote(purl.split("?", 1)[0].split("/", 1)[1].rsplit("@", 1)[0])
    return ecosystem, package_path, c.get("version"), arch


def compare(left, right):
    a, b = {}, {}
    for bom, index in [(left, a), (right, b)]:
        for c in bom["components"]:
            if c["type"] != "file":
                index.setdefault(identity(c), []).append(c)
    shared = []
    for key in sorted(a.keys() & b.keys(), key=str):
        # Preserve multiplicities and all original records; no lossy identity merging.
        ordered_a = sorted(
            a[key], key=lambda c: json.dumps([c.get("purl"), c.get("licenses")], sort_keys=True)
        )
        ordered_b = sorted(
            b[key], key=lambda c: json.dumps([c.get("purl"), c.get("licenses")], sort_keys=True)
        )
        shared.append(
            {
                "identity": key,
                "left": ordered_a,
                "right": ordered_b,
                "purl_equal": [c.get("purl") for c in ordered_a]
                == [c.get("purl") for c in ordered_b],
                "licenses_equal": [c.get("licenses") for c in ordered_a]
                == [c.get("licenses") for c in ordered_b],
            }
        )
    return {
        "left_count": len(left["components"]),
        "right_count": len(right["components"]),
        "left_file_count": sum(c["type"] == "file" for c in left["components"]),
        "right_file_count": sum(c["type"] == "file" for c in right["components"]),
        "shared": shared,
        "left_only": [c for k in sorted(a.keys() - b.keys(), key=str) for c in a[k]],
        "right_only": [c for k in sorted(b.keys() - a.keys(), key=str) for c in b[k]],
        "limitations": [
            "Architecture/name/version mismatches remain separate records requiring inventory review",
            "Matching package identity does not prove binary or license equivalence",
            "Syft does not perform a CVE scan in this pipeline",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["original", "normalized", "trivy", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    a, n, t = [json.loads(p.read_text()) for p in [args.original, args.normalized, args.trivy]]
    args.output.write_text(
        json.dumps(
            {"original_vs_trivy": compare(a, t), "normalized_vs_trivy": compare(n, t)},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
