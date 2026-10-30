#!/usr/bin/env python3
"""Render a sast_measure.py result as Markdown tables (no new calculation)."""

import argparse
import json
from pathlib import Path


def cell(r):
    return f"{r['num']}/{r['den']}"


def render(measure, configs=None):
    names = configs or list(measure["matrices"])
    cwes = sorted(
        {k for n in names for k in measure["matrices"][n]["by_cwe"]}, key=lambda c: int(c[4:])
    )
    flows = sorted({k for n in names for k in measure["matrices"][n]["by_flow"]})
    lines = [
        f"세트 `{measure['truth']['set']}`, 사례 {measure['truth']['cases']}건, measure v{measure['measure_version']}",
        "",
    ]
    lines += [
        "| 구성 | "
        + " | ".join(cwes)
        + " | 전체 탐지 | 수정본 오경보 | paired 정밀도 | 정답 밖(범위 CWE) |"
    ]
    lines += ["| --- |" + " ---: |" * (len(cwes) + 4)]
    for n in names:
        m = measure["matrices"][n]
        t = m["total"]
        row = [
            cell(m["by_cwe"][c]["recall"]) + f" (FA {m['by_cwe'][c]['false_alarms']['num']})"
            for c in cwes
        ]
        prec = t["precision_paired"]["value"]
        lines.append(
            f"| {n} | "
            + " | ".join(row)
            + f" | {cell(t['recall'])} | {cell(t['false_alarms'])} | {prec} | {t['unlabeled_in_scope']} |"
        )
    lines += ["", "| 구성 | " + " | ".join(flows) + " |", "| --- |" + " ---: |" * len(flows)]
    for n in names:
        m = measure["matrices"][n]["by_flow"]
        lines.append(
            f"| {n} | " + " | ".join(cell(m[f]["recall"]) if f in m else "-" for f in flows) + " |"
        )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("measure", type=Path)
    parser.add_argument("--configs", help="Comma-separated subset and order")
    args = parser.parse_args()
    configs = args.configs.split(",") if args.configs else None
    print(render(json.loads(args.measure.read_text()), configs), end="")


if __name__ == "__main__":
    main()
