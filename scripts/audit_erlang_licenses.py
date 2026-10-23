#!/usr/bin/env python3
"""Map cached OTP source license declarations to installed files and enrich its BOM."""

import argparse
import copy
import hashlib
import json
import re
import sqlite3
import tarfile
from pathlib import Path
from license_scope import record as scope_record, attach as scope_attach

RULE_VERSION = "erlang-internal-licenses-v2"
COMMIT = "09fb046150ab94104e03ee816b95c8b7e6b04683"
UNKNOWN = "LicenseRef-OTP-Megaco-Unresolved"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_files(path):
    with tarfile.open(path) as t:
        return {m.name.lstrip("./"): t.extractfile(m).read() for m in t if m.isfile()}


def declarations(raw):
    # Anchored comments, not generated strings containing the label.
    found = re.findall(
        rb"(?m)^\s*(?:--+|//+|/\*|\*+|%+|#+|\|)?\s*SPDX-License-Identifier:\s*(?:\|\s*)?([^\r\n]+)",
        raw[:12000],
    )
    return sorted(set(x.decode().strip(" */%#|\t") for x in found))


def installed_candidates(path, installed):
    match = re.match(r"lib/([^/]+)/(.*)", path)
    if not match:
        return []
    app, suffix = match.groups()
    suffix = suffix.removesuffix(".license")
    options = [suffix]
    if suffix.startswith("src/") and suffix.endswith(".erl"):
        options.append("ebin/" + Path(suffix).stem + ".beam")
    if path == "lib/public_key/asn1/PKCS5v2-0.asn1":
        options.append("ebin/PKCS-FRAME.beam")
    if path == "lib/public_key/asn1/PKCS-3.asn1":
        options.append("ebin/PKCS-3.beam")
    m = re.fullmatch(r"lib/megaco/src/binary/MEDIA-GATEWAY-CONTROL-v([123]).asn", path)
    if m:
        options.extend(
            "ebin/megaco_" + mode + "_media_gateway_control_v" + m[1] + ".beam"
            for mode in ("ber", "per")
        )
    prefix = "usr/local/lib/erlang/lib/"
    return sorted(
        name
        for name in installed
        if name.startswith(prefix + app + "-")
        and "/".join(name[len(prefix) :].split("/")[1:]) in options
    )


def audit(bom, installed, source, rules):
    result = copy.deepcopy(bom)
    unresolved_included = False
    matches = [
        c
        for c in result["components"]
        if c.get("name") == "erlang" and c.get("type") == "application"
    ]
    if len(matches) != 1 or matches[0].get("version") != "28.5.0.7":
        raise ValueError("Expected exact OTP version")
    runtime = matches[0]
    if installed.get("usr/local/lib/erlang/releases/28/OTP_VERSION", b"").strip() != b"28.5.0.7":
        raise ValueError("Installed OTP marker mismatch")
    entries, expressions, notices = [], {"Apache-2.0"}, {}
    for path, raw in source.items():
        ids = declarations(raw)
        if not ids or ids == ["Apache-2.0"]:
            continue
        candidates = installed_candidates(path, installed)
        # Source sidecars apply to the adjacent payload; generated code links are inference.
        rows = []
        for candidate in candidates:
            payload = source.get(path.removesuffix(".license"), raw)
            assessment = (
                "exact-file-match"
                if sha(payload) == sha(installed[candidate])
                else "inferred-from-source-path-and-installed-module"
            )
            rows.append(
                {"path": candidate, "sha256": sha(installed[candidate]), "assessment": assessment}
            )
        entry = {
            "source_path": path,
            "source_sha256": sha(raw),
            "declared_expressions": ids,
            "installed_files": rows,
            "status": "included" if rows else "not-mapped-to-installed-file",
            "source_url": f"https://github.com/erlang/otp/blob/{COMMIT}/{path}",
        }
        if rows:
            if "NOASSERTION" in ids:
                if not path.startswith("lib/megaco/src/binary/MEDIA-GATEWAY-CONTROL-"):
                    raise ValueError("New unresolved declaration requires a reviewed rule")
                entry["status"] = "included-license-unresolved"
                entry["tracking_identifier"] = UNKNOWN
                unresolved_included = True
                # Unknown tracking marker is not a license expression.
            else:
                expressions.update(ids)
            notices[path] = raw
        entries.append(entry)
    beam_paths = [
        p for p in installed if re.fullmatch(r"usr/local/lib/erlang/erts-[^/]+/bin/beam.smp", p)
    ]
    if len(beam_paths) != 1:
        raise ValueError("Expected one BEAM emulator")
    beam_path = beam_paths[0]
    beam = installed[beam_path]
    native = []
    for name, path, expression, indicator in rules:
        if path not in source:
            raise ValueError("Missing native source declaration")
        # Build selection + binary strings corroborate inclusion, not reproducible equivalence.
        present = indicator.encode() in beam
        native.append(
            {
                "name": name,
                "source_path": path,
                "source_sha256": sha(source[path]),
                "expression": expression,
                "installed_path": beam_path,
                "installed_sha256": sha(beam),
                "indicator": indicator,
                "status": "included-inferred" if present else "not-confirmed",
                "source_url": f"https://github.com/erlang/otp/blob/{COMMIT}/{path}",
            }
        )
        if present:
            expressions.add(expression)
            notices[path] = source[path]
    # Cache complete upstream license texts and native copyright documents for notice preparation.
    for path, raw in source.items():
        if (
            path.startswith("LICENSES/")
            or path == "LICENSE.txt"
            or (
                path.startswith("erts/emulator/")
                and any(x in Path(path).name.upper() for x in ("LICENSE", "LICENCE", "COPYING"))
                and "/internal_doc/" not in path
            )
        ):
            notices[path] = raw
    if any(x["status"] == "not-confirmed" for x in native):
        raise ValueError("Native inclusion unresolved; inspect changed build before proceeding")
    expression = " AND ".join(
        "(" + e + ")" if any(op in e for op in (" AND ", " OR ")) else e
        for e in sorted(expressions)
    )
    before = copy.deepcopy(runtime.get("licenses"))
    if before != [{"expression": expression}] and not (
        len(before or []) == 1 and before[0].get("license", {}).get("id") == "Apache-2.0"
    ):
        raise ValueError("Unexpected parent license value; review before replacement")
    scoped = []
    for item in entries:
        for target in item["installed_files"]:
            unknown = "NOASSERTION" in item["declared_expressions"]
            declared = (
                None
                if unknown
                else " AND ".join("(" + e + ")" for e in item["declared_expressions"])
            )
            scoped.append(
                scope_record(
                    runtime,
                    target["path"],
                    "installed-source-or-generated-module",
                    declared,
                    "confirmed" if target["assessment"] == "exact-file-match" else "inferred",
                    "unknown"
                    if unknown
                    else (
                        "confirmed" if target["assessment"] == "exact-file-match" else "inferred"
                    ),
                    {**item, "installed_target": target},
                )
            )
    for item in native:
        scoped.append(
            scope_record(
                runtime,
                item["name"],
                "binary-embedded-code",
                item["expression"],
                "inferred",
                "inferred",
                item,
            )
        )
    scope_attach(
        runtime,
        scoped,
        "Apache-2.0 project terms; installed and embedded code terms are separately scoped",
    )
    runtime["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    prefix = "hoplites:erlang-audit:"
    runtime["properties"] = [
        p for p in runtime.get("properties", []) if not p["name"].startswith(prefix)
    ]
    runtime["properties"].extend(
        {"name": prefix + k, "value": v}
        for k, v in [
            ("rule-version", RULE_VERSION),
            ("license-scope", "Project terms with per-target source/native license records"),
            (
                "assessment",
                "Source declarations and installed-file inventory; native/compiled links inferred",
            ),
            (
                "unresolved",
                (
                    "Megaco ASN.1 source declares NOASSERTION; "
                    + UNKNOWN
                    + " is an unresolved tracking marker, not a license"
                )
                if unresolved_included
                else "none detected in mapped declarations",
            ),
            ("source-commit", COMMIT),
        ]
    )
    for prop in runtime.get("properties", []):
        if prop["name"] == "hoplites:runtime:scope":
            prop["value"] = "Bundled source audit recorded" + (
                "; Megaco license remains explicitly unresolved" if unresolved_included else ""
            )
    report = {
        "rule_version": RULE_VERSION,
        "version": runtime["version"],
        "source_commit": COMMIT,
        "changes": [{"field": "licenses", "before": before, "after": runtime["licenses"]}],
        "license_expression": "Apache-2.0",
        "aggregate_candidate": expression,
        "license_scopes": scoped,
        "source_file_assessments": entries,
        "native_assessments": native,
        "unresolved": (
            [
                {
                    "identifier": UNKNOWN,
                    "reason": "Upstream Megaco ASN.1 explicitly declares NOASSERTION",
                    "next_action": "Confirm applicable terms for IETF/ITU derived ASN.1 with upstream or compliance reviewer",
                }
            ]
            if unresolved_included
            else []
        ),
        "limitations": [
            "Compiled/native attribution is inferred from source/build rules and installed evidence, not rebuild equivalence.",
            "Source SPDX/explicit native notice coverage is not a universal license detector.",
            "Unmapped source files are evidence exclusions, not a license waiver.",
            "Actual delivered notices and fulfillment have not been verified.",
        ],
    }
    return result, report, notices


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("sbom", "source", "rootfs", "output", "evidence", "notices-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    if args.output.exists() or args.evidence.exists() or args.notices_dir.exists():
        p.error("Use new output paths")
    db = sqlite3.connect(":memory:")
    migrations = Path(__file__).parents[1] / "migrations"
    for migration in sorted(migrations.glob("*.sql")):
        db.executescript(migration.read_text())
    expected = db.execute(
        "SELECT source_sha256 FROM source_release WHERE project='erlang' AND version='28.5.0.7'"
    ).fetchone()[0]
    source_hash = sha(args.source.read_bytes())
    if source_hash != expected:
        raise ValueError("OTP source differs from reviewed release archive")
    all_source = archive_files(args.source)
    source = {path.split("/", 1)[1]: raw for path, raw in all_source.items()}
    installed = archive_files(args.rootfs)
    rules = db.execute(
        "SELECT name,source_path,expression,binary_indicator FROM embedded_license_rule WHERE project='erlang' AND version='28.5.0.7' ORDER BY name"
    ).fetchall()
    raw = args.sbom.read_bytes()
    result, report, notices = audit(json.loads(raw), installed, source, rules)
    output = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
    report.update(
        input_sha256=sha(raw),
        output_sha256=sha(output),
        source_archive_sha256=source_hash,
        rootfs_sha256=sha(args.rootfs.read_bytes()),
        migrations=[
            {"path": f.name, "sha256": sha(f.read_bytes())}
            for f in sorted(migrations.glob("*.sql"))
        ],
    )
    args.notices_dir.mkdir(parents=True)
    for path, contents in notices.items():
        dest = args.notices_dir / path
        if not dest.resolve().is_relative_to(args.notices_dir.resolve()):
            raise ValueError("Unsafe notice path")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(contents)
    args.output.write_bytes(output)
    args.evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "included_source_files": sum(
                    bool(e["installed_files"]) for e in report["source_file_assessments"]
                ),
                "native_rules": len(rules),
                "license_expression": report["license_expression"],
                "unresolved": report["unresolved"],
            }
        )
    )


if __name__ == "__main__":
    main()
