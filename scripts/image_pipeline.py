#!/usr/bin/env python3
"""Image -> pinned scans/rootfs -> normalized SBOM/evidence -> optional DT/VEX."""

import argparse
import base64
import copy
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit, parse_qs
from datetime import datetime, timezone
from pathlib import Path
from enrich_syft_apk import enrich as apk_enrich
from normalize_syft_bom import normalize as package_view
from enrich_runtime_bom import enrich as runtime_enrich
from normalize_node_bom import process as node_view, archive_files as node_files
from normalize_platform_metadata import read_layers, normalize as platform_view
from normalize_debian_bom import process as debian_view
from audit_erlang_licenses import archive_files, audit
from build_evidence_bundle import safe_csv
from enrich_python_bom import process as python_view, LAUNCHER_URL, LAUNCHER_SHA256
from audit_cpython_terms import process as cpython_audit
from license_scope import collect as collect_scopes, render as render_scopes
from validate_enrichment import audit as audit_enrichment
from license_fields import (
    normalize as normalize_license_fields,
    validate as validate_license_fields,
    DIGEST,
)

ROOT = Path(__file__).resolve().parents[1]
SYFT = (
    "anchore/syft:v1.54.0@sha256:0356562f495d432056237fbea5cbc2d4839c9c75cd500784a66de2e7cc95ca7c"
)
TRIVY = (
    "aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"
)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    for f in sorted((ROOT / "migrations").glob("*.sql")):
        db.executescript(f.read_text())
    return db


def resolve_reference(image, descriptor, platform):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@\-]+", image):
        raise ValueError("Invalid image reference")
    os, arch, *variant = platform.split("/")
    if os != "linux":
        raise ValueError("Only Linux image filesystem adapters are implemented")
    manifest = descriptor
    if "manifests" in descriptor:
        matches = [
            m
            for m in descriptor["manifests"]
            if m.get("platform", {}).get("os") == os
            and m["platform"].get("architecture") == arch
            and (not variant or m["platform"].get("variant") == variant[0])
        ]
        if len(matches) != 1:
            raise ValueError("Missing/ambiguous platform manifest")
        manifest = matches[0]
    value = manifest.get("digest", "")
    if not re.fullmatch("sha256:[0-9a-f]{64}", value):
        raise ValueError("Missing manifest digest")
    base = image.split("@", 1)[0]
    if ":" in base.rsplit("/", 1)[-1]:
        base = base.rsplit(":", 1)[0]
    if "/" not in base:
        base = "docker.io/library/" + base
    elif (
        "." not in base.split("/")[0]
        and ":" not in base.split("/")[0]
        and base.split("/")[0] != "localhost"
    ):
        base = "docker.io/" + base
    return base + "@" + value


class Pipeline:
    def __init__(self, out, cache):
        self.out = out
        self.cache = cache
        self.commands = []
        self.pending = []
        self.stages = []

    def command(self, args, name):
        print("stage:", name, flush=True)
        start = time.monotonic()
        result = subprocess.run(list(map(str, args)), capture_output=True)
        logs = self.out / "logs"
        logs.mkdir(exist_ok=True)
        (logs / (name + ".stderr")).write_bytes(result.stderr)
        (logs / (name + ".stdout")).write_bytes(result.stdout)
        # Commands never contain DT keys. Credential-bearing image references are rejected.
        self.commands.append(
            {
                "stage": name,
                "command": list(map(str, args)),
                "exit_code": result.returncode,
                "seconds": round(time.monotonic() - start, 3),
            }
        )
        save(self.out / "commands.json", self.commands)
        if result.returncode:
            raise RuntimeError("Stage failed: " + name + "; inspect logs/" + name + ".stderr")
        return result.stdout

    def blob(self, url, expected):
        if not re.fullmatch("[0-9a-f]{64}", expected):
            raise ValueError("Invalid reviewed source SHA-256")
        path = self.cache / "blobs" / expected
        if path.exists():
            if digest(path) != expected:
                raise ValueError("Corrupt source cache")
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".download")
        try:
            with urllib.request.urlopen(url, timeout=60) as response, tmp.open("wb") as dest:
                shutil.copyfileobj(response, dest)
            if digest(tmp) != expected:
                raise ValueError("Source digest differs from reviewed rule: " + url)
            tmp.replace(path)
        finally:
            if tmp.exists():
                tmp.unlink()
        return path

    def stage(self, name, bom, report):
        save(self.out / "stages" / (name + ".cdx.json"), bom)
        save(self.out / "stages" / (name + "-evidence.json"), report)
        self.stages.append({"name": name, "remaining": len(bom.get("components", []))})
        return bom

    def scanner(self, pinned, name, platform):
        descriptor = json.loads(
            self.command(
                [
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    pinned,
                    "--format",
                    "{{json .Manifest}}",
                ],
                "resolve-" + name,
            )
        )
        if descriptor.get("digest") != pinned.split("@", 1)[1]:
            raise ValueError("Scanner index digest mismatch")
        ref = resolve_reference(pinned, descriptor, platform)
        self.command(["docker", "pull", "--platform", platform, ref], "pull-" + name)
        inspected = json.loads(
            self.command(["docker", "image", "inspect", ref], "inspect-" + name)
        )[0]
        if platform.split("/")[:2] != [inspected["Os"], inspected["Architecture"]]:
            raise ValueError("Scanner platform mismatch")
        path = self.out / "scanners.json"
        evidence = json.loads(path.read_bytes()) if path.exists() else {}
        evidence[name] = {
            "pinned_reference": pinned,
            "image_ref": ref,
            "platform": platform,
            "image_id": inspected["Id"],
            "repo_digests": inspected.get("RepoDigests", []),
            "descriptor": descriptor,
        }
        save(path, evidence)
        return ref

    def runtime(self, bom, rootfs, ref, db):
        rules = []
        sources = self.out / "sources/runtime"
        sources.mkdir(parents=True, exist_ok=True)
        for c in bom["components"]:
            if c.get("type") != "application" or c["name"] not in {"elixir", "erlang"}:
                continue
            rows = db.execute(
                "SELECT * FROM runtime_enrichment_release WHERE name=? AND version=?",
                (c["name"], c.get("version")),
            ).fetchall()
            if len(rows) != 1 or rows[0]["purl"] != c.get("purl"):
                self.pending.append(
                    {
                        "component": c["name"],
                        "version": c.get("version"),
                        "reason": "runtime release rule missing",
                        "next": "Add verified release URLs, hashes and version marker in a new migration",
                    }
                )
                continue
            r = dict(rows[0])
            r["license_file"] = c["name"] + "-LICENSE.txt"
            try:
                shutil.copyfile(
                    self.blob(r["license_url"], r["license_sha256"]), sources / r["license_file"]
                )
            except (ValueError, urllib.error.URLError) as e:
                self.pending.append(
                    {
                        "component": c["name"],
                        "reason": str(e),
                        "next": "Refresh and review release evidence",
                    }
                )
                continue
            rules.append(r)
        if rules:
            save(
                sources / "rules.json",
                {
                    "image_ref": ref,
                    "rootfs_sha256": digest(rootfs),
                    "rules": rules,
                    "limitations": [
                        "Upstream project license inferred from verified release association; bundled terms audited separately"
                    ],
                },
            )
            bom, report = runtime_enrich(bom, rootfs, sources)
            self.stage("runtime", bom, report)
        otp = next(
            (
                c
                for c in bom["components"]
                if c["name"] == "erlang" and c.get("type") == "application"
            ),
            None,
        )
        if otp and otp.get("version") == "28.5.0.7":
            expected = db.execute(
                "SELECT source_sha256 FROM source_release WHERE project='erlang' AND version=?",
                (otp["version"],),
            ).fetchone()[0]
            try:
                archive = self.blob(
                    "https://github.com/erlang/otp/releases/download/OTP-28.5.0.7/otp_src_28.5.0.7.tar.gz",
                    expected,
                )
            except (ValueError, urllib.error.URLError) as e:
                self.pending.append(
                    {
                        "component": "erlang",
                        "reason": str(e),
                        "next": "Obtain pinned OTP source archive",
                    }
                )
                return bom
            source = {k.split("/", 1)[1]: v for k, v in archive_files(archive).items()}
            selectors = db.execute(
                "SELECT name,source_path,expression,binary_indicator FROM embedded_license_rule WHERE project='erlang' AND version=? ORDER BY name",
                (otp["version"],),
            ).fetchall()
            bom, report, notices = audit(bom, archive_files(rootfs), source, selectors)
            report.update(source_archive_sha256=expected, rootfs_sha256=digest(rootfs))
            for path, raw in notices.items():
                dest = self.out / "sources/erlang-notices" / path
                if not dest.resolve().is_relative_to(
                    (self.out / "sources/erlang-notices").resolve()
                ):
                    raise ValueError("Unsafe notice path")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
            self.stage("erlang-audit", bom, report)
            self.pending.extend(dict(u, component="erlang") for u in report.get("unresolved", []))
        elif otp:
            self.pending.append(
                {
                    "component": "erlang",
                    "reason": "embedded license audit adapter unavailable for this release",
                    "next": "Add source release hash and embedded rules; keep identified component",
                }
            )
        return bom

    def normalize(self, original, rootfs, archive, ref, db=None):
        db = database() if db is None else db
        bom = copy.deepcopy(original)
        with tarfile.open(rootfs) as tar:
            names = {m.name.lstrip("./"): m for m in tar.getmembers()}
            apk = (
                tar.extractfile(names["lib/apk/db/installed"]).read()
                if "lib/apk/db/installed" in names
                else None
            )
            deb = "var/lib/dpkg/status" in names
        if apk is not None:
            bom, owners = apk_enrich(bom, rootfs, ref)
            self.stage("apk-enrichment", bom, owners)
            bom, report = package_view(bom, owners, apk)
            self.stage("apk-package-view", bom, report)
            found, _ = read_layers(archive)
            bom, report = platform_view(bom, found)
            self.stage("alpine-platform", bom, report)
        elif deb:
            bom, report, sources = debian_view(
                bom,
                rootfs,
                dict(db.execute("SELECT label,spdx_expression FROM debian_license_alias")),
                {
                    (r[0], r[1]): r[2]
                    for r in db.execute(
                        "SELECT copyright_sha256,label,expression FROM debian_reviewed_license"
                    )
                },
            )
            for path, raw in sources.items():
                dest = self.out / "sources/debian" / path
                if not dest.resolve().is_relative_to((self.out / "sources/debian").resolve()):
                    raise ValueError("Unsafe source path")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
            self.stage("debian-package-view", bom, report)
            self.pending.extend(report.get("unresolved", []))
            self.pending.extend(
                {
                    "component": identifier,
                    "reason": item["assessment"],
                    "next": "Review preserved source text and add canonical mapping",
                }
                for identifier, item in report["license_refs"].items()
            )
        else:
            self.pending.append(
                {
                    "reason": "Package database adapter unavailable",
                    "next": "Add adapter; original components retained",
                }
            )
        if any(c.get("purl", "").startswith("pkg:generic/python@") for c in bom["components"]):
            launcher_source = None
            if any(c.get("name") == "Simple Launcher" for c in bom["components"]):
                launcher_source = self.blob(LAUNCHER_URL, LAUNCHER_SHA256).read_bytes()
            bom, report, sources = python_view(
                bom,
                rootfs,
                [dict(r) for r in db.execute("SELECT * FROM python_shipped_license")],
                launcher_source,
            )
            for path, raw in sources.items():
                dest = self.out / "sources/python" / path
                if not dest.resolve().is_relative_to((self.out / "sources/python").resolve()):
                    raise ValueError("Unsafe Python source path")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
            self.stage("python-shipped", bom, report)
            self.pending.extend(report["unresolved"])
            terms = [
                dict(r)
                for r in db.execute("SELECT * FROM cpython_embedded_term")
                if any(
                    c.get("name") == "python" and c.get("version") == r["version"]
                    for c in bom["components"]
                )
            ]
            if terms:
                evidence = json.loads((self.out / "image.json").read_text())
                env = dict(item.split("=", 1) for item in evidence["inspect"]["Config"]["Env"])
                version = terms[0]["version"]
                archive = self.blob(
                    "https://www.python.org/ftp/python/"
                    + version
                    + "/Python-"
                    + version
                    + ".tar.xz",
                    terms[0]["archive_sha256"],
                )
                bom, report, notices = cpython_audit(bom, rootfs, archive, terms, env)
                for path, raw in notices.items():
                    dest = self.out / "sources/cpython" / path
                    if not dest.resolve().is_relative_to((self.out / "sources/cpython").resolve()):
                        raise ValueError("Unsafe CPython notice path")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(raw)
                save(
                    self.out / "sources/cpython/source-archive.json",
                    {
                        "url": "https://www.python.org/ftp/python/"
                        + version
                        + "/Python-"
                        + version
                        + ".tar.xz",
                        "sha256": terms[0]["archive_sha256"],
                    },
                )
                self.stage("cpython-embedded", bom, report)
                self.pending.extend(report["unresolved"])
        bom = self.runtime(bom, rootfs, ref, db)
        if any(c.get("purl", "").startswith("pkg:generic/node@") for c in bom["components"]):
            bom, report, sources = node_view(bom, node_files(rootfs))
            for path, raw in sources.items():
                dest = self.out / "sources/node" / path
                if not dest.resolve().is_relative_to((self.out / "sources/node").resolve()):
                    raise ValueError("Unsafe Node source path")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
            self.stage("node-package-view", bom, report)
            self.pending.extend(report["unresolved"])
        bom, report = normalize_license_fields(bom)
        self.stage("license-field-semantics", bom, report)
        self.pending.extend(report["unresolved"])
        for c in bom["components"]:
            if c.get("type") == "file":
                if any(
                    p.get("name") == "hoplites:inventory:type" and p.get("value") == "pip-RECORD"
                    for p in c.get("properties", [])
                ):
                    continue
                self.pending.append(
                    {
                        "component": c["name"],
                        "reason": "file ownership unresolved; component retained",
                        "next": "Add verifiable owner/hash rule",
                    }
                )
            elif c.get("type") != "operating-system" and not c.get("licenses"):
                self.pending.append(
                    {
                        "component": c["name"],
                        "version": c.get("version"),
                        "reason": "license missing",
                        "next": "Find shipped or version-pinned upstream terms",
                    }
                )
        save(
            self.out / "license-scopes.json",
            {
                "rule_version": "license-scope-v1",
                "records": collect_scopes(bom),
                "fulfillment": "not-verified",
                "scope": "Project license fields and per-target declarations are separate",
            },
        )
        (self.out / "license-scopes.html").write_text(render_scopes(bom))
        return bom

    def bundle(self, original, bom):
        save(self.out / "enrichment-validation.json", audit_enrichment(original, bom))
        save(
            self.out / "license-scopes.json",
            {
                "rule_version": "license-scope-v1",
                "source_bom_sha256": digest(self.out / "normalized.cdx.json"),
                "records": collect_scopes(bom),
                "fulfillment": "not-verified",
            },
        )
        (self.out / "license-scopes.html").write_text(render_scopes(bom))
        out = self.out / "submission"
        out.mkdir()
        for name in [
            "original.cdx.json",
            "normalized.cdx.json",
            "normalization-evidence.json",
            "license-scopes.json",
            "license-scopes.html",
            "enrichment-validation.json",
            "image.json",
            "commands.json",
            "summary.json",
        ] + ([name for name in ["trivy.cdx.json", "scanners.json"] if (self.out / name).exists()]):
            shutil.copyfile(self.out / name, out / name)
        for name in ["stages", "sources", "dt", "vex"]:
            if (self.out / name).exists():
                shutil.copytree(
                    self.out / name, out / name, ignore=shutil.ignore_patterns("*.sqlite")
                )
        shutil.copytree(ROOT / "migrations", out / "migrations")
        (out / "scripts").mkdir()
        for src in (ROOT / "scripts").glob("*.py"):
            shutil.copyfile(src, out / "scripts" / src.name)
        removed = {
            c["bom-ref"]: c
            for c in original["components"]
            if c["bom-ref"] not in {x["bom-ref"] for x in bom["components"]}
        }
        with (out / "excluded-components.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["bom-ref", "name", "type", "version", "sha256", "evidence"])
            for c in removed.values():
                w.writerow(
                    [
                        safe_csv(value) if value is not None else ""
                        for value in [
                            c["bom-ref"],
                            c["name"],
                            c["type"],
                            c.get("version"),
                            next(
                                (
                                    h["content"]
                                    for h in c.get("hashes", [])
                                    if h["alg"] == "SHA-256"
                                ),
                                "",
                            ),
                            "stages/*-evidence.json",
                        ]
                    ]
                )
        save(
            out / "manifest.json",
            {
                "files": [
                    {"path": str(f.relative_to(out)), "sha256": digest(f)}
                    for f in sorted(out.rglob("*"))
                    if f.is_file()
                ],
                "rootfs_sha256": digest(self.out / "rootfs.tar"),
                "image_archive_sha256": digest(self.out / "image-save.tar"),
            },
        )


def upload(pipeline, bom, ref, project):
    validate_license_fields(bom)
    key = (
        subprocess.run(
            [
                "security",
                "find-generic-password",
                "-a",
                "hoplites",
                "-s",
                "hoplites-dependency-track",
                "-w",
            ],
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )

    def api(path, body=None):
        req = urllib.request.Request(
            "http://localhost:18080/api/v1/" + path,
            data=json.dumps(body).encode() if body is not None else None,
            method="PUT" if body is not None else "GET",
            headers={"X-Api-Key": key, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    result = api(
        "bom",
        {
            "projectName": project,
            "projectVersion": ref.split("@")[1],
            "autoCreate": True,
            "bom": base64.b64encode((pipeline.out / "normalized.cdx.json").read_bytes()).decode(),
        },
    )
    save(pipeline.out / "dt/upload.json", result)
    for _ in range(30):
        event = api("event/token/" + result["token"])
        if event.get("status") == "COMPLETED":
            break
        time.sleep(2)
    else:
        raise ValueError("DT import not confirmed in 60 seconds")
    rows = []
    page = 1
    while True:
        batch = api(
            "component/project/" + result["projectUuid"] + "?pageSize=100&pageNumber=" + str(page)
        )
        rows.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    actual = {(c["name"], c.get("version"), c.get("purl")): c for c in rows}
    problems = []
    scope_verification = []
    for c in bom["components"]:
        found = actual.get((c["name"], c.get("version"), c.get("purl")))
        if not found:
            problems.append({"name": c["name"], "issue": "identity missing"})
            continue
        for h in c.get("hashes", []):
            if h["alg"] == "SHA-256" and found.get("sha256") != h["content"]:
                problems.append(
                    {"name": c["name"], "purl": c.get("purl"), "issue": "SHA-256 differs"}
                )
        expected_scopes = {
            p["name"]: p["value"]
            for p in c.get("properties", [])
            if p["name"].startswith("hoplites:license-scope:")
        }
        if expected_scopes:
            detail = api("component/" + found["uuid"] + "/property")
            stored = {
                (p.get("groupName", "") + ":" if p.get("groupName") else "")
                + p["propertyName"]: p.get("propertyValue")
                for p in detail
            }
            scoped_stored = {
                k: v for k, v in stored.items() if k.startswith("hoplites:license-scope:")
            }
            if set(scoped_stored) != set(expected_scopes):
                problems.append({"name": c["name"], "issue": "license scope property set differs"})
            scope_verification.append(
                {
                    "name": c["name"],
                    "purl": c.get("purl"),
                    "uuid": found["uuid"],
                    "stored_properties": scoped_stored,
                }
            )
            for name, value in expected_scopes.items():
                if stored.get(name) != value:
                    problems.append(
                        {"name": c["name"], "issue": "license scope differs", "property": name}
                    )
        licenses = c.get("licenses", [])
        if not licenses and any(
            found.get(k) for k in ("license", "licenseExpression", "resolvedLicense")
        ):
            problems.append({"name": c["name"], "issue": "stale license retained"})
        for value in [
            found.get("license"),
            found.get("licenseExpression"),
            (found.get("resolvedLicense") or {}).get("licenseId"),
            (found.get("resolvedLicense") or {}).get("name"),
        ]:
            if isinstance(value, str) and DIGEST.fullmatch(value.strip()):
                problems.append({"name": c["name"], "issue": "digest in DT license field"})
        if len(licenses) == 1:
            l = licenses[0]
            if "expression" in l and found.get("licenseExpression") != l["expression"]:
                problems.append({"name": c["name"], "issue": "license expression differs"})
            if (
                l.get("license", {}).get("id")
                and (found.get("resolvedLicense") or {}).get("licenseId") != l["license"]["id"]
            ):
                problems.append({"name": c["name"], "issue": "license ID differs"})
    save(
        pipeline.out / "dt/verification.json",
        {
            "event": event,
            "expected": len(bom["components"]),
            "actual": len(rows),
            "mismatches": problems,
            "license_scope_verification": scope_verification,
            "components": rows,
        },
    )
    if len(rows) != len(bom["components"]) or problems:
        raise ValueError("DT fields/count verification failed")
    return result["projectUuid"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--platform", default="linux/arm64")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".cache/hoplites")
    parser.add_argument("--trivy", action="store_true")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--vex", action="store_true")
    parser.add_argument("--dt-project")
    parser.add_argument("--advisory-commit")
    parser.add_argument("--debian-tracker", type=Path)
    parser.add_argument("--debian-tracker-sha256")
    args = parser.parse_args()
    if args.output_dir is None:
        slug = re.sub("[^A-Za-z0-9.-]", "-", args.image)[:80]
        args.output_dir = (
            ROOT
            / "artifacts"
            / ("image-" + slug + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        )
    if args.output_dir.exists():
        parser.error("Use a new output directory")
    if args.vex and not args.upload:
        parser.error("--vex requires --upload")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@\-]+", args.image):
        parser.error("Invalid image reference")
    args.output_dir.mkdir(parents=True)
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    pipe = Pipeline(args.output_dir.resolve(), args.cache_dir.resolve())
    summary = {
        "status": "running",
        "input_image": args.image,
        "platform": args.platform,
        "started": datetime.now(timezone.utc).isoformat(),
    }
    save(pipe.out / "summary.json", summary)
    try:
        descriptor = json.loads(
            pipe.command(
                [
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    args.image,
                    "--format",
                    "{{json .Manifest}}",
                ],
                "resolve-image",
            )
        )
        ref = resolve_reference(args.image, descriptor, args.platform)
        summary["image_ref"] = ref
        pipe.command(["docker", "pull", "--platform", args.platform, ref], "pull-image")
        inspected = json.loads(pipe.command(["docker", "image", "inspect", ref], "inspect-image"))[
            0
        ]
        if args.platform.split("/")[:2] != [inspected["Os"], inspected["Architecture"]]:
            raise ValueError("Local image platform mismatch")
        save(
            pipe.out / "image.json",
            {
                "input": args.image,
                "image_ref": ref,
                "platform": args.platform,
                "descriptor": descriptor,
                "inspect": inspected,
            },
        )
        pipe.command(
            ["docker", "image", "save", "-o", pipe.out / "image-save.tar", ref], "save-image"
        )
        container = (
            pipe.command(
                ["docker", "create", "--platform", args.platform, "--entrypoint", "/bin/true", ref],
                "create-export-container",
            )
            .decode()
            .strip()
        )
        try:
            pipe.command(
                ["docker", "export", "-o", pipe.out / "rootfs.tar", container], "export-rootfs"
            )
        finally:
            pipe.command(["docker", "rm", container], "remove-export-container")
        syft = pipe.scanner(SYFT, "syft", args.platform)
        raw = pipe.command(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                args.platform,
                syft,
                "scan",
                "registry:" + ref,
                "--platform",
                args.platform,
                "-o",
                "cyclonedx-json",
            ],
            "syft",
        )
        (pipe.out / "original.cdx.json").write_bytes(raw)
        original = json.loads(raw)
        if original["metadata"]["component"]["version"] != ref.split("@")[1]:
            raise ValueError("Scanner image digest mismatch")
        if args.trivy:
            trivy_cache = pipe.cache / "trivy"
            trivy_cache.mkdir(exist_ok=True)
            trivy = pipe.scanner(TRIVY, "trivy", args.platform)
            raw = pipe.command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    args.platform,
                    "-v",
                    str(trivy_cache) + ":/root/.cache/trivy",
                    trivy,
                    "image",
                    "--image-src",
                    "remote",
                    "--platform",
                    args.platform,
                    "--format",
                    "cyclonedx",
                    "--scanners",
                    "vuln,license",
                    ref,
                ],
                "trivy",
            )
            (pipe.out / "trivy.cdx.json").write_bytes(raw)
        bom = pipe.normalize(original, pipe.out / "rootfs.tar", pipe.out / "image-save.tar", ref)
        save(pipe.out / "normalized.cdx.json", bom)
        save(
            pipe.out / "normalization-evidence.json",
            {
                "rule_version": "image-pipeline-v1",
                "input_sha256": digest(pipe.out / "original.cdx.json"),
                "output_sha256": digest(pipe.out / "normalized.cdx.json"),
                "rootfs_sha256": digest(pipe.out / "rootfs.tar"),
                "image_ref": ref,
                "stages": pipe.stages,
                "unresolved": pipe.pending,
            },
        )
        summary.update(
            original_count=len(original["components"]),
            normalized_count=len(bom["components"]),
            unresolved_count=len(pipe.pending),
            stages=pipe.stages,
        )
        if args.upload:
            project = (
                args.dt_project
                or "hoplites-"
                + re.sub("[^A-Za-z0-9.-]", "-", ref.split("@")[0])
                + "-"
                + args.platform.split("/")[1]
            )
            summary["dt_project"] = upload(pipe, bom, ref, project)
            if args.vex:
                with tarfile.open(pipe.out / "rootfs.tar") as t:
                    names = {m.name.lstrip("./") for m in t}
                if "var/lib/dpkg/status" not in names:
                    pipe.pending.append(
                        {
                            "reason": "VEX distro adapter unavailable",
                            "next": "Add vendor advisory adapter; DT findings retained",
                        }
                    )
                else:
                    reviewed = pipe.out / "sources/reviewed-vex"
                    reviewed.mkdir(exist_ok=True)
                    for r in database().execute("SELECT * FROM distro_vex_decision"):
                        applicable = any(
                            c["name"] == r["binary_package"]
                            and c.get("version") == r["reviewed_version"]
                            and parse_qs(urlsplit(c.get("purl", "")).query).get("distro")
                            == [r["distro"]]
                            for c in bom["components"]
                        )
                        if not applicable:
                            continue
                        try:
                            shutil.copyfile(
                                pipe.blob(r["source_url"], r["source_sha256"]),
                                reviewed / (r["cve"] + ".html"),
                            )
                        except (ValueError, urllib.error.URLError) as error:
                            pipe.pending.append(
                                {
                                    "component": r["binary_package"],
                                    "cve": r["cve"],
                                    "reason": "Reviewed VEX evidence unavailable: " + str(error),
                                    "next": "Refresh/review the exact advisory; OSV evaluation continues",
                                }
                            )
                    command = [
                        sys.executable,
                        ROOT / "scripts/run_project_vex.py",
                        "--project",
                        summary["dt_project"],
                        "--sbom",
                        pipe.out / "normalized.cdx.json",
                        "--normalization-evidence",
                        pipe.out / "normalization-evidence.json",
                        "--rootfs",
                        pipe.out / "rootfs.tar",
                        "--reviewed-sources",
                        reviewed,
                        "--cache",
                        pipe.cache / "advisories.sqlite",
                        "--output-dir",
                        pipe.out / "vex",
                        "--apply",
                    ]
                    if args.advisory_commit:
                        command += ["--commit", args.advisory_commit]
                    if args.debian_tracker:
                        command += [
                            "--debian-tracker",
                            args.debian_tracker,
                            "--debian-tracker-sha256",
                            args.debian_tracker_sha256 or "",
                        ]
                    pipe.command(command, "vex")
                    decisions = json.loads((pipe.out / "vex/decisions.json").read_bytes())
                    summary["vex"] = {
                        "decisions": len(decisions["decisions"]),
                        "unresolved": len(decisions["unresolved"]),
                        "conflicts": len(decisions.get("conflicts", [])),
                        "applied": (pipe.out / "vex/dt-apply/after.json").exists(),
                    }
                    pipe.pending.extend(
                        {
                            "reason": "VEX unresolved: " + str(item),
                            "next": "Add vendor advisory or identity evidence",
                        }
                        for item in decisions["unresolved"]
                    )
        summary.update(
            status="execution-completed",
            enrichment_status=audit_enrichment(original, bom)["status"],
            enrichment_complete=False,
            unresolved_count=len(pipe.pending),
            unresolved=pipe.pending,
        )
        save(pipe.out / "summary.json", summary)
        pipe.bundle(original, bom)
        print(
            json.dumps(
                {k: v for k, v in summary.items() if k not in ["unresolved", "stages"]},
                ensure_ascii=False,
            )
        )
    except Exception as e:
        summary.update(status="failed", error=str(e))
        save(pipe.out / "summary.json", summary)
        raise


if __name__ == "__main__":
    main()
