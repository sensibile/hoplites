"""Decide whether reviewed vulnerable code is shipped, from explicit artifact inputs.

Pure core: callers pass the export, SBOM, reviewed rules, pinned sources and the
regular files under each package root. Nothing here reads the filesystem or DT.
"""

import base64
import copy
import hashlib
import json
import posixpath
import re
from urllib.parse import unquote, urlsplit

from elf_linkage import inspect as inspect_elf

RULE_VERSION = "code-presence-v1"
# Strongest first. Presence of any copy outranks absence; absence needs every copy.
PRESENT = ("confirmed-present", "inferred-present")
ABSENT = ("confirmed-absent", "inferred-absent")
BASE_IMAGE_NOTE = (
    "Base image without an application entry point: reachability not assessed and "
    "code_not_reachable is not used."
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def semver(version):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        raise ValueError("Unsupported version form for range check: " + str(version))
    return tuple(int(x) for x in m.groups())


def in_range(version, expression):
    """Evaluate a GHSA range such as '>= 6.7.0, < 6.28.1' for a plain x.y.z version."""
    value = semver(version)
    for clause in expression.split(","):
        m = re.fullmatch(r"\s*(>=|>|<=|<|=)\s*(\S+)\s*", clause)
        if not m:
            raise ValueError("Unsupported range clause: " + clause)
        bound = semver(m.group(2))
        ok = {
            ">=": value >= bound,
            ">": value > bound,
            "<=": value <= bound,
            "<": value < bound,
            "=": value == bound,
        }[m.group(1)]
        if not ok:
            return False
    return True


def purl_type(purl):
    p = urlsplit(purl or "")
    if p.scheme != "pkg":
        return None
    return unquote(p.path).split("/", 1)[0]


def package_roots(sbom, component):
    """Package directories (npm) or containing directories (generic) of SBOM copies."""
    identity = (component["name"], component.get("version"), component.get("purl"))
    kind = purl_type(component.get("purl"))
    roots = []
    for c in sbom.get("components", []):
        if (c["name"], c.get("version"), c.get("purl")) != identity:
            continue
        for prop in c.get("properties", []):
            if not re.fullmatch(r"syft:location:\d+:path", prop["name"]):
                continue
            path = prop["value"].lstrip("/")
            if kind == "npm" and posixpath.basename(path) == "package.json":
                roots.append(posixpath.dirname(path))
            elif kind == "generic":
                roots.append(posixpath.dirname(path))
    return sorted(set(roots))


def check_package_file(rule, root, files, version, links=()):
    """One rule target in one package root; returns (grade, evidence)."""
    path = posixpath.join(root, rule["target"])
    evidence = {"root": root, "path": path, "kind": "package-file"}
    if path in links:
        evidence.update(file="link", basis="target is a symbolic link; content not inspected")
        return "unresolved", evidence
    if path not in files:
        marker = rule.get("vulnerable_marker")
        evidence["file"] = "absent"
        if not marker:
            evidence["basis"] = "target absent; no reviewed marker to rule out relocated code"
            return "inferred-absent", evidence
        scanned = [p for p in files if p.startswith(root + "/")]
        hits = sorted(p for p in scanned if marker.encode() in files[p])
        evidence["marker_scan"] = {"marker": marker, "files_scanned": len(scanned), "hits": hits}
        if hits:
            evidence["basis"] = "target absent but vulnerable marker found elsewhere in package"
            return "inferred-present", evidence
        # A literal marker misses minified or renamed bundles and unread links; only an
        # unmodified release file set rules those out.
        listing = rule.get("listing_content")
        shipped = sorted(p[len(root) + 1 :] for p in scanned)
        linked = sorted(p for p in links if p.startswith(root + "/"))
        same_listing = (
            listing is not None
            and listing.get("version") == version
            and sorted(listing.get("files", [])) == shipped
            and not linked
        )
        evidence["release_listing"] = {
            "reviewed": listing is not None,
            "matches": same_listing,
            "links": linked,
        }
        if not same_listing:
            evidence["basis"] = (
                "target and marker absent, but the shipped file set is not shown to be the "
                "unmodified release; relocated or minified code not ruled out"
            )
            return "inferred-absent", evidence
        evidence["basis"] = (
            "target absent, vulnerable marker absent, and shipped files equal the reviewed release listing"
        )
        return "confirmed-absent", evidence
    raw = files[path]
    text = raw.decode("utf-8", "replace")
    evidence.update(file="present", sha256=sha(raw))
    checks = []
    if rule.get("release_content") is not None:
        if rule["release_ref"] != "v" + str(version):
            evidence["basis"] = (
                "reviewed release file is for another version; no identity comparison"
            )
            return "inferred-present", evidence
        same = sha(rule["release_content"]) == evidence["sha256"]
        evidence["release_identity"] = {"ref": rule["release_ref"], "identical": same}
        checks.append(same)
    if rule.get("vulnerable_marker"):
        found = rule["vulnerable_marker"] in text
        evidence["vulnerable_marker_found"] = found
        checks.append(found)
    if rule.get("fix_marker"):
        found = rule["fix_marker"] in text
        evidence["fix_marker_found"] = found
        checks.append(not found)
    if checks and all(checks):
        evidence["basis"] = "shipped module is the pre-fix code of the reviewed upstream change"
        return "confirmed-present", evidence
    evidence["basis"] = (
        "module shipped; pre-fix identity not shown (possible backport or local change)"
        if checks
        else "module shipped; no reviewed release file or marker to compare"
    )
    return "inferred-present", evidence


def check_elf_symbol(rule, root, files):
    path = posixpath.join(root, rule["target"])
    evidence = {
        "root": root,
        "path": path,
        "kind": "elf-symbol",
        "symbol": rule["vulnerable_marker"],
    }
    if path not in files:
        evidence.update(file="absent", basis="binary not found at reviewed path")
        return "unresolved", evidence
    try:
        result = inspect_elf(files[path], [rule["vulnerable_marker"]])
    except (ValueError, IndexError, StopIteration) as error:
        evidence.update(file="present", basis="ELF not parsed: " + str(error))
        return "unresolved", evidence
    evidence.update(file="present", sha256=sha(files[path]))
    if rule["vulnerable_marker"] in result["defined_symbols"]:
        evidence["basis"] = "vulnerable function is a defined symbol of the shipped binary"
        return "confirmed-present", evidence
    # Static or inlined functions leave no symbol; absence alone cannot exclude the code.
    evidence["basis"] = "symbol not defined; inlining or stripping can hide the code"
    return "inferred-absent", evidence


def combine(grades):
    for grade in PRESENT:
        if grade in grades:
            return grade
    if grades and all(g == "confirmed-absent" for g in grades):
        return "confirmed-absent"
    if "unresolved" in grades or not grades:
        return "unresolved"
    return "inferred-absent"


def verify_sources(rules, sources):
    """Reject rules whose pinned advisory/fix snapshot is missing, changed or inconsistent."""
    usable, rejected = [], []
    for rule in rules:
        try:
            advisory_raw = sources.get(rule["advisory_file"])
            fix_raw = sources.get(rule["fix_file"])
            if advisory_raw is None or sha(advisory_raw) != rule["advisory_sha256"]:
                raise ValueError("advisory snapshot unavailable or changed")
            if fix_raw is None or sha(fix_raw) != rule["fix_sha256"]:
                raise ValueError("fix snapshot unavailable or changed")
            advisory = json.loads(advisory_raw)
            if (
                advisory.get("cve_id") != rule["cve"]
                or advisory.get("ghsa_id") != rule["advisory_id"]
            ):
                raise ValueError("advisory identity mismatch")
            ranges = [
                v["vulnerable_version_range"]
                for v in advisory.get("vulnerabilities", [])
                if v["package"]["name"] == rule["package"]
                and v["package"]["ecosystem"] == rule["ecosystem"]
            ]
            if rule["vulnerable_range"] not in ranges:
                raise ValueError("reviewed range not present in advisory")
            fix = json.loads(fix_raw)
            if fix.get("html_url") != rule["fix_url"] or rule["fix_url"] not in advisory.get(
                "references", []
            ):
                raise ValueError("fix commit not referenced by advisory")
            release = None
            if rule.get("release_file"):
                release_raw = sources.get(rule["release_file"])
                ordering_raw = sources.get(rule["ordering_file"])
                if release_raw is None or sha(release_raw) != rule["release_sha256"]:
                    raise ValueError("release file snapshot unavailable or changed")
                if ordering_raw is None or sha(ordering_raw) != rule["ordering_sha256"]:
                    raise ValueError("release ordering snapshot unavailable or changed")
                snapshot = json.loads(release_raw)
                if snapshot.get("path") != rule["target"] or not snapshot.get("url", "").endswith(
                    "?ref=" + rule["release_ref"]
                ):
                    raise ValueError("release file snapshot is for another path or ref")
                if rule["target"] not in {f["filename"] for f in fix.get("files", [])}:
                    raise ValueError("fix commit does not modify the release file")
                ordering = json.loads(ordering_raw)
                # The fix must land strictly after the release tag, or the release is not pre-fix.
                if (ordering.get("base"), ordering.get("head")) != (
                    rule["release_ref"],
                    fix.get("sha"),
                ) or (
                    ordering.get("status"),
                    ordering.get("behind_by"),
                ) != ("ahead", 0):
                    raise ValueError("fix commit is not strictly after the reviewed release")
                release = base64.b64decode(snapshot["content"])
            listing = None
            if rule.get("listing_file"):
                listing_raw = sources.get(rule["listing_file"])
                if listing_raw is None or sha(listing_raw) != rule["listing_sha256"]:
                    raise ValueError("release listing snapshot unavailable or changed")
                listing = json.loads(listing_raw)
                if listing.get("package") != rule["package"]:
                    raise ValueError("release listing is for another package")
            usable.append(dict(rule, release_content=release, listing_content=listing))
        except (ValueError, KeyError, TypeError) as error:
            rejected.append(
                {
                    "cve": rule.get("cve"),
                    "package": rule.get("package"),
                    "target": rule.get("target"),
                    "reason": str(error),
                }
            )
    return usable, rejected


def evaluate(component, cve, rules, roots, files, manifests, links=(), rejected=()):
    """Decision for one DT component–vulnerability pair."""
    base = {
        "component": component["name"],
        "component_ref": component["bom-ref"],
        "version": component.get("version"),
        "purl": component.get("purl"),
        "cve": cve,
    }
    kind = purl_type(component.get("purl"))
    matching = [
        r
        for r in rules
        if r["cve"] == cve and r["package"] == component["name"] and r["ecosystem"] == kind
    ]
    if any(r.get("cve") == cve and r.get("package") == component["name"] for r in rejected):
        # A target whose rule failed verification was never checked; the rest cannot decide.
        return dict(
            base,
            grade="unresolved",
            reason="a reviewed rule for this CVE failed source verification",
            next="Restore or re-review the pinned snapshot named in rejected_rules",
        )
    if not matching:
        return dict(
            base,
            grade="unresolved",
            reason="no reviewed code-presence rule",
            next="Review advisory fix commit and add a code-presence rule migration",
        )
    if not roots:
        return dict(
            base,
            grade="unresolved",
            reason="package root not located in verified SBOM",
            next="Inspect SBOM locations for this component",
        )
    try:
        if not all(in_range(component["version"], r["vulnerable_range"]) for r in matching):
            return dict(
                base,
                grade="unresolved",
                reason="installed version outside reviewed vulnerable range",
                next="Version adjudication is separate; review advisory ranges",
            )
    except ValueError as error:
        return dict(
            base,
            grade="unresolved",
            reason=str(error),
            next="Add a version comparator for this form",
        )
    grades, evidence = [], []
    for root in roots:
        manifest = manifests.get(root)
        if purl_type(component.get("purl")) == "npm":
            identity = (manifest or {}).get("name"), (manifest or {}).get("version")
            if identity != (component["name"], component["version"]):
                grades.append("unresolved")
                evidence.append(
                    {"root": root, "basis": "package.json identity mismatch or missing"}
                )
                continue
        for rule in matching:
            if rule["evidence_kind"] == "package-file":
                grade, item = check_package_file(rule, root, files, component["version"], links)
            else:
                grade, item = check_elf_symbol(rule, root, files)
            grades.append(grade)
            evidence.append(item)
    grade = combine(grades)
    rule = matching[0]
    return dict(
        base,
        grade=grade,
        advisory_id=rule["advisory_id"],
        advisory_sha256=rule["advisory_sha256"],
        fix_url=rule["fix_url"],
        fix_sha256=rule["fix_sha256"],
        vulnerable_range=rule["vulnerable_range"],
        evidence=evidence,
    )


def analysis(decision):
    """Map a decision to CycloneDX analysis. Only confirmed absence suppresses."""
    head = f"Hoplites {RULE_VERSION}; {decision['component']}@{decision['version']}; grade={decision['grade']}"
    if "reason" in decision:
        return {
            "state": "in_triage",
            "detail": f"{head}; unresolved: {decision['reason']}. No safety decision inferred; earlier suppression must be cleared.",
        }
    paths = sorted({e["path"] for e in decision["evidence"] if "path" in e})
    bases = sorted({e["basis"] for e in decision["evidence"] if "basis" in e})
    detail = (
        f"{head}; advisory={decision['advisory_id']} (SHA-256={decision['advisory_sha256']}); "
        f"fix={decision['fix_url']} (SHA-256={decision['fix_sha256']}); range={decision['vulnerable_range']}; "
        f"checked={paths}; basis={bases}. {BASE_IMAGE_NOTE} Original finding retained."
    )
    if decision["grade"] == "confirmed-absent":
        return {"state": "not_affected", "justification": "code_not_present", "detail": detail}
    return {"state": "in_triage", "detail": detail}


def build(export, sbom, rules, roots_files, timestamp, serial, rejected=()):
    """Project VEX for every non-distro finding of the export plus a decision report.

    roots_files: {component_ref: (roots, files, manifests, links)} prepared by the shell.
    rejected: rules that failed source verification; their CVEs stay unresolved.
    """
    sbom_ids = {(c["name"], c.get("version"), c.get("purl")) for c in sbom.get("components", [])}
    components = {c["bom-ref"]: c for c in export.get("components", [])}
    output = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": dict(copy.deepcopy(export.get("metadata", {})), timestamp=timestamp),
        "components": [],
        "vulnerabilities": [],
    }
    report = {"rule_version": RULE_VERSION, "decisions": [], "unresolved": [], "out_of_scope": 0}
    for v in export.get("vulnerabilities", []):
        for affected in v.get("affects", []):
            c = components.get(affected["ref"])
            if c is None:
                raise ValueError("Export vulnerability references a missing component")
            if purl_type(c.get("purl")) in ("deb", "apk", "rpm"):
                # Distro packages belong to the distro VEX adapters.
                report["out_of_scope"] += 1
                continue
            if (c["name"], c.get("version"), c.get("purl")) not in sbom_ids:
                raise ValueError("Export finding component not in verified SBOM")
            roots, files, manifests, links = roots_files.get(c["bom-ref"], ([], {}, {}, ()))
            decision = evaluate(c, v["id"], rules, roots, files, manifests, links, rejected)
            finding = copy.deepcopy(v)
            finding["affects"] = [{"ref": c["bom-ref"]}]
            finding["analysis"] = analysis(decision)
            output["vulnerabilities"].append(finding)
            if c not in output["components"]:
                output["components"].append(copy.deepcopy(c))
            report["decisions"].append(dict(decision, state=finding["analysis"]["state"]))
            if decision["grade"] != "confirmed-absent":
                report["unresolved"].append(
                    {
                        "component": c["name"],
                        "version": c.get("version"),
                        "cve": v["id"],
                        "grade": decision["grade"],
                        "investigated": decision.get("reason")
                        or [e.get("basis") for e in decision.get("evidence", [])],
                        "next": decision.get("next")
                        or "Code is shipped: upgrade the bundling package or obtain an application-specific reachability assessment",
                    }
                )
    return output, report


def merge(distro, presence):
    """Overlay code-presence decisions on a distro VEX for the same DT project."""
    if distro["metadata"].get("component", {}).get("bom-ref") != presence["metadata"].get(
        "component", {}
    ).get("bom-ref"):
        raise ValueError("VEX documents target different projects")
    keys = {(v["id"], v["affects"][0]["ref"]) for v in presence["vulnerabilities"]}
    result = copy.deepcopy(distro)
    result["vulnerabilities"] = [
        v for v in result["vulnerabilities"] if (v["id"], v["affects"][0]["ref"]) not in keys
    ] + copy.deepcopy(presence["vulnerabilities"])
    refs = {c["bom-ref"] for c in result["components"]}
    result["components"] += [
        copy.deepcopy(c) for c in presence["components"] if c["bom-ref"] not in refs
    ]
    return result
