#!/usr/bin/env python3
"""Actual consumer HTTP/RocksDB cycle against a provided local provider checkout."""

import argparse
import copy
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
from acropolis_consumer import sync, call, credential, authenticated_report, ConsumerError
from hoplites_knowledge import encode, prepare, read_json
from render_knowledge_report import render


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check(provider, output):
    spec = importlib.util.spec_from_file_location(
        "local_provider_gateway", provider / "services/knowledge/gateway.py"
    )
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    tests = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        service_root = root / "service"
        secret = credential(gateway.provision(service_root, "hoplites", "hoplites-service"))
        gateway.provision(service_root, "other", "other-service")
        instance = gateway.server(
            gateway.Service(service_root, provider / "target/debug/akashic-knowledge"), 0
        )
        worker = threading.Thread(target=instance.serve_forever, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{instance.server_port}/v1/tenants/hoplites/knowledge"
        try:
            bom = {
                "components": [
                    {
                        "name": "sample",
                        "version": "1",
                        "purl": "pkg:deb/sample@1",
                        "bom-ref": "sample",
                    }
                ]
            }
            scopes = {
                "rule_version": "contract-test-v1",
                "records": [
                    {
                        "id": "notice",
                        "owner_bom_ref": "sample",
                        "subject": "notice",
                        "inclusion": "inferred",
                        "applicability": "unknown",
                        "fulfillment": "not-verified",
                        "review_actions": ["Inspect notice terms"],
                    }
                ],
            }
            bundle = prepare(
                bom,
                scopes,
                "pkg:deb/sample@1",
                "sha256:" + "a" * 64,
                "linux/arm64",
                {"bom": "b" * 64, "scopes": "c" * 64},
            )
            first = sync(bundle, url, secret, 0, root / "first")
            require(first["knowledge_version"] == 1, "initial pinned version differs")
            tests.append("authenticated import, pinned read, exact receipt and HTML")
            before = (root / "first/report.json").read_bytes()
            pinned = call(url, secret, {"command": "get", "version": 1})
            ops = bundle["write_template"]["request"]["operations"]
            revision = copy.deepcopy(ops[0]["record"])
            revision.update(
                id="revision-question",
                kind="question",
                assessment="unresolved",
                content="Additional investigation remains open",
            )
            changed = call(
                url,
                secret,
                {
                    "command": "apply",
                    "request": {
                        "request_id": "consumer-revision",
                        "expected_version": 1,
                        "operations": [{"op": "put", "record": revision}],
                    },
                },
            )
            require(changed["result"]["version"] == 2, "revision version differs")
            reread = call(url, secret, {"command": "get", "version": 1})
            require(reread == pinned, "historical snapshot changed")
            result = authenticated_report(bundle, reread, secret["principal"], url)
            require(encode(result) == before, "historical JSON changed")
            require(
                render(result) == (root / "first/report.html").read_text(),
                "historical HTML changed",
            )
            tests.append("old JSON and HTML remain identical after actual version 2 commit")
            retry = sync(bundle, url, secret, 0, root / "retry")
            require(retry["knowledge_version"] == 1, "replay version differs")
            tests.append(
                "same request replay returns original receipt/version after another commit"
            )
            for path, token in (
                ("/v1/tenants/other/knowledge", secret["token"]),
                ("/v1/tenants/hoplites/knowledge", None),
            ):
                for command in (
                    {"command": "get", "version": 1},
                    {"command": "history"},
                    bundle["write_template"],
                ):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", instance.server_port, timeout=10
                    )
                    headers = {"Content-Type": "application/json"}
                    if token:
                        headers["Authorization"] = "Bearer " + token
                    connection.request("POST", path, encode(command), headers)
                    response = connection.getresponse()
                    response.read()
                    connection.close()
                    require(
                        response.status == 403, "cross-tenant or anonymous request was not denied"
                    )
            tests.append("cross-tenant and anonymous read/write/history denied through actual HTTP")
            config = gateway.configuration(service_root)
            for grant in config["grants"]:
                if grant["tenant"] == "hoplites":
                    grant["active"] = False
            gateway.atomic_json(service_root / "access.json", config)
            try:
                call(url, secret, {"command": "get", "version": 1})
            except ConsumerError:
                pass
            else:
                raise AssertionError("revoked credential accepted")
            tests.append("revocation denies next consumer request")
            try:
                sync(bundle, url, secret, 0, root / "denied")
            except ConsumerError:
                pass
            else:
                raise AssertionError("revoked write accepted")
            failure, _ = read_json(root / "denied/summary.json")
            require(
                failure["status"] == "partial" and failure["write_outcome"] == "rejected",
                "rejected write result differs",
            )
            require((root / "denied/request.json").is_file(), "failed request evidence missing")
            require(
                not (root / "denied/report.html").exists(), "failed write produced completed report"
            )
            tests.append(
                "denied write preserves replay request and explicit failure, without completed report"
            )
        finally:
            instance.shutdown()
            instance.server_close()
            worker.join()
    result = {
        "status": "pass",
        "provider": str(provider),
        "checks": tests,
        "scope": "isolated actual local service and RocksDB; not NAS/SSO/production",
    }
    with output.open("xb") as target:
        target.write(encode(result))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    check(args.provider, args.output)
