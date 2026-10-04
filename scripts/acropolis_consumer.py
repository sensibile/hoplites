#!/usr/bin/env python3
"""Bounded local HTTP consumer of the authenticated Akashic prototype."""

import argparse
import copy
import http.client
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from hoplites_knowledge import TENANT, RULE, encode, sha, read_json, report
from render_knowledge_report import render

LIMIT = 8 * 1024 * 1024


class ConsumerError(ValueError):
    pass


class ServiceRejected(ConsumerError):
    def __init__(self, status):
        self.status = status
        super().__init__("service rejected request (HTTP " + str(status) + ")")


def endpoint(url):
    value = urlsplit(url)
    if (
        value.scheme != "http"
        or value.hostname != "127.0.0.1"
        or value.username
        or value.password
        or value.query
        or value.fragment
        or value.path != "/v1/tenants/hoplites/knowledge"
        or value.port is None
    ):
        raise ConsumerError("only the explicit Hoplites loopback endpoint is supported")
    return value


def credential(path):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ConsumerError("credential file must be private and owned by the current user")
    value, _ = read_json(path)
    if (
        value.get("tenant") != TENANT
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value.get("principal", ""))
        or not re.fullmatch(r"[0-9a-f]{64}", value.get("token", ""))
    ):
        raise ConsumerError("invalid credential binding")
    return value


def checked_response(value, principal):
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("result"), dict)
        or value.get("ok") is not True
        or value.get("tenant") != TENANT
        or value.get("principal") != principal
    ):
        raise ConsumerError("service identity or success result differs")
    return value["result"]


def call(url, secret, command):
    address = endpoint(url)
    raw = encode(command)
    if len(raw) > LIMIT:
        raise ConsumerError("request exceeds local contract limit")
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=40)
    try:
        connection.request(
            "POST",
            address.path,
            raw,
            {"Content-Type": "application/json", "Authorization": "Bearer " + secret["token"]},
        )
        response = connection.getresponse()
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ConsumerError("response exceeds local contract limit")
        if response.status != 200:
            # Neither request headers nor backend messages are exposed.
            raise ServiceRejected(response.status)

        def unique(pairs):
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ConsumerError("duplicate service response key")
                result[k] = v
            return result

        value = json.loads(body, object_pairs_hook=unique)
        checked_response(value, secret["principal"])
        return value
    except (OSError, http.client.HTTPException) as error:
        raise ConsumerError(
            "local service transport failed; write outcome may be unknown"
        ) from error
    finally:
        connection.close()


def authenticated_report(bundle, response, principal, url):
    endpoint(url)
    result = checked_response(response, principal)
    version = result["version"]
    if type(version) is not int or version < 1:
        raise ConsumerError("invalid pinned service version")
    output = report(
        bundle, {"tenant": TENANT, "version": version, "graph": result["graph"]}, version
    )
    output.update(
        status="local-authenticated",
        authentication="local-service-bearer",
        principal=principal,
        endpoint=url,
        response_sha256=sha(encode(response)),
    )
    return output


def sync(bundle, url, secret, expected_version, directory):
    endpoint(url)
    if (
        bundle.get("schema") != RULE
        or bundle.get("tenant") != TENANT
        or type(expected_version) is not int
        or expected_version < 0
    ):
        raise ConsumerError("invalid bundle or expected version")
    request = copy.deepcopy(bundle["write_template"])
    request["request"]["expected_version"] = expected_version
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)

    def save(name, value):
        with (directory / name).open("xb") as target:
            target.write(encode(value))

    # Preserve replay identity before any external write; never retry automatically.
    save("request.json", request)
    summary = {
        "tenant": TENANT,
        "principal": secret["principal"],
        "request_id": request["request"]["request_id"],
        "status": "in-progress",
        "write_outcome": "unknown",
        "deployment": "local-loopback",
    }
    try:
        applied = call(url, secret, request)
        save("apply-response.json", applied)
        summary["write_outcome"] = "confirmed"
        version = applied["result"]["version"]
        if type(version) is not int or version < 1:
            raise ConsumerError("invalid write version")
        pinned = call(url, secret, {"command": "get", "version": version})
        if pinned["result"]["version"] != version:
            raise ConsumerError("pinned version differs")
        save("snapshot-response.json", pinned)
        history = call(url, secret, {"command": "history"})
        receipt = history["result"]["receipts"].get(request["request"]["request_id"])
        if (
            not receipt
            or receipt["request"] != request["request"]
            or receipt["result"] != applied["result"]
        ):
            raise ConsumerError("write receipt differs")
        save("history-response.json", history)
        result = authenticated_report(bundle, pinned, secret["principal"], url)
        save("report.json", result)
        with (directory / "report.html").open("x", encoding="utf-8") as target:
            target.write(render(result))
        summary.update(
            status="complete",
            knowledge_version=version,
            report_sha256=sha(encode(result)),
            scope="local authenticated import, pinned read, receipt and report",
        )
    except (ConsumerError, ValueError, KeyError, TypeError, OSError) as error:
        if isinstance(error, ServiceRejected):
            summary["http_status"] = error.status
            if summary["write_outcome"] == "unknown" and error.status == 403:
                summary["write_outcome"] = "rejected"
        summary["status"] = "partial"
        save("summary.json", summary)
        raise
    save("summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "endpoint-file", "credential", "output-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-version", required=True, type=int)
    args = parser.parse_args()
    try:
        bundle, _ = read_json(args.bundle)
        config, _ = read_json(args.endpoint_file)
        secret = credential(args.credential)
        summary = sync(bundle, config["url"], secret, args.expected_version, args.output_dir)
        print(json.dumps(summary, ensure_ascii=False))
    except (ValueError, KeyError, TypeError, OSError):
        parser.exit(
            1,
            "Consumer did not complete; inspect preserved request and summary. Credentials were not logged.\n",
        )


if __name__ == "__main__":
    main()
