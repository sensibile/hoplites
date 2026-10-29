import urllib.request
from urllib.parse import urlparse

import requests
from flask import abort, current_app, request

HOSTS = {"billing": "billing.internal"}


def fetch():
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.get(request.args.get("url", ""), timeout=5)


def _allowed(url):
    return urlparse(url).hostname in {"api.example"}


def fetch_checked():
    url = request.args.get("url", "")
    if not _allowed(url):
        abort(400)
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.get(url, timeout=5)


def preview(url):
    # ruleid: hoplites.python.cwe-918.request-url-from-input.helper-param
    return urllib.request.urlopen(url, timeout=5)


def preview_checked(url):
    parsed = urlparse(url)
    if parsed.hostname not in {"api.example"}:
        return None
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return urllib.request.urlopen(url, timeout=5)


def webhook():
    url = request.form.get("url", "")
    if not url.startswith("http://partner.example"):
        abort(400)
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.post(url, timeout=5)


def health():
    host = request.get_json().get("host", "")
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.get(f"http://{host}/status", timeout=5)


def health_mapped():
    host = HOSTS.get(request.get_json().get("service", ""))
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.get(f"http://{host}/status", timeout=5)


def health_config():
    host = current_app.config["SERVICE_HOSTS"].get(request.get_json().get("service", ""))
    # ok: hoplites.python.cwe-918.request-url-from-input.helper-param
    return requests.get(f"http://{host}/status", timeout=5)
