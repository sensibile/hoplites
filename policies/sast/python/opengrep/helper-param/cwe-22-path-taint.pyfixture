import os
import tarfile

from flask import request, send_file
from werkzeug.security import safe_join

BASE = "/srv"


def note():
    name = request.args.get("name", "")
    # ok: hoplites.python.cwe-22.file-path-from-input.helper-param
    return open(os.path.join(BASE, name)).read()


def note_joined():
    path = safe_join(BASE, request.args.get("name", ""))
    # ok: hoplites.python.cwe-22.file-path-from-input.helper-param
    return open(path).read()


def document(name):
    # ruleid: hoplites.python.cwe-22.file-path-from-input.helper-param
    return send_file(os.path.join(BASE, name))


def attachment():
    name = request.args.get("name", "")
    if ".." in name:
        return None
    # ok: hoplites.python.cwe-22.file-path-from-input.helper-param
    return send_file(os.path.join(BASE, name))


def attachment_contained():
    base = os.path.realpath(BASE)
    path = os.path.realpath(os.path.join(base, request.args.get("name", "")))
    if os.path.commonpath([base, path]) != base:
        return None
    # ok: hoplites.python.cwe-22.file-path-from-input.helper-param
    return send_file(path)


def import_bundle(stream):
    with tarfile.open(fileobj=stream) as archive:
        archive.extractall("/srv/imports")


def import_bundle_filtered(stream):
    with tarfile.open(fileobj=stream) as archive:
        archive.extractall("/srv/imports", filter="data")
