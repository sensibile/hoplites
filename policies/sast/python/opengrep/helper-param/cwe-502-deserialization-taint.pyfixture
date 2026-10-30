import base64
import json
import pickle

import yaml
from flask import request

DEFAULTS = {"theme": "light"}


def restore():
    # ok: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return pickle.loads(request.get_data())


def restore_json():
    # ok: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return json.loads(request.get_data())


def prefs(blob):
    # ruleid: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return pickle.loads(base64.b64decode(blob))


def config():
    # ok: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return yaml.load(request.files["c"].read(), Loader=yaml.Loader)


def config_safe():
    # ok: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return yaml.safe_load(request.files["c"].read())


def snapshot(path):
    with open(path, "rb") as fh:
        # ruleid: hoplites.python.cwe-502.deserialize-untrusted.helper-param
        return pickle.load(fh)


def defaults():
    # ok: hoplites.python.cwe-502.deserialize-untrusted.helper-param
    return pickle.loads(pickle.dumps(DEFAULTS))
