import os
import shlex
import subprocess

from flask import request


def ping():
    host = request.form.get("host", "")
    # ok: hoplites.python.cwe-78.shell-command-from-input.helper-param
    os.system(f"ping -c 1 {host}")


def ping_argv():
    host = request.form.get("host", "")
    # ok: hoplites.python.cwe-78.shell-command-from-input.helper-param
    subprocess.run(["ping", "-c", "1", host])


def archive(name):
    # ruleid: hoplites.python.cwe-78.shell-command-from-input.helper-param
    subprocess.run(f"tar czf {name}.tgz .", shell=True)


def count(name):
    # ok: hoplites.python.cwe-78.shell-command-from-input.helper-param
    return subprocess.check_output("wc -l -- " + shlex.quote(name), shell=True)


def version():
    # ok: hoplites.python.cwe-78.shell-command-from-input.helper-param
    return subprocess.run("git rev-parse HEAD", shell=True)
