#!/usr/bin/env python3
"""Run `opengrep test` on a rule directory whose examples are stored as *.pyfixture.

The examples are intentionally vulnerable Python. They are kept without the .py suffix so
repository code scanning does not report them as application code; this runner copies the
rules and examples into a temporary directory with the .py suffix opengrep test expects.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def stage(rules_dir, dest):
    """Copy rule YAML and *.pyfixture examples as *.py; return the number of examples."""
    count = 0
    for path in sorted(Path(rules_dir).iterdir()):
        if path.suffix in (".yaml", ".yml"):
            shutil.copy(path, dest / path.name)
        elif path.suffix == ".pyfixture":
            shutil.copy(path, dest / (path.stem + ".py"))
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_dir", type=Path)
    parser.add_argument("--opengrep", default="opengrep")
    parser.add_argument("--taint-intrafile", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        if stage(args.rules_dir, Path(tmp)) == 0:
            raise SystemExit(f"no *.pyfixture examples in {args.rules_dir}")
        command = [
            args.opengrep,
            "test",
            *(["--taint-intrafile"] if args.taint_intrafile else []),
            tmp,
        ]
        done = subprocess.run(command, capture_output=True, text=True)
        sys.stdout.write(done.stdout)
        sys.stderr.write(done.stderr)
        if done.returncode == 0 and "All tests passed" not in done.stdout + done.stderr:
            raise SystemExit("opengrep test did not report a pass")
        sys.exit(done.returncode)


if __name__ == "__main__":
    main()
