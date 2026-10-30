#!/usr/bin/env python3
"""Run a seed set's PoC unittest module and record each test's outcome as JSON.

Shell only. Run it with the SAST venv interpreter from the seed set root, e.g.
`cd SEED && VENV/bin/python HOPLITES/scripts/sast_poc_run.py poc.test_agent --output OUT`.
"""

import argparse
import json
from pathlib import Path
import platform
import sys
import unittest


class Recorder(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes[test.id()] = "pass"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = "fail"

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = "error"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test.id()] = "skip"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output file")
    sys.path.insert(0, str(Path.cwd()))
    suite = unittest.defaultTestLoader.loadTestsFromName(args.module)
    runner = unittest.TextTestRunner(resultclass=Recorder, verbosity=1, stream=sys.stderr)
    result = runner.run(suite)
    args.output.write_text(
        json.dumps(
            {
                "module": args.module,
                "cwd": str(Path.cwd()),
                "python": platform.python_version(),
                "outcomes": dict(sorted(result.outcomes.items())),
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
