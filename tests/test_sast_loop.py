import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sast_agent import findings as agent_findings  # noqa: E402
from sast_measure import config_matrix, measure  # noqa: E402
from sast_normalize import normalize  # noqa: E402
from sast_rule_gate import judge, load_rules  # noqa: E402
from sast_truth import resolve  # noqa: E402

SOURCE = """\
def view(q):
    sql = "SELECT " + q
    return conn.execute(sql)


def view_v2(q):
    return conn.execute("SELECT ?", (q,))
"""


def spec(cases):
    return {
        "schema": "hoplites-sast-truth-spec/1",
        "set": "t",
        "language": "python",
        "cases": cases,
    }


def case(cid, polarity, pair, function, call="execute", cwe="CWE-89", flow="intra-function"):
    return {
        "id": cid,
        "cwe": cwe,
        "polarity": polarity,
        "pair": pair,
        "flow": flow,
        "sink": {"path": "app/a.py", "function": function, "call": call},
    }


TRUTH = resolve(
    spec([case("V", "vulnerable", "F", "view"), case("F", "fixed", "V", "view_v2")]),
    {"app/a.py": SOURCE},
)


def finding(line, cwe=("CWE-89",), rule="r1", path="app/a.py"):
    return {"rule_id": rule, "cwe": list(cwe), "path": path, "start_line": line, "end_line": line}


class TruthTests(unittest.TestCase):
    def test_sink_resolves_to_the_single_call_and_its_function(self):
        cases = {c["id"]: c for c in TRUTH["cases"]}
        self.assertEqual(
            (cases["V"]["sink"]["start_line"], cases["V"]["function_range"]), (3, [1, 3])
        )
        self.assertEqual(cases["F"]["sink"]["start_line"], 7)

    def test_ambiguous_call_is_rejected(self):
        src = "def v(r):\n    a = r.get('x')\n    return requests.get(a)\n"
        with self.assertRaisesRegex(ValueError, "expected 1 call"):
            resolve(spec([case("V", "vulnerable", None, "v", call="get")]), {"app/a.py": src})
        ok = resolve(
            spec([case("V", "vulnerable", None, "v", call="requests.get")]), {"app/a.py": src}
        )
        self.assertEqual(ok["cases"][0]["sink"]["start_line"], 3)

    def test_pairs_must_be_reciprocal_and_sinks_unique(self):
        with self.assertRaisesRegex(ValueError, "reciprocal"):
            resolve(
                spec([case("V", "vulnerable", "F", "view"), case("F", "fixed", None, "view_v2")]),
                {"app/a.py": SOURCE},
            )
        with self.assertRaisesRegex(ValueError, "shared"):
            resolve(
                spec(
                    [case("V", "vulnerable", None, "view"), case("W", "vulnerable", None, "view")]
                ),
                {"app/a.py": SOURCE},
            )

    def test_pair_must_have_opposite_polarity(self):
        with self.assertRaisesRegex(ValueError, "same polarity"):
            resolve(
                spec(
                    [case("V", "vulnerable", "W", "view"), case("W", "vulnerable", "V", "view_v2")]
                ),
                {"app/a.py": SOURCE},
            )


class NormalizeTests(unittest.TestCase):
    def test_cwe_from_rule_tags_and_paths_relative_to_target(self):
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bandit",
                            "rules": [
                                {"id": "B608", "properties": {"tags": ["external/cwe/cwe-89"]}}
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "B608",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file:///seed/dev/app/a.py"},
                                        "region": {"startLine": 2},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "X",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/b.py"},
                                        "region": {"startLine": 5, "endLine": 6},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ]
        }
        out = normalize(sarif, "bandit", Path("/seed/dev"))
        self.assertEqual(
            [(f["path"], f["cwe"], f["end_line"]) for f in out],
            [("app/a.py", ["CWE-89"], 2), ("app/b.py", [], 6)],
        )


class MeasureTests(unittest.TestCase):
    def test_strict_location_and_false_alarm_counts(self):
        m = config_matrix(TRUTH, [finding(3), finding(7), finding(3, cwe=("CWE-20",), rule="r2")])
        self.assertEqual(m["total"]["recall"]["value"], 1.0)
        self.assertEqual(m["total"]["false_alarms"]["num"], 1)
        self.assertEqual(m["total"]["precision_paired"]["value"], 0.5)

    def test_wrong_cwe_counts_only_as_location_and_unknown_ratio(self):
        m = config_matrix(TRUTH, [finding(3, cwe=("CWE-20",))])
        self.assertEqual(m["by_cwe"]["CWE-89"]["recall"]["num"], 0)
        self.assertEqual(m["by_cwe"]["CWE-89"]["recall_location_only"]["num"], 1)
        self.assertEqual(m["total"]["precision_paired"]["value"], "UNKNOWN")
        self.assertEqual(m["cases"]["V"]["other_cwe"], ["CWE-20"])

    def test_string_build_line_is_function_scope_only(self):
        m = config_matrix(TRUTH, [finding(2)])
        self.assertFalse(m["cases"]["V"]["strict"])
        self.assertTrue(m["cases"]["V"]["function_scope"])

    def test_unlabeled_and_disagreements(self):
        result = measure(TRUTH, {"a": [finding(3), finding(40)], "b": []})
        self.assertEqual(result["matrices"]["a"]["total"]["unlabeled_in_scope"], 1)
        self.assertEqual([d["case"] for d in result["disagreements"]], ["V"])

    def test_union_label_must_not_shadow_or_name_unknown_configs(self):
        with self.assertRaisesRegex(ValueError, "collides"):
            measure(TRUTH, {"a": []}, {"a": ["a"]})
        with self.assertRaisesRegex(ValueError, "unknown"):
            measure(TRUTH, {"a": []}, {"u": ["a", "b"]})


class AgentTests(unittest.TestCase):
    DOC = {
        "model": "m",
        "hypotheses": [
            {"id": "A-1", "cwe": "CWE-89", "sink": {"path": "app/a.py", "line": 3}},
            {"id": "A-2", "cwe": "CWE-89", "sink": {"path": "app/a.py", "line": 7}},
            {"id": "A-3", "cwe": "CWE-89", "sink": {"path": "app/a.py", "line": 9}},
        ],
        "reviewed_not_vulnerable": [{"cwe": "CWE-78", "sink": {"path": "app/b.py", "line": 1}}],
    }

    def test_only_passing_exploit_poc_confirms(self):
        inferred, confirmed, coverage = agent_findings(
            self.DOC, {"A-1": "t1", "A-2": "t2"}, {"t1": "pass", "t2": "fail"}, {}
        )
        self.assertEqual([f["status"] for f in inferred], ["confirmed", "inferred", "inferred"])
        self.assertEqual([f["rule_id"] for f in confirmed], ["A-1"])
        self.assertEqual(inferred[2]["evidence"]["outcome"], "not_run")
        self.assertEqual(coverage[0]["status"], "coverage_only")


class GateTests(unittest.TestCase):
    RULE = [{"id": "r1", "regression_cases": ["V"]}]

    def gate(self, base, cand, rule_only, confirmed=("V",)):
        return judge(
            self.RULE,
            TRUTH,
            set(confirmed),
            config_matrix(TRUTH, base),
            config_matrix(TRUTH, cand),
            config_matrix(TRUTH, rule_only),
        )

    def test_promotes_rule_that_detects_without_firing_on_pair(self):
        result = self.gate([], [finding(3)], [finding(3)])
        self.assertEqual(result["promote"], ["r1"])

    def test_rule_firing_on_fixed_pair_fails(self):
        result = self.gate([], [finding(3), finding(7)], [finding(3), finding(7)])
        self.assertEqual(result["promote"], [])
        self.assertIn("F: fires on fixed pair", result["rules"][0]["problems"])

    def test_unconfirmed_case_and_new_unlabeled_finding_block(self):
        self.assertIn(
            "V: not confirmed by PoC",
            self.gate([], [finding(3)], [finding(3)], confirmed=())["rules"][0]["problems"],
        )
        result = self.gate([], [finding(3), finding(40)], [finding(3), finding(40)])
        self.assertFalse(result["set"]["pass"])

    def test_precision_regression_blocks_set(self):
        result = self.gate([finding(3)], [finding(3), finding(7, rule="other")], [finding(3)])
        self.assertIn("paired precision 1.0 -> 0.5", result["set"]["problems"])


class OutputGuardTests(unittest.TestCase):
    """Collection and judgment outputs are evidence: a second run must not replace them."""

    def test_scripts_refuse_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            out.write_text("kept")
            spec_file = Path(tmp) / "truth-spec.json"
            spec_file.write_text(json.dumps(spec([])))
            commands = [
                ["sast_truth.py", str(spec_file), "--output", str(out)],
                [
                    "sast_rule_gate.py",
                    "--rules",
                    str(spec_file),
                    "--truth",
                    str(spec_file),
                    "--confirmed-measure",
                    str(spec_file),
                    "--measure",
                    str(spec_file),
                    "--baseline",
                    "a",
                    "--candidate",
                    "b",
                    "--rule-only",
                    "c",
                    "--output",
                    str(out),
                ],
            ]
            for command in commands:
                done = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / command[0]), *command[1:]],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("Use a new output file", done.stderr)
            self.assertEqual(out.read_text(), "kept")


class RuleLoadingTests(unittest.TestCase):
    def test_joern_sinks_without_regression_cases_are_judged(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Path(tmp) / "model.json"
            model.write_text(
                json.dumps({"sinks": [{"id": "s1", "regression_cases": ["V"]}, {"id": "s2"}]})
            )
            self.assertEqual(
                load_rules([model]),
                [{"id": "s1", "regression_cases": ["V"]}, {"id": "s2", "regression_cases": []}],
            )


OPENGREP = os.environ.get("OPENGREP") or shutil.which("opengrep")
RULES = ROOT / "policies/sast/python/opengrep"


@unittest.skipUnless(OPENGREP, "opengrep not installed (set OPENGREP)")
class RuleRegressionTests(unittest.TestCase):
    """Synthesized rules keep their annotated detect/ignore examples (ruleid/ok comments)."""

    def run_tests(self, directory, *flags):
        done = subprocess.run(
            [OPENGREP, "test", *flags, str(directory)], capture_output=True, text=True
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_request_source_rules(self):
        self.run_tests(RULES / "request", "--taint-intrafile")

    def test_helper_parameter_rules(self):
        self.run_tests(RULES / "helper-param")


if __name__ == "__main__":
    unittest.main()
