import hashlib
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from build_evidence_bundle import validate, safe_csv
from normalize_syft_bom import normalize


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.dumps({'components': [{'type': 'library', 'bom-ref': 'p', 'name': 'pkg', 'version': '1'}]}).encode()
        self.ownership = json.dumps({'files': [], 'input_sha256': hashlib.sha256(self.raw).hexdigest()}).encode()
        result, self.evidence = normalize(json.loads(self.raw), json.loads(self.ownership))
        self.output = json.dumps(result).encode()
        self.evidence.update(input_sha256=hashlib.sha256(self.raw).hexdigest(),
                             output_sha256=hashlib.sha256(self.output).hexdigest(),
                             ownership_sha256=hashlib.sha256(self.ownership).hexdigest())

    def test_valid_bundle_inputs(self):
        validate(self.raw, self.output, self.ownership, self.evidence)

    def test_tampered_output_and_report_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.raw, self.output + b' ', self.ownership, self.evidence)
        self.evidence['removed_count'] = 100
        with self.assertRaises(ValueError):
            validate(self.raw, self.output, self.ownership, self.evidence)

    def test_csv_formula_values_escaped(self):
        self.assertEqual(safe_csv('=1+1'), "'=1+1")
        self.assertEqual(safe_csv('/bin/busybox'), '/bin/busybox')
