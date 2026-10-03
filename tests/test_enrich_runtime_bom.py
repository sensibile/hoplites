import copy
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from enrich_runtime_bom import enrich


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p = Path(self.temp.name)
        self.tar = self.p / 'rootfs.tar'
        self.payload = b'{application,elixir,[{vsn,"1.18.4"}]}.'
        with tarfile.open(self.tar, 'w') as t:
            m = tarfile.TarInfo('elixir.app'); m.size = len(self.payload)
            t.addfile(m, io.BytesIO(self.payload))
        license_raw = b'Apache License\nVersion 2.0'
        (self.p / 'LICENSE').write_bytes(license_raw)
        self.rules = {'image_ref': 'image@sha256:abc',
                      'rootfs_sha256': hashlib.sha256(self.tar.read_bytes()).hexdigest(),
                      'limitations': ['upstream inference'], 'rules': [{
                          'name': 'elixir', 'version': '1.18.4', 'purl': 'pkg:generic/elixir@1.18.4',
                          'license_id': 'Apache-2.0', 'license_url': 'https://example.test/license',
                          'license_file': 'LICENSE', 'license_sha256': hashlib.sha256(license_raw).hexdigest(),
                          'source_commit': 'abc', 'version_marker': 'elixir.app'}]}
        self.save_rules()
        self.bom = {'metadata': {'component': {'version': 'sha256:abc'}}, 'components': [
            {'name': 'elixir', 'version': '1.18.4', 'purl': 'pkg:generic/elixir@1.18.4',
             'type': 'application', 'bom-ref': 'runtime',
             'properties': [{'name': 'syft:location:0:path', 'value': '/elixir.app'}]},
            {'name': '/elixir.app', 'type': 'file', 'bom-ref': 'file',
             'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(self.payload).hexdigest()}]}],
            'dependencies': [{'ref': 'runtime', 'dependsOn': ['file']}]}

    def save_rules(self):
        (self.p / 'rules.json').write_text(json.dumps(self.rules))

    def test_standard_license_file_collapse_and_repeat(self):
        original = copy.deepcopy(self.bom)
        result, report = enrich(self.bom, self.tar, self.p)
        self.assertEqual(self.bom, original)
        self.assertEqual(result['components'][0]['licenses'][0]['license']['id'], 'Apache-2.0')
        self.assertEqual(len(result['components']), 1)
        self.assertEqual(report['removed_runtime_files'][0]['component'], original['components'][1])
        self.assertEqual(result['dependencies'], [{'ref': 'runtime', 'dependsOn': []}])
        again, _ = enrich(result, self.tar, self.p)
        self.assertEqual(again, result)

    def test_license_conflict_and_file_hash_mismatch_rejected(self):
        self.bom['components'][0]['licenses'] = [{'license': {'id': 'MIT'}}]
        with self.assertRaises(ValueError): enrich(self.bom, self.tar, self.p)
        del self.bom['components'][0]['licenses']
        self.bom['components'][1]['hashes'][0]['content'] = 'wrong'
        with self.assertRaises(ValueError): enrich(self.bom, self.tar, self.p)

    def test_source_and_rootfs_tampering_rejected(self):
        (self.p / 'LICENSE').write_bytes(b'changed')
        with self.assertRaises(ValueError): enrich(self.bom, self.tar, self.p)
        self.rules['rootfs_sha256'] = 'wrong'; self.save_rules()
        with self.assertRaises(ValueError): enrich(self.bom, self.tar, self.p)

    def test_version_marker_mismatch_rejected(self):
        self.bom['components'][0]['version'] = '2'
        self.bom['components'][0]['purl'] = 'pkg:generic/elixir@2'
        self.rules['rules'][0].update(version='2', purl='pkg:generic/elixir@2')
        self.save_rules()
        with self.assertRaises(ValueError): enrich(self.bom, self.tar, self.p)
