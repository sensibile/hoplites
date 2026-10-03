import copy
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('enrich', Path(__file__).parents[1] / 'scripts/enrich_syft_apk.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / 'rootfs.tar'
        self.ref = 'example/image@sha256:' + 'a' * 64
        self.bom = {'bomFormat': 'CycloneDX', 'metadata': {'component': {'version': self.ref.split('@')[1]}},
                    'components': [{'type': 'library', 'name': 'busybox', 'version': '1-r1',
                                    'purl': 'pkg:apk/alpine/busybox@1-r1', 'bom-ref': 'package'},
                                   {'type': 'file', 'name': '/bin/busybox', 'bom-ref': 'file',
                                    'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(b'binary').hexdigest()}]}]}
        self.write_archive()

    def write_archive(self, content=b'binary', duplicate=False):
        db = b'P:busybox\nV:1-r1\nL:GPL-2.0-only\nF:bin\nR:busybox\n\n'
        if duplicate:
            db += b'P:other\nV:2\nF:bin\nR:busybox\n\n'
        with tarfile.open(self.archive, 'w') as t:
            for name, data in [('lib/apk/db/installed', db), ('bin/busybox', content)]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))

    def test_fills_standard_fields_with_inference_and_preserves_original(self):
        before = copy.deepcopy(self.bom)
        enriched, report = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(self.bom, before)
        self.assertEqual(report['counts'], {'linked': 1})
        file = enriched['components'][1]
        self.assertEqual(file['licenses'], [{'license': {'name': 'GPL-2.0-only'}}])
        self.assertEqual(file['version'], '1-r1')
        props = {p['name']: p['value'] for p in file['properties']}
        self.assertEqual(props[module.PREFIX + 'declared-license'], 'GPL-2.0-only')
        self.assertEqual(props[module.PREFIX + 'bom-ref'], 'package')
        twice, _ = module.enrich(enriched, self.archive, self.ref)
        self.assertEqual(enriched, twice)

    def test_existing_field_conflicts_are_preserved_and_reported(self):
        self.bom['components'][1]['version'] = 'different'
        self.bom['components'][1]['licenses'] = [{'license': {'id': 'MIT'}}]
        enriched, report = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(enriched['components'][1]['version'], 'different')
        self.assertEqual(enriched['components'][1]['licenses'], [{'license': {'id': 'MIT'}}])
        self.assertEqual(report['files'][0]['field_assessments'],
                         {'version': 'existing-value-conflict', 'licenses': 'existing-value-conflict'})

    def test_missing_license_does_not_block_version(self):
        with tarfile.open(self.archive, 'w') as t:
            for name, data in [('lib/apk/db/installed', b'P:busybox\nV:1-r1\nF:bin\nR:busybox\n\n'), ('bin/busybox', b'binary')]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        enriched, _ = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(enriched['components'][1]['version'], '1-r1')
        self.assertNotIn('licenses', enriched['components'][1])

    def test_changed_file_does_not_get_owner(self):
        self.write_archive(content=b'changed')
        _, report = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(report['counts'], {'hash-mismatch': 1})
        self.assertNotIn('owner', report['files'][0])

    def test_conflicting_ownership_is_not_chosen(self):
        self.write_archive(duplicate=True)
        _, report = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(report['counts'], {'ambiguous-owner': 1})

    def test_wrong_target_is_rejected(self):
        with self.assertRaises(ValueError):
            module.enrich(self.bom, self.archive, 'example/image@sha256:' + 'b' * 64)

    def test_missing_package_does_not_lose_declared_owner(self):
        self.bom['components'] = self.bom['components'][1:]
        _, report = module.enrich(self.bom, self.archive, self.ref)
        self.assertEqual(report['counts'], {'owner-package-unresolved': 1})


if __name__ == '__main__':
    unittest.main()
