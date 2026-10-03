import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('normalize', Path(__file__).parents[1] / 'scripts/normalize_syft_bom.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.bom = {'components': [
            {'bom-ref': 'pkg', 'type': 'library', 'name': 'busybox', 'version': '1'},
            {'bom-ref': 'file', 'type': 'file', 'name': '/bin/busybox', 'hashes': [{'alg': 'SHA-256', 'content': 'abc'}]},
            {'bom-ref': 'unknown', 'type': 'file', 'name': '/custom'},
            {'bom-ref': 'other', 'type': 'library', 'name': 'other'}],
            'dependencies': [{'ref': 'other', 'dependsOn': ['file']},
                             {'ref': 'file', 'dependsOn': ['other']},
                             {'ref': 'pkg', 'dependsOn': ['file']}]}
        self.report = {'files': [{'bom_ref': 'file', 'path': '/bin/busybox', 'status': 'linked',
                                 'owner_bom_ref': 'pkg', 'owner': {'name': 'busybox', 'version': '1'}}]}

    def test_collapse_preserves_evidence_and_transfers_edges(self):
        original = copy.deepcopy(self.bom)
        result, evidence = m.normalize(self.bom, self.report)
        self.assertEqual(self.bom, original)
        self.assertEqual(evidence['removed_files'][0]['component'], original['components'][1])
        self.assertEqual({c['bom-ref'] for c in result['components']}, {'pkg', 'unknown', 'other'})
        edges = {d['ref']: d['dependsOn'] for d in result['dependencies']}
        self.assertEqual(edges, {'other': ['pkg'], 'pkg': ['other']})
        again, _ = m.normalize(result, self.report)
        self.assertEqual(result, again)

    def test_unresolved_missing_owner_and_conflict_remain(self):
        for change in ({'status': 'unknown-owner'}, {'owner_bom_ref': 'missing'},
                       {'field_assessments': {'licenses': 'existing-value-conflict'}}):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                report['files'][0].update(change)
                result, evidence = m.normalize(self.bom, report)
                self.assertEqual(evidence['removed_count'], 0)
                self.assertEqual(len(result['components']), 4)

    def test_dangling_ref_rejected(self):
        self.bom['dependencies'].append({'ref': 'missing'})
        with self.assertRaises(ValueError):
            m.normalize(self.bom, self.report)

    def test_wrong_path_rejected(self):
        self.report['files'][0]['path'] = '/other'
        with self.assertRaises(ValueError):
            m.normalize(self.bom, self.report)

    def test_other_reference_structures_are_not_silently_broken(self):
        self.bom['compositions'] = [{'assemblies': ['file']}]
        with self.assertRaises(ValueError):
            m.normalize(self.bom, self.report)

    def test_fileless_virtual_package_removed_with_database_evidence(self):
        db = b'P:.erlang-rundeps\nV:1\nT:virtual meta package\nS:0\nI:0\nL:\nD:so:libc.so\n'
        self.report['apk_database_sha256'] = hashlib.sha256(db).hexdigest()
        c = {'bom-ref': 'virtual', 'name': '.erlang-rundeps', 'version': '1',
             'type': 'library', 'purl': 'pkg:apk/alpine/.erlang-rundeps@1'}
        self.bom['components'].append(c)
        self.bom['dependencies'].append({'ref': 'virtual', 'dependsOn': ['pkg']})
        result, evidence = m.normalize(self.bom, self.report, db)
        self.assertNotIn('virtual', {x['bom-ref'] for x in result['components']})
        self.assertEqual(evidence['removed_virtual_packages'][0]['component'], c)
        self.assertEqual(evidence['removed_virtual_packages'][0]['apk_record']['D'], ['so:libc.so'])
        self.assertEqual(evidence['removed_virtual_packages'][0]['dependency_records'],
                         [{'ref': 'virtual', 'dependsOn': ['pkg']}])
        self.assertNotIn('virtual', {d['ref'] for d in result['dependencies']})
        again, _ = m.normalize(result, self.report, db)
        self.assertEqual(result, again)
        with self.assertRaises(ValueError):
            m.normalize(self.bom, self.report, db + b'\n')

    def test_virtual_package_with_files_or_dependency_edges_retained(self):
        self.bom['components'].append({'bom-ref': 'virtual', 'name': '.deps', 'version': '1',
                                      'type': 'library', 'purl': 'pkg:apk/alpine/.deps@1'})
        for suffix, edge in [(b'F:usr\nR:payload\n', False), (b'', True)]:
            db = b'P:.deps\nV:1\nT:virtual meta package\nS:0\nI:0\n' + suffix
            self.report['apk_database_sha256'] = hashlib.sha256(db).hexdigest()
            if edge:
                self.bom['dependencies'].append({'ref': 'other', 'dependsOn': ['virtual']})
            result, evidence = m.normalize(self.bom, self.report, db)
            self.assertIn('virtual', {x['bom-ref'] for x in result['components']})
            self.assertEqual(evidence['removed_virtual_packages'], [])
