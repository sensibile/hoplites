import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from normalize_platform_metadata import normalize, sha


class PlatformTests(unittest.TestCase):
    def setUp(self):
        data = {'/etc/hosts': b'127.0.0.1 localhost\n', '/etc/hostname': b'localhost\n',
                '/lib/apk/db/installed': b'P:busybox\nV:1\n', '/etc/alpine-release': b'3.24.2\n',
                '/etc/os-release': b'ID=alpine\nVERSION_ID=3.24.2\n'}
        self.found = {k: {'raw': v, 'sha256': sha(v), 'layer': 'layer'} for k, v in data.items()}
        self.bom = {'components': [
            {'bom-ref': 'os', 'type': 'operating-system', 'name': 'alpine', 'version': '3.24.2'},
            {'bom-ref': 'package', 'type': 'library', 'name': 'busybox', 'version': '1',
             'licenses': [{'license': {'id': 'GPL-2.0-only'}}]}]}
        for path in list(data)[:3]:
            self.bom['components'].append({'bom-ref': path, 'type': 'file', 'name': path,
                                          'hashes': [{'alg': 'SHA-256', 'content': sha(data[path])}]})

    def test_three_files_separated_os_and_package_license_preserved(self):
        before = copy.deepcopy(self.bom)
        result, report = normalize(self.bom, self.found)
        self.assertEqual(self.bom, before)
        self.assertEqual(len(result['components']), 2)
        self.assertEqual(result['components'][1], before['components'][1])
        self.assertNotIn('licenses', result['components'][0])
        self.assertEqual(len(report['removed_metadata_files']), 3)
        self.assertEqual(report['removed_metadata_files'][0]['source_content'], '127.0.0.1 localhost\n')
        again, _ = normalize(result, self.found)
        self.assertEqual(again, result)

    def test_hash_mismatch_and_non_configuration_content_rejected(self):
        self.found['/etc/hosts']['raw'] = b'#!/bin/sh\necho unexpected\n'
        with self.assertRaises(ValueError): normalize(self.bom, self.found)
        h = sha(self.found['/etc/hosts']['raw'])
        self.found['/etc/hosts']['sha256'] = h
        self.bom['components'][2]['hashes'][0]['content'] = h
        with self.assertRaises(ValueError): normalize(self.bom, self.found)

    def test_referenced_file_and_os_version_mismatch_rejected(self):
        self.bom['dependencies'] = [{'ref': 'package', 'dependsOn': ['/etc/hosts']}]
        with self.assertRaises(ValueError): normalize(self.bom, self.found)
        del self.bom['dependencies']
        self.bom['components'][0]['version'] = 'wrong'
        with self.assertRaises(ValueError): normalize(self.bom, self.found)
