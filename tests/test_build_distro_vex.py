import copy
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from build_distro_vex import build,sha

class VexTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)
        self.raw=b'<table><tr><td>24.04 noble</td><td>Fixed 1.0-2</td></tr></table>'
        (self.path/'CVE-TEST.html').write_bytes(self.raw)
        self.rule={'cve':'CVE-TEST','distro':'ubuntu-24.04','source_package':'src','binary_package':'bin','reviewed_version':'1.0-3','state':'resolved','fixed_version':'1.0-2','source_url':'https://ubuntu.com/security/CVE-TEST','source_sha256':sha(self.raw),'reviewed_at':'2026-10-03'}
        self.status=b'Package: bin\nStatus: install ok installed\nVersion: 1.0-3\nSource: src\n'
        self.export={'components':[{'type':'library','bom-ref':'c','name':'bin','version':'1.0-3','purl':'pkg:deb/ubuntu/bin@1.0-3?distro=ubuntu-24.04'}], 'vulnerabilities':[{'id':'CVE-TEST','affects':[{'ref':'c'},{'ref':'other'}]}]}
    def test_scoped_decision_and_original_unchanged(self):
        original=copy.deepcopy(self.export)
        v,r=build(self.export,self.status,[self.rule],self.path)
        self.assertEqual(v['vulnerabilities'][0]['analysis']['state'],'resolved')
        self.assertEqual(v['vulnerabilities'][0]['affects'],[{'ref':'c'}])
        self.assertEqual(self.export,original);self.assertEqual(len(r['decisions']),1)
    def test_other_version_and_distro_not_adjudicated(self):
        self.export['components'][0]['version']='1.0-4'
        self.assertFalse(build(self.export,self.status,[self.rule],self.path)[0]['vulnerabilities'])
        self.export['components'][0]['version']='1.0-3'
        self.export['components'][0]['purl']='pkg:deb/ubuntu/bin@1.0-3?distro=ubuntu-22.04'
        self.assertFalse(build(self.export,self.status,[self.rule],self.path)[0]['vulnerabilities'])
    def test_unknown_cve_is_unresolved(self):
        self.export['vulnerabilities'][0]['id']='CVE-OTHER'
        v,r=build(self.export,self.status,[self.rule],self.path)
        self.assertFalse(v['vulnerabilities']);self.assertEqual(len(r['unresolved']),1)
    def test_modified_advisory_fails(self):
        (self.path/'CVE-TEST.html').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):build(self.export,self.status,[self.rule],self.path)
    def test_not_affected_no_invented_justification(self):
        raw=b'<tr><td>noble</td><td>Not affected</td></tr>'; (self.path/'CVE-TEST.html').write_bytes(raw)
        self.rule.update(state='not_affected',fixed_version='',source_sha256=sha(raw))
        a=build(self.export,self.status,[self.rule],self.path)[0]['vulnerabilities'][0]['analysis']
        self.assertEqual(a['state'],'not_affected');self.assertNotIn('justification',a)
