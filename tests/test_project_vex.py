import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from debian_version import compare
from build_project_vex import range_state,build,sha

class VersionTests(unittest.TestCase):
    def test_dpkg_ordering(self):
        for a,b in [('1.0~rc1','1.0'),('1.0','1.0-1'),('1:1.0','2:0.1'),('3.0.13-0ubuntu3.9','3.0.13-0ubuntu3.16'),('1.0-1+b1','1.0-2'),('1.0~~','1.0~'),('1.0a','1.0+'),('1.0~rc9','1.0~rc10')]:
            self.assertLess(compare(a,b),0);self.assertGreater(compare(b,a),0)
        self.assertEqual(compare('1.01-1','1.1-01'),0)
    def test_invalid_version(self):
        for v in ['', 'abc','1.0-','bad:1.0']:
            with self.assertRaises(ValueError):compare(v,'1.0')
    def test_range_fixed_boundary_and_reintroduced(self):
        r=[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'1.0-2'},{'introduced':'2.0'},{'fixed':'2.0-3'}]}]
        self.assertEqual(range_state(r,'1.0-1')[0],'exploitable')
        self.assertEqual(range_state(r,'1.0-2')[0],'resolved')
        self.assertEqual(range_state(r,'2.0-1')[0],'exploitable')
        self.assertEqual(range_state(r,'2.0-3')[0],'resolved')
    def test_unsupported_or_malformed_not_safe(self):
        for r in [[],[{'type':'SEMVER','events':[]}],[{'type':'ECOSYSTEM','events':[{'fixed':'1'}]}],[{'type':'ECOSYSTEM','events':[{'introduced':'2'},{'fixed':'1'}]}]]:
            with self.assertRaises(ValueError):range_state(r,'1')

class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)
        self.status=b'Package: bin\nStatus: install ok installed\nVersion: 2-2\nArchitecture: arm64\nSource: src (1-2)\n'
        self.release=b'ID=ubuntu\nVERSION_ID="24.04"\n'
        self.export={'metadata':{'component':{'bom-ref':'project'}},'components':[{'bom-ref':'c','type':'library','name':'bin','version':'2-2','purl':'pkg:deb/ubuntu/bin@2-2?arch=arm64&distro=ubuntu-24.04'}],'vulnerabilities':[{'id':'CVE-2025-0001','affects':[{'ref':'c'},{'ref':'other'}]}]}
        self.advisory={'upstream':['CVE-2025-0001'],'affected':[{'package':{'ecosystem':'Ubuntu:24.04:LTS','name':'src'},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'1-2'}]}]}]}
        self.index={'commit':'a'*40,'retrieved_at':'2026-10-03','records':[]};self.save()
    def save(self):
        raw=json.dumps(self.advisory).encode();(self.path/'CVE-2025-0001.json').write_bytes(raw)
        self.index['records']=[{'cve':'CVE-2025-0001','sha256':sha(raw),'url':'https://example.test'}]
    def run_build(self,reviewed=None):return build(self.export,self.status,self.release,self.index,self.path,reviewed)
    def test_source_version_boundary_and_component_scope(self):
        original=copy.deepcopy(self.export);v,r=self.run_build()
        self.assertEqual(v['vulnerabilities'][0]['analysis']['state'],'resolved')
        self.assertEqual(r['decisions'][0]['source_version'],'1-2')
        self.assertEqual(v['vulnerabilities'][0]['affects'],[{'ref':'c'}]);self.assertEqual(original,self.export)
    def test_unknown_package_or_wrong_arch_kept_unresolved(self):
        self.advisory['affected'][0]['package']['name']='other';self.save()
        self.assertEqual(len(self.run_build()[1]['unresolved']),1)
        self.export['components'][0]['purl']=self.export['components'][0]['purl'].replace('arm64','amd64')
        self.assertFalse(self.run_build()[0]['vulnerabilities'])
    def test_hash_corruption_not_suppressed(self):
        (self.path/'CVE-2025-0001.json').write_bytes(b'corrupt')
        self.assertFalse(self.run_build()[0]['vulnerabilities'])
    def test_withdrawn_requires_explicit_basis(self):
        self.advisory['withdrawn']='2026-04-01';self.save()
        self.assertEqual(len(self.run_build()[1]['unresolved']),1)
        prior=copy.deepcopy(self.export['vulnerabilities'][0]);prior['analysis']={'state':'not_affected','detail':'reviewed source'};prior['affects']=[{'ref':'c'}]
        self.assertEqual(self.run_build({('c','CVE-2025-0001'):prior})[0]['vulnerabilities'][0]['analysis']['state'],'not_affected')
    def test_conflict_returns_triage(self):
        prior={'analysis':{'state':'not_affected','detail':'reviewed'}}
        v,r=self.run_build({('c','CVE-2025-0001'):prior})
        self.assertEqual(v['vulnerabilities'][0]['analysis']['state'],'in_triage');self.assertEqual(len(r['conflicts']),1)
    def test_open_interval_affected(self):
        self.advisory['affected'][0]['ranges'][0]['events']=[{'introduced':'0'}];self.save()
        self.assertEqual(self.run_build()[0]['vulnerabilities'][0]['analysis']['state'],'exploitable')

    def test_multiarch_selection_and_ambiguity(self):
        self.status+=b'\nPackage: bin\nStatus: install ok installed\nVersion: 2-2\nArchitecture: amd64\nSource: src (1-2)\n'
        self.assertEqual(self.run_build()[0]['vulnerabilities'][0]['analysis']['state'],'resolved')
        self.export['components'][0]['purl']='pkg:deb/ubuntu/bin@2-2?distro=ubuntu-24.04'
        self.assertEqual(len(self.run_build()[1]['unresolved']),1)
