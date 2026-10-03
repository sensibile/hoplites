import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from image_pipeline import resolve_reference,Pipeline
from normalize_debian_bom import process

class ImagePipelineTests(unittest.TestCase):
    def test_platform_digest_selection_and_tag_removal(self):
        descriptor={'manifests':[{'digest':'sha256:'+'a'*64,'platform':{'os':'linux','architecture':'amd64'}},{'digest':'sha256:'+'b'*64,'platform':{'os':'linux','architecture':'arm64'}}]}
        self.assertEqual(resolve_reference('elixir:1.18',descriptor,'linux/arm64'),'docker.io/library/elixir@sha256:'+'b'*64)
        self.assertEqual(resolve_reference('localhost:5000/team/app:tag',descriptor,'linux/arm64'),'localhost:5000/team/app@sha256:'+'b'*64)
        with self.assertRaises(ValueError):resolve_reference('app',descriptor,'linux/s390x')
        descriptor['manifests'].append(descriptor['manifests'][1])
        with self.assertRaises(ValueError):resolve_reference('app',descriptor,'linux/arm64')
    def test_cached_source_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);out=p/'out';out.mkdir();cache=p/'cache';(cache/'blobs').mkdir(parents=True)
            sha=hashlib.sha256(b'expected').hexdigest();(cache/'blobs'/sha).write_bytes(b'corrupt')
            with self.assertRaises(ValueError):Pipeline(out,cache).blob('https://example.test',sha)
    def test_unsupported_package_db_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);rootfs=p/'rootfs.tar'
            with tarfile.open(rootfs,'w'):pass
            out=p/'out';out.mkdir();original={'components':[{'bom-ref':'a','type':'application','name':'unknown','version':'1'}]}
            pipe=Pipeline(out,p/'cache');bom=pipe.normalize(original,rootfs,p/'unused.tar','image@sha256:'+'a'*64)
            self.assertEqual(original,bom);self.assertTrue(pipe.pending)
    def test_debian_without_java_and_missing_copyright(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);rootfs=p/'rootfs.tar'
            files={'var/lib/dpkg/status':b'Package: pkg\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n','var/lib/dpkg/info/pkg.list':b'/usr/bin/a\n','usr/bin/a':b'abc'}
            with tarfile.open(rootfs,'w') as t:
                for name,raw in files.items():m=tarfile.TarInfo(name);m.size=len(raw);t.addfile(m,io.BytesIO(raw))
            bom={'components':[{'bom-ref':'p','name':'pkg','version':'1','type':'library','purl':'pkg:deb/ubuntu/pkg@1','licenses':[{'license':{'id':'MIT'}}]},{'bom-ref':'os','name':'ubuntu','version':'24.04','type':'operating-system'},{'bom-ref':'f','name':'/usr/bin/a','type':'file','hashes':[{'alg':'SHA-256','content':hashlib.sha256(b'abc').hexdigest()}]}]}
            out,report,_=process(bom,rootfs,{})
            self.assertEqual(len(out['components']),2);self.assertEqual(out['components'][0]['licenses'],bom['components'][0]['licenses'])
            self.assertTrue(report['unresolved']);self.assertEqual(report['jre_legal_documents'],[])
