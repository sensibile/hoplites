#!/usr/bin/env python3
"""Cache Canonical OSV snapshots for every CVE in a DT VEX export."""
import argparse
import concurrent.futures
import json
import re
import sqlite3
import urllib.request
import uuid
from datetime import datetime,timezone
from pathlib import Path
from build_distro_vex import sha

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--export',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--cache',type=Path,required=True);p.add_argument('--commit')
    a=p.parse_args()
    if a.output_dir.exists():p.error('Use new snapshot directory')
    commit=a.commit
    if not commit:
        with urllib.request.urlopen('https://api.github.com/repos/canonical/ubuntu-security-notices/commits/main',timeout=30) as r:commit=json.load(r)['sha']
    if not re.fullmatch('[0-9a-f]{40}',commit):p.error('Use a full upstream commit SHA')
    db=sqlite3.connect(a.cache)
    exists=db.execute("SELECT name FROM sqlite_master WHERE name='vex_advisory_cache'").fetchone()
    if not exists:db.executescript((Path(__file__).parents[1]/'migrations/0005_vex_advisory_cache.sql').read_text())
    cached={r[0]:r[1:] for r in db.execute('SELECT cve,source_url,source_sha256,payload_json,retrieved_at FROM vex_advisory_cache WHERE snapshot_commit=?',(commit,))}
    export=json.loads(a.export.read_bytes());cves=sorted({v['id'] for v in export['vulnerabilities']})
    now=datetime.now(timezone.utc).isoformat();a.output_dir.mkdir(parents=True);(a.output_dir/'advisories').mkdir()
    def fetch(cve):
        if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',cve):return {'cve':cve,'error':'Unsupported vulnerability ID'}
        url=f'https://raw.githubusercontent.com/canonical/ubuntu-security-notices/{commit}/osv/cve/{cve.split("-")[1]}/UBUNTU-{cve}.json'
        try:
            if cve in cached:
                old_url,digest,payload,retrieved=cached[cve];raw=payload.encode()
                if old_url!=url or sha(raw)!=digest:raise ValueError('Cache integrity mismatch')
            else:
                with urllib.request.urlopen(url,timeout=30) as r:raw=r.read()
                json.loads(raw);digest=sha(raw);retrieved=now
            (a.output_dir/'advisories'/(cve+'.json')).write_bytes(raw)
            return {'cve':cve,'url':url,'sha256':digest,'retrieved_at':retrieved,'cache_hit':cve in cached}
        except ValueError:raise
        except Exception as e:return {'cve':cve,'url':url,'error':str(e)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:records=list(pool.map(fetch,cves))
    for r in records:
        if 'sha256' in r:
            payload=(a.output_dir/'advisories'/(r['cve']+'.json')).read_text()
            db.execute('INSERT OR IGNORE INTO vex_advisory_cache VALUES (?,?,?,?,?,?)',(commit,r['cve'],r['url'],r['sha256'],payload,r['retrieved_at']))
    db.commit();db.close()
    (a.output_dir/'advisory-index.json').write_text(json.dumps({'commit':commit,'retrieved_at':now,'records':records},indent=2)+'\n')
    print(json.dumps({'requested':len(cves),'cached':sum(r.get('cache_hit',False) for r in records),'unavailable':sum('error' in r for r in records)}))
if __name__=='__main__':main()
