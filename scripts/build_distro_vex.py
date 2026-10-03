#!/usr/bin/env python3
"""Generate component-scoped VEX from exact-version, reviewed distro decisions."""
import argparse
import copy
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from normalize_debian_bom import fields

def sha(raw):return hashlib.sha256(raw).hexdigest()

def build(export, status, rules, sources):
    inventory={r['Package']:r for r in (fields(b) for b in status.decode().split('\n\n')) if r.get('Status')=='install ok installed'}
    components=[];findings=[];decisions=[];pending=[]
    for c in export.get('components',[]):
        matching=[v for v in export.get('vulnerabilities',[]) if any(a['ref']==c['bom-ref'] for a in v.get('affects',[]))]
        parsed=urlsplit(c.get('purl',''));query=parse_qs(parsed.query)
        distro=query.get('distro',[''])[0];identity=unquote(parsed.path).rsplit('@',1)
        purl_path=identity[0];purl_version=identity[1] if len(identity)==2 else None
        inv=inventory.get(c['name']);version=c.get('version')
        if not inv or inv.get('Version')!=version or purl_version!=version or purl_path!='deb/ubuntu/'+c['name']:
            pending.extend({'component':c['name'],'cve':v['id'],'reason':'identity/inventory not matched'} for v in matching);continue
        source=inv.get('Source',inv['Package']).split()[0]
        for v in matching:
            rows=[r for r in rules if (r['cve'],r['distro'],r['source_package'],r['binary_package'],r['reviewed_version'])==(v['id'],distro,source,c['name'],version)]
            if len(rows)!=1:
                pending.append({'component':c['name'],'cve':v['id'],'reason':'no unique reviewed exact-version decision'});continue
            r=rows[0];raw=(sources/(r['cve']+'.html')).read_bytes()
            if sha(raw)!=r['source_sha256']:raise ValueError('Advisory hash mismatch')
            expected='Fixed '+r['fixed_version'] if r['state']=='resolved' else 'Not affected'
            noble_rows=[re.sub('<[^>]+>',' ',row) for row in re.findall(r'<tr\b[^>]*>.*?</tr>',raw.decode(),re.S) if 'noble' in row]
            if not any(expected in ' '.join(row.split()) for row in noble_rows):raise ValueError('Advisory statement mismatch')
            details=(f"Hoplites reviewed distro decision v1: {distro}; source={source}; binary={c['name']}; installed={version}; "
                     f"Ubuntu status={expected}. Exact installed version was reviewed; no inference to other versions. "
                     f"Source: {r['source_url']}; retrieved/reviewed={r['reviewed_at']}; SHA-256={r['source_sha256']}. "
                     "Vendor advisory/package inventory assessment, not a runtime exploitability test. Original NVD finding retained.")
            finding=copy.deepcopy(v);finding['affects']=[{'ref':c['bom-ref']}];finding['analysis']={'state':r['state'],'detail':details}
            findings.append(finding);decisions.append(dict(r,component_ref=c['bom-ref']))
            if c not in components:components.append(copy.deepcopy(c))
    out={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,
         'metadata':copy.deepcopy(export.get('metadata',{})),'components':components,'vulnerabilities':findings}
    out['metadata']['timestamp']=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    return out,{'rule_version':'distro-vex-v1','decisions':decisions,'unresolved':pending}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['export','status','sources','output','evidence']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists() or a.evidence.exists():p.error('Use new output paths')
    db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
    for f in sorted((Path(__file__).parents[1]/'migrations').glob('*.sql')):db.executescript(f.read_text())
    rules=[dict(r) for r in db.execute('SELECT * FROM distro_vex_decision')]
    export=a.export.read_bytes();status=a.status.read_bytes()
    vex,report=build(json.loads(export),status,rules,a.sources)
    raw=(json.dumps(vex,ensure_ascii=False,indent=2)+'\n').encode()
    report.update(export_sha256=sha(export),status_sha256=sha(status),vex_sha256=sha(raw))
    a.output.write_bytes(raw);a.evidence.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'decisions':len(report['decisions']),'unresolved':len(report['unresolved'])}))
if __name__=='__main__':main()
