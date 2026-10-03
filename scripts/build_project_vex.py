#!/usr/bin/env python3
"""Evaluate every DT finding using pinned Ubuntu OSV snapshots and inventory."""
import argparse
import copy
import json
import sqlite3
import tarfile
import uuid
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit,parse_qs,unquote
from debian_version import compare
from build_distro_vex import build as reviewed_build,sha
from normalize_debian_bom import fields

def range_state(ranges,version):
    if not ranges:raise ValueError('Missing affected ranges')
    affected=False;fixed=[];before=False
    for r in ranges:
        if r.get('type')!='ECOSYSTEM':raise ValueError('Unsupported range type')
        opened=None
        for event in r.get('events',[]):
            if len(event)!=1:raise ValueError('Ambiguous range event')
            key,value=next(iter(event.items()))
            if key=='introduced':
                if opened is not None:raise ValueError('Unclosed interval')
                opened=value
            elif key=='fixed':
                if opened is None:raise ValueError('Fixed without introduced')
                if opened!='0' and compare(opened,value)>=0:raise ValueError('Invalid interval ordering')
                lower=opened=='0' or compare(version,opened)>=0
                affected |= lower and compare(version,value)<0
                if lower and compare(version,value)>=0:fixed.append(value)
                before |= not lower
                opened=None
            else:raise ValueError('Unsupported range event')
        if opened is not None:affected |= opened=='0' or compare(version,opened)>=0
    if affected:return 'exploitable',fixed
    if fixed:return 'resolved',fixed
    if before:return 'not_affected',fixed
    raise ValueError('No evaluable interval')

def build(export,status,os_release,index,sources,reviewed=None):
    inv={}
    for r in (fields(s) for s in status.decode().split('\n\n')):
        if r.get('Status')=='install ok installed':inv.setdefault(r['Package'],[]).append(r)
    release=dict(line.split('=',1) for line in os_release.decode().splitlines() if '=' in line)
    release={k:v.strip('"') for k,v in release.items()}
    records={r['cve']:r for r in index['records']};reviewed=reviewed or {}
    components=[];vulns=[];report={'rule_version':'project-vex-v1','decisions':[],'unresolved':[],'conflicts':[]}
    for c in export.get('components',[]):
        matching=[v for v in export.get('vulnerabilities',[]) if any(a['ref']==c['bom-ref'] for a in v.get('affects',[]))]
        for v in matching:
            base={'component':c['name'],'component_ref':c['bom-ref'],'version':c.get('version'),'cve':v['id']}
            try:
                p=urlsplit(c.get('purl',''));identity=unquote(p.path).rsplit('@',1);q=parse_qs(p.query)
                candidates=inv.get(c['name'],[])
                if 'arch' in q:candidates=[r for r in candidates if q['arch']==[r.get('Architecture')]]
                installed=candidates[0] if len(candidates)==1 else None
                if release.get('ID')!='ubuntu' or q.get('distro')!=['ubuntu-'+release.get('VERSION_ID','')]:raise ValueError('Unsupported/mismatched distro')
                if not installed or identity!=['deb/ubuntu/'+c['name'],c['version']] or installed['Version']!=c['version']:raise ValueError('Inventory/PURL/version mismatch')
                if 'arch' in q and q['arch']!=[installed['Architecture']]:raise ValueError('Architecture mismatch')
                source_field=installed.get('Source',installed['Package']).split()
                source=source_field[0];source_version=source_field[1].strip('()') if len(source_field)==2 else installed['Version']
                record=records.get(v['id'])
                if not record or 'sha256' not in record:raise ValueError('Advisory unavailable')
                raw=(sources/(v['id']+'.json')).read_bytes()
                if sha(raw)!=record['sha256']:raise ValueError('Advisory hash mismatch')
                advisory=json.loads(raw)
                if v['id'] not in advisory.get('upstream',[])+advisory.get('aliases',[]):raise ValueError('CVE identity mismatch')
                if advisory.get('withdrawn'):
                    prior=reviewed.get((c['bom-ref'],v['id']))
                    if prior is None or prior['analysis']['state']!='not_affected':raise ValueError('Advisory withdrawn; explicit not-affected basis required')
                    decision=copy.deepcopy(prior)
                    decision['analysis']['detail']+=f" Ubuntu OSV record withdrawn={advisory['withdrawn']}; snapshot={index['commit']}; source={record['url']}; SHA-256={record['sha256']}. No active range inferred from withdrawn data."
                    vulns.append(decision)
                    if c not in components:components.append(copy.deepcopy(c))
                    report['decisions'].append(dict(base,state='not_affected',source_package=source,source_version=source_version,advisory_sha256=record['sha256'],advisory_url=record['url'],withdrawn=advisory['withdrawn'],basis='explicit reviewed Ubuntu website; OSV withdrawn'))
                    continue
                entries=[a for a in advisory.get('affected',[]) if a['package'].get('ecosystem')=='Ubuntu:'+release['VERSION_ID']+':LTS' and a['package']['name']==source]
                if len(entries)!=1:raise ValueError('No unique source-package/distro entry; absence is not safety')
                entry=entries[0];state,fixed=range_state(entry.get('ranges'),source_version)
                prior=reviewed.get((c['bom-ref'],v['id']))
                conflict=prior is not None and prior['analysis']['state']!=state
                details=(f"Hoplites project-vex-v1; ubuntu-{release['VERSION_ID']}; binary={c['name']}@{c['version']}; source={source}@{source_version}; "
                         f"Ubuntu OSV assessment={state}; fixed endpoints={fixed}; source={record['url']}; SHA-256={record['sha256']}; snapshot={index['commit']}; retrieved={index['retrieved_at']}. "
                         "Vendor package range assessment; runtime exploitability not tested. Original finding retained.")
                if conflict:
                    state='in_triage';details+=' CONFLICT with reviewed website decision: '+prior['analysis']['detail']
                    report['conflicts'].append(dict(base,osv_state=range_state(entry['ranges'],source_version)[0],reviewed_state=prior['analysis']['state']))
                decision=copy.deepcopy(v);decision['affects']=[{'ref':c['bom-ref']}];decision['analysis']={'state':state,'detail':details}
                vulns.append(decision)
                if c not in components:components.append(copy.deepcopy(c))
                report['decisions'].append(dict(base,state=state,source_package=source,source_version=source_version,fixed_versions=fixed,advisory_sha256=record['sha256'],advisory_url=record['url']))
            except (ValueError,KeyError,FileNotFoundError) as e:
                report['unresolved'].append(dict(base,reason=str(e)))
    output={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':copy.deepcopy(export['metadata']),'components':components,'vulnerabilities':vulns}
    output['metadata']['timestamp']=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    return output,report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['export','sbom','normalization-evidence','rootfs','index','sources','reviewed-sources','output','evidence']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists() or a.evidence.exists():p.error('Use new output paths')
    export_raw=a.export.read_bytes();export=json.loads(export_raw)
    sbom_raw=a.sbom.read_bytes();sbom=json.loads(sbom_raw);normalization=json.loads(a.normalization_evidence.read_bytes())
    rootfs_hash=sha(a.rootfs.read_bytes())
    if normalization['rootfs_sha256']!=rootfs_hash or normalization['output_sha256']!=sha(sbom_raw):raise ValueError('Artifact/SBOM provenance hash mismatch')
    if export['metadata']['component']['version']!=sbom['metadata']['component']['version']:raise ValueError('DT project/image digest mismatch')
    identities={(c['name'],c.get('version'),c.get('purl')) for c in sbom['components']}
    if any((c['name'],c.get('version'),c.get('purl')) not in identities for c in export['components']):raise ValueError('Export finding component not in verified SBOM')
    with tarfile.open(a.rootfs) as tar:
        status=tar.extractfile('var/lib/dpkg/status').read();release=tar.extractfile('usr/lib/os-release').read()
    db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
    for f in sorted((Path(__file__).parents[1]/'migrations').glob('*.sql')):db.executescript(f.read_text())
    manual_rules=[];manual_missing=[]
    for row in db.execute('SELECT * FROM distro_vex_decision'):
        path=a.reviewed_sources/(row['cve']+'.html')
        if path.exists() and sha(path.read_bytes())==row['source_sha256']:manual_rules.append(dict(row))
        else:manual_missing.append({'cve':row['cve'],'reason':'Reviewed source unavailable or changed; exact-version rule not applied'})
    manual,_=reviewed_build(export,status,manual_rules,a.reviewed_sources)
    reviewed={(v['affects'][0]['ref'],v['id']):v for v in manual['vulnerabilities']}
    output,report=build(export,status,release,json.loads(a.index.read_bytes()),a.sources,reviewed)
    raw=(json.dumps(output,indent=2)+'\n').encode()
    report['reviewed_evidence_unavailable']=manual_missing
    report['coverage']={'sbom_components':len(sbom['components']),'finding_components':len(export['components']),'finding_pairs':sum(len(v['affects']) for v in export['vulnerabilities']),'components_without_DT_findings':[{'name':c['name'],'version':c.get('version'),'assessment':'no DT finding; not a safety decision'} for c in sbom['components'] if (c['name'],c.get('version'),c.get('purl')) not in {(e['name'],e.get('version'),e.get('purl')) for e in export['components']}]}
    report.update(export_sha256=sha(export_raw),sbom_sha256=sha(sbom_raw),rootfs_sha256=rootfs_hash,status_sha256=sha(status),release_sha256=sha(release),vex_sha256=sha(raw))
    a.output.write_bytes(raw);a.evidence.write_text(json.dumps(report,indent=2)+'\n')
    from collections import Counter
    print(json.dumps({'states':dict(Counter(d['state'] for d in report['decisions'])),'unresolved':len(report['unresolved']),'conflicts':len(report['conflicts'])}))
if __name__=='__main__':main()
