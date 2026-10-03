#!/usr/bin/env python3
"""Upload a project-scoped VEX and verify every decision via DT analysis API."""
import argparse
import base64
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vex',type=Path,required=True);p.add_argument('--project',required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--refresh-metrics',action='store_true')
    a=p.parse_args()
    document=json.loads(a.vex.read_bytes())
    if not document.get('vulnerabilities'):p.error('No adjudicated findings; inspect unresolved evidence')
    if document.get('metadata',{}).get('component',{}).get('bom-ref')!=a.project:p.error('VEX metadata must identify exact target DT project')
    if a.output_dir.exists():p.error('Use a new output directory')
    key=subprocess.run(['security','find-generic-password','-a','hoplites','-s','hoplites-dependency-track','-w'],capture_output=True,check=True).stdout.decode().strip()
    def api(path,body=None):
        req=urllib.request.Request('http://localhost:18080/api/v1/'+path,data=json.dumps(body).encode() if body is not None else None,method='PUT' if body is not None else 'GET',headers={'X-Api-Key':key,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=30) as r:
            raw=r.read();return json.loads(raw) if raw else None
    components={c['bom-ref']:c for c in document['components']};targets=[];existing={}
    for v in document['vulnerabilities']:
        for affected in v['affects']:
            ref=affected['ref'];expected=components[ref];actual=api('component/'+ref)
            if actual['project']['uuid']!=a.project or (actual['name'],actual['version'],actual.get('purl'))!=(expected['name'],expected['version'],expected.get('purl')):raise ValueError('DT component identity mismatch')
            if ref not in existing:
                rows=[];page=1
                while True:
                    batch=api('vulnerability/component/'+ref+'?suppressed=true&pageSize=100&pageNumber='+str(page));rows.extend(batch)
                    if len(batch)<100:break
                    page+=1
                existing[ref]=rows
            matches=[x for x in existing[ref] if x['vulnId']==v['id'] and x['source']==v['source']['name']]
            if len(matches)!=1:raise ValueError('Existing finding not uniquely matched')
            path='analysis?'+urllib.parse.urlencode({'project':a.project,'component':ref,'vulnerability':matches[0]['uuid']})
            try:before=api(path)
            except urllib.error.HTTPError as e:
                if e.code!=404:raise
                before={'analysis_record_absent':True,'http_status':404}
            targets.append({'cve':v['id'],'component':ref,'path':path,'expected':v['analysis'],'before':before})
    a.output_dir.mkdir(parents=True)
    (a.output_dir/'before.json').write_text(json.dumps(targets,indent=2)+'\n')
    try:response=api('vex',{'project':a.project,'vex':base64.b64encode(a.vex.read_bytes()).decode()})
    except urllib.error.HTTPError as e:
        (a.output_dir/'upload-error.json').write_text(json.dumps({'http_status':e.code,'operation':'PUT /api/v1/vex'})+'\n')
        raise SystemExit('DT VEX upload failed: HTTP '+str(e.code))
    (a.output_dir/'upload.json').write_text(json.dumps(response,indent=2)+'\n')
    for _ in range(30):
        event=api('event/token/'+response['token'])
        if event.get('status')=='COMPLETED':break
        time.sleep(2)
    else:raise SystemExit('Upload completion not confirmed within 60 seconds')
    after=[]
    for target in targets:
        decision=api(target['path']);expected=target['expected']
        should_suppress=expected['state'] in {'resolved','not_affected','false_positive'}
        if not should_suppress and decision.get('isSuppressed'):
            # VEX import does not clear earlier suppression for an active/triage state.
            decision=api('analysis',{'project':a.project,'component':target['component'],'vulnerability':urllib.parse.parse_qs(urllib.parse.urlsplit(target['path']).query)['vulnerability'][0],
                                    'analysisState':expected['state'].upper(),'analysisDetails':expected['detail'],'isSuppressed':False,
                                    'comment':'Hoplites VEX follow-up: reopen suppressed finding for active/triage assessment.'})
        passed=(decision.get('analysisState')==expected['state'].upper() and decision.get('analysisDetails')==expected['detail'] and decision.get('isSuppressed') is should_suppress)
        after.append({'cve':target['cve'],'passed':passed,'analysis':decision,'component':api('component/'+target['component'])})
    (a.output_dir/'after.json').write_text(json.dumps({'event':event,'decisions':after},indent=2)+'\n')
    if not all(r['passed'] for r in after):raise SystemExit('VEX analysis/suppression verification failed; inspect after.json')
    if a.refresh_metrics:
        ids=sorted({t['component'] for t in targets})
        for ref in ids:api('metrics/component/'+ref+'/refresh')
        api('metrics/project/'+a.project+'/refresh')
        metrics={'components':{ref:api('metrics/component/'+ref+'/current') for ref in ids},'project':api('metrics/project/'+a.project+'/current')}
        (a.output_dir/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n')
    print(json.dumps({'verified_decisions':len(after),'event':event}))
if __name__=='__main__':main()
