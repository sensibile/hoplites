#!/usr/bin/env python3
"""Build a locally verifiable BOM normalization evidence bundle."""
import argparse
import csv
import hashlib
import html
import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from normalize_syft_bom import normalize


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(original, normalized, ownership, evidence, apk_installed=None):
    if evidence['input_sha256'] != sha(original) or json.loads(ownership)['input_sha256'] != sha(original):
        raise ValueError('Original BOM hash mismatch')
    if evidence['output_sha256'] != sha(normalized) or evidence['ownership_sha256'] != sha(ownership):
        raise ValueError('Normalized BOM or ownership hash mismatch')
    if evidence['rule_version'] == 'package-view-v2':
        if apk_installed is None:
            raise ValueError('APK database required for v2 evidence replay')
    else:
        apk_installed = None
    regenerated, report = normalize(json.loads(original), json.loads(ownership), apk_installed)
    if regenerated != json.loads(normalized):
        raise ValueError('Normalization replay mismatch')
    for field in ('rule_version', 'removed_count', 'remaining_count', 'removed_files', 'retained_files'):
        if report[field] != evidence[field]:
            raise ValueError('Evidence mismatch: ' + field)
    if apk_installed is not None:
        for field in ('removed_virtual_packages', 'apk_database_sha256'):
            if report[field] != evidence.get(field):
                raise ValueError('Evidence mismatch: ' + field)


def safe_csv(value):
    value = str(value)
    return "'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'normalized', 'ownership', 'evidence', 'rootfs', 'output-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    original, normalized, ownership_raw, evidence_raw = [getattr(args, n).read_bytes()
                                                      for n in ('original', 'normalized', 'ownership', 'evidence')]
    evidence = json.loads(evidence_raw)
    # Refuse overwrite: old submission packages remain immutable local snapshots.
    if args.output_dir.exists():
        parser.error('Output directory already exists; use a new directory')
    with tarfile.open(args.rootfs) as tar:
        db = tar.extractfile('lib/apk/db/installed').read()
    validate(original, normalized, ownership_raw, evidence, db)
    ownership = json.loads(ownership_raw)
    files = {'original.cdx.json': original, 'normalized.cdx.json': normalized,
             'ownership.json': ownership_raw, 'normalization-evidence.json': evidence_raw,
             'apk-installed.txt': db}
    fields = ['path', 'file_sha256', 'original_bom_ref', 'package', 'package_version',
              'owner_bom_ref', 'declared_license', 'reason', 'ownership_rule', 'source', 'source_sha256']
    rows = []
    for item in evidence['removed_files']:
        component, owner = item['component'], item['ownership']
        rows.append([component['name'], next(h['content'] for h in component['hashes'] if h['alg'] == 'SHA-256'),
                     component['bom-ref'], owner['owner']['name'], owner['owner']['version'], owner['owner_bom_ref'],
                     owner['owner'].get('declared_license') or '', 'Consolidated into existing owning package',
                     ownership['rule_version'], '/lib/apk/db/installed', sha(db)])
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(fields)
    writer.writerows([[safe_csv(v) for v in row] for row in rows])
    files['excluded-files.csv'] = stream.getvalue().encode('utf-8-sig')
    esc = html.escape
    table = ''.join('<tr>' + ''.join('<td>' + esc(str(v)) + '</td>' for v in row) + '</tr>' for row in rows)
    virtual_section = '<h2>제외한 관리용 가상 패키지</h2><ul>' + ''.join(
        '<li>' + esc(item['component']['name']) + ': ' + esc(item['reason'])
        + '. APK DB 원문 필드와 의존성 연결은 normalization-evidence.json에 보존.</li>'
        for item in evidence.get('removed_virtual_packages', [])) + '</ul>'
    files['report.html'] = ('''<!doctype html><html lang="ko"><meta charset="utf-8"><title>Hoplites BOM normalization evidence</title>
<style>body{font:15px sans-serif;margin:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;text-align:left;overflow-wrap:anywhere}th{background:#eee}code{overflow-wrap:anywhere}</style>
<h1>BOM 정규화 증적</h1><p>개별 파일 항목을 이미 존재하는 소유 패키지로 통합한 기록입니다. 납품물에서 파일을 제거하거나 라이선스 의무를 면제한 것이 아닙니다.</p>'''
        + '<p>원본 ' + str(len(json.loads(original)['components'])) + '개 → 정규화본 ' + str(evidence['remaining_count'])
        + '개. 통합 파일 ' + str(len(rows)) + '개, 유지한 미해결 파일 ' + str(len(evidence['retained_files'])) + '개.</p>'
        + '<p>규칙: ' + esc(evidence['rule_version']) + '. 패키지 선언 라이선스는 개별 파일의 확정 라이선스가 아닙니다. 원본과 증거 JSON에서 각 항목을 추적하세요.</p>'
        + '<table><thead><tr>' + ''.join('<th>'+esc(f)+'</th>' for f in fields) + '</tr></thead><tbody>' + table + '</tbody></table>' + virtual_section + '</html>').encode()
    files['README.txt'] = b'''Hoplites normalization evidence bundle\n
Original and normalized BOMs, ownership evidence, APK database, and file consolidation report are included.
No files were removed from the delivered image. License obligations are not waived.
manifest.json hashes detect content changes but are not a digital signature or independent certification.
The rootfs archive is not included; its SHA-256 is recorded. Preserve it separately to replay file hashing.
Normalization execution time was not recorded in the earlier run. generated_at is bundle creation time only.
Verify files from this directory with Python:
import hashlib, json
from pathlib import Path
m = json.loads(Path('manifest.json').read_text())
for f in m['files']:
    assert hashlib.sha256(Path(f['path']).read_bytes()).hexdigest() == f['sha256'], f['path']
'''
    for script in ('normalize_syft_bom.py', 'enrich_syft_apk.py', 'build_evidence_bundle.py'):
        files['scripts/' + script] = Path(__file__).with_name(script).read_bytes()
    manifest = {'schema_version': 1, 'generated_at': datetime.now(timezone.utc).isoformat(),
                'normalization_rule': evidence['rule_version'], 'ownership_rule': ownership['rule_version'],
                'image_ref': ownership['image_ref'], 'tools': json.loads(original)['metadata'].get('tools'),
                'rootfs_sha256': sha(args.rootfs.read_bytes()), 'apk_database_sha256': sha(db),
                'verification': 'Normalization replay and input/output/evidence hash checks passed.',
                'limitations': ['Rootfs origin is established by local extraction, not cryptographic attestation.',
                                'License fulfillment is not verified.', 'No digital signature included.'],
                'files': [{'path': name, 'sha256': sha(data), 'bytes': len(data)} for name, data in sorted(files.items())]}
    args.output_dir.mkdir(parents=True)
    for name, data in files.items():
        dest = args.output_dir / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (args.output_dir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(f'Bundle created: {args.output_dir}; {len(rows)} consolidation records')


if __name__ == '__main__':
    main()
