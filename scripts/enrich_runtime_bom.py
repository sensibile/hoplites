#!/usr/bin/env python3
"""Enrich identified runtimes using cached upstream evidence and verified image files."""
import argparse
import copy
import hashlib
import json
import re
import tarfile
from pathlib import Path
from normalize_syft_bom import normalize

RULE_VERSION = 'runtime-enrichment-v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enrich(bom, rootfs, sources):
    rules = json.loads((sources / 'rules.json').read_text())
    target = bom.get('metadata', {}).get('component', {}).get('version')
    if rules['image_ref'].split('@', 1)[1] != target:
        raise ValueError('Image digest mismatch')
    if sha(rootfs.read_bytes()) != rules['rootfs_sha256']:
        raise ValueError('Rootfs evidence hash mismatch')
    result = copy.deepcopy(bom)
    changes, files, assessments = [], [], []
    with tarfile.open(rootfs) as tar:
        members = {m.name.lstrip('./'): m for m in tar}
        def read(path):
            member = members.get(path.lstrip('/'))
            if not member or not member.isfile():
                raise ValueError('Missing regular evidence file: ' + path)
            return tar.extractfile(member).read()
        for rule in rules['rules']:
            matches = [c for c in result['components'] if c.get('type') == 'application'
                       and c.get('name') == rule['name'] and c.get('version') == rule['version']
                       and c.get('purl') == rule['purl']]
            if len(matches) != 1:
                raise ValueError('Missing or ambiguous runtime: ' + rule['name'])
            runtime = matches[0]
            marker = read(rule['version_marker'])
            if rule['name'] == 'elixir':
                version = re.search(rb'\{vsn,\s*"([^"]+)"\}', marker)
                version = version.group(1).decode() if version else None
            elif rule['name'] == 'erlang':
                version = marker.decode().strip()
            else:
                raise ValueError('Unsupported runtime marker parser')
            if version != rule['version']:
                raise ValueError('Runtime version marker mismatch')
            license_path = (sources / rule['license_file']).resolve()
            if not license_path.is_relative_to(sources.resolve()):
                raise ValueError('License evidence path escapes source directory')
            license_raw = license_path.read_bytes()
            if sha(license_raw) != rule['license_sha256']:
                raise ValueError('License evidence hash mismatch')
            if rule['license_id'] != 'Apache-2.0' or b'Apache License' not in license_raw or b'Version 2.0' not in license_raw:
                raise ValueError('Unsupported or inconsistent license declaration')
            proposed = [{'license': {'id': rule['license_id'], 'url': rule['license_url']}}]
            existing = runtime.get('licenses')
            equivalent = existing and len(existing) == 1 and existing[0].get('license', {}).get('id') == rule['license_id']
            if existing and not equivalent:
                raise ValueError('Runtime license conflict; refusing overwrite')
            if not existing:
                runtime['licenses'] = proposed
                changes.append({'bom_ref': runtime['bom-ref'], 'field': 'licenses', 'before': existing,
                                'after': proposed, 'assessment': 'inferred-from-versioned-upstream'})
            prefix = 'hoplites:runtime:'
            props = [p for p in runtime.get('properties', []) if not p['name'].startswith(prefix)]
            props.extend({'name': prefix + key, 'value': value} for key, value in [
                ('rule-version', RULE_VERSION), ('license-assessment', 'inferred-from-versioned-upstream'),
                ('source-commit', rule['source_commit']), ('license-source', rule['license_url']),
                ('license-sha256', rule['license_sha256']),
                ('scope', 'Project license; bundled third-party license inventory remains pending')])
            runtime['properties'] = props
            locations = {p['value'] for p in props if re.fullmatch(r'syft:location:\d+:path', p['name'])}
            for c in result['components']:
                if c.get('type') != 'file' or c.get('name') not in locations:
                    continue
                hashes = [h['content'] for h in c.get('hashes', []) if h['alg'] == 'SHA-256']
                actual = sha(read(c['name']))
                if hashes != [actual]:
                    raise ValueError('Runtime file hash mismatch: ' + c['name'])
                files.append({'bom_ref': c['bom-ref'], 'path': c['name'], 'status': 'linked',
                              'owner_bom_ref': runtime['bom-ref'],
                              'owner': {'name': rule['name'], 'version': rule['version']},
                              'source': 'Syft runtime identification locations and rootfs SHA-256',
                              'file_sha256': actual})
            assessments.append({'name': rule['name'], 'version': version,
                                'version_marker': rule['version_marker'], 'marker_sha256': sha(marker),
                                'source': copy.deepcopy(rule), 'third_party_inventory': 'pending'})
    result, collapsed = normalize(result, {'files': files})
    report = {'rule_version': RULE_VERSION, 'changes': changes, 'runtimes': assessments,
              'removed_runtime_files': collapsed['removed_files'],
              'remaining_count': len(result['components']),
              'limitations': rules['limitations'], 'rules_sha256': sha((sources / 'rules.json').read_bytes())}
    return result, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sbom', 'rootfs', 'sources', 'output', 'evidence'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    paths = [getattr(args, n).resolve() for n in ('sbom', 'rootfs', 'output', 'evidence')]
    if len(set(paths)) != len(paths) or args.output.exists() or args.evidence.exists():
        p.error('Use distinct input paths and new output/evidence paths')
    raw = args.sbom.read_bytes()
    result, report = enrich(json.loads(raw), args.rootfs, args.sources)
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    report.update(input_sha256=sha(raw), output_sha256=sha(encoded), rootfs_sha256=sha(args.rootfs.read_bytes()))
    args.output.write_bytes(encoded)
    args.evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'license_fields_added': len(report['changes']),
                      'runtime_files_collapsed': len(report['removed_runtime_files']),
                      'remaining_count': report['remaining_count']}))


if __name__ == '__main__':
    main()
