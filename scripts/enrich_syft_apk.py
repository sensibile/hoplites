#!/usr/bin/env python3
"""Fill missing standard BOM fields from APK evidence, with explicit inference labels."""
import argparse
import copy
import hashlib
import json
import posixpath
import tarfile
from pathlib import Path

RULE_VERSION = 'apk-enrichment-v2'
PREFIX = 'hoplites:apk-owner:'


def parse_installed(text):
    owners = {}
    for block in text.split('\n\n'):
        package, paths, directory = {}, [], None
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ':':
                continue
            key, value = line[0], line[2:]
            if key in ('P', 'V', 'A', 'L'):
                package[key] = value
            elif key == 'F':
                directory = value
            elif key == 'R' and directory is not None:
                path = '/' + posixpath.normpath(posixpath.join(directory, value)).lstrip('/')
                paths.append(path)
        if package.get('P') and package.get('V'):
            for path in paths:
                owners.setdefault(path, []).append(dict(package))
    return owners


def enrich(bom, archive, image_ref):
    if bom.get('bomFormat') != 'CycloneDX':
        raise ValueError('Expected CycloneDX')
    target = bom.get('metadata', {}).get('component', {})
    if '@sha256:' not in image_ref or target.get('version') != image_ref.split('@', 1)[1]:
        raise ValueError('Image digest does not match SBOM metadata')
    result = copy.deepcopy(bom)
    report = {'rule_version': RULE_VERSION, 'image_ref': image_ref,
              'files': [], 'limitations': ['APK ownership is a package DB declaration, not a file-level license conclusion.',
                                         'Rootfs archive provenance must be established by the caller.']}
    with tarfile.open(archive, 'r:*') as tar:
        members = {m.name.lstrip('./'): m for m in tar.getmembers()}
        db_member = members.get('lib/apk/db/installed')
        if not db_member or not db_member.isfile():
            raise ValueError('Regular APK installed database missing')
        db = tar.extractfile(db_member).read()
        db_hash = hashlib.sha256(db).hexdigest()
        owners = parse_installed(db.decode('utf-8'))
        report['apk_database_sha256'] = db_hash
        for component in result.get('components', []):
            if component.get('type') != 'file':
                continue
            props = [p for p in component.get('properties', []) if not p['name'].startswith(PREFIX)]
            entry = {'bom_ref': component.get('bom-ref'), 'path': component.get('name')}
            path = component.get('name', '')
            hashes = [h['content'] for h in component.get('hashes', []) if h['alg'] == 'SHA-256']
            member = members.get(path.lstrip('/'))
            candidates = owners.get(path, [])
            if not member or not member.isfile():
                state = 'unverified-file'
            elif len(hashes) != 1:
                state = 'missing-or-ambiguous-sha256'
            elif hashlib.sha256(tar.extractfile(member).read()).hexdigest() != hashes[0]:
                state = 'hash-mismatch'
            elif len(candidates) != 1:
                state = 'unknown-owner' if not candidates else 'ambiguous-owner'
            else:
                owner = candidates[0]
                matches = [c for c in result['components'] if c.get('type') != 'file'
                           and c.get('name') == owner['P'] and c.get('version') == owner['V']
                           and c.get('purl', '').startswith('pkg:apk/')]
                state = 'linked' if len(matches) == 1 else 'owner-package-unresolved'
                entry['owner'] = {'name': owner['P'], 'version': owner['V'],
                                  'declared_license': owner.get('L') or None}
                for key, value in [('package-name', owner['P']), ('package-version', owner['V']),
                                   ('declared-license', owner.get('L'))]:
                    if value:
                        props.append({'name': PREFIX + key, 'value': value})
                entry['changes'] = []
                entry['field_assessments'] = {}
                proposed = {'version': owner['V']}
                if owner.get('L'):
                    # Prefer the original scanner's structured license representation.
                    # Unparsed APK expressions remain names, not fabricated SPDX IDs.
                    proposed['licenses'] = (copy.deepcopy(matches[0].get('licenses'))
                                            if len(matches) == 1 and matches[0].get('licenses')
                                            else [{'license': {'name': owner['L']}}])
                for field, value in proposed.items():
                    existing = component.get(field)
                    if not existing:
                        component[field] = value
                        entry['changes'].append({'field': field, 'before': existing,
                                                 'after': value, 'assessment': 'inferred-from-package'})
                    assessment = ('inferred-from-package' if not existing or existing == value
                                  else 'existing-value-conflict')
                    entry['field_assessments'][field] = assessment
                    props.append({'name': PREFIX + field + '-assessment', 'value': assessment})
                entry['warning'] = ('Version is the owning APK package version; license is inferred '
                                    'from its declaration and may differ for individual files. '
                                    'This is not proof of license obligation fulfillment.')
                props.append({'name': PREFIX + 'warning', 'value': entry['warning']})
                if len(matches) == 1:
                    entry['owner_bom_ref'] = matches[0]['bom-ref']
                    props.append({'name': PREFIX + 'bom-ref', 'value': matches[0]['bom-ref']})
            entry['status'] = state
            props.extend({'name': PREFIX + k, 'value': v} for k, v in
                         [('status', state), ('rule-version', RULE_VERSION),
                          ('source', '/lib/apk/db/installed'), ('source-sha256', db_hash)])
            component['properties'] = props
            report['files'].append(entry)
    for item in report['files']:
        if item['status'] not in ('linked', 'owner-package-unresolved'):
            item['next_action'] = {
                'unknown-owner': 'Inspect Syft binary/application locations and shipped license files; resolve build source if needed.',
                'hash-mismatch': 'Compare the registry layer file against export; container-generated files may differ.',
                'ambiguous-owner': 'Compare candidate package manifests and file checksums.',
            }.get(item['status'], 'Obtain a verifiable regular file and SHA-256 for this target.')
    report['counts'] = {state: sum(e['status'] == state for e in report['files'])
                        for state in sorted({e['status'] for e in report['files']})}
    return result, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sbom', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--image-ref', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() == args.sbom.resolve() or args.report.resolve() == args.sbom.resolve() or args.output.resolve() == args.report.resolve():
        parser.error('Input, output and report paths must be distinct')
    raw = args.sbom.read_bytes()
    result, report = enrich(json.loads(raw), args.rootfs, args.image_ref)
    # Deterministic transformation: same inputs produce same bytes, including repeated enrichment.
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    report.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  output_sha256=hashlib.sha256(encoded).hexdigest())
    args.output.write_bytes(encoded)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report['counts']))


if __name__ == '__main__':
    main()
