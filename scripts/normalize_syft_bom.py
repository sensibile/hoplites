#!/usr/bin/env python3
"""Collapse verified package-owned files into packages; preserve a file evidence sidecar."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

RULE_VERSION = 'package-view-v1'


def normalize(bom, ownership, apk_installed=None):
    result = copy.deepcopy(bom)
    components = result.get('components', [])
    refs = [c.get('bom-ref') for c in components]
    if any(not ref for ref in refs) or len(set(refs)) != len(refs):
        raise ValueError('Missing or duplicate component bom-ref')
    packages = {c['bom-ref']: c for c in components if c.get('type') != 'file'}
    entries = {e['bom_ref']: e for e in ownership['files']}
    if len(entries) != len(ownership['files']):
        raise ValueError('Duplicate ownership evidence')
    mapping, removed = {}, []
    for component in components:
        evidence = entries.get(component['bom-ref'])
        if component.get('type') != 'file' or not evidence or evidence.get('status') != 'linked':
            continue
        owner = packages.get(evidence.get('owner_bom_ref'))
        if not owner:
            continue
        declared = evidence.get('owner', {})
        if evidence['path'] != component['name'] or declared.get('name') != owner.get('name') or declared.get('version') != owner.get('version'):
            raise ValueError('Ownership evidence does not match component/package')
        if any(v == 'existing-value-conflict' for v in evidence.get('field_assessments', {}).values()):
            continue
        mapping[component['bom-ref']] = owner['bom-ref']
        removed.append({'component': copy.deepcopy(component), 'ownership': copy.deepcopy(evidence)})
    virtual_removed = []
    if apk_installed is not None:
        # Require the same database used for file ownership verification.
        if hashlib.sha256(apk_installed).hexdigest() != ownership.get('apk_database_sha256'):
            raise ValueError('APK database does not match ownership evidence')
        records = {}
        for block in apk_installed.decode('utf-8').split('\n\n'):
            fields = {}
            for line in block.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    fields.setdefault(key, []).append(value)
            key = (fields.get('P', [None])[0], fields.get('V', [None])[0])
            records.setdefault(key, []).append(fields)
        incident = {ref for d in result.get('dependencies', [])
                    for ref in d.get('dependsOn', []) + d.get('provides', [])}
        for c in components:
            matches = records.get((c.get('name'), c.get('version')), [])
            if not c.get('purl', '').startswith('pkg:apk/') or len(matches) != 1:
                continue
            record = matches[0]
            if (record.get('T') != ['virtual meta package'] or record.get('S') != ['0']
                    or record.get('I') != ['0'] or any(k in record for k in ('F', 'R'))
                    or c['bom-ref'] in incident or c['bom-ref'] in mapping.values()):
                continue
            nodes = [d for d in result.get('dependencies', []) if d['ref'] == c['bom-ref']]
            if any(set(d) - {'ref', 'dependsOn'} for d in nodes):
                continue
            virtual_removed.append({'component': copy.deepcopy(c), 'reason': 'fileless-apk-virtual-package',
                                    'apk_record': record, 'source': '/lib/apk/db/installed',
                                    'dependency_records': copy.deepcopy(nodes),
                                    'source_sha256': hashlib.sha256(apk_installed).hexdigest()})
    excluded = set(mapping) | {x['component']['bom-ref'] for x in virtual_removed}
    result['components'] = [c for c in components if c['bom-ref'] not in excluded]
    # Transfer incident dependency edges to owning packages, merging repeated sources.
    merged = {}
    for dependency in result.get('dependencies', []):
        if dependency['ref'] in excluded and dependency['ref'] not in mapping:
            continue
        if set(dependency) - {'ref', 'dependsOn', 'provides'}:
            raise ValueError('Unsupported dependency fields; refusing lossy transformation')
        ref = mapping.get(dependency['ref'], dependency['ref'])
        node = merged.setdefault(ref, {'ref': ref})
        for field in ('dependsOn', 'provides'):
            if field in dependency:
                values = node.setdefault(field, [])
                for value in dependency[field]:
                    value = mapping.get(value, value)
                    if value != ref and value not in values:
                        values.append(value)
    if 'dependencies' in result:
        result['dependencies'] = list(merged.values())
    valid = {c['bom-ref'] for c in result['components']}
    root_ref = result.get('metadata', {}).get('component', {}).get('bom-ref')
    if root_ref:
        valid.add(root_ref)
    for dependency in result.get('dependencies', []):
        referenced = [dependency['ref']] + dependency.get('dependsOn', []) + dependency.get('provides', [])
        if any(ref not in valid for ref in referenced):
            raise ValueError('Dangling dependency reference')
    # Additional CycloneDX structures require an explicit remapping rule.
    remainder = {k: v for k, v in result.items() if k not in ('components', 'dependencies')}
    def check(value):
        if isinstance(value, dict):
            for item in value.values():
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)
        elif isinstance(value, str) and value in excluded:
            raise ValueError('Removed ref used outside dependencies; add a remapping rule')
    check(remainder)
    report = {'rule_version': RULE_VERSION, 'removed_count': len(removed),
              'remaining_count': len(result['components']), 'removed_files': removed,
              'retained_files': [c['bom-ref'] for c in result['components'] if c.get('type') == 'file']}
    if apk_installed is not None:
        report.update(rule_version='package-view-v2', removed_virtual_packages=virtual_removed,
                      apk_database_sha256=hashlib.sha256(apk_installed).hexdigest())
    return result, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sbom', 'ownership', 'output', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--apk-installed', type=Path, help='Verified APK database; enables virtual-package exclusion')
    args = parser.parse_args()
    paths = [getattr(args, n).resolve() for n in ('sbom', 'ownership', 'output', 'evidence')]
    if args.apk_installed:
        paths.append(args.apk_installed.resolve())
    if len(set(paths)) != len(paths):
        parser.error('Input and output paths must be distinct')
    raw = args.sbom.read_bytes()
    ownership_raw = args.ownership.read_bytes()
    ownership = json.loads(ownership_raw)
    if hashlib.sha256(raw).hexdigest() != ownership.get('input_sha256'):
        parser.error('Ownership report does not belong to input SBOM')
    result, report = normalize(json.loads(raw), ownership,
                               args.apk_installed.read_bytes() if args.apk_installed else None)
    output = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    report.update(input_sha256=hashlib.sha256(raw).hexdigest(),
                  ownership_sha256=hashlib.sha256(ownership_raw).hexdigest(),
                  output_sha256=hashlib.sha256(output).hexdigest())
    args.output.write_bytes(output)
    args.evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('removed_count', 'remaining_count', 'retained_files')}))


if __name__ == '__main__':
    main()
