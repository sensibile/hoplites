#!/usr/bin/env python3
"""Separate verified system configuration/database files from software components."""
import argparse
import copy
import hashlib
import ipaddress
import json
import posixpath
import re
import tarfile
from pathlib import Path

RULE_VERSION = 'platform-metadata-v1'
TARGETS = {'/etc/hosts': 'host-address-configuration', '/etc/hostname': 'host-name-configuration',
           '/lib/apk/db/installed': 'package-inventory-database'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_layers(archive):
    targets = set(TARGETS) | {'/etc/os-release', '/usr/lib/os-release', '/etc/alpine-release'}
    found = {}
    symlinks = {}
    with tarfile.open(archive) as t:
        manifests = json.load(t.extractfile('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('Expected one image in Docker archive')
        manifest = manifests[0]
        config = t.extractfile(manifest['Config']).read()
        for layer in manifest['Layers']:
            # Addressed layer blobs must match their saved digest.
            raw = t.extractfile(layer).read()
            if layer.startswith('blobs/sha256/') and sha(raw) != layer.rsplit('/', 1)[1]:
                raise ValueError('Layer digest mismatch')
            import io
            with tarfile.open(fileobj=io.BytesIO(raw)) as lt:
                members = lt.getmembers()
                # Apply whiteouts before files, independent of tar member order.
                for m in members:
                    path = '/' + m.name.lstrip('./')
                    parent, name = path.rsplit('/', 1)
                    if name == '.wh..wh..opq':
                        found = {k: v for k, v in found.items() if not k.startswith(parent + '/')}
                        symlinks = {k: v for k, v in symlinks.items() if not k.startswith(parent + '/')}
                    elif name.startswith('.wh.'):
                        deleted = parent + '/' + name[4:]
                        found = {k: v for k, v in found.items() if k != deleted and not k.startswith(deleted + '/')}
                        symlinks = {k: v for k, v in symlinks.items() if k != deleted and not k.startswith(deleted + '/')}
                for m in members:
                    path = '/' + m.name.lstrip('./')
                    if path in targets:
                        if not m.isfile():
                            found.pop(path, None)
                            if m.issym():
                                symlinks[path] = posixpath.normpath(posixpath.join(posixpath.dirname(path), m.linkname))
                            continue
                        symlinks.pop(path, None)
                        payload = lt.extractfile(m).read()
                        found[path] = {'raw': payload, 'sha256': sha(payload), 'layer': layer}
    if symlinks.get('/etc/os-release') == '/usr/lib/os-release' and '/usr/lib/os-release' in found:
        found['/etc/os-release'] = found['/usr/lib/os-release']
    return found, sha(config)


def normalize(bom, found):
    result = copy.deepcopy(bom)
    removed = []
    for c in result['components']:
        if c.get('type') != 'file' or c.get('name') not in TARGETS:
            continue
        path = c['name']; source = found.get(path)
        hashes = [h['content'] for h in c.get('hashes', []) if h['alg'] == 'SHA-256']
        if not source or hashes != [sha(source['raw'])] or source['sha256'] != sha(source['raw']):
            raise ValueError('Original file does not match image layer: ' + path)
        text = source['raw'].decode('utf-8')
        if path == '/etc/hostname':
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*\n?', text):
                raise ValueError('Unexpected hostname content')
        elif path == '/etc/hosts':
            for line in text.splitlines():
                fields = line.split('#', 1)[0].split()
                if not fields: continue
                if len(fields) < 2: raise ValueError('Unexpected hosts content')
                ipaddress.ip_address(fields[0])
                if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) for name in fields[1:]):
                    raise ValueError('Unexpected hosts alias')
        else:
            records = [block for block in text.split('\n\n') if block.strip()]
            if not records or any(not re.search(r'^P:.+', b, re.M) or not re.search(r'^V:.+', b, re.M) for b in records):
                raise ValueError('Unexpected APK database content')
        removed.append({'component': copy.deepcopy(c), 'reason': TARGETS[path],
                        'source_sha256': source['sha256'], 'source_layer': source['layer'],
                        'source_content': text, 'assessment': 'verified-configuration-or-inventory-data'})
    excluded = {x['component']['bom-ref'] for x in removed}
    result['components'] = [c for c in result['components'] if c['bom-ref'] not in excluded]
    deps = []
    for d in result.get('dependencies', []):
        if d['ref'] in excluded and set(d) <= {'ref', 'dependsOn', 'provides'} and not d.get('dependsOn') and not d.get('provides'):
            continue
        deps.append(d)
    if 'dependencies' in result: result['dependencies'] = deps
    def check(value):
        if isinstance(value, dict):
            for v in value.values(): check(v)
        elif isinstance(value, list):
            for v in value: check(v)
        elif isinstance(value, str) and value in excluded:
            raise ValueError('Removed file still referenced; explicit remapping required')
    check(result)
    os_components = [c for c in result['components'] if c.get('type') == 'operating-system' and c.get('name') == 'alpine']
    if len(os_components) != 1: raise ValueError('Expected one Alpine OS component')
    os = os_components[0]
    release = found.get('/etc/alpine-release')
    os_release = found.get('/etc/os-release')
    if not release or not os_release or release['raw'].decode().strip() != os['version']:
        raise ValueError('Alpine version evidence mismatch')
    values = dict(line.split('=', 1) for line in os_release['raw'].decode().splitlines() if '=' in line)
    if values.get('ID', '').strip('"') != 'alpine' or values.get('VERSION_ID', '').strip('"') != os['version']:
        raise ValueError('OS identity mismatch')
    prefix = 'hoplites:os:'
    os['properties'] = [p for p in os.get('properties', []) if not p['name'].startswith(prefix)] + [
        {'name': prefix + 'license-assessment', 'value': 'distribution-aggregate; licenses-managed-per-component'},
        {'name': prefix + 'version-assessment', 'value': 'verified-image-release-files'},
        {'name': prefix + 'rule-version', 'value': RULE_VERSION}]
    report = {'rule_version': RULE_VERSION, 'removed_metadata_files': removed,
              'remaining_count': len(result['components']),
              'os': {'name': os['name'], 'version': os['version'], 'bom_ref': os['bom-ref'],
                     'license_assessment': 'Distribution aggregate, not one separately licensed code package',
                     'release_sha256': release['sha256'], 'os_release_sha256': os_release['sha256']}}
    return result, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sbom', 'image-archive', 'output', 'evidence'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    paths = [getattr(args, n).resolve() for n in ('sbom', 'image_archive', 'output', 'evidence')]
    if len(set(paths)) != len(paths) or args.output.exists() or args.evidence.exists():
        p.error('Use distinct inputs and new output paths')
    raw = args.sbom.read_bytes()
    found, config_sha = read_layers(args.image_archive)
    result, report = normalize(json.loads(raw), found)
    output = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    report.update(input_sha256=sha(raw), output_sha256=sha(output), image_config_sha256=config_sha,
                  image_archive_sha256=sha(args.image_archive.read_bytes()),
                  limitation='Local Docker image export; not an independent provenance attestation')
    args.output.write_bytes(output)
    args.evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'removed_metadata_files': len(report['removed_metadata_files']),
                      'remaining_count': report['remaining_count'], 'os': report['os']}))


if __name__ == '__main__': main()
