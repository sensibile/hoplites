#!/usr/bin/env python3
"""Extend a verified normalization bundle with runtime enrichment evidence."""
import argparse
import json
import shutil
from pathlib import Path
from enrich_runtime_bom import enrich, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base-bundle', 'sources', 'rootfs', 'normalized', 'evidence', 'output-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    if args.output_dir.exists():
        p.error('Use a new output directory')
    if any(args.output_dir.resolve().is_relative_to(path.resolve())
           for path in (args.base_bundle, args.sources)):
        p.error('Output directory must be outside input bundle/source directories')
    base = args.base_bundle.resolve()
    manifest = json.loads((base / 'manifest.json').read_text())
    for item in manifest['files']:
        path = (base / item['path']).resolve()
        if not path.is_relative_to(base) or sha(path.read_bytes()) != item['sha256']:
            raise ValueError('Base bundle file/hash mismatch')
    original = (base / 'normalized.cdx.json').read_bytes()
    normalized = args.normalized.read_bytes()
    evidence = json.loads(args.evidence.read_bytes())
    if evidence['input_sha256'] != sha(original) or evidence['output_sha256'] != sha(normalized):
        raise ValueError('Runtime input/output hash mismatch')
    if evidence['rootfs_sha256'] != sha(args.rootfs.read_bytes()):
        raise ValueError('Rootfs hash mismatch')
    regenerated, report = enrich(json.loads(original), args.rootfs, args.sources)
    if regenerated != json.loads(normalized) or any(evidence.get(k) != v for k, v in report.items()):
        raise ValueError('Runtime enrichment replay/evidence mismatch')
    shutil.copytree(base, args.output_dir / 'normalization')
    shutil.copytree(args.sources, args.output_dir / 'runtime-sources')
    shutil.copyfile(args.normalized, args.output_dir / 'normalized-runtime.cdx.json')
    shutil.copyfile(args.evidence, args.output_dir / 'runtime-evidence.json')
    for script in ('enrich_runtime_bom.py', 'normalize_syft_bom.py', 'build_runtime_evidence_bundle.py'):
        path = args.output_dir / 'scripts' / script
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(Path(__file__).with_name(script).read_bytes())
    (args.output_dir / 'README.txt').write_text(
        'Runtime enrichment evidence: upstream project license inference and verified file consolidation.\n'
        'Original normalization evidence is retained in normalization/. No files were removed from the image.\n'
        'Bundled third-party applicability and license fulfillment remain unverified.\n'
        'License texts, Elixir NOTICE, pinned commits, image history and per-file evidence are included.\n'
        'Rootfs is retained separately; hashes provide integrity checks, not signatures.\n')
    files = [{'path': str(path.relative_to(args.output_dir)), 'sha256': sha(path.read_bytes())}
             for path in sorted(args.output_dir.rglob('*')) if path.is_file()]
    (args.output_dir / 'manifest.json').write_text(json.dumps({
        'rule_version': evidence['rule_version'], 'verification': 'Base hashes and runtime replay passed',
        'rootfs_sha256': evidence['rootfs_sha256'], 'files': files}, indent=2) + '\n')
    print('Runtime bundle created; replay and ' + str(len(files)) + ' file hashes verified')


if __name__ == '__main__':
    main()
