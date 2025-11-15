#!/usr/bin/env python3
"""RAPTOR SCA Agent (safe)
- Inspects common dependency files (pom.xml, build.gradle, package.json, requirements.txt)
- Produces out/sca.json with discovered dependency files and a simple parse (list of deps)
- Non-network: does not contact package registries
"""
import argparse, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
import xml.etree.ElementTree as ET


def get_out_dir() -> Path:
    base = os.environ.get("RAPTOR_OUT_DIR")
    return Path(base).resolve() if base else Path("out").resolve()

def find_dependency_files(root: Path):
    candidates = []
    for pat in ['pom.xml','build.gradle','package.json','requirements.txt','pyproject.toml']:
        for p in root.rglob(pat):
            candidates.append(p)
    return candidates

def parse_pom(p):
    try:
        tree = ET.parse(p)
        root = tree.getroot()
        ns = {'m':'http://maven.apache.org/POM/4.0.0'}
        deps = []
        for d in root.findall('.//m:dependency', ns):
            g = d.find('m:groupId', ns)
            a = d.find('m:artifactId', ns)
            v = d.find('m:version', ns)
            deps.append({'group': g.text if g is not None else None, 'artifact': a.text if a is not None else None, 'version': v.text if v is not None else None})
        return deps
    except Exception as e:
        return {'error': str(e)}

def parse_requirements(p):
    deps = []
    for ln in p.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('#'): continue
        deps.append(ln)
    return deps

def parse_package_json(p):
    try:
        obj = json.loads(p.read_text())
        deps = obj.get('dependencies', {})
        return [{'name':k,'version':v} for k,v in deps.items()]
    except Exception as e:
        return {'error': str(e)}

def main():
    ap = argparse.ArgumentParser(description='RAPTOR SCA Agent')
    ap.add_argument('--repo', required=True)
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    if not repo.exists(): 
        raise SystemExit('repo not found')

    out = {'files':[], 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    for p in find_dependency_files(repo):
        entry = {'path': str(p)}
        if p.name == 'pom.xml':
            entry['deps'] = parse_pom(p)
        elif p.name == 'requirements.txt':
            entry['deps'] = parse_requirements(p)
        elif p.name == 'package.json':
            entry['deps'] = parse_package_json(p)
        else:
            entry['note'] = 'unsupported parser'
        out['files'].append(entry)

    out_dir = get_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'sca.json').write_text(json.dumps(out, indent=2))
    print(json.dumps({'status':'ok','files_found': len(out['files'])}))


if __name__ == '__main__':
    main()
