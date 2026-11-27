#!/usr/bin/env python3
"""Check that the built distributions are exactly what the tagged commit builds.

usage: verify_dist.py <dist-dir> <commit> <version>

The release job builds from its checkout. This script then builds the same commit again from a clean
``git archive`` export (no untracked, ignored or modified files, no CI cache) and requires both builds to
produce byte-identical sdist and wheel. The build backend writes fixed timestamps, so a difference means the
checkout held something the commit does not. It also requires the version inside each file to match the tag.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def metadata_version(text: str) -> str:
    for line in text.splitlines():
        if line.startswith('Version: '):
            return line.removeprefix('Version: ').strip()
    return ''


def main(dist: Path, commit: str, version: str) -> int:
    problems: list[str] = []
    head = run('git', 'rev-parse', 'HEAD').strip()
    full = run('git', 'rev-parse', f'{commit}^{{commit}}').strip()
    if head != full:
        problems.append(f'checkout is at {head}, the tagged commit is {full}')
    if run('git', 'status', '--porcelain', '--ignored=no').strip():
        problems.append('the checkout has modified or untracked files')

    built = sorted(path for path in dist.iterdir() if path.is_file())
    sdists = [path for path in built if path.name.endswith('.tar.gz')]
    wheels = [path for path in built if path.name.endswith('.whl')]
    if len(sdists) != 1 or len(wheels) != 1 or len(built) != 2:
        problems.append(f'expected one sdist and one wheel in {dist}, found {[path.name for path in built]}')
    else:
        with tarfile.open(sdists[0]) as archive:
            member = next((m for m in archive.getmembers() if m.name.endswith('/PKG-INFO')), None)
            found = metadata_version(archive.extractfile(member).read().decode()) if member else ''
        if found != version:
            problems.append(f'sdist version is {found or "missing"}, the tag says {version}')
        with zipfile.ZipFile(wheels[0]) as archive:
            name = next((n for n in archive.namelist() if n.endswith('.dist-info/METADATA')), '')
            found = metadata_version(io.TextIOWrapper(io.BytesIO(archive.read(name))).read()) if name else ''
        if found != version:
            problems.append(f'wheel version is {found or "missing"}, the tag says {version}')

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'
            source.mkdir()
            export = subprocess.run(['git', 'archive', full], check=True, capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(export)) as archive:
                archive.extractall(source, filter='data')
            rebuilt = Path(tmp) / 'dist'
            run('uv', 'build', '--out-dir', str(rebuilt), cwd=source)
            for path in built:
                other = rebuilt / path.name
                if not other.is_file():
                    problems.append(f'{path.name} is not produced by a clean build of {full}')
                elif sha256(path) != sha256(other):
                    problems.append(f'{path.name} differs from a clean build of {full}: {sha256(path)} != {sha256(other)}')
            for path in sorted(rebuilt.iterdir()):
                if not (dist / path.name).is_file():
                    problems.append(f'a clean build also produces {path.name}, which is not in {dist}')

    for problem in problems:
        print(f'verify_dist: {problem}', file=sys.stderr)
    if not problems:
        for path in built:
            print(f'verify_dist: ok {path.name} {sha256(path)}')
    return 1 if problems else 0


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    raise SystemExit(main(Path(sys.argv[1]), sys.argv[2], sys.argv[3]))
