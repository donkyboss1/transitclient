"""Prepare the standalone public repository locally; never commits or uploads."""
import argparse
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

from build_release import PRIVATE_IGNORE, build


REPOSITORY = 'donkyboss1/transitclient'


def prepare(destination):
    root = Path(__file__).resolve().parent
    destination = Path(destination).resolve()
    if destination != root and (root in destination.parents or destination in root.parents):
        raise ValueError('Publication directory must be separate from the source package.')
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?', version):
        raise ValueError('Invalid package version.')
    script = (root / 'selfsteal.sh').read_text(encoding='utf-8')
    for assignment in ("RELEASE_URL=''", "RELEASE_VERSION=''", "RELEASE_SHA256=''", 'bootstrap=false'):
        if script.count(assignment) != 1:
            raise ValueError('Unexpected bootstrap template: ' + assignment)
    destination.mkdir(parents=True, exist_ok=True)
    bundle = destination / 'dist' / f'transitclient-{version}.tar.gz'
    if destination.is_symlink() or bundle.parent.is_symlink() or bundle.is_symlink():
        raise ValueError('Publication paths must not be symlinks.')
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='transitclient-release-') as temporary:
        candidate = Path(temporary) / bundle.name
        digest = build(candidate, root=root)
        shutil.copyfile(candidate, bundle)
        shutil.copyfile(candidate.with_name(candidate.name + '.sha256'), bundle.with_name(bundle.name + '.sha256'))
    # The public bootstrap is outside the bundle: its embedded hash cannot
    # become a circular dependency on its own bytes.
    url = f'https://raw.githubusercontent.com/{REPOSITORY}/main/dist/{bundle.name}'
    script = (script.replace("RELEASE_URL=''", f"RELEASE_URL='{url}'")
              .replace("RELEASE_VERSION=''", f"RELEASE_VERSION='{version}'")
              .replace("RELEASE_SHA256=''", f"RELEASE_SHA256='{digest}'")
              .replace('bootstrap=false', 'bootstrap=true', 1)
              .replace('Без команды открывается меню. Публичный адрес пока не назначен.',
                       'Без команды открывается меню. Репозиторий: https://github.com/' + REPOSITORY))
    # Export only the builder's allowlisted package, never the private checkout.
    with tarfile.open(bundle) as archive:
        for member in archive.getmembers():
            if destination == root:
                continue
            relative = Path(member.name)
            if not member.isfile() or relative.is_absolute() or '..' in relative.parts:
                raise ValueError('Unexpected generated archive member.')
            target = destination / relative
            if any(path.is_symlink() for path in (target, *target.parents)
                   if path == destination or destination in path.parents):
                raise ValueError('Publication target must not be a symlink.')
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream:
                target.write_bytes(stream.read())
    for name, contents in {
        'install.sh': script,
        '.gitattributes': '* text=auto eol=lf\n*.tar.gz -text\n',
        '.gitignore': '__pycache__/\n*.py[cod]\n.pytest_cache/\n.ruff_cache/\n.venv/\n.cache/\n.tools/\n.test-tmp*/\n.env\n*.log\n' + PRIVATE_IGNORE,
    }.items():
        target = destination / name
        if target.is_symlink():
            raise ValueError('Publication target must not be a symlink.')
        target.write_text(contents, encoding='utf-8', newline='\n')
    print('Prepared public repository: ' + str(destination))
    return bundle, digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path, nargs='?', default=Path(__file__).resolve().parent,
                        help='Public checkout directory; defaults to this repository')
    prepare(parser.parse_args().destination)
