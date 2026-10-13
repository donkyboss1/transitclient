"""Build a source release for owner publication; performs no network operations."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile


PUBLIC_DOCS = {'implementation.md', 'integration.md', 'operations.md', 'publication.md'}
PRIVATE_IGNORE = 'AGENTS.md\n**/AGENTS.md\ndocs/*spec*.md\ndocs/*requirements*.md\ndocs/terminal-interface.md\n'


def build(destination, root=None):
    root = Path(root).resolve() if root is not None else Path(__file__).resolve().parent
    sources = ['selfsteal.sh', 'VERSION', 'dependencies.json', 'templates.json', 'README.md', 'LICENSE', 'NOTICE.md']
    # Runtime helpers must travel with the controller. Do not enumerate the
    # whole workspace: config, archives, Python caches and secrets are excluded.
    sources.extend(path.name for path in root.glob('*.py'))
    for directory in ('vendor', 'site', 'tests', 'docs'):
        sources.extend(str(path.relative_to(root)).replace('\\', '/')
                       for path in (root / directory).rglob('*')
                       if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'
                       and path.name.casefold() != 'agents.md'
                       and (directory != 'docs' or path.relative_to(root / 'docs').as_posix() in PUBLIC_DOCS))
    destination = destination.resolve()
    if destination == root or root in destination.parents:
        raise ValueError('Store the release outside the source package directory.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for relative in sorted(set(sources)):
                path = root / relative
                if any(parent.is_symlink() for parent in (path, *path.parents)
                       if parent.is_relative_to(root)) or not path.is_file():
                    raise ValueError('Missing or linked source: ' + relative)
                content = path.read_bytes()
                entry = tarfile.TarInfo(relative)
                entry.size, entry.mode = len(content), 0o755 if relative == 'selfsteal.sh' else 0o644
                archive.addfile(entry, io.BytesIO(content))
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_name(destination.name + '.sha256').write_text(digest + '  ' + destination.name + '\n', encoding='ascii')
    print(digest + '  ' + str(destination))
    return digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path, help='Output .tar.gz outside this package')
    build(parser.parse_args().destination)
