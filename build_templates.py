"""Freeze the catalog from clean, pinned Git objects; never executes site code."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


COMMIT = '24134e23a438217cd52373ecdb0fcf7983e0e72c'
THEMES = [('10gag', '😂 10gag — мемы'), ('convertit', '📁 Convertit — конвертер файлов'),
          ('converter', '🎬 Converter — видеоконвертер'), ('downloader', '⬇️ Downloader'),
          ('filecloud', '☁️ FileCloud'), ('games-site', '🎮 Игровой портал'),
          ('modmanager', '🛠️ ModManager'), ('speedtest', '🚀 SpeedTest'),
          ('YouTube', '📺 YouTube'), ('503-1', '⚠️ Страница 503 — вариант 1'),
          ('503-2', '⚠️ Страница 503 — вариант 2')]


def freeze(source):
    source = Path(source).resolve()
    root = Path(__file__).resolve().parent
    prefix = ['git', '-c', 'safe.directory=' + source.as_posix(), '-C', str(source)]

    def git(*arguments):
        return subprocess.run([*prefix, *arguments], capture_output=True, check=True).stdout

    themes = []
    for number, (folder, name) in enumerate(THEMES, 1):
        files = []
        for row in git('ls-tree', '-rz', COMMIT, 'sni-templates/' + folder).split(b'\0'):
            if not row:
                continue
            attributes, encoded = row.split(b'\t', 1)
            path = encoded.decode('utf-8')
            mode, kind, blob = attributes.decode().split()
            if mode not in ('100644', '100755') or kind != 'blob':
                raise ValueError('Non-regular template file: ' + path)
            relative = path.removeprefix('sni-templates/' + folder + '/')
            if relative.endswith(('.md', '.map')) or any(part.startswith('.') for part in relative.split('/')):
                continue
            content = git('cat-file', 'blob', blob)
            files.append({'path': relative, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        themes.append({'id': str(number), 'folder': folder, 'name': name, 'files': files})
    catalog = {'source': {'repository': 'DigneZzZ/remnawave-scripts', 'commit': COMMIT}, 'templates': themes}
    (root / 'templates.json').write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (root / 'vendor/templates-README.md').write_bytes(git('show', COMMIT + ':sni-templates/README-templates.md'))
    print('Frozen 11 templates from ' + COMMIT)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Upstream Git checkout')
    freeze(parser.parse_args().source)
