"""Pinned static site downloads and recoverable switches of the owned site only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import uuid


class TemplateError(ValueError):
    pass


def catalog(package):
    data = json.loads((Path(package) / 'templates.json').read_text(encoding='utf-8'))
    source = data['source']
    if source['repository'] != 'DigneZzZ/remnawave-scripts' or not re.fullmatch(r'[a-f0-9]{40}', source['commit']):
        raise TemplateError('Неверный источник каталога.')
    if len(data['templates']) != 11:
        raise TemplateError('Неполный каталог сайтов.')
    seen = set()
    for theme in data['templates']:
        identifier, folder = theme['id'], theme['folder']
        if identifier in seen or identifier not in [str(i) for i in range(1, 12)] or not re.fullmatch(r'[a-zA-Z0-9-]+', folder):
            raise TemplateError('Неверный идентификатор сайта.')
        seen.add(identifier)
        paths, total = set(), 0
        for entry in theme['files']:
            name = entry['path']
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or any(part in ('', '.', '..') or part.startswith('.') for part in name.split('/'))
                    or '\\' in name or ':' in name or any(ord(c) < 32 for c in name) or name in paths
                    or not re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])
                    or not isinstance(entry['size'], int) or not 0 < entry['size'] <= 4 * 1024 * 1024):
                raise TemplateError('Небезопасный файл каталога.')
            paths.add(name)
            total += entry['size']
        if 'index.html' not in paths or len(paths) > 256 or total > 16 * 1024 * 1024:
            raise TemplateError('Неполный или слишком большой сайт.')
    return data


def safe_tree(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise TemplateError('Каталог сайта отсутствует или является ссылкой.')
    for entry in path.rglob('*'):
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
            raise TemplateError('В сайте обнаружена ссылка или специальный файл.')


def ensure_site(state, package):
    site = Path(state) / 'site'
    site.mkdir(exist_ok=True)
    safe_tree(site)
    current = site / 'current'
    if current.exists():
        safe_tree(current)
        return
    # Preserve a pre-existing flat site when upgrading from 1.1; it is not
    # replaced by the bundled fallback. The parent Docker mount stays stable.
    legacy = [entry for entry in site.iterdir() if entry.name not in ('current', 'backups', 'staged')]
    current.mkdir(mode=0o755)
    if (site / 'index.html').is_file():
        for entry in legacy:
            target = current / entry.name
            if entry.is_dir():
                shutil.copytree(entry, target)
            else:
                shutil.copyfile(entry, target)
    else:
        shutil.copyfile(Path(package) / 'site/index.html', current / 'index.html')


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value):
        raise TemplateError('Неверный журнал смены сайта.')
    return value


def recover(state):
    state = Path(state)
    journal = state / 'site-transaction.json'
    if not journal.exists():
        return
    transaction = json.loads(journal.read_text())
    operation = identifier(transaction['id'])
    site = state / 'site'
    safe_tree(site)
    current, backup, staged = site / 'current', site / 'backups' / operation, site / 'staged' / identifier(transaction['staged'])
    if backup.exists():
        safe_tree(backup)
        if current.exists():
            safe_tree(current)
            shutil.rmtree(current)
        os.replace(backup, current)
    if staged.exists():
        safe_tree(staged)
        shutil.rmtree(staged)
    if not current.is_dir():
        raise TemplateError('Сайт не восстановлен; журнал сохранён.')
    metadata = state / 'site-template.json'
    if transaction.get('old_metadata') is None:
        metadata.unlink(missing_ok=True)
    else:
        metadata.write_text(json.dumps(transaction['old_metadata'], ensure_ascii=False), encoding='utf-8')
    journal.unlink()


def switch(state, staged, metadata, atomic_json, verify):
    state = Path(state)
    site = state / 'site'
    safe_tree(site)
    safe_tree(staged)
    if not (staged / 'index.html').is_file():
        raise TemplateError('В сайте нет index.html.')
    current = site / 'current'
    safe_tree(current)
    operation = uuid.uuid4().hex
    backup = site / 'backups' / operation
    backup.parent.mkdir(exist_ok=True)
    previous = state / 'site-template.json'
    old = json.loads(previous.read_text()) if previous.exists() else None
    atomic_json(state / 'site-transaction.json', {'id': operation, 'staged': identifier(staged.name), 'old_metadata': old})
    try:
        os.replace(current, backup)
        os.replace(staged, current)
        for path in current.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        current.chmod(0o755)
        verify(current / 'index.html')
        atomic_json(previous, dict(metadata, previous=operation))
        (state / 'site-transaction.json').unlink()
    except BaseException:
        recover(state)
        raise


def apply(state, package, selected, fetch, atomic_json, verify):
    state = Path(state)
    ensure_site(state, package)
    recover(state)
    operation = uuid.uuid4().hex
    staged = state / 'site/staged' / operation
    staged.mkdir(parents=True, mode=0o755)
    try:
        if selected == 'builtin':
            shutil.copyfile(Path(package) / 'site/index.html', staged / 'index.html')
            metadata = {'id': 'builtin', 'name': 'Сайт готов'}
        elif selected == 'rollback':
            previous = json.loads((state / 'site-template.json').read_text())['previous']
            backup = state / 'site/backups' / identifier(previous)
            safe_tree(backup)
            shutil.copytree(backup, staged, dirs_exist_ok=True)
            metadata = {'id': 'restored', 'name': 'Прежний сайт'}
        else:
            data = catalog(package)
            theme = next((theme for theme in data['templates'] if theme['id'] == selected), None)
            if theme is None:
                raise TemplateError('Неизвестный сайт.')
            base = ('https://raw.githubusercontent.com/' + data['source']['repository'] + '/'
                    + data['source']['commit'] + '/sni-templates/' + theme['folder'] + '/')
            for entry in theme['files']:
                target = staged / entry['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                fetch(base + entry['path'], entry['sha256'], target)
                content = target.read_bytes()
                if len(content) != entry['size'] or hashlib.sha256(content).hexdigest() != entry['sha256']:
                    raise TemplateError('Файл сайта не прошёл проверку.')
            metadata = {'id': selected, 'name': theme['name'], 'commit': data['source']['commit']}
        switch(state, staged, metadata, atomic_json, verify)
    finally:
        if staged.exists():
            safe_tree(staged)
            shutil.rmtree(staged)
    return metadata
