"""Existing-install entry point and explicit cleanup of owned local data."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import time
import uuid


def choose_existing(app, args):
    import terminal_ui
    if any((app.STATE / name).exists() for name in (
            'configuration-transaction.json', 'certificate-transaction.json',
            'update-transaction.json', 'operation.json', 'uninstall.json', 'ufw-activation.json')):
        raise app.Failure('Сначала восстановите незавершённую операцию: transitclient _recover.',
                          'RECOVERY_REQUIRED')
    config = app.validate_config(app.read_json(app.CONFIG))
    terminal = terminal_ui.Terminal(no_color=getattr(args, 'no_color', False))
    terminal.line('📦 Найдена установка Transit Client', 'bold')
    terminal.line('Домен: ' + config['domain'], 'domain')
    status = app.certificate_status(config)
    label = {'missing': 'отсутствует', 'invalid': 'не удалось прочитать',
             'expired': 'истёк', 'present': 'сохранён на диске'}.get(status['state'], 'неизвестно')
    if status['state'] == 'present':
        label += ', осталось дней: ' + str(status['days_remaining'])
    terminal.line('Сертификат: ' + label)
    managing = getattr(args, '_menu_mode', False)
    for number, label in [('1', 'Продолжить текущую установку' if managing else 'Открыть меню управления'),
                          ('2', 'Настроить новый домен из бота'), ('0', 'Выход')]:
        terminal.fragments(terminal_ui.option(number, label))
    while True:
        choice = app.ask('Выберите действие', '0')
        if choice in ('0', '1', '2'):
            return choice
        terminal.line('Выберите 1, 2 или 0.', 'warning')


def safe_tree(app, root, private=True):
    """Never follow directory links during backup or recursive deletion."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise app.Failure('Принадлежность каталога данных не подтверждена.', 'BACKUP_UNTRUSTED')
    for item in (root, *root.rglob('*')):
        if item.is_symlink():
            if item != root / 'certs/current' or not re.fullmatch(r'[0-9a-f]{32}', os.readlink(item)):
                raise app.Failure('В данных обнаружена неподтверждённая ссылка.', 'BACKUP_UNTRUSTED')
            continue
        if (not private and item == root / 'caddy-config/transitclient-admin.sock'
                and stat.S_ISSOCK(item.lstat().st_mode)):
            continue
        if not item.is_file() and not item.is_dir():
            raise app.Failure('В данных обнаружен специальный файл.', 'BACKUP_UNTRUSTED')
        if os.name == 'posix' and (item.stat().st_uid != 0 or (private and item.stat().st_mode & 0o077)):
            raise app.Failure('Данные должны быть доступны только root.', 'BACKUP_UNTRUSTED')


def backup_installation(app, config):
    safe_tree(app, app.STATE, private=False)
    backup = app.STATE.with_name('tenant-selfsteal-backup-' + time.strftime('%Y%m%d%H%M%S') + '-' + uuid.uuid4().hex)
    # The live Caddy admin socket is recreated by Caddy and cannot be copied.
    shutil.copytree(app.STATE, backup, symlinks=True,
                    ignore=lambda folder, names: ['transitclient-admin.sock']
                    if Path(folder) == app.STATE / 'caddy-config' else [])
    shutil.copy2(app.CONFIG, backup / 'config-backup.json')
    for item in (backup, *backup.rglob('*')):
        if not item.is_symlink():
            item.chmod(0o700 if item.is_dir() else 0o600)
    app.atomic_json(backup / 'backup-manifest.json', dict(kind='transitclient-backup', schema=1,
                    install_id=config['install_id'], domain=config['domain'],
                    config_sha256=hashlib.sha256((backup / 'config-backup.json').read_bytes()).hexdigest()))
    print('Прежняя установка сохранена в закрытую резервную копию: ' + str(backup))
    return backup


def certificate_domains(app, chain):
    decoded = ssl._ssl._test_decode_cert(str(chain))
    names = [value for kind, value in decoded.get('subjectAltName', ()) if kind == 'DNS']
    if not names:
        names = [value for row in decoded.get('subject', ()) for kind, value in row if kind == 'commonName']
    return frozenset(app.domain_value(name) for name in names)


def old_certificates(app, config):
    groups = {}
    root = app.STATE / 'certs'
    if root.is_symlink():
        raise app.Failure('Хранилище сертификатов содержит ссылку.', 'BACKUP_UNTRUSTED')
    current = root / 'current'
    if current.is_symlink() and not re.fullmatch(r'[0-9a-f]{32}', os.readlink(current)):
        raise app.Failure('Путь текущего сертификата не подтверждён.', 'BACKUP_UNTRUSTED')
    active = current.resolve() if current.exists() else None
    for path in root.iterdir() if root.is_dir() else ():
        if not re.fullmatch(r'[0-9a-f]{32}', path.name) or path.is_symlink() or path == active:
            continue
        try:
            safe_tree(app, path)
            names = certificate_domains(app, path / 'fullchain.pem')
        except (OSError, ValueError, app.Failure):
            continue
        # Multi-domain certificates are preserved rather than partially deleted.
        if len(names) == 1 and config['domain'] not in names:
            groups.setdefault(next(iter(names)), []).append(path)
    acme = app.STATE / 'acme'
    if acme.is_symlink():
        raise app.Failure('Хранилище ACME содержит ссылку.', 'BACKUP_UNTRUSTED')
    for path in acme.glob('*_ecc') if acme.is_dir() else ():
        try:
            domain = app.domain_value(path.name[:-4])
            safe_tree(app, path)
            names = certificate_domains(app, path / 'fullchain.cer')
        except (OSError, ValueError, app.Failure):
            continue
        if names == {domain} and domain != config['domain']:
            groups.setdefault(domain, [])
    return groups


def verified_backup(app, path):
    path = Path(path)
    if (path.parent.resolve() != app.STATE.parent.resolve() or path.is_symlink()
            or not re.fullmatch(r'tenant-selfsteal-backup-[0-9]{14}-[0-9a-f]{32}', path.name)):
        raise app.Failure('Путь резервной копии не подтверждён.', 'BACKUP_UNTRUSTED')
    safe_tree(app, path)
    manifest = app.read_json(path / 'backup-manifest.json')
    config = app.validate_config(app.read_json(path / 'config-backup.json'))
    if (manifest.get('kind') != 'transitclient-backup' or manifest.get('schema') != 1
            or not re.fullmatch(r'[0-9a-f]{32}', config.get('install_id', ''))
            or manifest.get('install_id') != config['install_id'] or manifest.get('domain') != config['domain']
            or manifest.get('config_sha256') != hashlib.sha256((path / 'config-backup.json').read_bytes()).hexdigest()):
        raise app.Failure('Принадлежность резервной копии не подтверждена.', 'BACKUP_UNTRUSTED')
    return config


def previous_package(app, path, config):
    path = Path(path)
    match = re.fullmatch(r'tenant-selfsteal\.previous-([0-9a-f]{32})', path.name)
    if (not match or path.is_symlink() or path.parent.resolve() != app.INSTALL.parent.resolve()
            or path.resolve() == app.INSTALL.resolve()):
        raise app.Failure('Путь прежней версии не подтверждён.', 'BACKUP_UNTRUSTED')
    safe_tree(app, path, private=False)
    root_files = {'selfsteal.sh', 'VERSION', 'dependencies.json', 'templates.json', 'README.md',
                  'LICENSE', 'NOTICE.md', '.transitclient-package.json'}
    root_dirs = {'vendor', 'site', 'docs', 'tests', '__pycache__'}
    if any((item.is_dir() and item.name not in root_dirs)
           or (item.is_file() and item.name not in root_files and item.suffix != '.py')
           for item in path.iterdir()):
        raise app.Failure('В прежней версии есть неизвестные файлы.', 'BACKUP_UNTRUSTED')
    marker = app.read_json(path / '.transitclient-package.json')
    if (not re.fullmatch(r'[0-9a-f]{32}', marker.get('install_id', ''))
            or marker.get('version') != (path / 'VERSION').read_text().strip()
            or marker.get('controller_sha256') != hashlib.sha256((path / 'selfsteal.py').read_bytes()).hexdigest()):
        raise app.Failure('Принадлежность прежней версии не подтверждена.', 'BACKUP_UNTRUSTED')
    snapshot = app.STATE / ('update-backup-' + match[1])
    if snapshot.is_symlink():
        raise app.Failure('Путь служебной копии не подтверждён.', 'BACKUP_UNTRUSTED')
    if snapshot.exists():
        safe_tree(app, snapshot, private=False)
        allowed = {'Caddyfile', 'compose.yaml', 'docker-compose', 'recover.py', 'diagnostics.py',
                   'site_templates.py', 'firewall_setup.py', 'recovery-current.json', 'schedule-pending.json',
                   'units.json', 'config.json'}
        if (any(not item.is_file() or item.name not in allowed for item in snapshot.iterdir())
                or app.read_json(snapshot / 'config.json').get('install_id')
                not in (config['install_id'], marker['install_id'])):
            raise app.Failure('Состав служебной копии не подтверждён.', 'BACKUP_UNTRUSTED')
    return marker, snapshot


def cleanup_previous_packages(app, config):
    """Discard only proven runtime backups after successful TLS and transaction commit."""
    try:
        if (not app.CONFIG.exists() or app.read_json(app.CONFIG) != config or not app.package_owned()
                or app.read_json(app.INSTALL / '.transitclient-package.json').get('install_id') != config.get('install_id')
                or not (app.STATE / 'lifecycle.json').exists()
                or app.read_json(app.STATE / 'lifecycle.json').get('stage') != 'ready'
                or any((app.STATE / name).exists() for name in (
                    'operation.json', 'configuration-transaction.json', 'certificate-transaction.json',
                    'update-transaction.json', 'uninstall.json', 'ufw-activation.json'))):
            return
        removed = skipped = 0
        for path in sorted(app.INSTALL.parent.glob('tenant-selfsteal.previous-*')):
            try:
                marker, snapshot = previous_package(app, path, config)
                # Keep recovery generations and installation/certificate backups intact.
                if snapshot.exists():
                    if snapshot.resolve().parent != app.STATE.resolve():
                        raise app.Failure('Путь служебной копии изменился.', 'BACKUP_UNTRUSTED')
                    shutil.rmtree(snapshot)
                if previous_package(app, path, config)[0] != marker:
                    raise app.Failure('Прежняя версия изменилась.', 'BACKUP_UNTRUSTED')
                shutil.rmtree(path)
                removed += 1
            except (OSError, ValueError, KeyError, TypeError, app.Failure):
                skipped += 1
        if removed:
            print('Удалены временные резервные файлы прежних версий Transit Client.')
        if skipped:
            print('⚠️ Неподтверждённые резервные файлы программы сохранены для ручной проверки.')
    except (OSError, ValueError, KeyError, TypeError, app.Failure):
        print('⚠️ Очистка прежних версий не завершена. Рабочая установка сохранена.')


def cleanup_old_data(app, config):
    """Called interactively only after the new domain's served TLS was verified."""
    if app.read_json(app.CONFIG) != config:
        raise app.Failure('Настройки изменились; очистка отменена.', 'OWNERSHIP_UNKNOWN')
    groups = old_certificates(app, config)
    for domain, paths in sorted(groups.items()):
        print(f'Прежний домен: {domain}; сохранённых версий сертификата: {max(1, len(paths))}.')
        if not app.confirm('Удалить сертификаты и ключи этого домена из рабочей установки?'):
            continue
        # Rebuild the allowlist after confirmation; current and transaction data stay protected.
        if any((app.STATE / name).exists() for name in ('certificate-transaction.json', 'configuration-transaction.json', 'operation.json')):
            raise app.Failure('Есть незавершённая операция; очистка отменена.', 'RECOVERY_REQUIRED')
        allowed = old_certificates(app, config).get(domain, [])
        if set(allowed) != set(paths):
            raise app.Failure('Список сертификатов изменился; очистка отменена.', 'OWNERSHIP_UNKNOWN')
        acme = app.STATE / 'acme'
        domain_dir = acme / (domain + '_ecc')
        if acme.is_symlink() or domain_dir.is_symlink():
            raise app.Failure('Путь ACME не подтверждён; очистка отменена.', 'BACKUP_UNTRUSTED')
        if domain_dir.exists():
            safe_tree(app, domain_dir)
            if certificate_domains(app, domain_dir / 'fullchain.cer') != {domain}:
                raise app.Failure('Сертификат ACME не соответствует домену.', 'BACKUP_UNTRUSTED')
        for path in paths:
            # Every target is a verified immediate child of our certificate store.
            if path.resolve().parent != (app.STATE / 'certs').resolve():
                raise app.Failure('Путь сертификата изменился.', 'BACKUP_UNTRUSTED')
            shutil.rmtree(path)
        if domain_dir.exists():
            shutil.rmtree(domain_dir)
        print('Сертификаты и ключи домена удалены из рабочей установки. Общий ACME-аккаунт сохранён.')
    for path in sorted(app.STATE.parent.glob('tenant-selfsteal-backup-*')):
        try:
            saved = verified_backup(app, path)
        except (OSError, ValueError, KeyError, TypeError, app.Failure):
            print('Копия без подтверждённой принадлежности пропущена: ' + path.name)
            continue
        if saved['domain'] == config['domain']:
            continue
        print('Резервная копия: ' + path.name + '; домен: ' + saved['domain'])
        print('Копия содержит настройки, сертификаты, ключи, ACME-данные и сайт; удаляется целиком.')
        if app.confirm('Безвозвратно удалить эту резервную копию установки?'):
            if verified_backup(app, path) != saved:
                raise app.Failure('Резервная копия изменилась; очистка отменена.', 'BACKUP_UNTRUSTED')
            shutil.rmtree(path)
            print('Резервная копия удалена: ' + path.name)
        else:
            print('Резервная копия сохранена; сертификаты и ключи остаются внутри неё.')
