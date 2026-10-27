#!/usr/bin/env python3
"""Standalone tenant HTTP-01 lifecycle; Python 3.10+, no service API calls.

Adapted workflow from DigneZzZ Selfsteal 2.10.0 (MIT, gig.ovh).
System-owned files only: /opt/tenant-selfsteal, /etc/tenant-selfsteal,
/var/lib/tenant-selfsteal, /run/lock/tenant-selfsteal.lock and named units.
"""
import argparse
import base64
import contextlib
import errno
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import urllib.request
from urllib.parse import urlsplit
import uuid

PACKAGE = Path(__file__).resolve().parent
INSTALL = Path('/opt/tenant-selfsteal')
STATE = Path('/var/lib/tenant-selfsteal')
CONFIG = Path('/etc/tenant-selfsteal/config.json')
LOCK = Path('/run/lock/tenant-selfsteal.lock')
UNITS = Path('/etc/systemd/system')
PROJECT = 'tenant-selfsteal'
PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory'
STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
ACME_TIMEOUT = 900
LAUNCHER = Path('/usr/local/bin/transitclient')
ADMIN = 'unix//config/transitclient-admin.sock'
_menu_tls_check = {}
_operation_id = None


class Failure(Exception):
    def __init__(self, message, code='OPERATION_FAILED'):
        super().__init__(message)
        self.code = code


def diagnostic_module():
    path = Path(__file__).resolve().parent / 'diagnostics.py'
    spec = importlib.util.spec_from_file_location('transitclient_diagnostics', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def template_module():
    spec = importlib.util.spec_from_file_location('transitclient_templates', PACKAGE / 'site_templates.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def firewall_module():
    spec = importlib.util.spec_from_file_location('transitclient_firewall', PACKAGE / 'firewall_setup.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select_template(value=None, rollback=False):
    catalog = template_module().catalog(PACKAGE)
    if value is None:
        print('🎨 Сайты-заглушки')
        print('0 🏠 Встроенная страница · r 🎲 Случайный сайт' + (' · b ↩️ Прежний сайт' if rollback else ''))
        for theme in catalog['templates']:
            print(theme['id'] + ' ' + theme['name'])
    choice = value if value is not None else ask('Выберите сайт', 'r')
    if choice in ('r', 'random'):
        choice = secrets.choice(catalog['templates'])['id']
    if choice == '0':
        choice = 'builtin'
    if choice == 'b':
        choice = 'rollback'
    if choice not in ('builtin', 'rollback') and choice not in [theme['id'] for theme in catalog['templates']]:
        raise Failure('Неизвестный сайт. Выберите 0, r или номер 1–11.', 'TEMPLATE_INVALID')
    if choice == 'rollback' and not rollback:
        raise Failure('Во время первой установки откатывать нечего.', 'TEMPLATE_INVALID')
    return choice


def verify_site(config, index):
    trust = config.get('staging_ca_file') if config['ca'] == STAGING else None
    context = ssl.create_default_context(cafile=trust)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    with socket.create_connection(served_endpoint(config), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=config['domain']) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {config['domain']}\r\nConnection: close\r\n\r\n".encode('ascii'))
            response = http.client.HTTPResponse(tls)
            response.begin()
            expected = index.read_bytes()
            if response.status != 200 or response.read(len(expected) + 1) != expected:
                raise Failure('Caddy не выдаёт выбранный сайт; выполняется откат.', 'TEMPLATE_HTTP_FAILED')


def change_template(config, selected=None, *, approved=False):
    choice = selected or select_template(rollback=True)
    if not approved and not confirm('Скачать и применить сайт с сохранением прежнего?'):
        raise Failure('Сайт не изменён.', 'CANCELLED')
    try:
        module = template_module()
        metadata = module.apply(STATE, PACKAGE, choice, verified_download, atomic_json,
                                (lambda index: verify_site(config, index))
                                if (STATE / 'certs/current').exists() else lambda _: None)
    except (ValueError, KeyError, StopIteration) as exc:
        raise Failure('Не удалось изменить сайт; прежние файлы сохранены.', 'TEMPLATE_FAILED') from exc
    print('✅ Сайт: ' + metadata['name'] + '. Сертификат и порты не изменены.')


def confirm(prompt):
    # Propagate EOF/interrupt through the lifecycle's finally/rollback handlers.
    answer = input(prompt + ' [y/N]: ').strip().lower()
    return answer == 'y'


def run(args, *, check=True, timeout=60, input=None):
    """Never invoke a shell or echo subprocess output, which may contain ACME data."""
    environment = dict(os.environ, LC_ALL='C')
    result = subprocess.run([str(a) for a in args], input=input, capture_output=True,
                            timeout=timeout, env=environment)
    if check and result.returncode:
        raise Failure(f'Команда {Path(str(args[0])).name} завершилась с кодом '
                      f'{result.returncode}. Используйте diagnose/journalctl.')
    return result


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate = path.with_name(path.name + '.tmp')
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(candidate, path)
    os.chmod(path, 0o600)
    # Persist intent before firewall mutation / certificate symlink switch.
    if os.name == 'posix':
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def domain_value(value):
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in value.split('.')
    ):
        raise Failure('Введите выданный DNS-домен без URL, порта и wildcard.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Failure('Нужен DNS-домен, а не IP.')


def port_value(value):
    if not re.fullmatch(r'[0-9]{4,5}', str(value)):
        raise Failure('Порт должен быть целым числом от 1024 до 65535.')
    number = int(value)
    if not 1024 <= number <= 65535:
        raise Failure('Порт должен быть от 1024 до 65535.')
    return number


def validate_config(config):
    config['domain'] = domain_value(config['domain'])
    config['challenge_port'] = port_value(config['challenge_port'])
    config['local_port'] = port_value(config['local_port'])
    if config['challenge_port'] == config['local_port']:
        raise Failure('Проверочный и локальный HTTPS-порты должны различаться.')
    config.setdefault('schema_version', 2)
    config.setdefault('vpn_port', None)  # Legacy installations never recorded this value.
    if config['vpn_port'] is not None:
        if not re.fullmatch(r'[0-9]{1,5}', str(config['vpn_port'])) or not 1 <= int(config['vpn_port']) <= 65535:
            raise Failure('VPN-порт должен быть целым числом от 1 до 65535.', 'INVALID_VPN_PORT')
        config['vpn_port'] = int(config['vpn_port'])
        if config['vpn_port'] in (config['challenge_port'], config['local_port']):
            raise Failure('VPN, проверочный HTTP и локальный HTTPS требуют разных портов.', 'PORT_COLLISION')
    config.setdefault('docker_network', '')
    config.setdefault('vpn_container', '')
    for name in ('docker_network', 'vpn_container'):
        if config[name] and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', config[name]):
            raise Failure('Некорректное имя Docker-сети/контейнера.', 'INVALID_DOCKER_NAME')
    if config.get('install_id') and not re.fullmatch(r'[0-9a-f]{32}', config['install_id']):
        raise Failure('Некорректный идентификатор установки.', 'OWNERSHIP_UNKNOWN')
    if config.get('relay_ip'):
        ip = ipaddress.ip_address(config['relay_ip'])
        if not ip.is_global:
            raise Failure('Ожидаемый IP релея должен быть публичным.')
        config['relay_ip'] = str(ip)
    if config['firewall'] not in ('auto', 'ufw', 'preserve', 'manual'):
        raise Failure('Выберите auto, ufw или preserve (manual — прежнее имя preserve).')
    if config.get('firewall_effective') not in (None, 'ufw', 'preserve'):
        raise Failure('Неизвестная сохранённая политика firewall.')
    if config['ca'] not in (PRODUCTION, STAGING):
        raise Failure("CA должна быть production или staging Let's Encrypt.")
    if config['ca'] == STAGING and not config.get('staging_ca_file'):
        raise Failure('Staging требует явно предоставленный тестовый trust bundle.')
    return config


def free_port(port, address='0.0.0.0'):
    sockets = []
    try:
        # Standalone acme.sh 3.1.6 uses IPv4 and IPv6; check both bind spaces.
        spaces = [(socket.AF_INET, address)]
        if address == '0.0.0.0':
            spaces.append((socket.AF_INET6, '::'))
        for family, bind in spaces:
            if family == socket.AF_INET6 and not socket.has_ipv6:
                continue
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
            except OSError as exc:
                if family == socket.AF_INET6 and exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
                    continue
                raise
            sockets.append(sock)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind((bind, port))
            except OSError as exc:
                if family == socket.AF_INET6 and exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                    continue
                raise
        return True
    except OSError:
        return False
    finally:
        for sock in sockets:
            sock.close()


def check_challenge_port(config):
    diagnostics = diagnostic_module()
    report = diagnostics.collect({key: value for key, value in config.items() if key != 'domain'})
    published = [row for row in diagnostics.listeners_for_port(report['listeners'], config['challenge_port'])
                 if row['source'] == 'docker' and not row.get('owned')]
    if published:
        raise Failure('Проверочный HTTP-порт уже опубликован Docker. Измените порт в боте '
                      'и дождитесь готовности маршрута. Контейнеры не остановлены.', 'HTTP_PORT_BUSY')
    if free_port(config['challenge_port']):
        return
    candidate = next((p for p in range(8081, 8101)
                      if p != config['local_port'] and free_port(p)), None)
    hint = f' Например, свободен {candidate}.' if candidate else ''
    raise Failure(f"Проверочный порт {config['challenge_port']} занят.{hint} "
                  'Измените порт в боте, дождитесь готовности маршрута и введите '
                  'тот же порт при установке. Чужой процесс не остановлен.', 'HTTP_PORT_BUSY')


def check_dns(config):
    try:
        values = {str(ipaddress.ip_address(row[4][0])) for row in socket.getaddrinfo(
            config['domain'], None, socket.AF_UNSPEC, socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise Failure('DNS ещё не готов. Дождитесь готовности подготовки в боте.') from exc
    if not values or any(not ipaddress.ip_address(ip).is_global for ip in values):
        raise Failure('Все опубликованные A/AAAA должны вести на публичные IP релея.')
    if config.get('relay_ip') and values != {config['relay_ip']}:
        raise Failure('A/AAAA не совпадают с ожидаемым IP релея. Проверьте DNS в боте; '
                      'лишний/неверный AAAA тоже блокирует проверку.')
    return sorted(values)


def require_host():
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise Failure('Установка и обслуживание: sudo bash selfsteal.sh ... на Ubuntu.')
    release = dict(line.rstrip().split('=', 1) for line in
                   Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get(
        'VERSION_ID', '').strip('"') not in ('22.04', '24.04', '26.04'):
        raise Failure('Матрица установки: Ubuntu 22.04/24.04/26.04; см. ограничения README.')
    if platform.machine() not in ('x86_64', 'aarch64'):
        raise Failure('Поддерживаются amd64 и arm64.')
    if not Path('/run/systemd/system').exists():
        raise Failure('Нужен работающий systemd; контейнер/chroot не поддерживается.')


@contextlib.contextmanager
def lifecycle_lock(wait=0):
    import fcntl
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a') as handle:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise Failure('Другая операция Transit Client уже выполняется. Повторите позже.',
                                  'OPERATION_BUSY') from exc
                time.sleep(0.2)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@contextlib.contextmanager
def resource_lock():
    """Hooks use a short independent lock; never wait for their parent's lock."""
    path = STATE / 'resources.lock'
    with path.open('a+b') as handle:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        else:
            import msvcrt
            handle.write(b'\0')
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            if os.name == 'posix':
                fcntl.flock(handle, fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def operation_record(identifier):
    if not identifier or not re.fullmatch(r'[0-9a-f]{32}', identifier):
        return None
    path = STATE / 'operation.json'
    record = read_json(path) if path.exists() else None
    if record and record.get('operation_id') == identifier:
        if CONFIG.exists() and record.get('install_id') != read_json(CONFIG).get('install_id'):
            raise Failure('Владелец операции не подтверждён.', 'OWNERSHIP_UNKNOWN')
        return record
    return None


@contextlib.contextmanager
def operation_scope(config, kind):
    global _operation_id
    if _operation_id:
        yield _operation_id
        return
    if (STATE / 'operation.json').exists():
        raise Failure('Сохранена незавершённая операция. Выполните transitclient _recover.', 'RECOVERY_REQUIRED')
    identifier = uuid.uuid4().hex
    if not config.get('install_id'):
        config['install_id'] = uuid.uuid4().hex
        if CONFIG.exists():
            saved = read_json(CONFIG)
            if saved.get('install_id'):
                config['install_id'] = saved['install_id']
            else:
                saved['install_id'] = config['install_id']
                atomic_json(CONFIG, saved)
    atomic_json(STATE / 'operation.json', dict(operation_id=identifier, install_id=config['install_id'],
                kind=kind, resources=[], started_at=int(time.time()), deadline=int(time.time()) + ACME_TIMEOUT + 120))
    _operation_id = identifier
    try:
        yield identifier
    finally:
        try:
            with resource_lock():
                record = operation_record(identifier)
                if record:
                    record['state'] = 'closing'
                    atomic_json(STATE / 'operation.json', record)
            abort_acme(identifier)
            stop_scoped_transient(identifier, 'probe')
            path = STATE / 'operation.json'
            if operation_record(identifier):
                path.unlink()
        finally:
            _operation_id = None


def lifecycle_stage(stage, **details):
    config = read_json(CONFIG) if CONFIG.exists() else {}
    old = read_json(STATE / 'lifecycle.json') if (STATE / 'lifecycle.json').exists() else {}
    record = dict(stage=stage, install_id=config.get('install_id'), at=int(time.time()),
                  issuance_authorized=old.get('issuance_authorized', False))
    record.update(details)
    atomic_json(STATE / 'lifecycle.json', record)


def scoped_unit(identifier, kind):
    if not re.fullmatch(r'[0-9a-f]{32}', identifier) or kind not in ('acme', 'probe', 'watchdog'):
        raise Failure('Некорректный ресурс операции.', 'OWNERSHIP_UNKNOWN')
    return 'tenant-selfsteal-' + kind + '-' + identifier


def claim_resource(identifier, kind):
    with resource_lock():
        record = operation_record(identifier)
        if not record or record.get('state', 'active') != 'active':
            raise Failure('Операция уже завершена.', 'OPERATION_EXPIRED')
        record['resources'] = sorted(set(record.get('resources', [])) | {kind})
        atomic_json(STATE / 'operation.json', record)


def stop_scoped_transient(identifier, kind, suffix='service'):
    record = operation_record(identifier)
    if not record or kind not in record.get('resources', []):
        return
    unit = scoped_unit(identifier, kind) + '.' + suffix
    state = transient_state(unit)
    if state.get('LoadState', 'not-found') == 'not-found':
        return
    description = 'Transitclient ' + kind + ' ' + record['install_id'] + ' ' + identifier
    proof = state.get('Triggers') == scoped_unit(identifier, kind) + '.service' if suffix == 'timer' else (
        (str(INSTALL / 'vendor/acme.sh') in state.get('ExecStart', '') and str(STATE / 'acme') in state.get('ExecStart', ''))
        if kind == 'acme' else (str(INSTALL / 'selfsteal.py') in state.get('ExecStart', '') and identifier in state.get('ExecStart', '')))
    if state.get('Description') != description or not proof:
        raise Failure('Владелец ресурса операции не подтверждён: ' + unit, 'OWNERSHIP_UNKNOWN')
    run(['systemctl', 'stop', unit])


def dependency_lock():
    return read_json(PACKAGE / 'dependencies.json')


def assert_local_docker():
    error = diagnostic_module().local_docker_error()
    if error:
        raise Failure('Docker context указывает на удалённый либо неподтверждённый daemon. '
                      'Выберите локальный Unix socket; чужой daemon не изменён.', 'DOCKER_REMOTE')


def assert_compose_owned():
    assert_local_docker()
    resources = run(['docker', 'ps', '-aq', '--filter',
                     'label=com.docker.compose.project=' + PROJECT]).stdout.decode().split()
    if not resources:
        return
    values = run(['docker', 'inspect', '--format', '{{json .Config.Labels}}', *resources]).stdout.decode().splitlines()
    if len(values) != len(resources):
        raise Failure('Не удалось проверить владельца Compose-ресурсов.', 'OWNERSHIP_UNKNOWN')
    owned = read_json(CONFIG).get('install_id') if CONFIG.exists() else None
    for value in values:
        labels = json.loads(value)
        if not CONFIG.exists() or labels.get('org.tenant-selfsteal.package') != 'true' or (
            labels.get('org.transitclient.install-id') and labels['org.transitclient.install-id'] != owned
        ):
            raise Failure('Имя Compose проекта занято чужими контейнерами. Они не изменены.', 'OWNERSHIP_CONFLICT')


def validate_network(config):
    assert_local_docker()
    if not config.get('docker_network'):
        return
    # Never connect or change the VPN container. Only our Caddy joins this network.
    result = run(['docker', 'network', 'inspect', config['docker_network'], '--format',
                  '{{json .}}'])
    network = json.loads(result.stdout)
    options = network.get('Options') or {}
    if (network.get('Driver') != 'bridge' or network.get('Name') == 'bridge'
            or network.get('Scope') != 'local'
            or any(options.get('com.docker.network.bridge.gateway_mode_' + family, 'nat') != 'nat'
                   for family in ('ipv4', 'ipv6'))
            or options.get('com.docker.network.bridge.trusted_host_interfaces')):
        raise Failure('Нужна существующая локальная user-defined bridge сеть без routed/'
                      'direct-routing режимов. Сеть не изменена.', 'UNSAFE_DOCKER_NETWORK')
    for identifier in (network.get('Containers') or {}):
        if not re.fullmatch(r'[0-9a-f]{12,64}', identifier):
            raise Failure('Не удалось проверить участников Docker-сети.', 'OWNERSHIP_UNKNOWN')
        details = json.loads(run(['docker', 'inspect', '--format',
                                 '{{json .NetworkSettings.Networks}}', identifier]).stdout)
        aliases = details.get(config['docker_network'], {}).get('Aliases') or []
        if 'transitclient-selfsteal' in aliases:
            labels = json.loads(run(['docker', 'inspect', '--format', '{{json .Config.Labels}}', identifier]).stdout)
            if (labels.get('org.tenant-selfsteal.package') != 'true'
                    or not config.get('install_id')
                    or labels.get('org.transitclient.install-id') != config['install_id']):
                raise Failure('Alias transitclient-selfsteal уже занят чужим контейнером.', 'DOCKER_ALIAS_CONFLICT')
    if config.get('vpn_container'):
        networks = json.loads(run(['docker', 'inspect', '--format',
                                  '{{json .NetworkSettings.Networks}}', config['vpn_container']]).stdout)
        if config['docker_network'] not in networks:
            raise Failure('VPN-контейнер ещё не подключён к выбранной сети. '
                          'Подключите его самостоятельно по инструкции.', 'VPN_NETWORK_MISSING')


def launcher_content():
    return '#!/usr/bin/env bash\n# transitclient-owned launcher v1\nexec /usr/bin/python3 ' + shlex.quote(str(INSTALL / 'selfsteal.py')) + ' "$@"\n'


def check_launcher():
    if LAUNCHER.is_symlink() or (LAUNCHER.exists() and (
        not LAUNCHER.is_file() or LAUNCHER.read_text() != launcher_content()
    )):
        raise Failure('Команда transitclient уже занята чужим файлом. Он не перезаписан.', 'COMMAND_CONFLICT')
    found = shutil.which('transitclient')
    if found and Path(found).absolute() != LAUNCHER.absolute():
        raise Failure('В PATH уже есть другая команда transitclient. Она не затенена.', 'COMMAND_CONFLICT')


def install_launcher():
    check_launcher()
    candidate = LAUNCHER.with_name('.transitclient-' + uuid.uuid4().hex)
    candidate.write_text(launcher_content(), encoding='utf-8')
    candidate.chmod(0o755)
    # Recheck immediately before replacing an existing owned launcher.
    check_launcher()
    os.replace(candidate, LAUNCHER)


def verified_download(url, digest, destination):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or any(ord(char) < 33 or ord(char) == 127 for char in url)
            or not re.fullmatch('[a-f0-9]{64}', digest)):
        raise Failure('Для загрузки нужны HTTPS URL и SHA256 выбранного релиза.')
    class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            if urlsplit(newurl).scheme != 'https':
                raise Failure('Загрузка перенаправлена на незашифрованный адрес.', 'RELEASE_REDIRECT')
            return super().redirect_request(request, fp, code, message, headers, newurl)
    with urllib.request.build_opener(HTTPSRedirect()).open(url, timeout=60) as response:
        if not response.url.startswith('https://'):
            raise Failure('Загрузка перенаправлена на незашифрованный адрес.')
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise Failure('Артефакт не прошёл проверку SHA256/размера.')
    destination.write_bytes(data)


def dependencies():
    assert_local_docker()
    missing = [name for name in ('openssl', 'socat', 'curl', 'docker')
               if shutil.which(name) is None]
    if not Path('/etc/ssl/certs/ca-certificates.crt').exists():
        missing.append('ca-certificates')
    if missing:
        print('Будут установлены системные зависимости: ' + ', '.join(missing))
        run(['apt-get', 'update'], timeout=300)
        packages = ['docker.io' if name == 'docker' else name for name in missing]
        run(['apt-get', 'install', '-y', *packages], timeout=600)
    run(['docker', 'info'], timeout=30)
    assert_compose_owned()
    manifest = dependency_lock()
    acme = PACKAGE / 'vendor/acme.sh'
    if hashlib.sha256(acme.read_bytes()).hexdigest() != manifest['acme']['sha256']:
        raise Failure('Встроенный acme.sh не соответствует зафиксированному SHA256.')
    compose = STATE / 'docker-compose'
    selected = manifest['compose'][platform.machine()]
    if not compose.exists() or hashlib.sha256(compose.read_bytes()).hexdigest() != selected['sha256']:
        candidate = STATE / 'docker-compose.download'
        verified_download(selected['url'], selected['sha256'], candidate)
        candidate.chmod(0o700)
        os.replace(candidate, compose)
    run(['docker', 'pull', manifest['caddy']['image']], timeout=300)
    validate_caddy_runtime(manifest['caddy']['image'])


def validate_caddy_runtime(image):
    # Check executable capabilities before any ACME request. Official Caddy
    # carries cap_net_bind_service=ep and cannot exec with an empty bounding set.
    result = run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                  '--cap-drop', 'ALL', '--cap-add', 'NET_BIND_SERVICE',
                  '--security-opt', 'no-new-privileges', image, 'caddy', 'version'], check=False)
    if result.returncode:
        raise Failure('Caddy не запускается в изолированной проверке. ' + compose_error_detail(result),
                      'CADDY_RUNTIME_FAILED')


def compose(*args, check=True):
    assert_compose_owned()
    result = run([STATE / 'docker-compose', '-p', PROJECT, '-f', STATE / 'compose.yaml',
                  *args], check=False, timeout=120)
    if check and result.returncode:
        operation = args[0] if args and args[0] in ('run', 'up', 'exec', 'ps', 'down', 'config', 'version') else 'command'
        code = 'CADDY_VALIDATE_FAILED' if operation == 'run' and 'validate' in args else 'COMPOSE_COMMAND_FAILED'
        detail = compose_error_detail(result)
        raise Failure(f'Compose: {operation}, код {result.returncode}. {detail}', code)
    return result


def compose_error_detail(result):
    """Classify known errors, never echo output that can contain keys or tokens."""
    output = (getattr(result, 'stderr', b'') + getattr(result, 'stdout', b'')).decode('utf-8', errors='replace').lower()
    for patterns, message in (
        (('client version', 'api version'), 'Несовместимость Docker API; проверьте версии Docker и Compose.'),
        (('read-only file system',), 'Попытка записи в файловую систему только для чтения; проверьте mounts Caddy.'),
        (('permission denied', 'operation not permitted'), 'Доступ запрещён; проверьте права файлов и ограничения контейнера.'),
        (('address already in use', 'port is already allocated'), 'Адрес или порт занят; чужой процесс не остановлен.'),
        (('cannot connect to the docker daemon', 'is the docker daemon running'), 'Нет подключения к локальному Docker daemon.'),
        (('error mounting', 'invalid mount', 'mount source path does not exist'), 'Ошибка монтирования каталогов Caddy.'),
        (('no such file or directory', 'does not exist'), 'Не найден файл или путь; проверьте конфигурацию и сертификат Caddy.'),
        (('adapting config', 'parsing caddyfile', 'unrecognized directive'), 'Caddy отклонил конфигурацию.'),
        (('oci runtime', 'failed to create task', 'failed to create shim'), 'Контейнер не запущен: ошибка OCI runtime.'),
    ):
        if any(pattern in output for pattern in patterns):
            return message
    return ('Причина не распознана. Проверьте Compose version/config и выполните отдельную '
            'проверку caddy validate; вывод команд автоматически не публикуется.')


def reload_caddy():
    # Legacy config has its old local admin endpoint until it is upgraded.
    text = (STATE / 'Caddyfile').read_text() if (STATE / 'Caddyfile').exists() else ''
    address = ['--address', ADMIN] if 'transitclient-admin.sock' in text else []
    compose('exec', '-T', 'caddy', 'caddy', 'reload', '--force', '--config', '/etc/caddy/Caddyfile', *address)


def owned_rule_numbers(text, tag):
    # No deletion by port: remove only rules carrying our UUID marker.
    return [int(m.group(1)) for line in text.splitlines()
            if tag in line and (m := re.match(r'^\[\s*(\d+)\]', line))]


def cleanup_firewall(identifier=None):
    identifier = identifier or _operation_id
    if not (STATE / 'firewall.json').exists():
        return
    with resource_lock():
        record = _cleanup_firewall_locked(identifier)
    # Stop outside the hook lock: ExecStopPost may itself run cleanup.
    if record and record.get('operation_id'):
        stop_scoped_transient(record['operation_id'], 'watchdog', 'timer')
    elif record:
        stop_owned_transient('tenant-selfsteal-watchdog.timer', 'Transitclient firewall watchdog')


def _cleanup_firewall_locked(identifier):
    marker = STATE / 'firewall.json'
    if not marker.exists():
        return
    record = read_json(marker)
    if record.get('operation_id') != identifier:
        return
    if identifier and not operation_record(identifier):
        return
    if not re.fullmatch(r'tenant-selfsteal-[0-9a-f]{32}', record['tag']):
        raise Failure('Повреждён маркер firewall; автоматическое удаление запрещено.')
    if record['mode'] != 'ufw':
        raise Failure('Неизвестный firewall в маркере; автоматическое удаление запрещено.')
    # A single numbered deletion changes every following number; read each time.
    if record['mode'] == 'ufw':
        for _ in range(4):
            status = run(['ufw', 'status', 'numbered']).stdout.decode()
            if 'Status: inactive' in status:
                raise Failure('UFW отключён после создания временного правила. '
                              'Маркер сохранён: сверка продолжится после включения UFW.')
            numbers = owned_rule_numbers(status, record['tag'])
            if not numbers:
                break
            run(['ufw', '--force', 'delete', str(max(numbers))])
        else:
            raise Failure('Не удалось удалить временные правила UFW; маркер сохранён.')
    marker.unlink()
    return record


def open_firewall(config, identifier=None):
    identifier = identifier or _operation_id
    check_challenge_port(config)
    cleanup_firewall(identifier)
    with resource_lock():
        if identifier:
            record = operation_record(identifier)
            if not record or record.get('state', 'active') != 'active' or record['deadline'] <= time.time():
                raise Failure('Операция завершена или её срок истёк.', 'OPERATION_EXPIRED')
        _open_firewall_locked(config, identifier)


def _open_firewall_locked(config, identifier):
    policy = config.get('firewall_effective') or config['firewall']
    if policy in ('manual', 'preserve'):
        print(f"Внешний/local firewall: TCP {config['challenge_port']} должен пропускать "
              'все источники на время ACME. Автоматические правила не изменяются.')
        return
    if policy != 'ufw':
        raise Failure('Режим firewall ещё не подготовлен. Откройте transitclient → Настройки → Firewall.',
                      'FIREWALL_MODE_REQUIRED')
    status = run(['ufw', 'status']).stdout.decode()
    if 'Status: active' not in status:
        raise Failure('Сохранён режим управления UFW, но UFW не активен. '
                      'Откройте transitclient → Настройки → Firewall: выберите preserve '
                      'для сохранения текущих правил либо настройте UFW. Автоматически UFW не включён.',
                      'UFW_INACTIVE')
    firewall = firewall_module()
    try:
        firewall.check_challenge_rules(run, config['challenge_port'])
    except firewall.FirewallError as exc:
        raise Failure(str(exc), exc.code) from exc
    tag = 'tenant-selfsteal-' + uuid.uuid4().hex
    unit = scoped_unit(identifier, 'watchdog') if identifier else 'tenant-selfsteal-watchdog'
    assert_transient_available(unit + '.timer')
    assert_transient_available(unit + '.service')
    if identifier:
        record = operation_record(identifier)
        record['resources'] = sorted(set(record.get('resources', [])) | {'watchdog'})
        atomic_json(STATE / 'operation.json', record)
    # Persist intent BEFORE adding the rule. Boot + watchdog recover after SIGKILL.
    atomic_json(STATE / 'firewall.json', {'tag': tag, 'mode': 'ufw',
                                        'port': config['challenge_port'], **({'operation_id': identifier,
                                        'install_id': config['install_id']} if identifier else {})})
    hook = [sys.executable, INSTALL / 'selfsteal.py', '_abort']
    if identifier:
        hook.extend(['--operation-id', identifier])
    description = ('Transitclient watchdog ' + config['install_id'] + ' ' + identifier) if identifier else 'Transitclient firewall watchdog'
    run(['systemd-run', '--unit=' + unit, '--on-active=17m',
         '--description=' + description, '--timer-property=Description=' + description,
         '--timer-property=AccuracySec=1s', '--collect', *hook])
    run(['ufw', 'prepend', 'allow', f"{config['challenge_port']}/tcp", 'comment', tag])
    # prepend skips duplicates without updating their comments. Ordinary allow
    # can retag a foreign rule, which must never become eligible for cleanup.


def recover_certificate():
    journal = STATE / 'certificate-transaction.json'
    if not journal.exists():
        return
    transaction = read_json(journal)
    old = transaction['old']
    current = STATE / 'certs/current'
    if old:
        if not re.fullmatch(r'[0-9a-f]{32}', old):
            raise Failure('Повреждён журнал сертификата; откат остановлен.')
        swap_current(old)
        reload_caddy()
    else:
        compose('down', check=False)
        current.unlink(missing_ok=True)
    journal.unlink()


def recover_update():
    """Stable recovery helper remains in STATE even if INSTALL rename was killed."""
    global PACKAGE
    journal = STATE / 'update-transaction.json'
    if not journal.exists():
        return
    transaction = read_json(journal)
    identifier = transaction['id']
    if not re.fullmatch(r'[0-9a-f]{32}', identifier):
        raise Failure('Повреждён журнал update; автоматическое восстановление запрещено.')
    backup = INSTALL.with_name('tenant-selfsteal.previous-' + identifier)
    snapshot = STATE / ('update-backup-' + identifier)
    if backup.exists():
        if INSTALL.exists():
            failed = INSTALL.with_name('tenant-selfsteal.failed-' + identifier)
            if failed.exists():
                raise Failure('Неоднозначное восстановление update; сохранён журнал.')
            os.replace(INSTALL, failed)
        os.replace(backup, INSTALL)
    PACKAGE = INSTALL
    for name in ('Caddyfile', 'compose.yaml', 'docker-compose', 'recover.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py', 'recovery-current.json', 'schedule-pending.json'):
        if (snapshot / name).exists():
            shutil.copy2(snapshot / name, STATE / name)
        elif name in ('recovery-current.json', 'schedule-pending.json'):
            (STATE / name).unlink(missing_ok=True)
    if (snapshot / 'config.json').exists():
        atomic_json(CONFIG, read_json(snapshot / 'config.json'))
    if (snapshot / 'units.json').exists():
        restore_units(read_json(snapshot / 'units.json'))
    if (STATE / 'certs/current').exists():
        compose('up', '-d', '--no-build', 'caddy')
        reload_caddy()
        config = validate_config(read_json(CONFIG))
        domain_journal = STATE / 'configuration-transaction.json'
        if not domain_journal.exists() or not read_json(domain_journal).get('domain_switch'):
            verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem'))
    journal.unlink()


def abort_acme(identifier=None):
    # Stop only our managed transient cgroup, including its socat listeners.
    # _cleanup is a hook and must not stop the ACME process invoking it.
    identifier = identifier or _operation_id
    if identifier:
        stop_scoped_transient(identifier, 'acme')
        cleanup_firewall(identifier)
    elif not (STATE / 'operation.json').exists():
        stop_owned_transient('tenant-selfsteal-acme.service', 'Transitclient ACME')
        cleanup_firewall()


def transient_state(unit):
    result = run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'Description',
                  '-p', 'ExecStart', '-p', 'Triggers'], check=False)
    if result.returncode:
        raise Failure('Не удалось проверить владельца временного systemd unit.', 'OWNERSHIP_UNKNOWN')
    return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)


def assert_transient_available(unit):
    state = transient_state(unit)
    if state.get('LoadState', 'not-found') != 'not-found':
        raise Failure('Имя временной systemd-службы занято: ' + unit + '. Она не изменена.', 'UNIT_CONFLICT')


def stop_owned_transient(unit, description):
    state = transient_state(unit)
    if state.get('LoadState', 'not-found') == 'not-found':
        return
    owned_start = {
        'tenant-selfsteal-acme.service': (str(INSTALL / 'vendor/acme.sh'), str(STATE / 'acme')),
        'tenant-selfsteal-probe.service': (str(INSTALL / 'selfsteal.py'), '_probe-server'),
        'tenant-selfsteal-watchdog.service': (str(INSTALL / 'selfsteal.py'), '_abort'),
    }
    proof = (state.get('Triggers') == 'tenant-selfsteal-watchdog.service') if unit.endswith('.timer') else all(
        token in state.get('ExecStart', '') for token in owned_start.get(unit, ('not-owned',)))
    if state.get('Description') != description or not proof:
        raise Failure('Владелец временного unit не подтверждён: ' + unit + '. Он не остановлен.', 'OWNERSHIP_UNKNOWN')
    run(['systemctl', 'stop', unit])


def swap_current(generation):
    root = STATE / 'certs'
    candidate = root / 'current.next'
    candidate.unlink(missing_ok=True)
    candidate.symlink_to(generation, target_is_directory=True)
    os.replace(candidate, root / 'current')
    if os.name == 'posix':
        fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def validate_certificate(config, chain, key):
    pem = chain.read_bytes()
    leaf_match = re.search(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                           pem, re.S)
    if not leaf_match:
        raise Failure('ACME не предоставил сертификат.')
    # Diagnose never writes into installed certificate generations.
    with tempfile.TemporaryDirectory(prefix='transitclient-cert-') as temporary:
        leaf = Path(temporary) / 'leaf.pem'
        leaf.write_bytes(leaf_match.group(0) + b'\n')
        leaf.chmod(0o600)
        decoded = ssl._ssl._test_decode_cert(str(leaf))
        if ('DNS', config['domain']) not in decoded.get('subjectAltName', []):
            raise Failure('SAN сертификата не содержит выданный домен.', 'CERT_SAN_MISMATCH')
        if run(['openssl', 'x509', '-in', leaf, '-checkend', '3600', '-noout'], check=False).returncode:
            raise Failure('Сертификат просрочен либо истекает менее чем через час.', 'CERT_EXPIRED')
        trust = config.get('staging_ca_file') if config['ca'] == STAGING else '/etc/ssl/certs/ca-certificates.crt'
        if run(['openssl', 'verify', '-CAfile', trust, '-untrusted', chain,
                '-verify_hostname', config['domain'], '-purpose', 'sslserver', leaf], check=False).returncode:
            raise Failure('Сертификат не прошёл проверку цепочки доверия, имени или срока.', 'CERT_TRUST_FAILED')
        cert_public = run(['openssl', 'x509', '-in', leaf, '-pubkey', '-noout']).stdout
    cert_der = run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=cert_public).stdout
    key_der = run(['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER']).stdout
    if key_der != cert_der:
        raise Failure('Сертификат не соответствует приватному ключу.', 'CERT_KEY_MISMATCH')
    return ssl.PEM_cert_to_DER_cert(leaf_match.group(0).decode())


def verify_served(config, expected, attempts=15):
    trust = config.get('staging_ca_file') if config['ca'] == STAGING else None
    context = ssl.create_default_context(cafile=trust)
    context.set_alpn_protocols(['h2', 'http/1.1'])
    last = None
    for _ in range(attempts):
        try:
            with socket.create_connection(served_endpoint(config), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=config['domain']) as tls:
                    if tls.getpeercert(binary_form=True) != expected:
                        raise Failure('Caddy выдаёт другой сертификат; выполняется откат.')
                    if tls.selected_alpn_protocol() != 'h2':
                        raise Failure('Selfsteal не поддерживает h2.')
                    if tls.version() != 'TLSv1.3':
                        raise Failure('Selfsteal не поддерживает TLS 1.3.')
                    return
        except (OSError, Failure) as exc:
            last = exc
            time.sleep(1)
    detail = ' ' + str(last) if isinstance(last, Failure) else ' Проверьте доступ к HTTPS target и цепочку доверия.'
    raise Failure('Не подтверждён сертификат действующего Caddy; выполняется откат.' + detail, 'CERT_NOT_APPLIED') from last


def served_endpoint(config):
    if not config.get('docker_network'):
        return '127.0.0.1', config['local_port']
    identifier = compose('ps', '-q', 'caddy').stdout.decode().strip()
    if not re.fullmatch(r'[0-9a-f]{12,64}', identifier):
        raise Failure('Собственный Caddy-контейнер не найден.', 'TARGET_UNREACHABLE')
    networks = json.loads(run(['docker', 'inspect', '--format',
                              '{{json .NetworkSettings.Networks}}', identifier]).stdout)
    address = networks.get(config['docker_network'], {}).get('IPAddress', '')
    try:
        selected = ipaddress.ip_address(address)
    except ValueError as exc:
        raise Failure('Caddy не получил адрес в выбранной Docker-сети.', 'TARGET_UNREACHABLE') from exc
    if not selected.is_private or selected.is_loopback or selected.is_unspecified:
        raise Failure('Caddy получил небезопасный адрес Docker-сети.', 'UNSAFE_DOCKER_NETWORK')
    return str(selected), config['local_port']


def target(config):
    host = 'transitclient-selfsteal' if config.get('docker_network') else '127.0.0.1'
    return f"{host}:{config['local_port']}"


def render_caddy(config):
    # Mount the certificate DIRECTORY, not individual files/symlink targets.
    # Directory generation + relative current symlink remain visible after swap.
    port = config['local_port']
    bind = '0.0.0.0' if config.get('docker_network') else '127.0.0.1'
    (STATE / 'Caddyfile').write_text(f'''{{
    admin {ADMIN}
    auto_https off
    servers {{
        protocols h1 h2
    }}
}}
https://{config['domain']}:{port} {{
    bind {bind}
    tls /certs/current/fullchain.pem /certs/current/key.pem
    root * /srv/current
    try_files {{path}} /index.html
    file_server
}}
''', encoding='utf-8')
    image = dependency_lock()['caddy']['image']
    if config.get('docker_network'):
        networking = '''    networks:
      selfsteal:
        aliases: [transitclient-selfsteal]
'''
        external_network = f'''networks:
  selfsteal:
    external: true
    name: {config['docker_network']}
'''
    else:
        networking = '    network_mode: host\n'
        external_network = ''
    (STATE / 'compose.yaml').write_text(f'''services:
  caddy:
    image: {image}
    labels:
      org.tenant-selfsteal.package: "true"
      org.transitclient.install-id: "{config.get('install_id', '')}"
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    # Official Caddy has this file capability; keep it in the bounding set.
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
{networking.rstrip()}
    volumes:
      - "{STATE}/Caddyfile:/etc/caddy/Caddyfile:ro"
      - "{STATE}/certs:/certs:ro"
      - "{STATE}/site:/srv:ro"
      - "{STATE}/caddy-data:/data"
      - "{STATE}/caddy-config:/config"
{external_network}
''', encoding='utf-8')
    template_module().ensure_site(STATE, PACKAGE)


def apply_certificate(config, chain, key):
    certs = STATE / 'certs'
    certs.mkdir(exist_ok=True, mode=0o700)
    generation = uuid.uuid4().hex
    staged = certs / generation
    staged.mkdir(mode=0o700)
    shutil.copyfile(chain, staged / 'fullchain.pem')
    shutil.copyfile(key, staged / 'key.pem')
    for path in staged.iterdir():
        path.chmod(0o600)
    expected = validate_certificate(config, staged / 'fullchain.pem', staged / 'key.pem')
    current = certs / 'current'
    old = os.readlink(current) if current.is_symlink() else None
    if old and not re.fullmatch(r'[0-9a-f]{32}', old):
        raise Failure('Неизвестный путь предыдущего сертификата; применение запрещено.')
    atomic_json(STATE / 'certificate-transaction.json', {'old': old, 'new': generation})
    try:
        swap_current(generation)
        compose('run', '--rm', '--no-deps', 'caddy', 'caddy', 'validate',
                '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')
        compose('up', '-d', '--no-build', 'caddy')
        reload_caddy()
        verify_served(config, expected)
    except BaseException:
        recover_certificate()
        raise
    (STATE / 'certificate-transaction.json').unlink()
    # Keep previous generation as an explicit backup; garbage collection is manual.
    atomic_json(STATE / 'result.json', {'success': True, 'at': int(time.time()),
                                      'certificate_sha256': hashlib.sha256(expected).hexdigest(),
                                      'staging': config['ca'] == STAGING})


def acme_command(config, *args):
    return ['bash', PACKAGE / 'vendor/acme.sh', '--home', STATE / 'acme',
            '--config-home', STATE / 'acme', '--server', config['ca'], *args]


def synchronize_acme_parameters(config, pre, post):
    """acme.sh 3.1.6 renew sources saved domain config over CLI hook/port args.

    Sync only our three package-owned values, leaving account/order/due/ARI and
    certificate metadata intact. Encoding matches pinned _save_conf exactly.
    No shell source or evaluation of that configuration in this controller.
    """
    path = STATE / 'acme' / (config['domain'] + '_ecc') / (config['domain'] + '.conf')
    if not path.exists():
        return
    values = {'Le_HTTPPort': str(config['challenge_port'])}
    for key, hook in [('Le_PreHook', pre), ('Le_PostHook', post)]:
        values[key] = '__ACME_BASE64__START_' + base64.b64encode(hook.encode()).decode() + '__ACME_BASE64__END_'
    lines = [line for line in path.read_text().splitlines()
             if not any(re.match('^' + key + r'\s*=', line) for key in values)]
    content = '\n'.join(lines + [f"{key}='{value}'" for key, value in values.items()]) + '\n'
    candidate = path.with_name(path.name + '.tenant-next')
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(candidate, path)
    path.chmod(0o600)


def recover_configuration():
    journal = STATE / 'configuration-transaction.json'
    if not journal.exists():
        return
    previous = read_json(journal)
    config = validate_config(previous['config'])
    for name in ('Caddyfile', 'compose.yaml'):
        if previous[name] is None:
            (STATE / name).unlink(missing_ok=True)
        else:
            (STATE / name).write_text(previous[name], encoding='utf-8')
    if previous.get('domain_switch'):
        old = previous['certificate']
        if old is not None:
            if not re.fullmatch(r'[0-9a-f]{32}', old):
                raise Failure('Журнал смены домена повреждён.', 'RECOVERY_INVALID')
            swap_current(old)
        else:
            compose('down', check=False)
            (STATE / 'certs/current').unlink(missing_ok=True)
        for name, value in previous['metadata'].items():
            if name not in ('lifecycle.json', 'http-path.json', 'result.json', 'schedule-pending.json'):
                raise Failure('Неизвестные данные в журнале смены домена.', 'RECOVERY_INVALID')
            if value is None:
                (STATE / name).unlink(missing_ok=True)
            else:
                atomic_json(STATE / name, value)
    if previous.get('units'):
        for name, content in previous['units'].items():
            if name not in ('renew.service', 'renew.timer', 'recover.service'):
                raise Failure('Неизвестный unit в журнале настройки.', 'RECOVERY_INVALID')
            (UNITS / ('tenant-selfsteal-' + name)).write_text(content, encoding='utf-8')
        run(['systemctl', 'daemon-reload'])
    if (STATE / 'certs/current').exists():
        compose('up', '-d', '--no-build', 'caddy')
        atomic_json(CONFIG, config)
        reload_caddy()
        if not previous.get('domain_switch'):
            verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem',
                                                        STATE / 'certs/current/key.pem'))
    else:
        atomic_json(CONFIG, config)
    journal.unlink()


def configure(config, choice=None, firewall_request=None):
    if choice is None:
        print('⚙️ Настройки: 1 HTTP-порт для сертификата · 2 Порт для проксирования трафика · '
              '3 Локальный HTTPS-порт веб-сервера · 4 Docker-сеть · 5 Firewall · 0 назад')
        choice = input('Выберите настройку: ').strip()
    candidate = dict(config)
    firewall_plan = None
    if choice == '0':
        return config
    if choice == '1':
        print(f"HTTP-порт для выпуска и продления сертификата: {config['challenge_port']}.")
        print('Сначала измените этот порт в боте и дождитесь готовности маршрута.')
        candidate['challenge_port'] = port_value(input('Новый HTTP-порт для сертификата: '))
        validate_config(candidate)
        check_challenge_port(candidate)
    elif choice == '2':
        print('Порт VPN-ноды на вашем сервере, куда транзит направляет клиентский трафик.')
        candidate['vpn_port'] = input('Порт для проксирования трафика [443]: ').strip() or '443'
        validate_config(candidate)
        diagnostic_module().display(diagnostic_module().collect(candidate))
    elif choice == '3':
        candidate['local_port'] = port_value(input('Новый локальный HTTPS-порт веб-сервера: '))
        validate_config(candidate)
        if not candidate.get('docker_network') and not free_port(candidate['local_port'], '127.0.0.1'):
            raise Failure('Выбранный HTTPS-порт занят. Чужой процесс не остановлен.', 'HTTPS_PORT_BUSY')
        print('VPN target необходимо изменить самостоятельно после применения.')
    elif choice == '4':
        print('Docker-сеть определяет, как VPN-нода достигает локального Caddy.')
        print('Пустое имя — host networking. Bridge — существующая user-defined Docker-сеть.')
        candidate['docker_network'] = input('Имя сети: ').strip()
        candidate['vpn_container'] = input('VPN-контейнер (необязательно): ').strip()
        validate_config(candidate)
        validate_network(candidate)
        if not candidate['docker_network'] and not free_port(candidate['local_port'], '127.0.0.1'):
            raise Failure('HTTPS-порт host занят. Измените его перед переключением.', 'HTTPS_PORT_BUSY')
    elif choice == '5':
        candidate['firewall'] = firewall_request or ask('Firewall: auto, ufw, preserve', config['firewall'])
        candidate.pop('firewall_effective', None)
        validate_config(candidate)
        firewall = firewall_module()
        try:
            firewall_plan = firewall.plan(candidate, diagnostic_module().collect(candidate), run)
        except firewall.FirewallError as exc:
            raise Failure(str(exc), exc.code) from exc
        candidate['firewall_effective'] = firewall_plan['effective']
        for change in firewall_plan['changes']:
            print('🛡️ ' + change)
    else:
        raise Failure('Неизвестная настройка.', 'INVALID_OPTION')
    labels = {'challenge_port': 'HTTP-порт для сертификата', 'vpn_port': 'Порт для проксирования трафика',
              'local_port': 'Локальный HTTPS-порт веб-сервера', 'docker_network': 'Docker-сеть',
              'vpn_container': 'Контейнер ноды', 'firewall': 'Режим firewall', 'firewall_effective': 'Выбранная политика'}
    for key, label in labels.items():
        if config.get(key) != candidate.get(key):
            print(f"{label}: {config.get(key) or 'не задано'} → {candidate.get(key) or 'не задано'}")
    print(f"Домен сохраняется: {candidate['domain']}; VPN: {candidate.get('vpn_port')}; "
          f"HTTP: {candidate['challenge_port']}; target: {target(candidate)}.")
    if not confirm('Маршрут в боте согласован, применить только эти изменения?'):
        raise Failure('Настройки не изменены.', 'CANCELLED')
    if choice == '5':
        cleanup_firewall()
        if firewall_plan['mode'] in ('inactive', 'missing'):
            run(['systemctl', 'stop', 'tenant-selfsteal-renew.timer'])
            atomic_json(STATE / 'schedule-pending.json', {'install_id': config.get('install_id', '')})
        atomic_json(CONFIG, candidate)
        try:
            applied = firewall.apply(firewall_plan, candidate, STATE, run, atomic_json)
        except firewall.FirewallError as exc:
            lifecycle_stage('recovery_required', reason=exc.code)
            raise Failure(str(exc), exc.code) from exc
        if applied.get('status') == 'awaiting-confirmation':
            lifecycle_stage('awaiting_firewall')
            print('Подключитесь по SSH заново и выполните в течение 180 секунд:')
            print('sudo transitclient firewall-confirm --confirmation-token ' + applied['token'])
        return candidate
    if choice in ('1', '2'):
        atomic_json(CONFIG, candidate)
        if choice == '1':
            (STATE / 'http-path.json').unlink(missing_ok=True)
            if (STATE / 'lifecycle.json').exists() and not (STATE / 'certs/current').exists():
                lifecycle_stage('awaiting_http', reason='HTTP_ROUTE_CHANGED')
    else:
        snapshot = {'config': config}
        for name in ('Caddyfile', 'compose.yaml'):
            snapshot[name] = (STATE / name).read_text()
        atomic_json(STATE / 'configuration-transaction.json', snapshot)
        try:
            render_caddy(candidate)
            compose('run', '--rm', '--no-deps', 'caddy', 'caddy', 'validate',
                    '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')
            compose('up', '-d', '--no-build', 'caddy')
            reload_caddy()
            verify_served(candidate, validate_certificate(candidate, STATE / 'certs/current/fullchain.pem',
                                                           STATE / 'certs/current/key.pem'))
            atomic_json(CONFIG, candidate)
            (STATE / 'configuration-transaction.json').unlink()
        except BaseException:
            recover_configuration()
            raise
    print('✅ Настройка сохранена. Сертификат и ACME identity не перевыпущены.')
    return candidate


def renew(config):
    with operation_scope(config, 'renew'):
        result = _renew(config)
    import installation_flow
    installation_flow.cleanup_previous_packages(SimpleNamespace(**globals()), config)
    return result


def _renew(config):
    print('🔐 Проверяем срок сертификата и расписание продления.')
    print('Если продление ещё не требуется, новый сертификат не запрашивается; '
          'если требуется — выполняется выпуск и применение в Caddy.')
    lifecycle = read_json(STATE / 'lifecycle.json') if (STATE / 'lifecycle.json').exists() else {}
    if lifecycle.get('stage') in ('preparing', 'awaiting_firewall', 'uninstalling', 'recovery_required'):
        raise Failure('Подготовка установки ещё не завершена. Повторите install или _recover.', 'RUNTIME_NOT_READY')
    if lifecycle.get('stage') == 'awaiting_http':
        raise Failure('Сначала подтвердите HTTP-путь: transitclient self-test --http01.', 'HTTP_PATH_UNCONFIRMED')
    if lifecycle and not lifecycle.get('issuance_authorized'):
        raise Failure('Выпуск/продление для восстановленной установки ещё не разрешены.', 'ACME_NOT_AUTHORIZED')
    if not lifecycle:
        # Upgrades preserve the issuance consent of existing installations.
        lifecycle_stage('ready' if (STATE / 'certs/current').exists() else 'certificate_pending',
                        issuance_authorized=True)
    check_dns(config)
    home = STATE / 'acme'
    home.mkdir(exist_ok=True, mode=0o700)
    # Run the pinned script directly: no --install, no cron, no --cron autoupgrade.
    account = home / 'account.conf'
    if not account.exists():
        account.write_text("AUTO_UPGRADE='0'\n", encoding='utf-8')
        account.chmod(0o600)
    domain_dir = home / (config['domain'] + '_ecc')
    identifier = _operation_id
    record = operation_record(identifier)
    if not (STATE / 'certs/current').exists():
        lifecycle_stage('certificate_pending')
    pre = shlex.join([sys.executable, str(INSTALL / 'selfsteal.py'), '_open', '--operation-id', identifier])
    post = shlex.join([sys.executable, str(INSTALL / 'selfsteal.py'), '_cleanup', '--operation-id', identifier])
    synchronize_acme_parameters(config, pre, post)
    if (domain_dir / (config['domain'] + '.conf')).exists():
        args = ['--renew', '-d', config['domain'], '--ecc',
                '--httpport', str(config['challenge_port']), '--pre-hook', pre, '--post-hook', post]
    else:
        args = ['--issue', '--standalone', '--httpport', str(config['challenge_port']),
                '-d', config['domain'], '--keylength', 'ec-256',
                '--pre-hook', pre, '--post-hook', post]
    try:
        # The transient service owns the standalone listener and survives loss of
        # the interactive parent only up to its strict deadline. ExecStopPost,
        # watchdog and boot recovery close tagged rules after SIGKILL too.
        unit = scoped_unit(identifier, 'acme')
        assert_transient_available(unit + '.service')
        claim_resource(identifier, 'acme')
        result = run(['systemd-run', '--unit=' + unit, '--description=Transitclient acme ' + record['install_id'] + ' ' + identifier, '--wait', '--pipe',
                      '--collect', '--service-type=exec',
                      '--property=RuntimeMaxSec=15min', '--property=KillMode=control-group',
                      '--property=UMask=0077', '--setenv=LC_ALL=C',
                      '--property=ExecStopPost=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py _cleanup --operation-id ' + identifier,
                      *acme_command(config, *args)], check=False, timeout=ACME_TIMEOUT + 60)
        # acme.sh's documented RENEW_SKIP=2 is not a CA error. It runs the
        # pre-hook AFTER its due/ARI checks, so skipped runs never open firewall.
        if result.returncode not in (0, 2):
            raise Failure('ACME-проверка не завершена. Проверьте маршрут в боте, '
                          'DNS и входящий проверочный порт в firewall/NAT. '
                          'Прежний сертификат сохранён; повтор через таймер.')
        if result.returncode == 2:
            print('Срок продления ещё не наступил. Используется имеющийся сертификат.')
        chain = domain_dir / 'fullchain.cer'
        key = domain_dir / (config['domain'] + '.key')
        if not chain.exists() or not key.exists():
            raise Failure('ACME не выдал сертификат/ключ; self-signed не применяется.')
        current = STATE / 'certs/current/fullchain.pem'
        if not current.exists() or current.read_bytes() != chain.read_bytes():
            apply_certificate(config, chain, key)
        else:
            expected = validate_certificate(config, current, STATE / 'certs/current/key.pem')
            verify_served(config, expected)
            atomic_json(STATE / 'result.json', {'success': True, 'at': int(time.time()),
                                              'renewal_due': False, 'staging': config['ca'] == STAGING})
        label = 'STAGING: тестовая цепочка, НЕ публичное доверие' if config['ca'] == STAGING else "Let's Encrypt: доверенная цепочка"
        print(f"{label}; Caddy проверен с SNI {config['domain']} на {target(config)}.")
        print('✅ Проверка продления завершена.')
        lifecycle_stage('ready')
    finally:
        abort_acme()


def install_recovery():
    """Publish one complete generation before swapping a root-only pointer."""
    generation = uuid.uuid4().hex
    root = STATE / 'recovery' / generation
    root.mkdir(parents=True, mode=0o700)
    for source in PACKAGE.glob('*.py'):
        shutil.copyfile(source, root / source.name)
        (root / source.name).chmod(0o600)
    for name in ('dependencies.json', 'templates.json', 'VERSION'):
        shutil.copyfile(PACKAGE / name, root / name)
        (root / name).chmod(0o600)
    pointer = dict(generation=generation, install_id=read_json(CONFIG).get('install_id') if CONFIG.exists() else None)
    # The wrapper never imports modules from a partly replaced INSTALL directory.
    wrapper = '''#!/usr/bin/env python3
import json
from pathlib import Path
import re
import runpy
import sys
state = Path(__file__).resolve().parent
record = json.loads((state / 'recovery-current.json').read_text())
if not re.fullmatch(r'[0-9a-f]{32}', record['generation']):
    raise SystemExit('Invalid recovery generation')
root = state / 'recovery' / record['generation']
sys.path.insert(0, str(root))
runpy.run_path(str(root / 'selfsteal.py'), run_name='__main__')
'''
    candidate = STATE / 'recover.py.next'
    candidate.write_text(wrapper, encoding='utf-8')
    candidate.chmod(0o600)
    # On first install no recovery unit exists yet. On update an existing wrapper
    # continues using its old complete generation until this atomic pointer swap.
    atomic_json(STATE / 'recovery-current.json', pointer)
    os.replace(candidate, STATE / 'recover.py')


def snapshot_units():
    values = {}
    for name in ('renew.service', 'renew.timer', 'recover.service'):
        unit = 'tenant-selfsteal-' + name
        path = UNITS / unit
        result = run(['systemctl', 'show', unit, '-p', 'UnitFileState', '-p', 'ActiveState'], check=False)
        props = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        if path.exists() and (result.returncode or not props.get('UnitFileState') or not props.get('ActiveState')):
            raise Failure('Не удалось сохранить состояние собственного unit: ' + unit, 'SYSTEMD_STATE_UNKNOWN')
        values[name] = dict(content=path.read_text() if path.exists() else None,
                            enabled=props.get('UnitFileState') == 'enabled',
                            active=props.get('ActiveState') == 'active')
    return values


def restore_units(values):
    # All names were proved owned by the caller before rollback. Stop before
    # rewriting; otherwise a newly enabled timer can survive a missing old file.
    current_unit = None
    invocation = os.environ.get('INVOCATION_ID')
    if invocation:
        for name in ('recover.service', 'renew.service'):
            unit = 'tenant-selfsteal-' + name
            if run(['systemctl', 'show', unit, '-p', 'InvocationID', '--value']).stdout.decode().strip() == invocation:
                current_unit = unit
                break
        if current_unit is None:
            raise Failure('Не удалось определить службу восстановления.', 'SYSTEMD_STATE_UNKNOWN')
    protected = {current_unit}
    if current_unit == 'tenant-selfsteal-renew.service':
        # Requires=recover.service would stop this worker along with recovery.
        protected.add('tenant-selfsteal-recover.service')
    for name in values:
        if name not in ('renew.service', 'renew.timer', 'recover.service'):
            raise Failure('Неизвестный unit в резервной копии.', 'RECOVERY_INVALID')
        if (UNITS / ('tenant-selfsteal-' + name)).exists() and 'tenant-selfsteal-' + name not in protected:
            run(['systemctl', 'disable', '--now', 'tenant-selfsteal-' + name])
    for name, item in values.items():
        if name not in ('renew.service', 'renew.timer', 'recover.service'):
            raise Failure('Неизвестный unit в резервной копии.', 'RECOVERY_INVALID')
        path = UNITS / ('tenant-selfsteal-' + name)
        if item['content'] is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(item['content'], encoding='utf-8')
    run(['systemctl', 'daemon-reload'])
    for name, item in values.items():
        if item['content'] is None:
            continue
        unit = 'tenant-selfsteal-' + name
        run(['systemctl', 'enable' if item['enabled'] else 'disable', unit])
        # Do not resurrect an ACME worker from a stale active service snapshot.
        if name != 'renew.service' and not item['active'] and unit not in protected:
            run(['systemctl', 'stop', unit])
    atomic_json(STATE / 'units-restore-pending.json', values)


def activate_restored_units():
    path = STATE / 'units-restore-pending.json'
    if not path.exists() or not CONFIG.exists():
        return
    values = read_json(path)
    check_install_resources()
    for name in ('recover.service', 'renew.timer'):
        item = values.get(name, {})
        if item.get('content') is not None and item.get('active'):
            # Recovery may still be starting; never wait on our own unit/dependants.
            run(['systemctl', 'start', '--no-block', 'tenant-selfsteal-' + name])
    path.unlink()


def install_units():
    install_recovery()
    service = '''[Unit]
Description=Tenant selfsteal HTTP-01 renewal
After=network-online.target docker.service tenant-selfsteal-recover.service
Wants=network-online.target
Requires=tenant-selfsteal-recover.service
StartLimitIntervalSec=0
[Service]
Type=oneshot
UMask=0077
Environment=LC_ALL=C
ExecStart=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py renew --worker
TimeoutStartSec=20min
TimeoutStopSec=60s
KillMode=control-group
Restart=on-failure
RestartSec=1h
RestartPreventExitStatus=75
'''
    timer = '''[Unit]
Description=Check tenant selfsteal renewal regularly (acme.sh ARI policy)
[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=45min
Persistent=true
[Install]
WantedBy=timers.target
'''
    recover = '''[Unit]
Description=Recover tenant selfsteal temporary resources after reboot/SIGKILL
After=docker.service
Before=tenant-selfsteal-renew.service
[Service]
Type=oneshot
UMask=0077
Environment=LC_ALL=C
ExecStart=/usr/bin/python3 /var/lib/tenant-selfsteal/recover.py _recover
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
    for name, content in [('renew.service', service), ('renew.timer', timer),
                          ('recover.service', recover)]:
        identifier = read_json(CONFIG).get('install_id', '') if CONFIG.exists() else ''
        content = '# transitclient-install-id=' + identifier + '\n' + content
        (UNITS / ('tenant-selfsteal-' + name)).write_text(content, encoding='utf-8')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'tenant-selfsteal-recover.service'])
    # Activation is deferred until the caller releases its lifecycle lock.
    atomic_json(STATE / 'schedule-pending.json', {'install_id': identifier})


def activate_schedule():
    from renewal_schedule import PROPERTIES, fields, health
    pending = STATE / 'schedule-pending.json'
    activate_restored_units()
    if not pending.exists():
        return
    stage = read_json(STATE / 'lifecycle.json').get('stage') if (STATE / 'lifecycle.json').exists() else None
    if stage in ('preparing', 'awaiting_firewall', 'uninstalling', 'recovery_required'):
        return
    config = read_json(CONFIG)
    if read_json(pending).get('install_id') != config.get('install_id', ''):
        raise Failure('Владелец расписания не подтверждён.', 'OWNERSHIP_UNKNOWN')
    if any((STATE / name).exists() for name in ('update-transaction.json', 'configuration-transaction.json', 'uninstall.json')):
        return
    run(['systemctl', 'enable', '--now', 'tenant-selfsteal-renew.timer'])
    run(['systemctl', 'is-enabled', '--quiet', 'tenant-selfsteal-renew.timer'])
    run(['systemctl', 'is-active', '--quiet', 'tenant-selfsteal-renew.timer'])
    deadline = time.monotonic() + 10
    while True:
        timer = fields(run(['systemctl', 'show', 'tenant-selfsteal-renew.timer',
                            *[part for prop in PROPERTIES for part in ('-p', prop)]]).stdout.decode())
        service = fields(run(['systemctl', 'show', 'tenant-selfsteal-renew.service',
                              '-p', 'ActiveState', '-p', 'Result']).stdout.decode())
        state = health(timer, service)
        if state in ('running', 'waiting', 'service_failed'):
            pending.unlink(missing_ok=True)
            if state == 'service_failed':
                print('⚠️ Расписание включено; последняя проверка продления завершилась ошибкой. Используйте diagnose.')
            return
        if time.monotonic() >= deadline:
            raise Failure('Состояние расписания не подтверждено. Проверьте systemd timer.', 'RENEW_TIMER_UNKNOWN')
        time.sleep(0.2)


def ask(label, default=''):
    suffix = f' [{default}]' if default != '' else ''
    return input(label + suffix + ': ').strip() or str(default)


def interactive_config(args):
    print('⚙️ Настройка')
    config = {'domain': ask('Домен из бота', getattr(args, 'domain', None) or ''),
              'vpn_port': ask('Порт для проксирования трафика', getattr(args, 'vpn_port', None) or 443),
              'challenge_port': ask('HTTP-порт для сертификата из бота', getattr(args, 'challenge_port', None) or 8080),
              'relay_ip': getattr(args, 'relay_ip', None) or '',
              'local_port': ask('Локальный HTTPS-порт веб-сервера', getattr(args, 'local_port', None) or 9443),
              'docker_network': getattr(args, 'docker_network', None) or '',
              'vpn_container': getattr(args, 'vpn_container', None) or '',
              'firewall': getattr(args, 'firewall', None) or 'auto',
              'ca': STAGING if args.staging_ca_file else PRODUCTION,
              'staging_ca_file': str(Path(args.staging_ca_file).resolve()) if args.staging_ca_file else None,
              'package_url': '', 'package_version': '', 'package_sha256': '',
              'install_id': uuid.uuid4().hex, 'schema_version': 2}
    config = validate_config(config)
    return config


def detect_vpn_network(config, report):
    """Derive only the attributed listener's container, never guess from its image."""
    containers = {row['name']: row for row in report.get('docker', {}).get('containers', [])
                  if row['running']}
    owners = {row.get('container') for row in report.get('selected_ports', {}).get('vpn', {}).get('listeners', [])}
    candidates = sorted(name for name in owners if name in containers)
    chosen = config.get('vpn_container')
    if not chosen and len(candidates) == 1:
        chosen = candidates[0]
    elif not chosen and len(candidates) > 1:
        print('На VPN-порту несколько контейнеров: ' + ', '.join(candidates))
        chosen = ask('Контейнер ноды')
        if chosen not in candidates:
            raise Failure('Выберите контейнер из найденного списка.', 'VPN_CONTAINER_UNKNOWN')
    if not chosen:
        return
    if chosen not in containers:
        raise Failure('Указанный контейнер ноды не найден среди работающих.', 'VPN_CONTAINER_UNKNOWN')
    config['vpn_container'] = chosen
    mode = containers[chosen]['network_mode']
    if mode == 'host':
        if config.get('docker_network'):
            raise Failure('Нода использует host; отдельная bridge-сеть ей недоступна.', 'VPN_NETWORK_MISSING')
        print('Нода: ' + chosen + ' · host')
        return
    if mode in ('none',) or mode.startswith('container:'):
        raise Failure('Сетевой режим ноды требует ручной настройки доступа к Caddy.', 'VPN_NETWORK_MISSING')
    if config.get('docker_network'):
        return
    assert_local_docker()
    networks = json.loads(run(['docker', 'inspect', '--format',
                              '{{json .NetworkSettings.Networks}}', chosen]).stdout)
    names = sorted(name for name in networks if name != 'bridge')
    if len(names) == 1:
        config['docker_network'] = names[0]
    elif names:
        print('Сети ноды: ' + ', '.join(names))
        config['docker_network'] = ask('Общая сеть для Caddy')
        if config['docker_network'] not in names:
            raise Failure('Выбранная сеть недоступна ноде.', 'VPN_NETWORK_MISSING')
    else:
        raise Failure('Нода в стандартной bridge-сети. Нужна отдельная общая сеть по инструкции; '
                      'контейнер ноды не изменён.', 'VPN_NETWORK_MISSING')
    validate_config(config)
    print('Нода: ' + chosen + ' · сеть ' + config['docker_network'])


def check_install_resources():
    if CONFIG.with_name('restore-transaction.json').exists():
        raise Failure('Восстановление прервано. Выполните transitclient _recover или повторите restore.', 'RESTORE_RECOVERY_REQUIRED')
    if CONFIG.with_name('uninstall-transaction.json').exists():
        raise Failure('Удаление прервано. Завершите его через transitclient _recover.', 'UNINSTALL_RECOVERY_REQUIRED')
    if CONFIG.is_symlink() or INSTALL.is_symlink() or STATE.is_symlink():
        raise Failure('Пути установки заняты символическими ссылками.', 'OWNERSHIP_CONFLICT')
    if not CONFIG.exists() and ((INSTALL.exists() and not package_owned()) or (STATE.exists() and any(STATE.iterdir()))):
        raise Failure('Каталоги установки уже заняты без сохранённой конфигурации. '
                      'Проверьте их вручную; они не перезаписаны.', 'OWNERSHIP_UNKNOWN')
    for name in ('renew.service', 'renew.timer', 'recover.service'):
        path = UNITS / ('tenant-selfsteal-' + name)
        content = path.read_text() if path.is_file() and not path.is_symlink() else ''
        expected = {'renew.service': 'ExecStart=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py renew',
                    'renew.timer': 'Description=Check tenant selfsteal renewal regularly (acme.sh ARI policy)',
                    'recover.service': 'ExecStart=/usr/bin/python3 /var/lib/tenant-selfsteal/recover.py _recover'}[name]
        match = re.search(r'^# transitclient-install-id=([0-9a-f]{32})$', content, re.M)
        identifier = read_json(CONFIG).get('install_id') if CONFIG.exists() else None
        if path.is_symlink() or (path.exists() and (not CONFIG.exists() or expected not in content
                                                  or match and match.group(1) != identifier)):
            raise Failure('Имена systemd units заняты чужими ресурсами.', 'OWNERSHIP_CONFLICT')
    check_launcher()


def package_owned():
    try:
        marker = read_json(INSTALL / '.transitclient-package.json')
        return (not INSTALL.is_symlink() and not (INSTALL / 'selfsteal.py').is_symlink()
                and re.fullmatch(r'[0-9a-f]{32}', marker['install_id'])
                and hashlib.sha256((INSTALL / 'selfsteal.py').read_bytes()).hexdigest() == marker['controller_sha256'])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def mark_package(config):
    atomic_json(INSTALL / '.transitclient-package.json', {
        'install_id': config.get('install_id') or uuid.uuid4().hex,
        'controller_sha256': hashlib.sha256((INSTALL / 'selfsteal.py').read_bytes()).hexdigest(),
        'version': (INSTALL / 'VERSION').read_text().strip()})


def copy_package(source, destination):
    """Only distributable sources; never copy a clone's .git, .env or test caches."""
    files = [source / name for name in ('selfsteal.sh', 'VERSION', 'dependencies.json', 'templates.json', 'README.md', 'LICENSE', 'NOTICE.md')]
    files.extend(source.glob('*.py'))
    for directory in ('vendor', 'site', 'docs', 'tests'):
        if (source / directory).is_symlink():
            raise Failure('Каталог пакета содержит символическую ссылку.', 'PACKAGE_UNSAFE')
        files.extend(path for path in (source / directory).rglob('*') if path.is_file()
                     and '__pycache__' not in path.parts and path.suffix != '.pyc'
                     and path.name.casefold() != 'agents.md'
                     and (directory != 'docs' or path.relative_to(source / 'docs').as_posix()
                          in ('implementation.md', 'integration.md', 'operations.md', 'publication.md')))
    for path in files:
        if not path.is_file() or any(parent.is_symlink() for parent in (path, *path.parents)
                                    if parent.is_relative_to(source)):
            raise Failure('Пакет содержит отсутствующий файл/символическую ссылку.', 'PACKAGE_UNSAFE')
    destination.mkdir(mode=0o700)
    for path in files:
        copied = destination / path.relative_to(source)
        copied.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(path, copied)
        copied.chmod(0o600)


def installation_plan(config):
    manifest = dependency_lock()
    missing = [name for name in ('openssl', 'socat', 'curl', 'docker') if not shutil.which(name)]
    if not Path('/etc/ssl/certs/ca-certificates.crt').exists():
        missing.append('ca-certificates')
    print('\n📋 План установки')
    print('  Домен: ' + config['domain'])
    print(f"  VPN {config.get('vpn_port') or '?'} · HTTP {config['challenge_port']} · HTTPS {target(config)}")
    print('  Отдельный Caddy ' + manifest['caddy']['version'] + ' в Docker Compose.')
    if missing:
        print('  Установить пакеты: ' + ', '.join(missing))
    print('  Сертификат: ' + ('тестовый' if config['ca'] == STAGING else "Let's Encrypt") + '; автоматическое продление.')
    print('  Сначала HTTP-проверка до двух минут без CA; первый выпуск только после её успеха.')
    print('  Команда управления: transitclient. Нода и существующие сайты сохраняются.')
    return confirm('Установить?')


def install(args):
    global PACKAGE
    check_install_resources()
    if (STATE / 'update-transaction.json').exists():
        raise Failure('Замена пакета не завершена. Сначала выполните '
                      'sudo python3 /var/lib/tenant-selfsteal/recover.py _recover.', 'UPDATE_RECOVERY_REQUIRED')
    switching = getattr(args, '_new_domain', False)
    retained_package = (not CONFIG.exists() or switching) and INSTALL.exists() and PACKAGE != INSTALL
    retained_marker = read_json(INSTALL / '.transitclient-package.json') if retained_package else None
    if retained_package:
        print('📦 Будет обновлён Transit Client: ' + (INSTALL / 'VERSION').read_text().strip()
              + ' → ' + (PACKAGE / 'VERSION').read_text().strip() + '.')
        print('Прежняя версия сохранится на время установки для восстановления.')
    diagnostics = diagnostic_module()
    initial_config = validate_config(read_json(CONFIG)) if CONFIG.exists() else None
    if switching and (STATE / 'certs/current').exists() and not (STATE / 'certs/current').is_symlink():
        raise Failure('Неизвестный формат текущего сертификата; требуется ручная сверка.', 'OWNERSHIP_UNKNOWN')
    # An obsolete domain must not fail DNS before the user selects the new one.
    initial_report = diagnostics.collect({key: value for key, value in (initial_config or {}).items()
                                          if key != 'domain'} if switching else initial_config)
    diagnostics.display_compact(initial_report)
    import terminal_ui
    terminal = terminal_ui.Terminal(no_color=getattr(args, 'no_color', False))
    terminal.line('Режим установки', 'bold')
    for number, label in [('1', '🚀 Установить веб-сервер Caddy [Рекомендуем]'),
                          ('2', '📖 Свой веб-сервер [Инструкция]'), ('0', '⬅️ Выход')]:
        values = terminal_ui.option(number, label)
        if ' [' in label and sum(terminal_ui.display_width(value) for value, _ in values) > terminal.width:
            title, tag = label.rsplit(' ', 1)
            terminal.fragments(terminal_ui.option(number, title))
            terminal.line('      ' + tag)
        else:
            terminal.fragments(values)
    mode = ask('Режим', '1')
    if mode == '2':
        guide(None)
        return
    if mode != '1':
        raise Failure('Установка отменена.', 'CANCELLED')
    if CONFIG.exists() and not switching:
        if (STATE / 'ufw-activation.json').exists():
            raise Failure('Незавершённая настройка UFW. Выполните sudo transitclient _recover, '
                          'затем повторите установку.', 'FIREWALL_RECOVERY_REQUIRED')
        config = validate_config(read_json(CONFIG))
        if getattr(args, 'firewall', None) and args.firewall != config['firewall']:
            raise Failure('Для смены firewall используйте transitclient configure --firewall ' + args.firewall +
                          ' и пункт 5. Сохранённая политика не изменена.', 'FIREWALL_CHANGE_REQUIRED')
        print('Сохранены прежние настройки, ACME account и сертификат.')
        if INSTALL.exists() and PACKAGE != INSTALL:
            if not package_owned() or (INSTALL / 'VERSION').read_text().strip() != (PACKAGE / 'VERSION').read_text().strip():
                raise Failure('Обнаружен прежний установленный пакет. Для смены версии используйте update '
                              'с архивом, версией и доверенным SHA256; данные не перезаписаны.', 'UPDATE_REQUIRED')
            PACKAGE = INSTALL
    else:
        defaults = SimpleNamespace(**vars(args))
        if switching:
            if not initial_config.get('install_id'):
                raise Failure('Сначала обновите прежнюю установку штатной командой update.', 'OWNERSHIP_UNKNOWN')
            for name in ('vpn_port', 'challenge_port', 'local_port', 'docker_network', 'vpn_container', 'firewall'):
                if not getattr(defaults, name, None):
                    setattr(defaults, name, initial_config.get(name))
            defaults.staging_ca_file = initial_config.get('staging_ca_file')
        config = interactive_config(defaults)
        if switching:
            if config['domain'] == initial_config['domain']:
                raise Failure('Домен совпадает с текущим. Используйте меню управления.', 'DOMAIN_UNCHANGED')
            config['install_id'] = initial_config['install_id']
            config['firewall'] = initial_config['firewall']
            policy = initial_config.get('firewall_effective') or initial_config['firewall']
            config['firewall_effective'] = 'preserve' if policy == 'manual' else policy
            if config['firewall_effective'] not in ('ufw', 'preserve'):
                raise Failure('Сначала выберите режим в transitclient → Настройки → Firewall.',
                              'FIREWALL_MODE_REQUIRED')
            config['ca'] = initial_config['ca']
            config['staging_ca_file'] = initial_config.get('staging_ca_file')
        report = diagnostics.collect(config)
        detect_vpn_network(config, report)
        check_dns(config)
        check_challenge_port(config)
        if (not config.get('docker_network') and not (switching and config['local_port'] == initial_config['local_port'])
                and not free_port(config['local_port'], '127.0.0.1')):
            raise Failure('Локальный HTTPS-порт занят; выберите другой, не останавливая процесс.', 'HTTPS_PORT_BUSY')
    report = diagnostics.collect(config)
    diagnostics.display_compact(report, ports=True)
    for check in report['checks']:
        if check['code'] in ('HTTP_PORT_BUSY', 'HTTPS_PORT_BUSY', 'DOCKER_CONTEXT_UNSAFE', 'DOCKER_INVENTORY_FAILED',
                             'CONTAINER_INSPECT_FAILED', 'DNS_RELAY_MISMATCH', 'DNS_LOOKUP_FAILED'):
            raise Failure(check['message'], check['code'])
    assert_local_docker()
    if shutil.which('docker'):
        assert_compose_owned()
        validate_network(config)
        run(['docker', 'info'], timeout=30)
    elif config.get('docker_network'):
        raise Failure('Выбранная bridge-сеть требует уже работающий Docker.', 'DOCKER_MISSING')
    vpn_checks = [item for item in report['checks'] if item['code'].startswith('VPN_')]
    if any(item['code'] in ('VPN_LISTENER_MISSING', 'VPN_LOOPBACK_ONLY', 'VPN_PORT_UNKNOWN') for item in vpn_checks):
        print('⚠️ VPN не подтверждён. Установщик не устанавливает ноду и не проверяет REALITY credentials.')
        if not confirm('Продолжить только подготовку selfsteal?'):
            raise Failure('Подготовка отменена.', 'CANCELLED')
    firewall = firewall_module()
    try:
        firewall_plan = ({'changes': [], 'effective': config['firewall_effective']}
                         if switching else firewall.plan(config, report, run))
    except firewall.FirewallError as exc:
        raise Failure(str(exc), exc.code) from exc
    for change in firewall_plan['changes']:
        print('🛡️ ' + change)
    chosen_template = None
    if not switching and (not CONFIG.exists() or getattr(args, 'template', None) is not None):
        chosen_template = select_template(getattr(args, 'template', None) or 'random')
        print('🎨 Выбранный сайт: ' + chosen_template)
    if switching:
        print('Прежний домен: ' + initial_config['domain'] + ' → новый: ' + config['domain'])
        print('Сайт, ACME-аккаунт и постоянные правила firewall сохраняются. '
              'При смене портов согласуйте доступ в firewall и настройки VPN-ноды.')
    if not installation_plan(config):
        raise Failure('Установка отменена.', 'CANCELLED')
    if switching:
        import installation_flow
        installation_flow.backup_installation(SimpleNamespace(**globals()), initial_config)
        previous = {'config': initial_config, 'domain_switch': True,
                    'certificate': os.readlink(STATE / 'certs/current') if (STATE / 'certs/current').is_symlink() else None,
                    'metadata': {name: read_json(STATE / name) if (STATE / name).exists() else None
                                 for name in ('lifecycle.json', 'http-path.json', 'result.json', 'schedule-pending.json')},
                    **{name: (STATE / name).read_text() if (STATE / name).exists() else None
                       for name in ('Caddyfile', 'compose.yaml')}}
        # The stable boot helper must understand this journal before config changes.
        install_recovery()
        atomic_json(STATE / 'configuration-transaction.json', previous)
    package_transaction = False
    try:
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        STATE.chmod(0o700)
        config.setdefault('install_id', uuid.uuid4().hex)
        config['firewall_effective'] = firewall_plan.get('effective', 'preserve' if config['firewall'] == 'manual' else config['firewall'])
        if not CONFIG.exists():
            if config['ca'] == STAGING:
                trust = STATE / 'staging-trust.pem'
                shutil.copyfile(config['staging_ca_file'], trust)
                trust.chmod(0o600)
                config['staging_ca_file'] = str(trust)
            atomic_json(CONFIG, config)
        else:
            previous = read_json(CONFIG)
            if not (STATE / 'legacy-config-backup.json').exists():
                atomic_json(STATE / 'legacy-config-backup.json', previous)
            if not switching and all((STATE / name).exists() for name in ('Caddyfile', 'compose.yaml')):
                atomic_json(STATE / 'configuration-transaction.json', {'config': previous,
                            **{name: (STATE / name).read_text() for name in ('Caddyfile', 'compose.yaml')},
                            'units': {name: (UNITS / ('tenant-selfsteal-' + name)).read_text()
                                      for name in ('renew.service', 'renew.timer', 'recover.service')
                                      if (UNITS / ('tenant-selfsteal-' + name)).exists()}})
            atomic_json(CONFIG, config)
        lifecycle_stage('preparing', issuance_authorized=True)
        dependencies()
        if PACKAGE != INSTALL:
            with tempfile.TemporaryDirectory(dir=INSTALL.parent, prefix='tenant-selfsteal-stage-') as staging:
                staged = Path(staging) / 'package'
                copy_package(PACKAGE, staged)
                if retained_package and not INSTALL.exists():
                    raise Failure('Сохранённый пакет исчез после диагностики.', 'OWNERSHIP_CONFLICT')
                if INSTALL.exists():
                    if (not retained_package or not package_owned()
                            or read_json(INSTALL / '.transitclient-package.json') != retained_marker):
                        raise Failure('Путь установки изменился после диагностики.', 'OWNERSHIP_CONFLICT')
                    identifier = uuid.uuid4().hex
                    backup = INSTALL.with_name('tenant-selfsteal.previous-' + identifier)
                    snapshot = STATE / ('update-backup-' + identifier)
                    if backup.exists() or snapshot.exists() or (STATE / 'update-transaction.json').exists():
                        raise Failure('Сохранена прежняя операция замены пакета; выполните '
                                      'sudo python3 /var/lib/tenant-selfsteal/recover.py _recover.', 'UPDATE_RECOVERY_REQUIRED')
                    snapshot.mkdir(mode=0o700)
                    helpers = ('recover.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py')
                    for name in ('Caddyfile', 'compose.yaml', 'docker-compose', 'recovery-current.json', 'schedule-pending.json', *helpers):
                        if (STATE / name).exists():
                            shutil.copy2(STATE / name, snapshot / name)
                    atomic_json(snapshot / 'units.json', snapshot_units())
                    atomic_json(snapshot / 'config.json', initial_config if switching else read_json(CONFIG))
                    # Stable recovery must exist before a possible rename gap.
                    install_recovery()
                    atomic_json(STATE / 'update-transaction.json', {'id': identifier})
                    package_transaction = True
                    os.replace(INSTALL, backup)
                os.replace(staged, INSTALL)
            PACKAGE = INSTALL
        (INSTALL / 'selfsteal.sh').chmod(0o700)
        mark_package(config)
        install_launcher()
        render_caddy(config)
        # Recovery is installed before issuance, not after a successful first run.
        install_units()
        if package_transaction:
            # Commit the package before firewall/ACME: later issuance failure
            # leaves the new partial installation available for normal renew.
            (STATE / 'update-transaction.json').unlink()
            package_transaction = False
        try:
            firewall_result = None if switching else firewall.apply(firewall_plan, config, STATE, run, atomic_json)
        except firewall.FirewallError as exc:
            raise Failure(str(exc), exc.code) from exc
        if chosen_template is not None:
            change_template(config, chosen_template, approved=True)
        if not switching and (STATE / 'certs/current').exists():
            compose('run', '--rm', '--no-deps', 'caddy', 'caddy', 'validate',
                    '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')
            compose('up', '-d', '--no-build', 'caddy')
            reload_caddy()
            verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem'))
        if not switching:
            (STATE / 'configuration-transaction.json').unlink(missing_ok=True)
        lifecycle_stage('runtime_ready')
        if firewall_result and firewall_result.get('status') == 'awaiting-confirmation':
            lifecycle_stage('awaiting_firewall')
            print('Откройте НОВОЕ SSH-соединение и в течение 180 секунд выполните:')
            print('sudo transitclient firewall-confirm --confirmation-token ' + firewall_result['token'])
            return
        if switching or not (STATE / 'certs/current').exists():
            try:
                http_self_test(config, approved=True)
            except Failure as exc:
                if switching:
                    raise
                lifecycle_stage('awaiting_http', reason=exc.code)
                print('⚠️ Пакет подготовлен. HTTP-путь пока не подтверждён; запрос в CA не отправлен.')
                print('После исправления маршрута: sudo transitclient self-test --http01, затем sudo transitclient renew.')
                return
        renew(config)
        (STATE / 'configuration-transaction.json').unlink(missing_ok=True)
        print('Теперь настройте VPN-ноду и нажмите в боте «Готово, проверить backend».')
    except BaseException:
        try:
            if package_transaction:
                recover_update()
        finally:
            recover_configuration()
        raise
    if switching:
        print('✅ Новый домен настроен: ' + config['domain'])
        print('Проверьте новый домен/SNI и target в VPN-ноде. Правила постоянного firewall сохранены.')
        installation_flow.cleanup_previous_packages(SimpleNamespace(**globals()), config)
        try:
            installation_flow.cleanup_old_data(SimpleNamespace(**globals()), config)
        except (KeyboardInterrupt, EOFError):
            print('\nОчистка отменена. Новая установка сохранена.')
        except (Failure, OSError, ValueError, KeyError, TypeError):
            print('⚠️ Очистка старых данных остановлена. Новый домен настроен; оставшиеся данные сохранены.')


def safe_config():
    if not CONFIG.exists():
        return None
    try:
        return validate_config(read_json(CONFIG))
    except (OSError, ValueError, Failure, KeyError, TypeError):
        return None


def certificate_status(config):
    if config is None:
        return {'state': 'missing'}
    chain = STATE / 'certs/current/fullchain.pem'
    if not chain.exists():
        return {'state': 'missing'}
    try:
        decoded = ssl._ssl._test_decode_cert(str(chain))
        expiry = int(ssl.cert_time_to_seconds(decoded['notAfter']))
        issuer = [str(value) for fields in decoded.get('issuer', []) for name, value in fields
                  if name in ('organizationName', 'commonName')]
        return {'state': 'expired' if expiry <= int(time.time()) else 'present',
                'domain': config['domain'], 'issuer': issuer,
                'not_before': decoded['notBefore'], 'not_after': decoded['notAfter'],
                'days_remaining': max(0, (expiry - int(time.time())) // 86400),
                'staging': config['ca'] == STAGING}
    except (OSError, ValueError, KeyError):
        return {'state': 'invalid', 'error': 'CERT_UNREADABLE'}


def saved_status(config):
    """Read installation metadata without inventory, network checks or recovery."""
    report = {'checks': []}
    report['installation'] = {'configured': config is not None,
                              'config_present': CONFIG.exists(),
                              'version': (PACKAGE / 'VERSION').read_text().strip(),
                              'target': target(config) if config else None,
                              'caddy_image': dependency_lock()['caddy']['image'],
                              'certificate': certificate_status(config)}
    if (STATE / 'lifecycle.json').exists():
        report['installation']['lifecycle'] = read_json(STATE / 'lifecycle.json')
    if config:
        report['installation']['firewall_requested'] = config['firewall']
        report['installation']['firewall_effective'] = config.get('firewall_effective') or config['firewall']
    report['pending'] = [name for name in ('firewall.json', 'ufw-activation.json', 'certificate-transaction.json',
                         'configuration-transaction.json', 'update-transaction.json', 'site-transaction.json',
                         'operation.json', 'uninstall.json', 'schedule-pending.json') if (STATE / name).exists()]
    if CONFIG.with_name('uninstall-transaction.json').exists():
        report['pending'].append('uninstall-transaction.json')
        report['checks'].append(dict(code='UNINSTALL_RECOVERY_REQUIRED', status='unknown',
                                    message='Удаление прервано после остановки ресурсов. Выполните transitclient _recover.'))
    preparation = STATE / 'ufw-package-preparation.json'
    if preparation.exists():
        try:
            if read_json(preparation).get('status') != 'installed':
                report['pending'].append(preparation.name)
                report['checks'].append({'code': 'UFW_PACKAGE_PREPARATION_PENDING', 'status': 'error',
                                        'message': 'Установка UFW не завершена; резервная копия сохранена. Повторите install после проверки пакета.'})
        except (OSError, ValueError, AttributeError):
            report['pending'].append(preparation.name)
            report['checks'].append({'code': 'UFW_PACKAGE_PREPARATION_UNREADABLE', 'status': 'error',
                                    'message': 'Не удалось прочитать журнал подготовки UFW.'})
    try:
        site = read_json(STATE / 'site-template.json') if (STATE / 'site-template.json').exists() else {}
        report['installation']['site'] = {key: site[key] for key in ('id', 'name', 'commit') if key in site}
    except (ValueError, OSError):
        report['installation']['site'] = {'error': 'TEMPLATE_METADATA_UNREADABLE'}
    try:
        last = read_json(STATE / 'result.json') if (STATE / 'result.json').exists() else None
        allowed = ('success', 'at', 'error', 'message', 'stage', 'staging', 'renewal_due', 'certificate_sha256')
        report['last_operation'] = {key: last[key] for key in allowed if key in last and
                                    isinstance(last[key], (str, int, bool, type(None)))} if isinstance(last, dict) else None
    except (OSError, ValueError):
        report['last_operation'] = {'success': False, 'error': 'RESULT_UNREADABLE'}
    return report


def status(config, json_output=False, no_color=False):
    """Standalone CLI snapshot; the menu already shows these seven rows."""
    report = saved_status(config)
    import client_panel
    import terminal_ui
    app = SimpleNamespace(**globals())
    app.safe_config = lambda: config
    panel = client_panel.snapshot(app)
    report['summary'] = dict(panel['rows'])
    report['installation']['state'] = panel['installation']
    if json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        terminal = terminal_ui.Terminal(no_color=no_color)
        terminal.line('📊 Transit Client · ' + report['installation']['version'], 'bold')
        terminal_ui.draw_rows(terminal, panel['rows'])
        if report['pending']:
            terminal.line('⚠️ Есть незавершённая операция → Диагностика.', 'warning')
        elif panel['installation'] in ('broken', 'incomplete'):
            terminal.line('⚠️ ' + panel['hint'], 'warning')
    return report


def diagnose(config, json_output=False, interactive=False, full=False, no_color=False):
    """Collect inventory and verify HTTPS only for explicitly requested checks."""
    report = saved_status(config)
    diagnostics = diagnostic_module()
    inventory = diagnostics.collect(config)
    report['checks'] = inventory['checks'] + report['checks']
    report.update({key: value for key, value in inventory.items() if key != 'checks'})
    report['units'] = {}
    for unit in ('tenant-selfsteal-renew.timer', 'tenant-selfsteal-renew.service'):
        try:
            result = run(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'Result',
                          '-p', 'UnitFileState', '-p', 'SubState', '-p', 'Job', '-p', 'NextElapseUSecRealtime',
                          '-p', 'ExecMainStartTimestamp', '-p', 'ExecMainExitTimestamp'], check=False)
            report['units'][unit] = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        except (OSError, subprocess.SubprocessError):
            report['units'][unit] = {'error': 'SYSTEMD_UNAVAILABLE'}
    timer = report['units']['tenant-selfsteal-renew.timer']
    from renewal_schedule import health
    schedule = health(timer, report['units']['tenant-selfsteal-renew.service'])
    report['renewal_schedule'] = schedule
    if config and schedule not in ('waiting', 'running'):
        report['checks'].append({'code': 'RENEW_TIMER_INACTIVE', 'status': 'error',
                                 'message': 'Продление требует проверки: ' + schedule + '.'})
    verified_identity = None
    if config and (STATE / 'certificate-transaction.json').exists():
        report['checks'].append({'code': 'CERT_SWITCH_PENDING', 'status': 'unknown',
                                 'message': 'Переключение сертификата не завершено; диагностика не запускает recovery.'})
    elif config:
        if interactive:
            import client_panel
            verified_identity = client_panel.tls_identity(SimpleNamespace(**globals()), config)
        try:
            verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem',
                                                        STATE / 'certs/current/key.pem'), attempts=1)
            report['checks'].append({'code': 'CERT_SERVED', 'status': 'ok',
                                     'message': 'SNI, SAN, цепочка, ключ, TLS 1.3/h2 и выдаваемый сертификат подтверждены.'})
        except (Failure, OSError, ValueError, subprocess.SubprocessError) as exc:
            report['checks'].append({'code': 'CERT_NOT_APPLIED', 'status': 'error',
                                     'message': str(exc) if isinstance(exc, Failure) else 'Не удалось проверить сертификат/HTTPS. Проверьте наличие файлов и Caddy.'})
    if interactive:
        import client_panel
        identity = client_panel.tls_identity(SimpleNamespace(**globals()), config) if config else None
        checked = any(item['code'] in ('CERT_SERVED', 'CERT_NOT_APPLIED') for item in report['checks'])
        if checked:
            _menu_tls_check.clear()
            _menu_tls_check.update(at=int(time.time()), identity=verified_identity,
                                   success=identity is not None and identity == verified_identity
                                   and any(item['code'] == 'CERT_SERVED' for item in report['checks']))
    if json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return report
    if not full:
        diagnostics.display(report, no_color=no_color)
        return report
    print('🔍 Подробный отчёт · Transit Client · ' + report['installation']['version'])
    if config:
        print(f"Домен: {config['domain']}; VPN: {config.get('vpn_port') or 'не подтверждён'}; "
              f"HTTP: {config['challenge_port']}; HTTPS target: {target(config)}")
        print('Веб-сервер: отдельный Caddy · Docker Compose · ' +
              ('сеть ' + config['docker_network'] if config.get('docker_network') else 'host / loopback'))
    else:
        print('Установка ещё не настроена.' if not CONFIG.exists() else '❌ CONFIG_INVALID: сохранённая конфигурация повреждена; автоматическое исправление не выполняется.')
    print('Сертификат: ' + json.dumps(report['installation']['certificate'], ensure_ascii=False))
    import client_panel
    site = report['installation']['site']
    print('Сайт: ' + client_panel.sanitize(site.get('name', 'неизвестно')))
    print('Последняя операция: ' + json.dumps(report['last_operation'], ensure_ascii=False))
    print('Незавершённые ресурсы: ' + (', '.join(report['pending']) or 'нет'))
    for unit, values in report['units'].items():
        print(unit + ': ' + json.dumps(values, ensure_ascii=False))
    diagnostics.display(report, full=True)
    return report


def guide(config, interactive=False):
    print('📖 Существующий веб-сервер: интеграция только по инструкции.')
    print('Инструкция: https://github.com/donkyboss1/transitclient/blob/main/docs/integration.md')
    if config:
        if interactive:
            print(f"REALITY: target {target(config)} · serverNames {config['domain']} · xver 0")
        else:
            print('REALITY (несекретные поля): ' + json.dumps({'target': target(config), 'xver': 0,
                                                            'serverNames': [config['domain']]}, ensure_ascii=False))
        print('Для bridge VPN подключите ноду к выбранной сети самостоятельно. '
              'Не используйте её loopback для доступа к Caddy на host.')
    print('Нода/панель не устанавливается и не изменяется. TCP listener не доказывает исправность REALITY.')


def probe_server(config, token):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    if not re.fullmatch(r'[0-9a-f]{32}', token or ''):
        raise Failure('Некорректный идентификатор сетевого теста.', 'INVALID_PROBE')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            valid = self.path == '/.well-known/acme-challenge/' + token and self.headers.get('Host', '').split(':')[0] == config['domain']
            body = ('transitclient-check:' + token).encode() if valid else b'Not found'
            self.send_response(200 if valid else 404)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass
    with HTTPServer(('0.0.0.0', config['challenge_port']), Handler) as server:
        server.serve_forever()


def stop_probe():
    if _operation_id:
        stop_scoped_transient(_operation_id, 'probe')
    else:
        stop_owned_transient('tenant-selfsteal-probe.service', 'Transitclient HTTP probe')
    cleanup_firewall()


def http_self_test(config, *, approved=False, external_check=False):
    if not approved:
        check_dns(config)
        check_challenge_port(config)
        if not confirm('Запустить HTTP self-test на срок до двух минут?'):
            raise Failure('Сетевой тест отменён.', 'CANCELLED')
    with operation_scope(config, 'http_probe'):
        return _http_self_test(config, approved=True, external_check=external_check)


def _http_self_test(config, *, approved=False, external_check=False):
    addresses = check_dns(config)
    check_challenge_port(config)
    print(f"🔍 Временный HTTP self-test: домен:80 релея → backend:{config['challenge_port']}.")
    print('Это сетевой тест из текущей точки, без CA и выпуска сертификата. Firewall/слушатель будут временными.')
    if not approved and not confirm('Запустить HTTP self-test на срок до двух минут?'):
        raise Failure('Сетевой тест отменён.', 'CANCELLED')
    token = uuid.uuid4().hex  # A disposable public diagnostic nonce, never an ACME response.
    address = f"http://{config['domain']}/.well-known/acme-challenge/{token}"
    print('Для независимой проверки во время теста: curl --fail --noproxy "*" ' + shlex.quote(address))
    created = False
    scope = 'backend'
    started = time.monotonic()
    try:
        identifier = _operation_id
        record = operation_record(identifier)
        unit = scoped_unit(identifier, 'probe')
        assert_transient_available(unit + '.service')
        open_firewall(config)
        claim_resource(identifier, 'probe')
        run(['systemd-run', '--unit=' + unit, '--description=Transitclient probe ' + record['install_id'] + ' ' + identifier, '--collect', '--service-type=exec',
             '--property=RuntimeMaxSec=120s', '--property=KillMode=control-group',
             '--property=ExecStopPost=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py _cleanup --operation-id ' + identifier,
             '/usr/bin/python3', INSTALL / 'selfsteal.py', '_probe-server', '--operation-id', identifier, '--probe-token', token])
        created = True
        results = []
        for ip in addresses:
            confirmed = False
            last_failure = 'не получен ответ'
            for attempt in range(5):
                remaining = 120 - (time.monotonic() - started)
                if remaining <= 0:
                    break
                connection = http.client.HTTPConnection(ip, 80, timeout=min(5, remaining))
                try:
                    connection.request('GET', '/.well-known/acme-challenge/' + token,
                                       headers={'Host': config['domain'], 'Connection': 'close'})
                    upstream = connection.getresponse()
                    confirmed = upstream.status == 200 and upstream.read(128) == ('transitclient-check:' + token).encode()
                    last_failure = ('HTTP 200: неверный контрольный ответ' if upstream.status == 200
                                    else f'HTTP {upstream.status}')
                    # systemd exec readiness precedes Python binding the listener.
                    if confirmed or upstream.status not in (502, 503, 504):
                        break
                except (OSError, http.client.HTTPException) as exc:
                    last_failure = ('таймаут' if isinstance(exc, TimeoutError) else
                                    'отказ в соединении' if isinstance(exc, ConnectionRefusedError) else
                                    'ошибка сети' if isinstance(exc, OSError) else 'ошибка HTTP')
                finally:
                    connection.close()
                pause = min(1, max(0, 120 - (time.monotonic() - started)))
                if attempt < 4 and pause > 0:
                    time.sleep(pause)
            if not confirmed:
                print(f'⚠️ Проверка {ip}:80: {last_failure}.')
            results.append(dict(address=ip, confirmed=confirmed))
        if not results or not all(row['confirmed'] for row in results):
            if not external_check:
                raise Failure('HTTP-путь не подтверждён из этой точки. Проверьте готовность маршрута в боте, '
                              'NAT/firewall; при NAT hairpin повторите self-test --http01 --external-check '
                              'с независимой внешней машиной.', 'HTTP_PATH_UNCONFIRMED')
            print('Локальная проверка не подтвердилась. Пока работает слушатель, проверьте показанный URL с внешней машины.')
            for ip in addresses:
                resolved = '[' + ip + ']' if ':' in ip else ip
                print('curl --fail --noproxy "*" --resolve ' + shlex.quote(config['domain'] + ':80:' + resolved) + ' ' + shlex.quote(address))
            print('Требуется точный ответ: transitclient-check:' + token)
            if not confirm('Внешняя машина получила HTTP200 и точный ответ для КАЖДОГО указанного A/AAAA?') or time.monotonic() - started >= 120:
                raise Failure('Внешняя проверка не подтверждена либо её срок истёк.', 'HTTP_PATH_UNCONFIRMED')
            scope = 'operator_reported'
            print('⚠️ Внешний HTTP-путь подтверждён по вашему сообщению; установщик не проверял внешнюю машину.')
        else:
            print('✅ HTTP-путь подтверждён из текущей точки. Доступность со всех точек CA этим не доказана.')
        fingerprint = hashlib.sha256(json.dumps({key: config.get(key) for key in
                        ('domain', 'relay_ip', 'challenge_port')}, sort_keys=True).encode()).hexdigest()
        atomic_json(STATE / 'http-path.json', dict(status='confirmed', scope=scope, at=int(time.time()),
                    install_id=config['install_id'], fingerprint=fingerprint, addresses=results))
        if (STATE / 'lifecycle.json').exists():
            lifecycle = read_json(STATE / 'lifecycle.json')
            if lifecycle.get('stage') in ('runtime_ready', 'awaiting_http', 'certificate_pending'):
                lifecycle_stage('certificate_pending')
    finally:
        # Only stop a listener after this invocation has successfully created it.
        if created:
            stop_probe()
        else:
            cleanup_firewall()


def vpn_self_test(config):
    container = config.get('vpn_container')
    if not container:
        raise Failure('Сначала укажите VPN-контейнер в configure → Docker-сеть.', 'VPN_CONTAINER_UNKNOWN')
    validate_network(config)
    mode = run(['docker', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', container]).stdout.decode().strip()
    if not config.get('docker_network') and mode != 'host':
        raise Failure('VPN-контейнер не использует host networking. Выберите общую bridge-сеть.', 'VPN_NETWORK_MISSING')
    print('🔍 Проверка HTTPS target из VPN-контейнера: используется только имеющийся openssl, без установки пакетов.')
    if not confirm('Выполнить TLS-проверку в выбранном контейнере?'):
        raise Failure('Проверка отменена.', 'CANCELLED')
    result = run(['docker', 'exec', '-i', container, 'openssl', 's_client', '-connect', target(config),
                  '-servername', config['domain'], '-verify_hostname', config['domain'],
                  '-verify_return_error', '-CApath', '/etc/ssl/certs', '-alpn', 'h2',
                  '-tls1_3', '-showcerts'], check=False, input=b'', timeout=15)
    if result.returncode:
        raise Failure('TLS-проверка в VPN-контейнере не завершена: проверьте наличие openssl, '
                      'CA bundle, DNS alias и доступ к target. Контейнер не изменён.', 'VPN_TARGET_UNCONFIRMED')
    match = re.search(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', result.stdout, re.S)
    expected = validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem')
    if not match or ssl.PEM_cert_to_DER_cert(match.group(0).decode()) != expected or b'ALPN protocol: h2' not in result.stdout:
        raise Failure('В контейнере не подтверждён нужный сертификат или h2.', 'VPN_TARGET_UNCONFIRMED')
    print('✅ VPN-контейнер достигает нужного HTTPS target (SNI, trust, TLS 1.3/h2). REALITY credentials не проверялись.')


def local_self_test(config):
    """Explicit read-only TLS test, never performed while drawing a menu."""
    import client_panel
    identity = client_panel.tls_identity(SimpleNamespace(**globals()), config)
    _menu_tls_check.clear()
    _menu_tls_check.update(at=int(time.time()), identity=identity, success=False)
    expected = validate_certificate(config, STATE / 'certs/current/fullchain.pem',
                                    STATE / 'certs/current/key.pem')
    verify_served(config, expected, attempts=1)
    _menu_tls_check.update(at=int(time.time()), success=identity is not None and
                           identity == client_panel.tls_identity(SimpleNamespace(**globals()), config))
    if not _menu_tls_check['success']:
        raise Failure('Сертификат или маршрут изменился во время проверки. Повторите самопроверку.',
                      'HTTPS_CHANGED')
    print('✅ Локальная HTTPS подтверждена: сертификат, SNI, trust, TLS 1.3/h2.')
    print('REALITY требует отдельного подключения клиента.')


def update(config, args):
    """Only owner-configured target release. No invented publication address."""
    url = args.package_url or config.get('package_url')
    digest = args.sha256 or config.get('package_sha256')
    version = args.version or config.get('package_version')
    if not url or not digest or not version:
        raise Failure('Публичный URL ещё не настроен. Укажите --package-url HTTPS, '
                      '--version и --sha256 реального релиза этого пакета.')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise Failure('Нужна фиксированная версия major.minor.patch.')
    with tempfile.TemporaryDirectory(prefix='tenant-selfsteal-update-') as temporary:
        root = Path(temporary)
        archive = root / 'release.tar.gz'
        verified_download(url, digest, archive)
        extracted = root / 'package'
        extracted.mkdir()
        with tarfile.open(archive, 'r:gz') as tar:
            members = tar.getmembers()
            if len(members) > 2048 or sum(member.size for member in members) > 100 * 1024 * 1024:
                raise Failure('Слишком большой распакованный пакет.')
            names = set()
            for member in members:
                target = (extracted / member.name).resolve()
                if (not target.is_relative_to(extracted.resolve()) or not (member.isfile() or member.isdir())
                        or '\\' in member.name or member.name in names or member.size < 0
                        or any(part in ('', '.', '..') or ':' in part for part in member.name.split('/'))):
                    raise Failure('Небезопасный путь/тип в архиве обновления.')
                names.add(member.name)
            tar.extractall(extracted, members=members,
                           **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
        if (extracted / 'VERSION').read_text().strip() != version:
            raise Failure('Версия артефакта не совпадает с выбранной.')
        for name in ('selfsteal.py', 'selfsteal.sh', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py', 'templates.json', 'vendor/acme.sh', 'dependencies.json', 'docs/integration.md'):
            if not (extracted / name).is_file():
                raise Failure('Неполный артефакт обновления.')
        if tuple(int(part) for part in version.split('.')) >= (1, 4, 0):
            if not all((extracted / name).is_file() for name in ('terminal_ui.py', 'client_panel.py')):
                raise Failure('Неполный артефакт обновления: отсутствует интерфейс.')
        if tuple(int(part) for part in version.split('.')) >= (1, 5, 0) and not (extracted / 'renewal_schedule.py').is_file():
            raise Failure('Неполный артефакт обновления: отсутствует модуль расписания.')
        if tuple(int(part) for part in version.split('.')) >= (1, 5, 2) and not (extracted / 'installation_flow.py').is_file():
            raise Failure('Неполный артефакт обновления: отсутствует модуль повторной установки.')
        deps = read_json(extracted / 'dependencies.json')
        if hashlib.sha256((extracted / 'vendor/acme.sh').read_bytes()).hexdigest() != deps['acme']['sha256']:
            raise Failure('acme.sh в обновлении не соответствует манифесту.')
        check_install_resources()
        assert_compose_owned()
        print('🔄 Проверен релиз ' + version + '. Будут заменены только пакет, собственный Caddy/Compose и recovery; identity/cert/key сохраняются.')
        if not confirm('Применить проверенное обновление с резервной копией и откатом?'):
            raise Failure('Обновление отменено.', 'CANCELLED')
        identifier = uuid.uuid4().hex
        candidate = INSTALL.with_name('tenant-selfsteal.next')
        backup = INSTALL.with_name('tenant-selfsteal.previous-' + identifier)
        if candidate.exists() or backup.exists():
            raise Failure('Сохранена предыдущая попытка update; проверьте её вручную.')
        shutil.copytree(extracted, candidate)
        snapshot = STATE / ('update-backup-' + identifier)
        snapshot.mkdir(mode=0o700)
        for name in ('Caddyfile', 'compose.yaml', 'docker-compose', 'recover.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py', 'recovery-current.json', 'schedule-pending.json'):
            if (STATE / name).exists():
                shutil.copy2(STATE / name, snapshot / name)
        atomic_json(snapshot / 'units.json', snapshot_units())
        atomic_json(snapshot / 'config.json', read_json(CONFIG))
        atomic_json(STATE / 'update-transaction.json', {'id': identifier, 'parent_pid': os.getpid()})
        os.replace(INSTALL, backup)
        os.replace(candidate, INSTALL)
        try:
            run([sys.executable, INSTALL / 'selfsteal.py', '_update-apply', '--operation-id', identifier], timeout=600)
        except BaseException:
            recover_update()
            raise
        config.update(package_url=url, package_version=version, package_sha256=digest)
        atomic_json(CONFIG, config)
        (STATE / 'update-transaction.json').unlink()
        print('Обновление проверено; предыдущий пакет сохранён: ' + str(backup))
        print('Для запуска меню: transitclient')


def uninstall():
    print('Удаление остановит продление и локальный selfsteal. VPN-нода и чужие ресурсы сохраняются.')
    print(f'Ресурсы: {LAUNCHER}, свои tenant-selfsteal units и Compose проект {PROJECT}.')
    print('⚠️ VPN selfsteal target перестанет работать. Данные/сертификаты будут сохранены в backup.')
    if not confirm('Удалить ресурсы tenant-selfsteal?'):
        raise Failure('Удаление отменено.', 'CANCELLED')
    check_install_resources()
    assert_compose_owned()
    config = read_json(CONFIG)
    if not config.get('install_id'):
        config['install_id'] = read_json(INSTALL / '.transitclient-package.json')['install_id'] if package_owned() else uuid.uuid4().hex
        atomic_json(CONFIG, config)
    backup = STATE.with_name('tenant-selfsteal-backup-' + time.strftime('%Y%m%d%H%M%S') + '-' + uuid.uuid4().hex)
    if backup.exists():
        raise Failure('Имя резервной копии уже занято.', 'BACKUP_CONFLICT')
    atomic_json(STATE / 'uninstall.json', {'install_id': read_json(CONFIG).get('install_id')})
    lifecycle_stage('uninstalling')
    run(['systemctl', 'disable', '--now', 'tenant-selfsteal-renew.timer',
         'tenant-selfsteal-recover.service'])
    run(['systemctl', 'stop', 'tenant-selfsteal-renew.service'])
    stop_retry()
    recover_operation()
    # Lock proves no other renewal is executing; no killing third-party listeners.
    cleanup_firewall()
    compose('down')
    # Persistent timer stamp is state, not a unit file. Clean while the stopped
    # owned timer is still loaded; a fresh installation must not inherit it.
    run(['systemctl', 'clean', '--what=state', 'tenant-selfsteal-renew.timer'])
    for name in ('renew.timer', 'renew.service', 'recover.service'):
        (UNITS / ('tenant-selfsteal-' + name)).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    # This journal survives STATE's final rename. A kill between rename and
    # CONFIG deletion must not leave an apparently configured empty install.
    atomic_json(CONFIG.with_name('uninstall-transaction.json'), dict(
                stage='resources_removed', install_id=config['install_id'], backup=str(backup)))
    finish_uninstall(backup, config)


def finish_uninstall(backup, config):
    marker = CONFIG.with_name('uninstall-transaction.json')
    transaction = read_json(marker)
    if (transaction.get('stage') != 'resources_removed' or transaction.get('install_id') != config.get('install_id')
            or transaction.get('backup') != str(backup) or backup.parent != STATE.parent
            or not re.fullmatch(r'tenant-selfsteal-backup-[0-9]{14}-[0-9a-f]{32}', backup.name)
            or backup.is_symlink() or STATE.is_symlink()):
        raise Failure('Журнал удаления требует ручной сверки.', 'UNINSTALL_RECOVERY_REQUIRED')
    if backup.exists():
        if STATE.exists() or read_json(backup / 'backup-manifest.json').get('install_id') != config.get('install_id'):
            raise Failure('Данные удаления неоднозначны; копия сохранена.', 'UNINSTALL_RECOVERY_REQUIRED')
    else:
        prepare_uninstall_backup(backup, config)
    CONFIG.unlink(missing_ok=True)
    if LAUNCHER.exists() and not LAUNCHER.is_symlink() and LAUNCHER.read_text() == launcher_content():
        LAUNCHER.unlink()
    marker.unlink()
    print('Данные/сертификаты/ACME account сохранены с root-only доступом: ' + str(backup))
    print('Установленный исходный пакет сохранён в /opt/tenant-selfsteal; удалите вручную при необходимости.')


def prepare_uninstall_backup(backup, config):
    STATE.chmod(0o700)
    shutil.copy2(CONFIG, STATE / 'config-backup.json')
    atomic_json(STATE / 'backup-manifest.json', dict(kind='transitclient-backup', schema=1,
                install_id=config['install_id'], domain=config['domain'],
                config_sha256=hashlib.sha256((STATE / 'config-backup.json').read_bytes()).hexdigest()))
    for item in STATE.rglob('*'):
        if not item.is_symlink():
            item.chmod(0o700 if item.is_dir() else 0o600)
    os.replace(STATE, backup)


def resume_uninstall():
    marker = CONFIG.with_name('uninstall-transaction.json')
    if not marker.exists():
        return False
    transaction = read_json(marker)
    backup = Path(transaction.get('backup', ''))
    if backup.parent != STATE.parent or not re.fullmatch(r'tenant-selfsteal-backup-[0-9]{14}-[0-9a-f]{32}', backup.name):
        raise Failure('Путь резервной копии не подтверждён.', 'UNINSTALL_RECOVERY_REQUIRED')
    config = read_json(CONFIG) if CONFIG.exists() else read_json(backup / 'config-backup.json')
    finish_uninstall(backup, config)
    return True


def recover_restore():
    """Preserve interrupted publication; the selected source backup stays intact."""
    marker = CONFIG.with_name('restore-transaction.json')
    if not marker.exists():
        return False
    transaction = read_json(marker)
    identifier = transaction.get('id', '')
    if not re.fullmatch(r'[0-9a-f]{32}', identifier):
        raise Failure('Журнал восстановления требует ручной сверки.', 'RESTORE_RECOVERY_REQUIRED')
    config = transaction['config']
    if CONFIG.exists() and (CONFIG.is_symlink() or read_json(CONFIG) != config):
        raise Failure('Конфигурация изменилась после начала восстановления.', 'RESTORE_RECOVERY_REQUIRED')
    saved = STATE.with_name('tenant-selfsteal-restore-interrupted-' + identifier)
    proof = 'restore-publication.json'
    for path in (STATE, saved):
        if path.is_symlink():
            raise Failure('Путь восстановления занят ссылкой.', 'RESTORE_RECOVERY_REQUIRED')
        if path.exists() and any(path.iterdir()):
            if not (path / proof).is_file() or (path / proof).is_symlink() or read_json(path / proof) != {'id': identifier}:
                raise Failure('Принадлежность данных восстановления не подтверждена.', 'RESTORE_RECOVERY_REQUIRED')
    if STATE.exists() and any(STATE.iterdir()):
        if saved.exists():
            raise Failure('Данные восстановления неоднозначны.', 'RESTORE_RECOVERY_REQUIRED')
        os.replace(STATE, saved)
    CONFIG.unlink(missing_ok=True)
    marker.unlink()
    print('Прерванный перенос отменён; исходная резервная копия сохранена.'
          + (' Незавершённые данные: ' + str(saved) if saved.exists() else ''))
    return True


def restore_backup(args):
    """Restore only explicit local owner backups, using this trusted runtime."""
    if not getattr(args, 'backup', None):
        raise Failure('Укажите выбранную копию: restore --backup /var/lib/tenant-selfsteal-backup-…', 'BACKUP_REQUIRED')
    source = Path(args.backup)
    if source.is_symlink() or source.resolve().parent != STATE.parent.resolve() or not source.name.startswith('tenant-selfsteal-backup-'):
        raise Failure('Ожидается собственная локальная резервная копия.', 'BACKUP_UNTRUSTED')
    manifest_path, config_path = source / 'backup-manifest.json', source / 'config-backup.json'
    if not manifest_path.is_file() or not config_path.is_file():
        raise Failure('У копии нет подтверждённого manifest. Старая копия сохранена для ручной сверки.', 'BACKUP_UNTRUSTED')
    for item in (source, *source.rglob('*')):
        if item.is_symlink():
            if item != source / 'certs/current' or not re.fullmatch(r'[0-9a-f]{32}', os.readlink(item)):
                raise Failure('В резервной копии обнаружена неподтверждённая ссылка.', 'BACKUP_UNTRUSTED')
            continue
        if not item.is_file() and not item.is_dir():
            raise Failure('В резервной копии обнаружен специальный файл.', 'BACKUP_UNTRUSTED')
        if os.name == 'posix' and (item.stat().st_uid != 0 or item.stat().st_mode & 0o077):
            raise Failure('Резервная копия должна быть доступна только root.', 'BACKUP_UNTRUSTED')
    manifest = read_json(manifest_path)
    config = validate_config(read_json(config_path))
    if (manifest.get('kind') != 'transitclient-backup' or manifest.get('install_id') != config.get('install_id')
            or not config.get('install_id') or manifest.get('domain') != config['domain']
            or manifest.get('config_sha256') != hashlib.sha256(config_path.read_bytes()).hexdigest()):
        raise Failure('Принадлежность резервной копии не подтверждена.', 'BACKUP_UNTRUSTED')
    changed_domain = bool(getattr(args, 'domain', None) and domain_value(args.domain) != config['domain'])
    if changed_domain:
        config['domain'] = domain_value(args.domain)
        config['relay_ip'] = getattr(args, 'relay_ip', None) or ''
    if config['ca'] == STAGING:
        config['staging_ca_file'] = str(STATE / 'staging-trust.pem')
    if CONFIG.exists() or STATE.exists() and any(STATE.iterdir()):
        raise Failure('Активные данные уже существуют. Восстановление поверх них запрещено.', 'RESTORE_CONFLICT')
    check_install_resources()
    check_dns(config)
    check_challenge_port(config)
    assert_local_docker()
    if not confirm('Восстановить выбранную установку ' + config['domain'] + ' с прежней ACME identity?'):
        raise Failure('Восстановление отменено.', 'CANCELLED')
    # Never execute any helper/script or take dependency pins from the backup.
    with tempfile.TemporaryDirectory(dir=STATE.parent, prefix='transitclient-restore-') as directory:
        staged = Path(directory) / 'state'
        staged.mkdir(mode=0o700)
        for name in ('acme', 'certs', 'site', 'site-template.json', 'site-history.json', 'staging-trust.pem'):
            item = source / name
            if item.is_dir():
                shutil.copytree(item, staged / name, symlinks=True)
            elif item.is_file():
                shutil.copy2(item, staged / name)
        identifier = uuid.uuid4().hex
        atomic_json(staged / 'restore-publication.json', {'id': identifier})
        atomic_json(CONFIG.with_name('restore-transaction.json'), {'id': identifier, 'config': config})
        STATE.mkdir(mode=0o700, exist_ok=True)
        STATE.rmdir()  # Known empty; rename publishes the complete staged state.
        os.replace(staged, STATE)
    if changed_domain:
        current = STATE / 'certs/current'
        if current.is_symlink():
            current.unlink()
        elif current.exists():
            os.replace(current, current.with_name('restored-unselected-' + uuid.uuid4().hex))
    atomic_json(CONFIG, config)
    lifecycle_stage('preparing', issuance_authorized=False)
    CONFIG.with_name('restore-transaction.json').unlink()
    (STATE / 'restore-publication.json').unlink()
    dependencies()
    global PACKAGE
    if PACKAGE != INSTALL:
        identifier = uuid.uuid4().hex
        staged = INSTALL.with_name('tenant-selfsteal.restore-' + identifier)
        copy_package(PACKAGE, staged)
        if INSTALL.exists():
            os.replace(INSTALL, INSTALL.with_name('tenant-selfsteal.previous-' + identifier))
        os.replace(staged, INSTALL)
        PACKAGE = INSTALL
    mark_package(config)
    install_launcher()
    render_caddy(config)
    install_units()
    expected = None
    if (STATE / 'certs/current/fullchain.pem').exists():
        try:
            expected = validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem')
        except Failure:
            print('⚠️ Сохранённый сертификат требует проверки/продления; автоматического выпуска не будет.')
    if expected is not None:
        compose('up', '-d', '--no-build', 'caddy')
        reload_caddy()
        verify_served(config, expected)
        lifecycle_stage('ready')
    else:
        lifecycle_stage('awaiting_http')
    print('✅ Восстановлены прежние данные. Исходная резервная копия сохранена. Запрос в CA не отправлен.')


def recover_operation():
    path = STATE / 'operation.json'
    if not path.exists():
        abort_acme()
        return
    with resource_lock():
        record = read_json(path)
        identifier = record.get('operation_id')
        if not operation_record(identifier):
            raise Failure('Повреждён журнал операции.', 'OWNERSHIP_UNKNOWN')
        record['state'] = 'recovering'
        atomic_json(path, record)
    abort_acme(identifier)
    stop_scoped_transient(identifier, 'probe')
    stop_scoped_transient(identifier, 'watchdog', 'service')
    with resource_lock():
        if operation_record(identifier):
            path.unlink()


def queue_retry():
    """One delayed retry per busy episode; never a second periodic scheduler."""
    if not CONFIG.exists() or not STATE.exists():
        return
    config = validate_config(read_json(CONFIG))
    identifier = config.get('install_id')
    if not identifier:
        return
    if (STATE / 'uninstall.json').exists():
        return
    with resource_lock():
        path = STATE / 'retry.json'
        if path.exists():
            prior = read_json(path)
            if prior.get('install_id') != identifier:
                raise Failure('Владелец отложенного повтора не подтверждён.', 'OWNERSHIP_UNKNOWN')
            if prior.get('created_at', 0) + 3600 > time.time():
                return
        retry_id = uuid.uuid4().hex
        unit = 'tenant-selfsteal-retry-' + identifier + '-' + retry_id
        assert_transient_available(unit + '.timer')
        assert_transient_available(unit + '.service')
        atomic_json(path, dict(install_id=identifier, retry_id=retry_id, unit=unit, state='pending', created_at=int(time.time())))
        description = 'Transitclient renewal retry ' + identifier + ' ' + retry_id
        run(['systemd-run', '--unit=' + unit, '--on-active=5min', '--collect',
             '--description=' + description, '--timer-property=Description=' + description,
             '--property=RuntimeMaxSec=21min', '/usr/bin/python3', INSTALL / 'selfsteal.py',
             '_retry-renew', '--retry-install-id', identifier, '--operation-id', retry_id])


def retry_renew(identifier, retry_id=None):
    if not CONFIG.exists() or not (STATE / 'retry.json').exists():
        return
    with resource_lock():
        config, record = read_json(CONFIG), read_json(STATE / 'retry.json')
        if (not retry_id or record.get('retry_id') != retry_id or record.get('install_id') != identifier
                or config.get('install_id') != identifier or record.get('state') != 'pending'):
            return
        if (STATE / 'uninstall.json').exists():
            return
        record['state'] = 'fired'
        atomic_json(STATE / 'retry.json', record)
    stop_retry_unit(record, 'timer')
    # Do not hold either lock while systemctl waits for the renewal worker.
    check_install_resources()
    run(['systemctl', 'start', 'tenant-selfsteal-renew.service'], timeout=ACME_TIMEOUT + 180)


def stop_retry():
    path = STATE / 'retry.json'
    if not path.exists():
        return
    record = read_json(path)
    identifier = read_json(CONFIG).get('install_id')
    if record.get('install_id') != identifier:
        raise Failure('Владелец отложенного повтора не подтверждён.', 'OWNERSHIP_UNKNOWN')
    for suffix in ('timer', 'service'):
        stop_retry_unit(record, suffix)
    path.unlink()


def stop_retry_unit(record, suffix):
    identifier, retry_id = record.get('install_id'), record.get('retry_id')
    if not all(re.fullmatch(r'[0-9a-f]{32}', value or '') for value in (identifier, retry_id)):
        raise Failure('Повреждён журнал отложенного повтора.', 'OWNERSHIP_UNKNOWN')
    unit = 'tenant-selfsteal-retry-' + identifier + '-' + retry_id
    if record.get('unit') != unit:
        raise Failure('Владелец отложенного повтора не подтверждён.', 'OWNERSHIP_UNKNOWN')
    properties = transient_state(unit + '.' + suffix)
    if properties.get('LoadState', 'not-found') == 'not-found':
        return
    proof = properties.get('Triggers') == unit + '.service' if suffix == 'timer' else (
        str(INSTALL / 'selfsteal.py') in properties.get('ExecStart', '')
        and '_retry-renew' in properties.get('ExecStart', '') and identifier in properties.get('ExecStart', '')
        and retry_id in properties.get('ExecStart', ''))
    if properties.get('Description') != 'Transitclient renewal retry ' + identifier + ' ' + retry_id or not proof:
        raise Failure('Владелец отложенного unit не подтверждён.', 'OWNERSHIP_UNKNOWN')
    run(['systemctl', 'stop', unit + '.' + suffix])


def dispatch(args):
    activate = args.command in ('install', 'update', '_recover', 'firewall-confirm', 'restore', 'configure') and not (
        args.command == '_recover' and os.environ.get('INVOCATION_ID'))
    restore = args.command in ('renew', 'template', '_recover')
    try:
        result = _dispatch(args)
    except BaseException:
        # A committed partial installation still needs renewal scheduling. Keep
        # the original exception if schedule verification itself fails.
        if activate or restore:
            try:
                activate_schedule() if activate else activate_restored_units()
            except (Failure, OSError, ValueError, subprocess.SubprocessError):
                print('⚠️ Расписание требует проверки: transitclient diagnose.', file=sys.stderr)
        raise
    if activate:
        activate_schedule()
    elif restore:
        activate_restored_units()
    return result


def _dispatch(args):
    command = args.command
    interactive = getattr(args, '_menu_mode', False)
    if command == 'self-test' and interactive and not args.http01 and not args.vpn:
        config = safe_config()
        if config is None:
            raise Failure('Сначала завершите установку.', 'NOT_INSTALLED')
        local_self_test(config)
        return 0
    if command == 'status':
        status(safe_config(), json_output=args.json, no_color=getattr(args, 'no_color', False))
        return 0
    if command in ('diagnose', 'self-test') and not args.http01 and not args.vpn:
        report = diagnose(safe_config(), json_output=args.json, interactive=interactive,
                          full=getattr(args, 'full', False), no_color=getattr(args, 'no_color', False))
        return 1 if command == 'self-test' and any(item['status'] == 'error' for item in report['checks']) else 0
    if command == 'guide':
        guide(safe_config(), interactive=True) if interactive else guide(safe_config())
        return 0
    if command == 'version':
        print('transitclient ' + (PACKAGE / 'VERSION').read_text().strip())
        return 0
    require_host()
    os.umask(0o077)
    if command == '_cleanup':
        cleanup_firewall(getattr(args, 'operation_id', None))
        return 0
    if command == '_abort':
        abort_acme(getattr(args, 'operation_id', None))
        return 0
    if command == '_retry-renew':
        retry_renew(args.retry_install_id, getattr(args, 'operation_id', None))
        return 0
    config = validate_config(read_json(CONFIG)) if CONFIG.exists() and command in ('_open', '_probe-server', '_update-apply') else None
    if command in ('_open', '_probe-server'):
        identifier = getattr(args, 'operation_id', None)
        record = operation_record(identifier)
        if not record or record.get('state', 'active') != 'active' or record.get('deadline', 0) <= time.time():
            raise Failure('Устаревший либо неподтверждённый обработчик операции.', 'OPERATION_EXPIRED')
        if config is None:
            raise Failure('Установка ещё не настроена.', 'NOT_INSTALLED')
        if command == '_open':
            open_firewall(config, identifier)
        else:
            probe_server(config, args.probe_token)
        return 0
    if command == '_update-apply':
        journal = STATE / 'update-transaction.json'
        transaction = read_json(journal) if journal.exists() else {}
        if (transaction.get('id') != getattr(args, 'operation_id', None)
                or transaction.get('parent_pid') != os.getppid()):
            raise Failure('Обновление должно выполняться дочерним процессом владельца блокировки.', 'OPERATION_EXPIRED')
        if config is None:
            raise Failure('Установка ещё не настроена.', 'NOT_INSTALLED')
        check_install_resources()
        chain, key = STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem'
        has_certificate = chain.is_file() and key.is_file()
        if not has_certificate:
            assert_compose_owned()
            if run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT]).stdout.strip():
                raise Failure('Caddy-контейнер есть, но активный сертификат отсутствует. '
                              'Сначала восстановите сертификат; пакет не применяется.', 'UPDATE_CERT_MISSING')
        dependencies()
        validate_network(config)
        render_caddy(config)
        install_units()
        install_launcher()
        mark_package(config)
        if not has_certificate:
            compose('config', '--quiet')
            print('Пакет обновлён для незавершённой установки. Сертификаты сохранены; '
                  'продолжите через transitclient renew.')
            return 0
        compose('up', '-d', '--no-build', 'caddy')
        reload_caddy()
        verify_served(config, validate_certificate(config, chain, key))
        return 0
    with lifecycle_lock(wait=30 if getattr(args, 'worker', False) else 0):
        if command in ('_recover', 'restore', 'install'):
            if recover_restore() and command == '_recover' and not CONFIG.exists():
                return 0
        if command in ('_recover', 'uninstall') and resume_uninstall():
            return 0
        # A waiting worker must use the settings committed by the previous owner.
        config = validate_config(read_json(CONFIG)) if CONFIG.exists() else None
        if command == 'install':
            # Preflight must not stop services, clean rules or replace files.
            install(args)
            return 0
        if command == 'restore':
            restore_backup(args)
            return 0
        if config is None:
            raise Failure('Сначала выполните install.', 'NOT_INSTALLED')
        assert_local_docker()
        if command == 'self-test':
            if args.http01:
                http_self_test(config, external_check=getattr(args, 'external_check', False))
            if args.vpn:
                vpn_self_test(config)
            return 0
        check_install_resources()
        if command == 'firewall-confirm':
            firewall = firewall_module()
            try:
                firewall.confirm_activation(STATE, config, args.confirmation_token, run, atomic_json)
            except firewall.FirewallError as exc:
                raise Failure(str(exc), exc.code) from exc
            lifecycle_stage('runtime_ready')
            try:
                http_self_test(config, approved=True)
            except Failure as exc:
                lifecycle_stage('awaiting_http', reason=exc.code)
                print('UFW подтверждён. HTTP-путь ожидает проверки: transitclient self-test --http01.')
                return 0
            renew(config)
            return 0
        if (STATE / 'ufw-activation.json').exists():
            if command != '_recover':
                raise Failure('UFW ожидает подтверждения из нового SSH. Используйте firewall-confirm '
                              'или _recover для отката.', 'FIREWALL_CONFIRMATION_REQUIRED')
            firewall = firewall_module()
            try:
                firewall.recover_activation(STATE, run, atomic_json)
            except firewall.FirewallError as exc:
                raise Failure(str(exc), exc.code) from exc
        recover_operation()
        recover_update()
        recover_configuration()
        recover_certificate()
        template_module().recover(STATE)
        config = validate_config(read_json(CONFIG))
        if command == '_recover':
            return 0
        if command == 'renew' and getattr(args, 'worker', False) and (STATE / 'lifecycle.json').exists():
            if read_json(STATE / 'lifecycle.json').get('stage') in ('awaiting_http', 'awaiting_firewall', 'preparing', 'uninstalling'):
                print('Первый выпуск ожидает готовности установки; запрос в CA не отправлен.')
                return 0
            if not read_json(STATE / 'lifecycle.json').get('issuance_authorized'):
                print('Первый выпуск ещё не разрешён владельцем; запрос в CA не отправлен.')
                return 0
        if command == 'renew' and not getattr(args, 'worker', False) and (STATE / 'lifecycle.json').exists():
            lifecycle = read_json(STATE / 'lifecycle.json')
            if lifecycle.get('stage') in ('certificate_pending', 'ready') and not lifecycle.get('issuance_authorized'):
                if not confirm('Разрешить выпуск/продление восстановленной установки в выбранной CA?'):
                    raise Failure('Выпуск отменён.', 'CANCELLED')
                lifecycle_stage(lifecycle['stage'], issuance_authorized=True)
        {'renew': lambda: renew(config), 'configure': lambda: configure(config, getattr(args, '_configure_choice', None), getattr(args, 'firewall', None)),
         'update': lambda: update(config, args), 'template': lambda: change_template(config, select_template(args.template, rollback=True)),
         'uninstall': uninstall}[command]()
    return 0


def perform(args):
    try:
        if args.command == 'install' and CONFIG.exists():
            import installation_flow
            action = installation_flow.choose_existing(SimpleNamespace(**globals()), args)
            if action == '0':
                return 0
            if action == '1' and not getattr(args, '_menu_mode', False):
                check_install_resources()
                if not package_owned():
                    raise Failure('Принадлежность установленного пакета не подтверждена.', 'OWNERSHIP_UNKNOWN')
                return subprocess.call([sys.executable, str(INSTALL / 'selfsteal.py'), 'menu',
                                        *(['--no-color'] if getattr(args, 'no_color', False) else [])])
            args._new_domain = action == '2'
        return dispatch(args)
    except (Failure, OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        if isinstance(exc, Failure) and exc.code == 'CANCELLED':
            print('Действие отменено.')
            return 0 if getattr(args, '_menu_mode', False) else 1
        message = str(exc) if isinstance(exc, Failure) else 'Не удалось завершить операцию: ' + type(exc).__name__ + '. Используйте diagnose.'
        code = exc.code if isinstance(exc, Failure) else type(exc).__name__
        if code == 'OPERATION_BUSY' and getattr(args, 'worker', False):
            try:
                queue_retry()
            except (Failure, OSError, ValueError, subprocess.SubprocessError):
                print('⚠️ Отложенный повтор требует проверки systemd.', file=sys.stderr)
        if code != 'OPERATION_BUSY' and not args.command.startswith('_') and STATE.exists() and CONFIG.exists() and args.command not in ('status', 'diagnose', 'guide', 'self-test'):
            atomic_json(STATE / 'result.json', {'success': False, 'at': int(time.time()),
                                              'error': code, 'message': message, 'stage': args.command})
        print('❌ [' + code + '] ' + message, file=sys.stderr)
        return 75 if code == 'OPERATION_BUSY' else 1


def menu(args):
    import terminal_ui
    return terminal_ui.run(sys.modules.get(__name__) or SimpleNamespace(**globals()), args)


def main():
    parser = argparse.ArgumentParser(description='HTTP-01 tenant selfsteal без API сервиса')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu', 'install', 'configure', 'status', 'diagnose', 'self-test', 'renew', 'update',
                                          'uninstall', 'restore', 'template', 'guide', 'help', 'version', 'firewall-confirm', '_open', '_cleanup', '_abort', '_recover', '_update-apply', '_probe-server', '_retry-renew'])
    parser.add_argument('--template', help='Номер сайта 1–11, random, builtin или rollback (после установки)')
    parser.add_argument('--staging-ca-file', help='Явный trust bundle тестовой CA, только новая установка')
    parser.add_argument('--package-url')
    parser.add_argument('--version')
    parser.add_argument('--sha256')
    parser.add_argument('--domain')
    parser.add_argument('--relay-ip')
    parser.add_argument('--vpn-port')
    parser.add_argument('--challenge-port')
    parser.add_argument('--local-port')
    parser.add_argument('--docker-network')
    parser.add_argument('--vpn-container')
    parser.add_argument('--firewall', choices=['auto', 'ufw', 'preserve', 'manual'], help='auto (по умолчанию), ufw или сохранение firewall: preserve')
    parser.add_argument('--operation-id', help=argparse.SUPPRESS)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--retry-install-id', help=argparse.SUPPRESS)
    parser.add_argument('--confirmation-token', help='Одноразовое подтверждение UFW из нового SSH')
    parser.add_argument('--backup', help='Явно выбранная локальная резервная копия для restore')
    parser.add_argument('--probe-token', help=argparse.SUPPRESS)
    parser.add_argument('--json', action='store_true', help='JSON отчёт status/diagnose/self-test')
    parser.add_argument('--full', action='store_true', help='Подробный отчёт diagnose')
    parser.add_argument('--no-color', action='store_true', help='Без ANSI цветов в интерактивном меню')
    parser.add_argument('--http01', action='store_true', help='Явный временный HTTP self-test, без ACME')
    parser.add_argument('--external-check', action='store_true', help='При NAT hairpin явно подтвердить nonce с внешней машины')
    parser.add_argument('--vpn', action='store_true', help='Явная TLS-проверка в указанном VPN-контейнере')
    args = parser.parse_args()
    if args.command == 'help':
        parser.print_help()
        return
    if (args.http01 or args.vpn) and args.command != 'self-test':
        parser.error('--http01/--vpn применимы только к self-test')
    if args.external_check and (args.command != 'self-test' or not args.http01):
        parser.error('--external-check применим только к self-test --http01')
    if args.full and args.command != 'diagnose':
        parser.error('--full применим только к diagnose')
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        result = menu(args) if args.command == 'menu' else perform(args)
    except (EOFError, KeyboardInterrupt) as exc:
        print('\nДействие отменено.' if isinstance(exc, KeyboardInterrupt) else '\nВыход.')
        result = 130 if isinstance(exc, KeyboardInterrupt) else 0
    except Failure as exc:
        print('❌ ' + str(exc), file=sys.stderr)
        result = 1
    sys.exit(result)


if __name__ == '__main__':
    main()
