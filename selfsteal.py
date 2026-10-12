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
    if config['firewall'] not in ('ufw', 'manual'):
        raise Failure('Поддерживается active UFW или явно подтверждённый manual firewall.')
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
def lifecycle_lock():
    import fcntl
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Failure('Установка/продление/обновление уже выполняется.') from exc
        yield


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


def cleanup_firewall():
    marker = STATE / 'firewall.json'
    if not marker.exists():
        return
    record = read_json(marker)
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
    stop_owned_transient('tenant-selfsteal-watchdog.timer', 'Transitclient firewall watchdog')


def open_firewall(config):
    check_challenge_port(config)
    cleanup_firewall()
    if config['firewall'] == 'manual':
        print(f"Внешний/local firewall: TCP {config['challenge_port']} должен пропускать "
              'все источники на время ACME. Автоматические правила не изменяются.')
        return
    status = run(['ufw', 'status']).stdout.decode()
    if 'Status: active' not in status:
        raise Failure('UFW не активен. Он не будет включён. Выберите manual осознанно.')
    firewall = firewall_module()
    try:
        firewall.check_challenge_rules(run, config['challenge_port'])
    except firewall.FirewallError as exc:
        raise Failure(str(exc), exc.code) from exc
    tag = 'tenant-selfsteal-' + uuid.uuid4().hex
    assert_transient_available('tenant-selfsteal-watchdog.timer')
    assert_transient_available('tenant-selfsteal-watchdog.service')
    # Persist intent BEFORE adding the rule. Boot + watchdog recover after SIGKILL.
    atomic_json(STATE / 'firewall.json', {'tag': tag, 'mode': 'ufw',
                                        'port': config['challenge_port']})
    hook = [sys.executable, INSTALL / 'selfsteal.py', '_abort']
    run(['systemd-run', '--unit=tenant-selfsteal-watchdog', '--on-active=25m',
         '--description=Transitclient firewall watchdog', '--timer-property=Description=Transitclient firewall watchdog',
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
    for name in ('Caddyfile', 'compose.yaml', 'docker-compose', 'recover.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py'):
        if (snapshot / name).exists():
            shutil.copy2(snapshot / name, STATE / name)
    if (STATE / 'certs/current').exists():
        compose('up', '-d', '--no-build', 'caddy')
        reload_caddy()
        config = validate_config(read_json(CONFIG))
        verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem'))
    journal.unlink()


def abort_acme():
    # Stop only our managed transient cgroup, including its socat listeners.
    # _cleanup is a hook and must not stop the ACME process invoking it.
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
        (STATE / name).write_text(previous[name], encoding='utf-8')
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
        verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem',
                                                    STATE / 'certs/current/key.pem'))
    else:
        atomic_json(CONFIG, config)
    journal.unlink()


def configure(config, choice=None):
    if choice is None:
        print('⚙️ Настройки: 1 HTTP-порт для сертификата · 2 Порт для проксирования трафика · '
              '3 Локальный HTTPS-порт веб-сервера · 4 Docker-сеть · 0 назад')
        choice = input('Выберите настройку: ').strip()
    candidate = dict(config)
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
    else:
        raise Failure('Неизвестная настройка.', 'INVALID_OPTION')
    labels = {'challenge_port': 'HTTP-порт для сертификата', 'vpn_port': 'Порт для проксирования трафика',
              'local_port': 'Локальный HTTPS-порт веб-сервера', 'docker_network': 'Docker-сеть',
              'vpn_container': 'Контейнер ноды'}
    for key, label in labels.items():
        if config.get(key) != candidate.get(key):
            print(f"{label}: {config.get(key) or 'не задано'} → {candidate.get(key) or 'не задано'}")
    print(f"Домен сохраняется: {candidate['domain']}; VPN: {candidate.get('vpn_port')}; "
          f"HTTP: {candidate['challenge_port']}; target: {target(candidate)}.")
    if not confirm('Маршрут в боте согласован, применить только эти изменения?'):
        raise Failure('Настройки не изменены.', 'CANCELLED')
    if choice in ('1', '2'):
        atomic_json(CONFIG, candidate)
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
    print('🔐 Проверяем срок сертификата и расписание продления.')
    print('Если продление ещё не требуется, новый сертификат не запрашивается; '
          'если требуется — выполняется выпуск и применение в Caddy.')
    check_dns(config)
    home = STATE / 'acme'
    home.mkdir(exist_ok=True, mode=0o700)
    # Run the pinned script directly: no --install, no cron, no --cron autoupgrade.
    account = home / 'account.conf'
    if not account.exists():
        account.write_text("AUTO_UPGRADE='0'\n", encoding='utf-8')
        account.chmod(0o600)
    domain_dir = home / (config['domain'] + '_ecc')
    pre = shlex.join([sys.executable, str(INSTALL / 'selfsteal.py'), '_open'])
    post = shlex.join([sys.executable, str(INSTALL / 'selfsteal.py'), '_cleanup'])
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
        assert_transient_available('tenant-selfsteal-acme.service')
        result = run(['systemd-run', '--unit=tenant-selfsteal-acme', '--description=Transitclient ACME', '--wait', '--pipe',
                      '--collect', '--service-type=exec',
                      '--property=RuntimeMaxSec=15min', '--property=KillMode=control-group',
                      '--property=UMask=0077', '--setenv=LC_ALL=C',
                      '--property=ExecStopPost=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py _cleanup',
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
    finally:
        abort_acme()


def install_units():
    # Independent stable helper survives a killed package-directory replacement.
    recovery = STATE / 'recover.py.next'
    shutil.copyfile(PACKAGE / 'selfsteal.py', recovery)
    recovery.chmod(0o600)
    os.replace(recovery, STATE / 'recover.py')
    shutil.copyfile(PACKAGE / 'diagnostics.py', STATE / 'diagnostics.py')
    shutil.copyfile(PACKAGE / 'site_templates.py', STATE / 'site_templates.py')
    shutil.copyfile(PACKAGE / 'firewall_setup.py', STATE / 'firewall_setup.py')
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
ExecStart=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py renew
ExecStopPost=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py _abort
TimeoutStartSec=20min
TimeoutStopSec=60s
KillMode=control-group
Restart=on-failure
RestartSec=1h
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
    run(['systemctl', 'enable', '--now', 'tenant-selfsteal-renew.timer'])
    run(['systemctl', 'is-enabled', '--quiet', 'tenant-selfsteal-renew.timer'])
    run(['systemctl', 'is-active', '--quiet', 'tenant-selfsteal-renew.timer'])
    next_run = run(['systemctl', 'show', 'tenant-selfsteal-renew.timer',
                    '-p', 'NextElapseUSecRealtime', '--value']).stdout.decode().strip()
    if not next_run or next_run in ('0', 'n/a'):
        raise Failure('Timer включён, но следующий запуск не назначен. Проверьте systemd timer.')


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
              'firewall': getattr(args, 'firewall', None) or 'ufw',
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
                     and '__pycache__' not in path.parts and path.suffix != '.pyc')
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
    print('  Команда управления: transitclient. Нода и существующие сайты сохраняются.')
    return confirm('Установить?')


def install(args):
    global PACKAGE
    check_install_resources()
    if (STATE / 'update-transaction.json').exists():
        raise Failure('Замена пакета не завершена. Сначала выполните '
                      'sudo python3 /var/lib/tenant-selfsteal/recover.py _recover.', 'UPDATE_RECOVERY_REQUIRED')
    retained_package = not CONFIG.exists() and INSTALL.exists() and PACKAGE != INSTALL
    retained_marker = read_json(INSTALL / '.transitclient-package.json') if retained_package else None
    if retained_package:
        print('📦 Сохранён собственный пакет ' + (INSTALL / 'VERSION').read_text().strip()
              + '. После подтверждения будет установлен входящий пакет '
              + (PACKAGE / 'VERSION').read_text().strip() + '; прежний пакет сохранится для отката.')
    diagnostics = diagnostic_module()
    initial_config = validate_config(read_json(CONFIG)) if CONFIG.exists() else None
    initial_report = diagnostics.collect(initial_config)
    diagnostics.display_compact(initial_report)
    import terminal_ui
    terminal = terminal_ui.Terminal(no_color=getattr(args, 'no_color', False))
    terminal.line('Режим установки', 'bold')
    for number, label in [('1', '🚀 Установить Caddy'), ('2', '📖 Свой веб-сервер'), ('0', '⬅️ Выход')]:
        terminal.fragments(terminal_ui.option(number, label))
    mode = ask('Режим', '1')
    if mode == '2':
        guide(None)
        return
    if mode != '1':
        raise Failure('Установка отменена.', 'CANCELLED')
    if CONFIG.exists():
        if (STATE / 'ufw-activation.json').exists():
            raise Failure('Незавершённая настройка UFW. Выполните sudo transitclient _recover, '
                          'затем повторите установку.', 'FIREWALL_RECOVERY_REQUIRED')
        config = validate_config(read_json(CONFIG))
        print('Сохранены прежние настройки, ACME account и сертификат.')
        if INSTALL.exists() and PACKAGE != INSTALL:
            if not package_owned() or (INSTALL / 'VERSION').read_text().strip() != (PACKAGE / 'VERSION').read_text().strip():
                raise Failure('Обнаружен прежний установленный пакет. Для смены версии используйте update '
                              'с архивом, версией и доверенным SHA256; данные не перезаписаны.', 'UPDATE_REQUIRED')
            PACKAGE = INSTALL
    else:
        config = interactive_config(args)
        report = diagnostics.collect(config)
        detect_vpn_network(config, report)
        check_dns(config)
        check_challenge_port(config)
        if not config.get('docker_network') and not free_port(config['local_port'], '127.0.0.1'):
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
        firewall_plan = firewall.plan(config, report, run)
    except firewall.FirewallError as exc:
        raise Failure(str(exc), exc.code) from exc
    for change in firewall_plan['changes']:
        print('🛡️ ' + change)
    chosen_template = None
    if not CONFIG.exists() or getattr(args, 'template', None) is not None:
        chosen_template = select_template(getattr(args, 'template', None) or 'random')
        print('🎨 Выбранный сайт: ' + chosen_template)
    if not installation_plan(config):
        raise Failure('Установка отменена.', 'CANCELLED')
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    config.setdefault('install_id', uuid.uuid4().hex)
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
        if all((STATE / name).exists() for name in ('Caddyfile', 'compose.yaml')):
            atomic_json(STATE / 'configuration-transaction.json', {'config': previous,
                        **{name: (STATE / name).read_text() for name in ('Caddyfile', 'compose.yaml')},
                        'units': {name: (UNITS / ('tenant-selfsteal-' + name)).read_text()
                                  for name in ('renew.service', 'renew.timer', 'recover.service')
                                  if (UNITS / ('tenant-selfsteal-' + name)).exists()}})
        atomic_json(CONFIG, config)
    package_transaction = False
    try:
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
                    for name in ('Caddyfile', 'compose.yaml', 'docker-compose', *helpers):
                        if (STATE / name).exists():
                            shutil.copy2(STATE / name, snapshot / name)
                    # Stable recovery must exist before a possible rename gap.
                    for name in helpers:
                        shutil.copyfile(PACKAGE / ('selfsteal.py' if name == 'recover.py' else name), STATE / name)
                        (STATE / name).chmod(0o600)
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
            firewall.apply(firewall_plan, config, STATE, run, atomic_json)
        except firewall.FirewallError as exc:
            raise Failure(str(exc), exc.code) from exc
        if chosen_template is not None:
            change_template(config, chosen_template, approved=True)
        if (STATE / 'certs/current').exists():
            compose('run', '--rm', '--no-deps', 'caddy', 'caddy', 'validate',
                    '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')
            compose('up', '-d', '--no-build', 'caddy')
            reload_caddy()
            verify_served(config, validate_certificate(config, STATE / 'certs/current/fullchain.pem', STATE / 'certs/current/key.pem'))
        (STATE / 'configuration-transaction.json').unlink(missing_ok=True)
        renew(config)
        print('Теперь настройте VPN-ноду и нажмите в боте «Готово, проверить backend».')
    except BaseException:
        if package_transaction:
            recover_update()
        recover_configuration()
        raise


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
    report['pending'] = [name for name in ('firewall.json', 'ufw-activation.json', 'certificate-transaction.json',
                         'configuration-transaction.json', 'update-transaction.json', 'site-transaction.json') if (STATE / name).exists()]
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
                          '-p', 'UnitFileState', '-p', 'NextElapseUSecRealtime',
                          '-p', 'ExecMainStartTimestamp', '-p', 'ExecMainExitTimestamp'], check=False)
            report['units'][unit] = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        except (OSError, subprocess.SubprocessError):
            report['units'][unit] = {'error': 'SYSTEMD_UNAVAILABLE'}
    timer = report['units']['tenant-selfsteal-renew.timer']
    if config and (timer.get('ActiveState') != 'active' or timer.get('UnitFileState') != 'enabled'
                   or timer.get('NextElapseUSecRealtime', '') in ('', '0', 'n/a')):
        report['checks'].append({'code': 'RENEW_TIMER_INACTIVE', 'status': 'error',
                                 'message': 'Автоматическое продление не подтверждено: таймер выключен либо следующий запуск неизвестен.'})
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
    stop_owned_transient('tenant-selfsteal-probe.service', 'Transitclient HTTP probe')
    cleanup_firewall()


def http_self_test(config):
    check_dns(config)
    check_challenge_port(config)
    print(f"🔍 Временный HTTP self-test: домен:80 релея → backend:{config['challenge_port']}.")
    print('Это сетевой тест из текущей точки, без CA и выпуска сертификата. Firewall/слушатель будут временными.')
    if not confirm('Запустить HTTP self-test на срок до двух минут?'):
        raise Failure('Сетевой тест отменён.', 'CANCELLED')
    token = uuid.uuid4().hex  # A disposable public diagnostic nonce, never an ACME response.
    address = f"http://{config['domain']}/.well-known/acme-challenge/{token}"
    print('Для независимой проверки во время теста: curl --fail --noproxy "*" ' + shlex.quote(address))
    created = False
    try:
        assert_transient_available('tenant-selfsteal-probe.service')
        open_firewall(config)
        run(['systemd-run', '--unit=tenant-selfsteal-probe', '--description=Transitclient HTTP probe', '--collect', '--service-type=exec',
             '--property=RuntimeMaxSec=120s', '--property=KillMode=control-group',
             '--property=ExecStopPost=/usr/bin/python3 /opt/tenant-selfsteal/selfsteal.py _cleanup',
             '/usr/bin/python3', INSTALL / 'selfsteal.py', '_probe-server', '--probe-token', token])
        created = True
        response = None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        for _ in range(5):
            try:
                with opener.open(address, timeout=5) as upstream:
                    response = upstream.read(128)
                break
            except OSError:
                time.sleep(1)
        if response != ('transitclient-check:' + token).encode():
            raise Failure('HTTP-путь не подтверждён из этой точки. Проверьте готовность маршрута в боте, '
                          'NAT/firewall; при NAT hairpin повторите проверку с внешней машины.', 'HTTP_PATH_UNCONFIRMED')
        print('✅ HTTP-путь подтверждён из текущей точки. Доступность со всех точек CA этим не доказана.')
    finally:
        # Only stop a listener after this invocation has successfully created it.
        if created:
            stop_probe()
        else:
            cleanup_firewall()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise Failure('HTTP-маршрут вернул redirect вместо диагностического ответа.', 'HTTP_REDIRECT')


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
            tar.extractall(extracted, members=members)
        if (extracted / 'VERSION').read_text().strip() != version:
            raise Failure('Версия артефакта не совпадает с выбранной.')
        for name in ('selfsteal.py', 'selfsteal.sh', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py', 'templates.json', 'vendor/acme.sh', 'dependencies.json', 'docs/integration.md'):
            if not (extracted / name).is_file():
                raise Failure('Неполный артефакт обновления.')
        if tuple(int(part) for part in version.split('.')) >= (1, 4, 0):
            if not all((extracted / name).is_file() for name in ('terminal_ui.py', 'client_panel.py')):
                raise Failure('Неполный артефакт обновления: отсутствует интерфейс.')
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
        for name in ('Caddyfile', 'compose.yaml', 'docker-compose', 'recover.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py'):
            if (STATE / name).exists():
                shutil.copy2(STATE / name, snapshot / name)
        atomic_json(STATE / 'update-transaction.json', {'id': identifier})
        os.replace(INSTALL, backup)
        os.replace(candidate, INSTALL)
        try:
            run([sys.executable, INSTALL / 'selfsteal.py', '_update-apply'], timeout=600)
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
    run(['systemctl', 'disable', '--now', 'tenant-selfsteal-renew.timer',
         'tenant-selfsteal-recover.service'], check=False)
    # Lock proves no other renewal is executing; no killing third-party listeners.
    cleanup_firewall()
    compose('down')
    for name in ('renew.timer', 'renew.service', 'recover.service'):
        (UNITS / ('tenant-selfsteal-' + name)).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    backup = STATE.with_name('tenant-selfsteal-backup-' + time.strftime('%Y%m%d%H%M%S'))
    if backup.exists():
        raise Failure('Имя резервной копии уже занято.', 'BACKUP_CONFLICT')
    STATE.chmod(0o700)
    shutil.copy2(CONFIG, STATE / 'config-backup.json')
    os.replace(STATE, backup)
    CONFIG.unlink()
    if LAUNCHER.exists() and not LAUNCHER.is_symlink() and LAUNCHER.read_text() == launcher_content():
        LAUNCHER.unlink()
    # Keep recoverable ACME account/cert/key; never print those contents.
    print('Данные/сертификаты/ACME account сохранены с root-only доступом: ' + str(backup))
    print('Установленный исходный пакет сохранён в /opt/tenant-selfsteal; удалите вручную при необходимости.')


def dispatch(args):
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
        cleanup_firewall()
        return 0
    if command == '_abort':
        abort_acme()
        return 0
    config = validate_config(read_json(CONFIG)) if CONFIG.exists() else None
    if command in ('_open', '_probe-server'):
        if config is None:
            raise Failure('Установка ещё не настроена.', 'NOT_INSTALLED')
        if command == '_open':
            open_firewall(config)
        else:
            probe_server(config, args.probe_token)
        return 0
    if command == '_update-apply':
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
    with lifecycle_lock():
        if command == 'install':
            # Preflight must not stop services, clean rules or replace files.
            install(args)
            return 0
        if config is None:
            raise Failure('Сначала выполните install.', 'NOT_INSTALLED')
        assert_local_docker()
        if command == 'self-test':
            if args.http01:
                http_self_test(config)
            if args.vpn:
                vpn_self_test(config)
            return 0
        check_install_resources()
        if (STATE / 'ufw-activation.json').exists():
            firewall = firewall_module()
            try:
                firewall.recover_activation(STATE, run, atomic_json)
            except firewall.FirewallError as exc:
                raise Failure(str(exc), exc.code) from exc
        abort_acme()
        recover_update()
        recover_configuration()
        recover_certificate()
        template_module().recover(STATE)
        config = validate_config(read_json(CONFIG))
        if command == '_recover':
            return 0
        {'renew': lambda: renew(config), 'configure': lambda: configure(config, getattr(args, '_configure_choice', None)),
         'update': lambda: update(config, args), 'template': lambda: change_template(config, select_template(args.template, rollback=True)),
         'uninstall': uninstall}[command]()
    return 0


def perform(args):
    try:
        return dispatch(args)
    except (Failure, OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        if isinstance(exc, Failure) and exc.code == 'CANCELLED':
            print('Действие отменено.')
            return 0 if getattr(args, '_menu_mode', False) else 1
        message = str(exc) if isinstance(exc, Failure) else 'Не удалось завершить операцию: ' + type(exc).__name__ + '. Используйте diagnose.'
        code = exc.code if isinstance(exc, Failure) else type(exc).__name__
        if STATE.exists() and CONFIG.exists() and args.command not in ('status', 'diagnose', 'guide', 'self-test', '_cleanup', '_open'):
            atomic_json(STATE / 'result.json', {'success': False, 'at': int(time.time()),
                                              'error': code, 'message': message, 'stage': args.command})
        print('❌ [' + code + '] ' + message, file=sys.stderr)
        return 1


def menu(args):
    import terminal_ui
    return terminal_ui.run(sys.modules.get(__name__) or SimpleNamespace(**globals()), args)


def main():
    parser = argparse.ArgumentParser(description='HTTP-01 tenant selfsteal без API сервиса')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu', 'install', 'configure', 'status', 'diagnose', 'self-test', 'renew', 'update',
                                          'uninstall', 'template', 'guide', 'help', 'version', '_open', '_cleanup', '_abort', '_recover', '_update-apply', '_probe-server'])
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
    parser.add_argument('--firewall', choices=['ufw', 'manual'], help='Управление UFW (по умолчанию) или собственный firewall')
    parser.add_argument('--probe-token', help=argparse.SUPPRESS)
    parser.add_argument('--json', action='store_true', help='JSON отчёт status/diagnose/self-test')
    parser.add_argument('--full', action='store_true', help='Подробный отчёт diagnose')
    parser.add_argument('--no-color', action='store_true', help='Без ANSI цветов в интерактивном меню')
    parser.add_argument('--http01', action='store_true', help='Явный временный HTTP self-test, без ACME')
    parser.add_argument('--vpn', action='store_true', help='Явная TLS-проверка в указанном VPN-контейнере')
    args = parser.parse_args()
    if args.command == 'help':
        parser.print_help()
        return
    if (args.http01 or args.vpn) and args.command != 'self-test':
        parser.error('--http01/--vpn применимы только к self-test')
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
