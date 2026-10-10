"""Read-only host inventory for transitclient, including before installation.

No shell, service changes, container pulls, TCP probes, or raw command output in
reports. A listener is evidence of a bind only, never proof of VPN/REALITY health.
"""
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def _token(value, limit=128):
    """Allow only inert identifiers, not control characters or arbitrary text."""
    value = str(value).strip()
    return value[:limit] if re.fullmatch(r'[A-Za-z0-9_.:/@+\-]+', value) else 'unknown'


def _run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, LC_ALL='C'))
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def _check(report, code, status, message, **detail):
    report['checks'].append(dict(code=code, status=status, message=message, **detail))


def _resolve_dns(domain):
    # Bound DNS resolver runtime too; socket.getaddrinfo has no Python timeout.
    output = _run([sys.executable, '-c',
                   'import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,socket.AF_UNSPEC,socket.SOCK_STREAM)})))',
                   domain])
    if output is None:
        return None
    try:
        addresses = json.loads(output)
        if not isinstance(addresses, list):
            return None
        return sorted({str(ipaddress.ip_address(address)) for address in addresses})
    except (ValueError, TypeError):
        return None


def _address(value):
    value = value.strip('[]')
    if value == '*':
        return '*'
    try:
        return str(ipaddress.ip_address(value.split('%', 1)[0]))
    except ValueError:
        return None


def parse_ss(text):
    """Parse `ss -H -lntp`; discard peer addresses, command lines and raw errors."""
    listeners = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or parts[0] != 'LISTEN':
            continue
        try:
            host, port = parts[3].rsplit(':', 1)
            host, port = _address(host), int(port)
        except ValueError:
            continue
        if host is None or not 1 <= port <= 65535:
            continue
        processes = [dict(name=_token(name), pid=int(pid)) for name, pid in
                     re.findall(r'\("([^"\n]+)",pid=(\d+),', parts[5] if len(parts) > 5 else '')]
        listeners.append(dict(address=host, port=port, source='ss', processes=processes))
    return listeners


def listeners_for_port(listeners, port, address=None):
    """IPv4 loopback does not conflict with an unrelated specific IPv6 bind.

An unspecified IPv6 bind is conservative: ss does not disclose IPV6_V6ONLY.
Docker port publication is considered even when userland proxy is disabled.
"""
    matches = []
    for listener in listeners:
        if listener['port'] != int(port):
            continue
        host = listener['address']
        if address in (None, '0.0.0.0', '::', '*') or host in ('*', '0.0.0.0', '::'):
            matches.append(listener)
        elif host == address or host == '::ffff:' + address:
            matches.append(listener)
    return matches


def docker_local_context():
    """Verify local Unix endpoint before any daemon operation.

Client context inspection itself does not contact the daemon. TCP, SSH and
unrecognised endpoints are rejected, including localhost TCP proxies.
"""
    result = dict(available=bool(shutil.which('docker')), local=False,
                  context=None, endpoint_kind=None, version=None, containers=[], inventory_complete=False)
    if not result['available']:
        return result
    explicit = os.environ.get('DOCKER_HOST') if not os.environ.get('DOCKER_CONTEXT') else None
    if explicit:
        endpoint = explicit
    else:
        context = os.environ.get('DOCKER_CONTEXT') or _run(['docker', 'context', 'show'])
        if not context or _token(context) == 'unknown':
            return result
        result['context'] = _token(context)
        output = _run(['docker', 'context', 'inspect', result['context'], '--format',
                       '{{json .Endpoints.docker.Host}}'])
        try:
            endpoint = json.loads(output or 'null')
        except (ValueError, TypeError):
            return result
    if not isinstance(endpoint, str):
        return result
    result['endpoint_kind'] = endpoint.split(':', 1)[0] if ':' in endpoint else 'unknown'
    result['local'] = bool(re.fullmatch(r'unix:///[^\x00-\x20]+', endpoint))
    return result


def local_docker_error():
    """Return a safe blocking reason for daemon mutations, or None.

Docker being absent is not a context error: dependency installation can precede
daemon use, but this guard must then be called again with Docker present.
"""
    if os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'):
        if not re.fullmatch(r'unix:///[^\x00-\x20]+', os.environ['DOCKER_HOST']):
            return 'DOCKER_HOST не указывает на локальный Unix socket; работа с daemon запрещена.'
    result = docker_local_context()
    if result['available'] and not result['local']:
        return 'Локальный Unix endpoint выбранного Docker context не подтверждён; работа с daemon запрещена.'
    return None


def _docker_inventory(report, config=None):
    docker = report['docker'] = docker_local_context()
    if not docker['available']:
        _check(report, 'DOCKER_MISSING', 'warning', 'Docker отсутствует; установка требует отдельного согласия.')
        return
    if not docker['local']:
        _check(report, 'DOCKER_CONTEXT_UNSAFE', 'error', 'Локальный Unix endpoint Docker не подтверждён. Запросы к daemon не выполнялись.')
        return
    version = _run(['docker', 'info', '--format', '{{.ServerVersion}}'])
    if version is None:
        _check(report, 'DOCKER_UNAVAILABLE', 'unknown', 'Локальный Docker daemon недоступен либо нет прав; службы не запускались.')
        return
    docker['version'] = _token(version)
    _check(report, 'DOCKER_LOCAL', 'ok', 'Доступен локальный Docker daemon.')
    compose = _run(['docker', 'compose', 'version', '--short'])
    docker['compose_version'] = _token(compose) if compose else None
    _check(report, 'COMPOSE_AVAILABLE', 'ok' if compose else 'warning',
           'Docker Compose доступен.' if compose else 'Docker Compose plugin отсутствует; установщик использует свой закреплённый Compose.')
    ids = _run(['docker', 'ps', '-aq'])
    if ids is None:
        _check(report, 'DOCKER_INVENTORY_FAILED', 'unknown', 'Не удалось получить список контейнеров.')
        return
    docker['inventory_complete'] = True
    for container_id in ids.split():
        if not re.fullmatch('[a-f0-9]{12,64}', container_id):
            continue
        # Select fields explicitly; never read Env, Args, labels, mounts or secrets.
        output = _run(['docker', 'inspect', '--format',
                       '{{json .NetworkSettings.Ports}}|{{json .HostConfig.NetworkMode}}|{{json .Name}}|{{json .Config.Image}}|{{json .State.Running}}|{{json (index .Config.Labels "org.tenant-selfsteal.package")}}|{{json (index .Config.Labels "org.transitclient.install-id")}}', container_id])
        try:
            ports, mode, name, image, running, package_label, install_label = [json.loads(item) for item in (output or '').split('|')]
            if not isinstance(ports, (dict, type(None))) or not isinstance(running, bool):
                raise ValueError
        except (ValueError, TypeError):
            docker['inventory_complete'] = False
            _check(report, 'CONTAINER_INSPECT_FAILED', 'unknown', 'Не удалось проверить один из контейнеров.', container=container_id)
            continue
        expected = (config or {}).get('install_id')
        owned = bool(expected and re.fullmatch(r'[0-9a-f]{32}', str(expected))
                     and package_label == 'true' and install_label == expected)
        container = dict(id=container_id, name=_token(str(name).lstrip('/')),
                         image=_token(image), network_mode=_token(mode), running=running, published=[],
                         owned=owned)
        docker['containers'].append(container)
        for internal, bindings in ((ports or {}) if running else {}).items():
            if not isinstance(internal, str) or not re.fullmatch(r'\d+/tcp', internal):
                continue
            for binding in bindings or []:
                try:
                    host = _address(binding.get('HostIp') or '0.0.0.0')
                    port = int(binding['HostPort'])
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue
                if host is None or not 1 <= port <= 65535:
                    continue
                record = dict(address=host, port=port, source='docker', processes=[],
                              container=container['name'], container_id=container_id, owned=owned,
                              container_port=int(internal.split('/')[0]), network_mode=container['network_mode'])
                container['published'].append(record)
                report['listeners'].append(record)
                version_match = re.match(r'(\d+)\.', docker['version'])
                if host == '127.0.0.1' and (not version_match or int(version_match.group(1)) < 28):
                    _check(report, 'DOCKER_LOOPBACK_PUBLICATION', 'warning',
                           'Docker до 28 может открывать опубликованный loopback-порт соседним хостам L2. Для своего Caddy используется host network без публикации портов.', container=container['name'])


def _web_inventory(report):
    names = ('caddy', 'nginx', 'apache2', 'httpd', 'lighttpd', 'haproxy', 'traefik')
    for name in names:
        unit = name + '.service'
        active = _run(['systemctl', 'is-active', unit]) if report['systemd']['available'] else None
        load = _run(['systemctl', 'show', unit, '--property=LoadState', '--value']) if report['systemd']['available'] else None
        matching = [row for row in report['listeners'] if any(proc['name'].lower() == name
                    for proc in row.get('processes', []))]
        containers = [row for row in report['docker']['containers'] if
                      re.search(r'(^|[/_.:\-])' + name + r'($|[/_.:\-])', row['image'].lower())]
        installed = bool(shutil.which(name)) or bool(load and load.strip() == 'loaded') or bool(containers)
        is_active = bool(active and active.strip() == 'active')
        if installed or matching or is_active:
            report['web_servers'].append(dict(name=name, installed=installed,
                                             active=is_active or bool(matching) or any(row['running'] for row in containers),
                                             unit=unit if load and load.strip() == 'loaded' else None,
                                             listeners=matching, containers=[row['name'] for row in containers]))
    # Other HTTP software is not guessed from a successful TCP connection.
    unidentified = [row for row in report['listeners'] if row['port'] in (80, 443)
                    and not any(proc['name'].lower() in names for proc in row['processes'])]
    report['other_web_port_listeners'] = unidentified
    if report['web_servers']:
        _check(report, 'EXISTING_WEB_SERVER', 'warning', 'Обнаружен веб-сервер. Его службы, конфигурация и контейнеры сохраняются.')
    if unidentified:
        _check(report, 'OTHER_WEB_PORT_LISTENER', 'unknown',
               'На 80/443 есть другой TCP-слушатель; наличие веб-сервера не подтверждено.')


def _attribute_processes(report):
    """Use only cgroup identifiers, never /proc cmdline, environ or configuration."""
    for listener in report['listeners']:
        for proc in listener['processes']:
            try:
                cgroups = Path(f"/proc/{proc['pid']}/cgroup").read_text()
            except (OSError, UnicodeError):
                continue
            units = re.findall(r'(?:^|/)([A-Za-z0-9_.@\-]+\.service)(?:/|$)', cgroups, re.M)
            if units:
                proc['unit'] = _token(units[-1])
            for container in report['docker']['containers']:
                if re.search(r'(?:^|[/\-])' + re.escape(container['id']) + r'[a-f0-9]*(?:\.scope)?(?:/|$)', cgroups, re.M):
                    listener['container'] = container['name']
                    listener['container_id'] = container['id']
                    listener['network_mode'] = container['network_mode']
                    listener['owned'] = container['owned']


def collect(config=None):
    """Return a JSON-serializable report; unavailable checks accumulate, not abort.

Keys: checks, os, dependencies, systemd, docker, listeners, web_servers,
selected_ports and dns. statuses are ok/warning/error/unknown.
"""
    config = config or {}
    report = dict(checks=[], os=dict(system=platform.system(), architecture=_token(platform.machine())),
                  dependencies={}, systemd={}, listeners=[], web_servers=[], selected_ports={}, dns={})
    try:
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        report['os'].update(id=_token(release.get('ID', '').strip('"')),
                            version=_token(release.get('VERSION_ID', '').strip('"')))
    except (OSError, ValueError, UnicodeError):
        pass
    supported = report['os'].get('id') == 'ubuntu' and report['os'].get('version') in ('22.04', '24.04', '26.04')
    _check(report, 'OS_SUPPORTED', 'ok' if supported else 'warning', 'Целевая ОС Ubuntu 22.04/24.04/26.04; реальная приёмка заявляется отдельно.')
    for name in ('bash', 'curl', 'wget', 'python3', 'openssl', 'ss', 'systemctl', 'docker', 'ufw', 'socat', 'tar'):
        report['dependencies'][name] = bool(shutil.which(name))
    report['systemd'] = dict(available=report['dependencies']['systemctl'], running=Path('/run/systemd/system').is_dir())
    _check(report, 'SYSTEMD_RUNNING', 'ok' if report['systemd']['running'] else 'warning',
           'systemd работает.' if report['systemd']['running'] else 'Работающий systemd не подтверждён; установка служб заблокирована.')
    try:
        report['disk'] = {'free_bytes': shutil.disk_usage('/').free}
        _check(report, 'DISK_SPACE', 'ok' if report['disk']['free_bytes'] >= 1024 ** 3 else 'warning',
               'Свободное место для установки: ' + str(report['disk']['free_bytes'] // (1024 ** 2)) + ' МБ; дополнительно учитывайте размер Docker images.')
    except OSError:
        _check(report, 'DISK_SPACE', 'unknown', 'Свободное место не удалось проверить.')
    ufw = _run(['ufw', 'status']) if report['dependencies']['ufw'] else None
    report['firewall'] = {'ufw': 'active' if ufw and 'Status: active' in ufw else
                           'inactive' if ufw and 'Status: inactive' in ufw else 'unknown'}
    _check(report, 'LOCAL_FIREWALL', 'ok' if report['firewall']['ufw'] == 'active' else 'unknown',
           'UFW активен; чужие правила сохраняются.' if report['firewall']['ufw'] == 'active' else
           'UFW не активен либо недоступен. Установка подготовит его после проверки SSH и служб; внешний firewall/NAT проверяется отдельно.')
    clock = _run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value']) if shutil.which('timedatectl') else None
    _check(report, 'SYSTEM_CLOCK', 'ok' if clock and clock.strip() == 'yes' else 'unknown',
           'Системное время синхронизировано.' if clock and clock.strip() == 'yes' else
           'Синхронизация времени не подтверждена. Неверное время мешает проверке TLS.')
    output = _run(['ss', '-H', '-lntp']) if report['dependencies']['ss'] else None
    if output is None:
        _check(report, 'LISTENER_INVENTORY_UNAVAILABLE', 'unknown', 'Инвентаризация TCP через ss недоступна; отсутствие слушателей не доказано.')
    else:
        report['listeners'] = parse_ss(output)
        _check(report, 'LISTENER_INVENTORY', 'ok', 'Получен список TCP-слушателей; без root владелец может быть неизвестен.')
    _docker_inventory(report, config)
    _attribute_processes(report)
    _web_inventory(report)
    inventory_complete = output is not None and (not report['docker']['available'] or report['docker']['inventory_complete'])
    for role, key, default, address in [('vpn', 'vpn_port', 443, None), ('challenge', 'challenge_port', 8080, None), ('local', 'local_port', 9443, '127.0.0.1')]:
        if role == 'vpn' and key in config and config[key] is None:
            _check(report, 'VPN_PORT_UNKNOWN', 'unknown', 'VPN-порт старой установки неизвестен; подтвердите его в настройках.')
            continue
        try:
            port = int(config.get(key, default))
            if not 1 <= port <= 65535 or (role != 'vpn' and port < 1024):
                raise ValueError
        except (ValueError, TypeError):
            _check(report, 'PORT_INVALID', 'error', 'Некорректный номер порта.', role=role)
            continue
        owners = listeners_for_port(report['listeners'], port, address)
        report['selected_ports'][role] = dict(port=port, address=address, listeners=owners)
        if role == 'vpn':
            code = 'VPN_LISTENER_PRESENT' if owners else 'VPN_LISTENER_MISSING'
            status = 'warning' if owners else ('unknown' if output is None else 'warning')
            message = 'VPN TCP-слушатель найден. Работоспособность Xray/REALITY и доступ с релея не подтверждены.' if owners else 'VPN TCP-слушатель не найден; нода автоматически не устанавливается.'
            _check(report, code, status, message)
            if owners and all(row['address'] in ('127.0.0.1', '::1') for row in owners):
                _check(report, 'VPN_LOOPBACK_ONLY', 'error', 'VPN доступен только на loopback; релей не сможет подключиться напрямую.')
        elif role == 'local' and config.get('docker_network'):
            _check(report, 'HTTPS_DOCKER_TARGET', 'unknown', 'Выбран HTTPS target в отдельной Docker-сети без публикации; host loopback не используется. Доступ из VPN-контейнера требует self-test.')
        else:
            foreign = [row for row in owners if not row.get('owned')]
            if owners and not foreign:
                _check(report, 'HTTPS_OWN_LISTENER' if role == 'local' else 'HTTP_OWN_LISTENER',
                       'ok', 'Порт обслуживает контейнер с идентификатором этой установки.', role=role)
                continue
            _check(report, 'HTTP_PORT_BUSY' if role == 'challenge' and owners else 'HTTPS_PORT_BUSY' if owners else 'HTTP_PORT_AVAILABLE' if role == 'challenge' else 'HTTPS_PORT_AVAILABLE',
                   'error' if owners else 'ok' if inventory_complete else 'unknown',
                   'Порт занят; выберите другой порт без остановки чужого слушателя.' if owners else 'Слушатель не обнаружен; bind будет повторно проверен перед применением.', role=role)
    if len({row['port'] for row in report['selected_ports'].values()}) != len(report['selected_ports']):
        _check(report, 'PORTS_OVERLAP', 'error', 'VPN, проверочный HTTP и локальный HTTPS должны иметь разные номера портов.')
    _check(report, 'RELAY_REACHABILITY_UNPROVEN', 'unknown', 'Внешнюю доступность backend/NAT и HTTP-01 с релея локальная диагностика не доказывает. Внешний HTTP-01 приходит на TCP 80 релея.')
    _check(report, 'VPN_CONTAINER_TARGET', 'warning', '127.0.0.1:9443 доступен VPN на хосте или в host network. Для bridge-контейнера нужен отдельный согласованный закрытый сетевой target; чужие сети не меняются.')
    domain = config.get('domain')
    if domain and isinstance(domain, str) and re.fullmatch(r'[A-Za-z0-9.\-]{1,253}', domain):
        report['dns']['domain'] = domain
        try:
            addresses = _resolve_dns(domain)
            if addresses is None:
                raise ValueError
            report['dns']['addresses'] = addresses
            expected = config.get('relay_ip')
            bad = not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses) or (expected and set(addresses) != {expected})
            _check(report, 'DNS_RELAY_MISMATCH' if bad else 'DNS_RESOLVED', 'error' if bad else 'ok' if expected else 'unknown',
                   'DNS не совпадает с ожидаемым публичным IP релея.' if bad else 'DNS разрешается; без ожидаемого IP принадлежность адресов релею не доказана.' if not expected else 'A/AAAA совпадают с ожидаемым IP релея.')
        except (OSError, ValueError):
            _check(report, 'DNS_LOOKUP_FAILED', 'error', 'DNS домена не разрешается; дождитесь готовности подготовки в боте.')
    return report


def display_compact(report, ports=False):
    """Installer summary; the full inventory remains available in diagnose."""
    system = report.get('os', {})
    if not ports:
        print('🔍 ' + ' '.join(str(system.get(key, '')) for key in ('id', 'version', 'architecture')).strip())
        docker = report.get('docker', {})
        print('Docker: ' + ('доступен' if docker.get('local') and docker.get('available') else 'нужна подготовка'))
        firewall = report.get('firewall', {}).get('ufw')
        print('UFW: ' + {'active': 'включён', 'inactive': 'выключен'}.get(firewall, 'нужна проверка'))
        for server in report.get('web_servers', []):
            print('⚠️ Веб-сервер: ' + server['name'] + '. Его настройки сохраняются.')
    else:
        labels = {'vpn': 'Нода', 'challenge': 'HTTP', 'local': 'HTTPS'}
        for role, selected in report.get('selected_ports', {}).items():
            listeners = selected['listeners']
            if role == 'vpn':
                owners = sorted({row.get('container') or ', '.join(p['name'] for p in row.get('processes', []))
                                 or 'процесс неизвестен' for row in listeners})
                detail = ', '.join(owners) if owners else 'слушатель не найден'
            else:
                detail = 'занят' if listeners else 'свободен'
            print(f"{labels[role]}: {selected['port']} · {detail}")
    for item in report.get('checks', []):
        if item['status'] == 'error':
            print('❌ [' + item['code'] + '] ' + item['message'])


def display(report):
    """Print only the allowlisted report, never subprocess stdout/stderr."""
    print('🔍 Диагностика transitclient · без изменения инфраструктуры')
    system = report['os']
    print(f"ОС: {system.get('id', system['system'])} {system.get('version', '')} · {system['architecture']}")
    print('Зависимости: ' + ', '.join(f'{name}={"есть" if present else "нет"}' for name, present in report['dependencies'].items()))
    for container in report['docker']['containers']:
        print(f"Контейнер: {container['name']} · {container['image']} · {'работает' if container['running'] else 'остановлен'} · сеть={container['network_mode']} · {'свой' if container['owned'] else 'владение не подтверждено'}")
    for row in report['listeners']:
        owner = row.get('container') or ', '.join(f"{proc['name']} (pid {proc['pid']}, {proc.get('unit', 'unit неизвестен')})" for proc in row['processes']) or 'владелец неизвестен'
        print(f"  TCP {row['address']}:{row['port']} · {owner} · {row['source']}")
    for server in report['web_servers']:
        print(f"Веб-сервер: {server['name']} · установлен={server['installed']} · активен={server['active']}")
    if report['dns'].get('addresses'):
        print('DNS A/AAAA: ' + ', '.join(report['dns']['addresses']))
    icons = dict(ok='✅', warning='⚠️', error='❌', unknown='❔')
    for item in report['checks']:
        print(f"{icons[item['status']]} [{item['code']}] {item['message']}")
