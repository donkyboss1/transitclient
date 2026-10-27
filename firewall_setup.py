"""Conservative firewall planning: preserve complex hosts, manage simple UFW.

No reset, policy changes, foreign rule deletion or Docker network mutations.
The persistent service allowances deliberately survive client uninstallation.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import time
import uuid


UFW_DIR = Path('/etc/ufw')
UFW_DEFAULT = Path('/etc/default/ufw')


class FirewallError(Exception):
    def __init__(self, message, code='FIREWALL_UNSAFE'):
        super().__init__(message)
        self.code = code


def _read(run, args, optional=False, missing_only=False):
    try:
        result = run(args, check=False, timeout=15)
    except Exception as exc:
        if (optional or missing_only) and isinstance(exc, FileNotFoundError):
            return None
        raise FirewallError('Не удалось проверить firewall. Изменения не применены.') from exc
    if result.returncode:
        if optional:
            return None
        raise FirewallError('Проверка firewall завершилась ошибкой. Изменения не применены.')
    try:
        return result.stdout.decode('utf-8', errors='strict')
    except UnicodeError as exc:
        raise FirewallError('Не удалось разобрать ответ проверки firewall.') from exc


def _listeners(text, protocol):
    records = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or parts[0] not in ('LISTEN', 'UNCONN'):
            raise FirewallError('Не удалось разобрать TCP/UDP-слушатели.')
        try:
            address, port = parts[3].rsplit(':', 1)
            port = int(port)
            address = address.strip('[]').split('%', 1)[0]
            if address != '*':
                parsed = ipaddress.ip_address(address)
                if parsed.is_loopback or (getattr(parsed, 'ipv4_mapped', None) and parsed.ipv4_mapped.is_loopback):
                    continue
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError as exc:
            raise FirewallError('Не удалось определить адрес/порт службы.') from exc
        process = parts[5] if len(parts) == 6 else ''
        if not re.search(r'pid=\d+', process):
            raise FirewallError('Не удалось определить владельца открытого порта; UFW не включён.')
        records.append((port, protocol, bool(re.search(r'\("sshd(?:-session)?"', process))))
    return records


def _docker_chain(value):
    return bool(re.fullmatch(r'DOCKER(?:-[A-Z0-9-]+)?', value))


def _native_filters(run, docker_host_only=False, active_ufw=False):
    for command in ('iptables-save', 'ip6tables-save'):
        text = _read(run, [command])
        table = None
        for line in text.splitlines():
            if line.startswith('*'):
                table = line[1:]
            if table != 'filter':
                # Native mangle/raw drops can block preserved host endpoints too.
                if re.search(r'\s-j (?:DROP|REJECT)\b', line):
                    raise FirewallError('Обнаружены другие фильтрующие правила; требуется ручная настройка.')
                if line.startswith('-A ') and table == 'nat':
                    args = shlex.split(line)
                    target = args[args.index('-j') + 1] if '-j' in args else ''
                    if not (docker_host_only and (_docker_chain(args[1]) or _docker_chain(target)
                            or target == 'MASQUERADE' and re.search(r'\b(?:docker0|br-[a-f0-9]+)\b', line))):
                        raise FirewallError('Нестандартные NAT-правила требуют ручной проверки.')
                continue
            if docker_host_only and re.match(r':FORWARD DROP\b', line):
                continue
            if not active_ufw and re.match(r':(?:INPUT|OUTPUT|FORWARD) (?!ACCEPT\b)', line):
                raise FirewallError('Обнаружена чужая политика firewall; автоматическое включение запрещено.')
            if line.startswith('-A '):
                args = shlex.split(line)
                chain = args[1]
                target = args[args.index('-j') + 1] if '-j' in args else ''
                sets = [args[i + 1] for i, value in enumerate(args[:-1]) if value == '--match-set']
                if (chain.startswith('f2b-') or target.startswith('f2b-')
                        or any(name.startswith('f2b-') for name in sets)):
                    raise FirewallError('Обнаружены правила Fail2Ban. Автоматическое включение UFW '
                                        'может изменить порядок блокировок; требуется согласованная интеграция. '
                                        'Для сохранения текущего firewall используйте install --firewall manual.',
                                        'FIREWALL_FAIL2BAN_PRESENT')
                if active_ufw and (chain.startswith('ufw-') or chain in ('INPUT', 'OUTPUT', 'FORWARD') and target.startswith('ufw-')):
                    continue
                if docker_host_only and (chain == 'FORWARD' and _docker_chain(target)):
                    continue
                if docker_host_only and _docker_chain(chain) and target in ('RETURN', 'ACCEPT', 'DROP'):
                    if chain == 'DOCKER-USER' and args != ['-A', 'DOCKER-USER', '-j', 'RETURN']:
                        raise FirewallError('Пользовательские Docker firewall-правила требуют ручной проверки.')
                    continue
                if docker_host_only and _docker_chain(chain) and _docker_chain(target):
                    continue
                raise FirewallError('Обнаружены активные правила другого firewall; требуется ручная настройка.')
    nft = _read(run, ['nft', '--json', 'list', 'ruleset'], missing_only=True)
    if nft is not None:
        try:
            objects = json.loads(nft)['nftables']
            for item in objects:
                # iptables-nft is covered above. Native nft chains may implement
                # base policy, rate limiting, queues, sets or interface filters.
                for kind in ('rule', 'chain'):
                    value = item.get(kind)
                    ufw_owned = bool(value and active_ufw and value.get('family') in ('ip', 'ip6')
                                     and value.get('table') == 'filter' and (
                                         value.get('chain', value.get('name', '')).startswith('ufw-') or
                                         kind == 'chain' and value.get('name') in ('INPUT', 'OUTPUT', 'FORWARD') or
                                         kind == 'rule' and value.get('chain') in ('INPUT', 'OUTPUT', 'FORWARD')
                                         and all(set(expr) == {'jump'} and expr['jump'].get('target', '').startswith('ufw-')
                                                 for expr in value.get('expr', []))))
                    if ufw_owned:
                        continue
                    if value and value.get('family') not in (None, 'ip', 'ip6'):
                        raise FirewallError('Нестандартное семейство nftables требует ручной проверки.')
                    docker_forward = bool(value and docker_host_only and value.get('table') == 'filter'
                                          and (value.get('chain', value.get('name')) == 'FORWARD'
                                               or _docker_chain(value.get('chain', value.get('name', ''))))
                                          and value.get('hook') in (None, 'forward'))
                    if kind == 'chain' and value and value.get('policy', 'accept') != 'accept' and not docker_forward:
                        raise FirewallError('Обнаружена ограничивающая политика nftables; требуется ручная настройка.')
                    if value and value.get('table') not in ('filter', 'nat', 'mangle', 'raw', 'security'):
                        raise FirewallError('Обнаружен самостоятельный nftables firewall; требуется ручная настройка.')
                    if kind == 'chain' and value and value.get('hook') not in (None, 'input', 'output', 'forward') and value.get('table') != 'nat':
                        raise FirewallError('Обнаружена нестандартная nftables цепочка; требуется ручная настройка.')
                    if kind == 'rule' and value and value.get('table') != 'nat' and not docker_forward:
                        raise FirewallError('Обнаружены nftables-фильтры; требуется ручная настройка.')
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise FirewallError('Не удалось проверить nftables; автоматическое включение запрещено.') from exc
    else:
        for binary in ('iptables', 'ip6tables'):
            if 'nf_tables' in _read(run, [binary, '--version']):
                raise FirewallError('Для проверки nft-backend нужен nft; включение UFW запрещено.')


def _defaults():
    try:
        contents = UFW_DEFAULT.read_text()
    except OSError as exc:
        raise FirewallError('Не удалось прочитать настройки UFW.') from exc
    settings = dict(re.findall(r'^([A-Z0-9_]+)=["\x27]?([^"\x27\n]+)', contents, re.M))
    if (settings.get('DEFAULT_OUTPUT_POLICY') != 'ACCEPT' or settings.get('IPV6') != 'yes'
            or settings.get('MANAGE_BUILTINS') != 'no'):
        raise FirewallError('Настройки UFW требуют ручной проверки: исходящая политика или IPv6.')
    return contents


def _vendor_configuration(run):
    """UFW status omits custom before/after rules; verify package baselines."""
    entries = _read(run, ['dpkg-query', '-W', '-f=${Conffiles}', 'ufw'])
    baseline = dict(re.findall(r'^\s+(\S+) ([0-9a-f]{32})(?:\s+obsolete)?$', entries, re.M))
    for name in ('before.rules', 'before6.rules', 'after.rules', 'after6.rules', 'before.init', 'after.init'):
        path = UFW_DIR / name
        if not path.exists():
            if name.endswith('.init'):
                continue
            raise FirewallError('Отсутствует стандартная конфигурация UFW.')
        if path.is_symlink() or str(path) not in baseline:
            raise FirewallError('Нестандартные файлы UFW требуют ручной проверки.')
        actual = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
        if actual != baseline[str(path)]:
            raise FirewallError('Изменённая конфигурация UFW требует ручной проверки.')
    return entries


def _added_rules(run):
    text = _read(run, ['ufw', 'show', 'added'])
    for line in text.splitlines():
        if not line.startswith('ufw '):
            continue
        try:
            args = shlex.split(line)
        except ValueError as exc:
            raise FirewallError('Нестандартные правила UFW требуют ручной проверки.') from exc
        # Accept ordinary port allowances without rewriting their comments.
        if len(args) >= 3 and args[1] == 'allow' and re.fullmatch(r'\d+(?::\d+)?(?:/(?:tcp|udp))?', args[2]):
            continue
        # Never override any denial or limiter. Advanced allow/app/interface
        # rules also need manual review before activation.
        raise FirewallError('Существующие ограничения или сложные правила UFW требуют ручной проверки.')
    return text


def check_challenge_rules(run, port, *, check_vendor=True):
    """Never prepend a challenge allowance ahead of an owner's deny/limit."""
    if check_vendor:
        _vendor_configuration(run)
    text = _read(run, ['ufw', 'show', 'added'])
    for line in text.splitlines():
        if not line.startswith('ufw '):
            continue
        try:
            args = shlex.split(line)
        except ValueError as exc:
            raise FirewallError('Нестандартные правила UFW требуют ручной проверки.') from exc
        if len(args) < 2 or args[1] == 'route' or 'out' in args[:4]:
            continue
        if args[1] not in ('deny', 'reject', 'limit'):
            continue
        if 'proto' in args and args[args.index('proto') + 1] == 'udp':
            continue
        candidate = args[2] if len(args) > 2 else 'any'
        if candidate in ('in', 'from', 'to', 'log', 'log-all'):
            candidate = 'any'
            if 'to' in args:
                target = args[args.index('to') + 1:]
                if 'port' in target:
                    candidate = target[target.index('port') + 1]
        if candidate.endswith('/udp'):
            continue
        match = re.fullmatch(r'(\d+)(?::(\d+))?(?:/tcp)?', candidate)
        if match and not int(match[1]) <= int(port) <= int(match[2] or match[1]):
            continue
        raise FirewallError('Правило UFW ограничивает проверочный порт; измените его вручную.', 'FIREWALL_RULE_CONFLICT')


def plan(config, report, run):
    """Read-only JSON-serializable activation plan; raise for uncertain safety."""
    requested = config.get('firewall_effective') or config.get('firewall', 'auto')
    if requested in ('manual', 'preserve'):
        return dict(mode=requested, effective='preserve', rules=[], changes=[
                    'Сохранить существующий firewall; временные разрешения также настраиваются владельцем.'], fingerprint=requested)
    try:
        prepared = _ufw_plan(config, report, run)
    except FirewallError as exc:
        if requested != 'auto':
            raise FirewallError(str(exc) + ' Чтобы продолжить без изменения firewall, используйте --firewall preserve.', exc.code) from exc
        return dict(mode='preserve', effective='preserve', rules=[], fingerprint='preserve',
                    reason=exc.code, changes=['Режим auto выбрал preserve: ' + str(exc),
                    'Текущие UFW/nftables/Docker/Fail2Ban правила сохраняются.'])
    prepared['effective'] = 'ufw'
    return prepared


def _ufw_plan(config, report, run):
    installed = report.get('dependencies', {}).get('ufw', False)
    status = _read(run, ['ufw', 'status']) if installed else ''
    if 'Status: active' in status:
        _native_filters(run, bool(report.get('docker', {}).get('inventory_complete')), active_ufw=True)
        check_challenge_rules(run, config['challenge_port'])
        # Existing active firewall and service rules are never changed here.
        return dict(mode='active', rules=[], changes=['UFW уже включён; SSH, службы и политики сохраняются.'],
                    fingerprint=hashlib.sha256(status.encode()).hexdigest())
    if installed and 'Status: inactive' not in status:
        raise FirewallError('Состояние UFW неизвестно; включение запрещено.')
    docker = report.get('docker', {})
    if docker.get('available') and (not docker.get('inventory_complete') or not docker.get('local')):
        raise FirewallError('Не удалось проверить локальные Docker-сети; UFW не включён.')
    if any(c.get('running') and c.get('network_mode') not in ('host', 'none') for c in docker.get('containers', [])):
        raise FirewallError('Работает Docker-контейнер с отдельной сетью; включение UFW требует ручной проверки.')
    for unit in ('firewalld.service', 'nftables.service', 'netfilter-persistent.service'):
        active = _read(run, ['systemctl', 'is-active', unit], optional=True)
        if active and active.strip() == 'active':
            raise FirewallError('Работает другой менеджер firewall; требуется ручная настройка.')
    _native_filters(run, bool(docker.get('available') and docker.get('inventory_complete')))
    tcp = _read(run, ['ss', '-H', '-lntp'])
    udp = _read(run, ['ss', '-H', '-lnup'])
    listeners = _listeners(tcp, 'tcp') + _listeners(udp, 'udp')
    ssh_ports = {port for port, protocol, is_ssh in listeners if is_ssh and protocol == 'tcp'}
    if not ssh_ports:
        raise FirewallError('SSH-слушатель не подтверждён; включение UFW запрещено.')
    vpn = config.get('vpn_port')
    required = {(port, protocol) for port, protocol, ssh in listeners if ssh or protocol == 'tcp' and port == vpn}
    unknown = [(port, protocol) for port, protocol, ssh in listeners if not ssh and not (protocol == 'tcp' and port == vpn)]
    if unknown:
        raise FirewallError('Есть публичные слушатели с неподтверждённым назначением. Их доступ не будет расширен; '
                            'для сохранения доступности выберите preserve.', 'FIREWALL_LISTENER_UNCLASSIFIED')
    connection = os.environ.get('SSH_CONNECTION')
    if connection:
        try:
            peer, peer_port, local, ssh_port = connection.split()
            ipaddress.ip_address(peer)
            ipaddress.ip_address(local)
            peer_port = int(peer_port)
            ssh_port = int(ssh_port)
            if not 1 <= peer_port <= 65535 or ssh_port not in ssh_ports:
                raise ValueError
        except ValueError as exc:
            raise FirewallError('Текущий SSH-порт не подтверждён среди слушателей.') from exc
        required.add((ssh_port, 'tcp'))
    # Native rules are independently validated on both planning and applying.
    # Do not hash them: starting an approved missing Docker dependency adds its
    # own harmless forwarding/NAT chains before activation.
    evidence = [sorted(listeners)]
    if installed:
        evidence += [_defaults(), _vendor_configuration(run), _added_rules(run)]
        for port, protocol in sorted(required):
            _read(run, ['ufw', '--dry-run', 'prepend', 'allow', f'{port}/{protocol}', 'comment', 'transitclient-preserve'])
        _read(run, ['ufw', '--dry-run', '--force', 'enable'])
    rules = [dict(port=port, protocol=protocol) for port, protocol in sorted(required)]
    changes = ([] if installed else ['Установить пакет UFW и повторить проверки.']) + [
        'Сохранить резервную копию UFW.',
        'Сохранить доступ: ' + ', '.join(f"{r['port']}/{r['protocol']}" for r in rules) + '.',
        'Включить UFW с откатом через 180 секунд; подтвердить из НОВОГО SSH-соединения.',
        f"TCP {int(config['challenge_port'])} открывать только на время выпуска/продления сертификата.",
    ]
    return dict(mode='inactive' if installed else 'missing', rules=rules, changes=changes,
                fingerprint=hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest())


def _backup(state):
    path = state / 'ufw-backups' / uuid.uuid4().hex
    path.mkdir(parents=True, mode=0o700)
    if UFW_DIR.is_symlink() or UFW_DEFAULT.is_symlink():
        raise FirewallError('Символические ссылки в конфигурации UFW запрещены.')
    for item in UFW_DIR.rglob('*'):
        if item.is_symlink() or (not item.is_file() and not item.is_dir()):
            raise FirewallError('Нестандартные файлы UFW блокируют резервное копирование.')
    if UFW_DIR.exists():
        shutil.copytree(UFW_DIR, path / 'ufw', copy_function=shutil.copyfile)
    if UFW_DEFAULT.exists():
        shutil.copyfile(UFW_DEFAULT, path / 'default-ufw')
    (path / 'original-presence.json').write_text(json.dumps(dict(directory=UFW_DIR.exists(), default=UFW_DEFAULT.exists())))
    for item in path.rglob('*'):
        os.chmod(item, 0o700 if item.is_dir() else 0o600)
    os.chmod(path, 0o700)
    return path


def apply(prepared, config, state, run, atomic_json):
    """Apply already-approved plan. Caller owns installation lock/confirmation."""
    if prepared['mode'] in ('manual', 'preserve', 'active'):
        return dict(status='unchanged', mode=prepared['mode'])
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        raise FirewallError('Подготовка UFW требует root.')
    # Recollect host/container state immediately before mutation.
    import diagnostics
    current_report = diagnostics.collect(config)
    current = plan(config, current_report, run)
    if current['fingerprint'] != prepared['fingerprint'] or current['mode'] != prepared['mode']:
        raise FirewallError('Состояние firewall/служб изменилось; повторите установку.', 'FIREWALL_PLAN_CHANGED')
    state = Path(state)
    if state.is_symlink():
        raise FirewallError('Символическая ссылка вместо каталога состояния запрещена.')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'posix' and (state.stat().st_uid != 0 or state.stat().st_mode & 0o077):
        raise FirewallError('Каталог состояния должен быть доступен только root.')
    backup_root = state / 'ufw-backups'
    if backup_root.is_symlink():
        raise FirewallError('Символическая ссылка вместо каталога резервных копий запрещена.')
    marker = state / 'ufw-activation.json'
    if marker.exists():
        raise FirewallError('Незавершённая подготовка UFW; проверьте её журнал и резервную копию.')
    before_install = None
    if current['mode'] == 'missing':
        before_install = _backup(state)
        atomic_json(state / 'ufw-package-preparation.json', dict(status='installing', backup=str(before_install)))
        run(['apt-get', 'update'], timeout=300)
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'ufw'], timeout=300)
        current = plan(config, diagnostics.collect(config), run)
        if current['mode'] == 'active':
            raise FirewallError('Пакет неожиданно включил UFW; требуется ручная проверка.')
        if current['mode'] != 'inactive' or current['rules'] != prepared['rules']:
            raise FirewallError('После установки пакета состояние изменилось; повторите проверку.')
        atomic_json(state / 'ufw-package-preparation.json', dict(status='installed', backup=str(before_install)))
    backup = _backup(state)
    unit = 'transitclient-ufw-rollback-' + uuid.uuid4().hex
    fired = backup / 'rollback-fired'
    script = backup / 'rollback.sh'
    # The watchdog is autonomous and needs neither installer nor Python modules.
    script.write_text('#!/bin/sh\nset -eu\n/usr/sbin/ufw --force disable\n'
                      + 'touch ' + shlex.quote(str(fired)) + '\nchmod 600 ' + shlex.quote(str(fired)) + '\n')
    os.chmod(script, 0o700)
    journal = dict(status='prepared', backup=str(backup), unit=unit, rules=current['rules'], original='inactive',
                   install_id=config.get('install_id'), token=uuid.uuid4().hex,
                   activated_uptime=float(Path('/proc/uptime').read_text().split()[0]) if os.name == 'posix' else 0,
                   deadline=int(time.time()) + 180)
    if before_install:
        journal['before_install_backup'] = str(before_install)
    atomic_json(marker, journal)
    armed = False
    try:
        for rule in current['rules']:
            run(['ufw', 'prepend', 'allow', f"{rule['port']}/{rule['protocol']}", 'comment', 'transitclient-preserve'])
        run(['systemd-run', '--unit=' + unit, '--on-active=180s', '--timer-property=AccuracySec=1s',
             '--description=Transitclient UFW activation rollback', '/bin/sh', str(script)])
        armed = True
        journal['status'] = 'enabling'
        journal['activated_uptime'] = float(Path('/proc/uptime').read_text().split()[0]) if os.name == 'posix' else 0
        atomic_json(marker, journal)
        run(['ufw', '--force', 'enable'])
        status = _read(run, ['ufw', 'status', 'numbered'])
        if 'Status: active' not in status:
            raise FirewallError('UFW не включился; выполняется откат.')
        for rule in current['rules']:
            for family in ('', r'\s+\(v6\)'):
                if not re.search(r'\]\s+' + re.escape(f"{rule['port']}/{rule['protocol']}") + family + r'\s+ALLOW IN\s+Anywhere\b', status):
                    raise FirewallError('Разрешение служебного порта IPv4/IPv6 не подтверждено; выполняется откат.')
        # An existing SSH stream / local status cannot prove new inbound access.
        journal['status'] = 'awaiting-confirmation'
        atomic_json(marker, journal)
        return journal
    except BaseException:
        if armed:
            # Best effort only; the independent watchdog remains armed if the
            # parent dies, times out, loses SSH or cannot execute this command.
            try:
                run(['ufw', '--force', 'disable'])
            except BaseException:
                pass
        journal['status'] = 'needs-review'
        atomic_json(marker, journal)
        raise


def fresh_ssh(journal, run):
    """Require a new sshd ancestor and its live, matching transport socket."""
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) != 4 or journal.get('activated_uptime') is None:
        return False
    peer, peer_port, local, port = connection
    try:
        ipaddress.ip_address(peer)
        ipaddress.ip_address(local)
        int(peer_port)
        if int(port) not in [r['port'] for r in journal['rules'] if r['protocol'] == 'tcp']:
            return False
        sockets = _read(run, ['ss', '-H', '-tnp', 'state', 'established'])
        transport = [line for line in sockets.splitlines() if (
                     f'{peer}:{peer_port}' in line or f'[{peer}]:{peer_port}' in line) and (
                     f'{local}:{port}' in line or f'[{local}]:{port}' in line)]
        proved = False
        pid = os.getppid()
        for _ in range(32):
            root = Path('/proc') / str(pid)
            stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
            executable = (root / 'comm').read_text().strip()
            started = int(stat[19]) / os.sysconf('SC_CLK_TCK')
            if executable.startswith('sshd') and any(re.search(r'\bpid=' + str(pid) + r'\b', line) for line in transport):
                # A newly forked channel on an old ControlMaster transport must
                # not validate activation. Check every socket-owning ancestor.
                if started <= journal['activated_uptime']:
                    return False
                proved = True
            pid = int(stat[1])
            if pid <= 1:
                break
        return proved
    except (OSError, ValueError, IndexError):
        return False
    return False


def confirm_activation(state, config, token, run, atomic_json):
    marker = Path(state) / 'ufw-activation.json'
    if not marker.exists():
        raise FirewallError('Ожидающей подтверждения активации UFW нет.')
    journal = json.loads(marker.read_text())
    if (journal.get('install_id') != config.get('install_id') or journal.get('token') != token
            or journal.get('status') != 'awaiting-confirmation' or journal.get('deadline', 0) <= time.time()
            or not re.fullmatch(r'transitclient-ufw-rollback-[0-9a-f]{32}', journal.get('unit', ''))):
        raise FirewallError('Подтверждение активации недействительно; откат остаётся включён.')
    if not fresh_ssh(journal, run):
        raise FirewallError('Подключитесь по SSH заново после включения UFW и повторите команду. '
                            'Старое соединение не подтверждает доступ.', 'FIREWALL_FRESH_SSH_REQUIRED')
    run(['systemctl', 'stop', journal['unit'] + '.timer', journal['unit'] + '.service'])
    if (Path(journal['backup']) / 'rollback-fired').exists() or 'Status: active' not in _read(run, ['ufw', 'status']):
        raise FirewallError('Откат уже сработал; повторите диагностику.')
    journal['status'] = 'active'
    atomic_json(Path(state) / 'ufw-setup.json', journal)
    marker.unlink()
    return journal


def recover_activation(state, run, atomic_json):
    """Boot/interruption recovery; permanent preservation permissions stay."""
    marker = Path(state) / 'ufw-activation.json'
    if not marker.exists():
        return
    try:
        journal = json.loads(marker.read_text())
        unit = journal['unit']
        if journal['original'] != 'inactive' or not re.fullmatch(r'transitclient-ufw-rollback-[0-9a-f]{32}', unit):
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise FirewallError('Журнал подготовки UFW повреждён; автоматический откат запрещён.') from exc
    if journal['status'] != 'active':
        run(['ufw', '--force', 'disable'])
    run(['systemctl', 'stop', unit + '.timer', unit + '.service'], check=False)
    journal['status'] = 'recovered'
    atomic_json(Path(state) / 'ufw-setup.json', journal)
    marker.unlink()
