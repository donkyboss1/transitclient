"""Small read-only menu snapshot; external commands share a two-second budget.

This is not a diagnostic report. It never probes TLS, invokes recovery, or reads
historical operation results as evidence about the currently served certificate.
"""
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import time
import unicodedata


_ANSI = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')
_CONTAINER = re.compile(r'[a-f0-9]{12,64}')
_NEXT_TIME = re.compile(r'[A-Za-z]{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: [A-Za-z0-9:+-]{1,16})?')


def sanitize(value, limit=180):
    """Discard terminal escape sequences and invisible direction/control marks."""
    value = _ANSI.sub('', str(value))
    value = ''.join(' ' if unicodedata.category(char) in ('Cc', 'Cf', 'Cs') else char for char in value)
    return ' '.join(value.split())[:limit]


class _Budget:
    def __init__(self):
        self.deadline = time.monotonic() + 2.0

    def run(self, args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=min(0.4, remaining),
                                    env=dict(os.environ, LC_ALL='C'))
            return result.stdout if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return None


def _local_docker(budget):
    if not shutil.which('docker'):
        return False
    context = os.environ.get('DOCKER_CONTEXT')
    endpoint = os.environ.get('DOCKER_HOST') if not context else None
    if not endpoint:
        context = context or budget.run(['docker', 'context', 'show'])
        if not isinstance(context, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', context.strip()):
            return False
        output = budget.run(['docker', 'context', 'inspect', context.strip(), '--format', '{{json .Endpoints.docker.Host}}'])
        try:
            endpoint = json.loads(output or 'null')
        except (ValueError, TypeError):
            return False
    return isinstance(endpoint, str) and bool(re.fullmatch(r'unix:///[^\x00-\x20\x7f]+', endpoint))


def _caddy(config, budget):
    if not _local_docker(budget):
        return '⚠ Docker недоступен / локальный endpoint не подтверждён', 'unavailable'
    install_id = (config or {}).get('install_id')
    if not isinstance(install_id, str) or not re.fullmatch(r'[a-f0-9]{32}', install_id):
        return '⚠ Владелец контейнера не подтверждён', 'unknown'
    # Filter before inspecting, then verify again: never inventory foreign apps.
    output = budget.run(['docker', 'ps', '-a', '--filter', 'label=org.tenant-selfsteal.package=true',
                         '--filter', 'label=org.transitclient.install-id=' + install_id,
                         '--filter', 'label=com.docker.compose.service=caddy', '--format', '{{.ID}}'])
    if output is None:
        return '⚠ Docker недоступен', 'unavailable'
    identifiers = output.split()
    if not identifiers:
        return '⚠ Не найден', 'missing'
    if len(identifiers) != 1 or not _CONTAINER.fullmatch(identifiers[0]):
        return '⚠ Состояние неизвестно', 'unknown'
    output = budget.run(['docker', 'inspect', '--format',
                         '{{json .State.Status}}|{{json (index .Config.Labels "org.tenant-selfsteal.package")}}|'
                         '{{json (index .Config.Labels "org.transitclient.install-id")}}|'
                         '{{json (index .Config.Labels "com.docker.compose.service")}}', identifiers[0]])
    try:
        state, package, owner, service = [json.loads(item) for item in (output or '').strip().split('|')]
    except (ValueError, TypeError):
        return '⚠ Состояние неизвестно', 'unknown'
    if (package, owner, service) != ('true', install_id, 'caddy'):
        return '⚠ Владелец контейнера не подтверждён', 'unknown'
    states = {'running': ('✅ Работает', 'running'), 'exited': ('⏹ Остановлен', 'stopped'),
              'created': ('⏹ Остановлен', 'stopped'), 'dead': ('⏹ Остановлен', 'stopped'),
              'restarting': ('⚠ Перезапускается', 'restarting')}
    return states.get(state, ('⚠ Состояние неизвестно', 'unknown')) if isinstance(state, str) else ('⚠ Состояние неизвестно', 'unknown')


def _renewal(budget):
    from renewal_schedule import PROPERTIES, fields, health
    output = budget.run(['systemctl', 'show', 'tenant-selfsteal-renew.timer',
                         *[part for prop in PROPERTIES for part in ('-p', prop)]])
    timer = fields(output or '')
    service = fields(budget.run(['systemctl', 'show', 'tenant-selfsteal-renew.service',
                                '-p', 'ActiveState', '-p', 'Result']) or '')
    state = health(timer, service)
    next_time = timer.get('NextElapseUSecRealtime', '')
    if state == 'waiting':
        return '✅ Включено · следующий: ' + next_time, True
    if state == 'running':
        return '✅ Включено · проверка продления выполняется', True
    if state == 'service_failed':
        return '⚠ Расписание включено · последняя проверка завершилась ошибкой', False
    if timer.get('UnitFileState') in ('disabled', 'masked', 'masked-runtime') or timer.get('ActiveState') in ('inactive', 'failed'):
        return '⏹ Выключено · автоматическое продление не подтверждено', False
    if timer.get('UnitFileState') == 'enabled' and timer.get('ActiveState') == 'active':
        return '⚠ Включено · следующий запуск неизвестен', False
    return '⚠ Неизвестно · автоматическое продление не подтверждено', False


def tls_identity(app, config):
    """Cache key also used by the explicit menu self-check after it succeeds."""
    if config is None:
        return None
    try:
        certificate = (app.STATE / 'certs/current/fullchain.pem').read_bytes()
        return dict(domain=config['domain'], target=app.target(config),
                    docker_network=config.get('docker_network') or '',
                    certificate_sha256=hashlib.sha256(certificate).hexdigest())
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _https(app, config):
    identity = tls_identity(app, config)
    checked = getattr(app, '_menu_tls_check', None)
    if not isinstance(checked, dict) or not checked:
        return '⚠ Не проверен · запустите самопроверку', False
    timestamp = checked.get('at')
    age = time.time() - timestamp if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool) else -1
    if not math.isfinite(age) or age < 0 or not isinstance(checked.get('success'), bool):
        return '⚠ Не проверен · запустите самопроверку', False
    elapsed = int(age)
    ago = (f'{elapsed} с' if elapsed < 60 else f'{elapsed // 60} мин {elapsed % 60} с') + ' назад'
    if identity is None or checked.get('identity') != identity or age > 300:
        return '⚠ Проверка устарела · ' + ago + ' · запустите самопроверку', False
    if checked.get('success') is True:
        return '✅ Подтверждён самопроверкой · ' + ago, True
    return '⚠ Самопроверка не пройдена · ' + ago, False


def _certificate(app, config):
    try:
        result = app.certificate_status(config)
    except (OSError, ValueError, KeyError, TypeError):
        result = {'state': 'invalid'}
    if not isinstance(result, dict):
        result = {'state': 'invalid'}
    state = result.get('state')
    if state != 'present':
        return {'expired': '❌ Срок истёк', 'invalid': '❌ Сертификат повреждён', 'missing': '⚠ Сертификата нет'}.get(state, '⚠ Состояние неизвестно'), state
    days = result.get('days_remaining')
    if not isinstance(days, int) or isinstance(days, bool) or days < 0:
        return '⚠ Состояние неизвестно', 'unknown'
    issuer = result.get('issuer')
    issuer = ' / '.join(sanitize(item, 70) for item in issuer if isinstance(item, str)) if isinstance(issuer, list) else ''
    status = '⚠ Скоро истекает (на диске)' if days <= 14 else '✅ Действителен на диске'
    return status + (f' · {issuer}' if issuer else '') + f' · осталось {days} дн.' + (' · тестовый' if result.get('staging') is True else ''), ('soon' if days <= 14 else 'present')


def _site(app):
    try:
        metadata = json.loads((app.STATE / 'site-template.json').read_text(encoding='utf-8'))
        name = metadata.get('name') if isinstance(metadata, dict) else None
        if isinstance(name, str) and sanitize(name):
            return re.sub(r'^([^\w\s]+)(?=\w)', r'\1 ', sanitize(name))
    except (OSError, ValueError):
        pass
    return 'встроенная страница' if (app.STATE / 'site/current/index.html').is_file() else 'не выбран'


def _pending(app):
    journals = ('operation.json', 'uninstall.json', 'firewall.json', 'certificate-transaction.json', 'configuration-transaction.json',
                'update-transaction.json', 'site-transaction.json', 'ufw-activation.json')
    if any((app.STATE / name).exists() for name in journals):
        return True
    preparation = app.STATE / 'ufw-package-preparation.json'
    if preparation.exists():
        try:
            value = json.loads(preparation.read_text(encoding='utf-8'))
            return not isinstance(value, dict) or value.get('status') != 'installed'
        except (OSError, ValueError):
            return True
    return False


def snapshot(app):
    budget = _Budget()
    config = app.safe_config()
    if config is None:
        installation = 'broken' if app.CONFIG.exists() else ('incomplete' if app.STATE.exists() or app.INSTALL.exists() else 'none')
    else:
        installation = 'configured' if (app.STATE / 'compose.yaml').is_file() and (app.STATE / 'certs/current/fullchain.pem').is_file() and not _pending(app) else 'incomplete'
    caddy, caddy_state = _caddy(config, budget) if config else ('⚠ Не настроен', 'missing')
    if installation == 'incomplete':
        caddy += ' · ⚠ установка не завершена'
    certificate, certificate_state = _certificate(app, config)
    https, https_ok = _https(app, config)
    renewal, renewal_ok = _renewal(budget) if config else ('⚠ Не настроено', False)
    domain = config['domain'] if config else ('конфигурация повреждена' if installation == 'broken' else 'не настроен')
    ports = (f"VPN {config.get('vpn_port') or '?'} · HTTP {config['challenge_port']} · HTTPS {app.target(config)}" if config else 'не настроены')
    rows = [('Сервер', 'Caddy · ' + caddy), ('Домен', domain), ('Порты', ports),
            ('SSL', certificate), ('HTTPS', https), ('Продление', renewal), ('Заглушка', _site(app))]
    if installation == 'none':
        hint = 'Начните с установки: понадобятся домен и три порта.'
    elif installation == 'broken':
        hint = 'Конфигурация повреждена. Откройте диагностику перед исправлением.'
    elif installation == 'incomplete':
        hint = 'Установка не завершена. Откройте диагностику и завершите настройку.'
    elif caddy_state != 'running' or certificate_state in ('missing', 'invalid', 'expired', 'unknown'):
        hint = 'Сайт пока не подтверждён. Запустите самопроверку и откройте диагностику.'
    elif certificate_state == 'soon' or not renewal_ok:
        hint = 'Проверьте продление сертификата через самопроверку и диагностику.'
    elif not https_ok:
        hint = 'Запустите самопроверку для подтверждения HTTPS.'
    else:
        hint = 'HTTPS подтверждён последней самопроверкой. Выберите действие.'
    return dict(rows=[(label, sanitize(value)) for label, value in rows], hint=hint,
                config=config, installation=installation)
