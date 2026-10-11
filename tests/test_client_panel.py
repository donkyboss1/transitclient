"""Read-only start panel acceptance: no daemon/network calls outside mocks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture
def panel(monkeypatch):
    spec = importlib.util.spec_from_file_location('client_panel_test', Path(__file__).resolve().parents[1] / 'client_panel.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.shutil, 'which', lambda name: '/usr/bin/' + name)
    monkeypatch.delenv('DOCKER_HOST', raising=False)
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout='', stderr='SECRET'))
    return module


@pytest.fixture
def app(tmp_path):
    state = tmp_path / 'state'
    state.mkdir()
    config = dict(domain='node.example.com', vpn_port=443, challenge_port=8080,
                  local_port=9443, docker_network=None, install_id='a' * 32)
    module = SimpleNamespace(STATE=state, CONFIG=tmp_path / 'config.json',
                             INSTALL=tmp_path / 'install', safe_config=lambda: config,
                             certificate_status=lambda config: dict(state='present', days_remaining=60, issuer=['Let’s Encrypt']),
                             target=lambda config: '127.0.0.1:' + str(config['local_port']))
    module.CONFIG.write_text('{}')
    (state / 'compose.yaml').write_text('')
    (state / 'certs/current').mkdir(parents=True)
    (state / 'certs/current/fullchain.pem').write_bytes(b'certificate')
    return module


def rows(snapshot):
    return dict(snapshot['rows'])


def docker_runner(calls, *, state='running', labels=None, ids='abc123456789'):
    def run(args, **kwargs):
        calls.append((args, kwargs))
        output = None
        if args[:3] == ['docker', 'context', 'show']:
            output = 'default\n'
        elif args[:3] == ['docker', 'context', 'inspect']:
            output = json.dumps('unix:///var/run/docker.sock')
        elif args[:2] == ['docker', 'ps']:
            output = ids
        elif args[:2] == ['docker', 'inspect']:
            output = '|'.join(json.dumps(item) for item in [state, *(labels or ['true', 'a' * 32, 'caddy'])])
        elif args[0] == 'systemctl':
            output = 'UnitFileState=enabled\nActiveState=active\nNextElapseUSecRealtime=Sun 2026-10-11 05:00:00 UTC\n'
        return SimpleNamespace(returncode=0 if output is not None else 1, stdout=output or '', stderr='PRIVATE')
    return run


def test_snapshot_rows_and_no_network_or_full_diagnostics(panel, app, monkeypatch):
    calls = []
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner(calls))
    app.diagnostic_module = app.verify_served = app.recover = lambda *args: pytest.fail('panel must not invoke lifecycle')
    value = panel.snapshot(app)
    assert [label for label, _ in value['rows']] == ['Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка']
    assert value['config'] == app.safe_config()
    assert value['installation'] == 'configured'
    assert '✅ Работает' in rows(value)['Сервер']
    assert '443' in rows(value)['Порты'] and '8080' in rows(value)['Порты'] and '9443' in rows(value)['Порты']
    assert 'самопровер' in rows(value)['HTTPS'].lower()
    assert '✅ Включено' in rows(value)['Продление'] and 'следующий:' in rows(value)['Продление']
    assert not any(word in ' '.join(args) for args, _ in calls for word in ('pull', 'restart', 'openssl', 'curl', 'enable', 'acme'))


def test_header_describes_web_server_without_reading_hostname_or_os(panel, app, monkeypatch):
    import platform
    def forbidden():
        pytest.fail('The header must not read host identity or OS')
    monkeypatch.setattr(platform, 'node', forbidden)
    monkeypatch.setattr(platform, 'freedesktop_os_release', forbidden)
    monkeypatch.setattr(platform, 'system', forbidden)
    monkeypatch.setattr(platform, 'release', forbidden)
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner([]))
    assert rows(panel.snapshot(app))['Сервер'] == 'Caddy · ✅ Работает'


@pytest.mark.parametrize('name,expected', [('☁️FileCloud', '☁️ FileCloud'),
                                        ('☁️ FileCloud', '☁️ FileCloud'),
                                        ('☁FileCloud', '☁ FileCloud')])
def test_placeholder_name_has_space_after_icon(panel, app, name, expected):
    (app.STATE / 'site-template.json').write_text(json.dumps(dict(name=name)))
    assert rows(panel.snapshot(app))['Заглушка'] == expected


@pytest.mark.parametrize('kind,expected', [('none', 'none'), ('artifacts', 'incomplete'), ('bad', 'broken'), ('missing-cert', 'incomplete')])
def test_installation_states(panel, app, kind, expected):
    if kind in ('none', 'artifacts'):
        app.CONFIG.unlink()
        app.safe_config = lambda: None
        if kind == 'none':
            import shutil
            shutil.rmtree(app.STATE)
    elif kind == 'bad':
        app.safe_config = lambda: None
    else:
        (app.STATE / 'certs/current/fullchain.pem').unlink()
    assert panel.snapshot(app)['installation'] == expected


@pytest.mark.parametrize('endpoint', ['ssh://root:SECRET@host', 'tcp://127.0.0.1:2375', 'npipe:////./pipe/docker_engine'])
def test_remote_context_never_contacts_daemon(panel, app, monkeypatch, endpoint):
    calls = []
    monkeypatch.setenv('DOCKER_HOST', endpoint)
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner(calls))
    value = panel.snapshot(app)
    assert not any(args[0] == 'docker' for args, _ in calls)
    assert 'SECRET' not in json.dumps(value, ensure_ascii=False)


def test_context_precedence_and_foreign_container_rejected(panel, app, monkeypatch):
    calls = []
    monkeypatch.setenv('DOCKER_HOST', 'ssh://SECRET@remote')
    monkeypatch.setenv('DOCKER_CONTEXT', 'default')
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner(calls, labels=['true', 'b' * 32, 'caddy']))
    value = panel.snapshot(app)
    assert calls[0][0][:3] == ['docker', 'context', 'inspect']
    ps = next(args for args, _ in calls if args[:2] == ['docker', 'ps'])
    assert 'label=org.transitclient.install-id=' + 'a' * 32 in ps
    assert 'label=com.docker.compose.service=caddy' in ps
    assert 'не подтверждён' in rows(value)['Сервер']


@pytest.mark.parametrize('state,label', [('running', 'работает'), ('exited', 'остановлен'), ('restarting', 'перезапускается'), ('paused', 'неизвестно')])
def test_owned_caddy_states(panel, app, monkeypatch, state, label):
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner([], state=state))
    assert label in rows(panel.snapshot(app))['Сервер'].lower()


def test_missing_caddy(panel, app, monkeypatch):
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner([], ids=''))
    assert 'не найден' in rows(panel.snapshot(app))['Сервер'].lower()


def test_total_subprocess_budget_is_two_seconds(panel, app, monkeypatch):
    elapsed = [100.0]
    calls = []
    monkeypatch.setattr(panel.time, 'monotonic', lambda: elapsed[0])
    def run(args, **kwargs):
        calls.append((args, kwargs['timeout']))
        elapsed[0] += 0.8
        return docker_runner([])(args, **kwargs)
    monkeypatch.setattr(panel.subprocess, 'run', run)
    panel.snapshot(app)
    assert [round(timeout, 2) for _, timeout in calls] == [0.4, 0.4, 0.4]
    assert len(calls) == 3


def test_timeout_is_unknown_and_raw_errors_not_displayed(panel, app, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs['timeout'], output='SECRET')
    monkeypatch.setattr(panel.subprocess, 'run', timeout)
    value = panel.snapshot(app)
    assert 'SECRET' not in json.dumps(value, ensure_ascii=False)
    assert 'не подтверждено' in rows(value)['Продление']


@pytest.mark.parametrize('state,days,label', [('missing', 0, 'нет'), ('invalid', 0, 'повреждён'), ('expired', 0, 'истёк'), ('present', 14, 'скоро истекает'), ('present', 15, '15')])
def test_certificate_states(panel, app, state, days, label):
    app.certificate_status = lambda config: dict(state=state, days_remaining=days, issuer=['Issuer'])
    text = rows(panel.snapshot(app))['SSL']
    assert label in text.lower()
    if state == 'present':
        assert 'Issuer' in text


def test_saved_result_never_proves_https(panel, app):
    (app.STATE / 'result.json').write_text(json.dumps(dict(success=True, at=9999999999)))
    assert 'самопровер' in rows(panel.snapshot(app))['HTTPS'].lower()


@pytest.mark.parametrize('change', ['none', 'domain', 'target', 'certificate', 'old'])
def test_tls_cache_bound_to_current_identity_and_freshness(panel, app, monkeypatch, change):
    monkeypatch.setattr(panel.time, 'time', lambda: 1000)
    config = app.safe_config()
    identity = dict(domain=config['domain'], target=app.target(config), docker_network='',
                    certificate_sha256=hashlib.sha256(b'certificate').hexdigest())
    app._menu_tls_check = dict(at=900, success=True, identity=identity)
    if change == 'domain':
        identity['domain'] = 'other.example.com'
    elif change == 'target':
        identity['target'] = '127.0.0.1:9999'
    elif change == 'certificate':
        (app.STATE / 'certs/current/fullchain.pem').write_bytes(b'new certificate')
    elif change == 'old':
        app._menu_tls_check['at'] = 699
    text = rows(panel.snapshot(app))['HTTPS']
    assert ('подтверждён' in text.lower()) == (change == 'none')
    assert ('5 мин 1 с назад' if change == 'old' else '1 мин 40 с назад') in text
    if change != 'none':
        assert 'самопровер' in text.lower()


def test_changing_bridge_network_invalidates_same_alias_target(panel, app, monkeypatch):
    config = app.safe_config()
    config['docker_network'] = 'network-a'
    monkeypatch.setattr(panel.time, 'time', lambda: 1000)
    app._menu_tls_check = dict(at=999, success=True, identity=panel.tls_identity(app, config))
    config['docker_network'] = 'network-b'
    assert 'устарела' in rows(panel.snapshot(app))['HTTPS'].lower()


def test_control_ansi_bidi_sanitized_in_site_and_issuer(panel, app):
    (app.STATE / 'site-template.json').write_text(json.dumps(dict(name='Safe\x1b[31m\n\u202eSite')))
    app.certificate_status = lambda config: dict(state='present', days_remaining=60, issuer=['Issuer\x1b]0;SECRET\x07\u2066'])
    text = json.dumps(panel.snapshot(app)['rows'], ensure_ascii=False)
    assert '\u202e' not in text and '\u2066' not in text and 'SECRET' not in text and '\\u001b' not in text


def test_timer_requires_enabled_active_and_valid_next_time(panel, app, monkeypatch):
    base = docker_runner([])
    def run(args, **kwargs):
        if args[0] == 'systemctl':
            return SimpleNamespace(returncode=0, stdout='UnitFileState=enabled\nActiveState=inactive\nNextElapseUSecRealtime=SECRET\n', stderr='')
        return base(args, **kwargs)
    monkeypatch.setattr(panel.subprocess, 'run', run)
    text = rows(panel.snapshot(app))['Продление']
    assert 'не подтверждено' in text and 'SECRET' not in text


@pytest.mark.parametrize('journal', ['firewall.json', 'certificate-transaction.json', 'configuration-transaction.json',
                                     'update-transaction.json', 'site-transaction.json', 'ufw-activation.json'])
def test_pending_journal_marks_completed_files_incomplete(panel, app, monkeypatch, journal):
    monkeypatch.setattr(panel.subprocess, 'run', docker_runner([]))
    (app.STATE / journal).write_text('{}')
    value = panel.snapshot(app)
    assert value['installation'] == 'incomplete'
    assert 'установка не завершена' in rows(value)['Сервер']
    assert 'не завершена' in value['hint']


@pytest.mark.parametrize('preparation,expected', [('{}', 'incomplete'), ('{"status":"installed"}', 'configured'),
                                                ('{"status":"pending"}', 'incomplete'), ('invalid', 'incomplete'), ('null', 'incomplete')])
def test_ufw_preparation_status(panel, app, preparation, expected):
    (app.STATE / 'ufw-package-preparation.json').write_text(preparation)
    assert panel.snapshot(app)['installation'] == expected


@pytest.mark.parametrize('timer,label', [
    (None, '⚠ Неизвестно'),
    ('UnitFileState=enabled\nActiveState=active\nNextElapseUSecRealtime=SECRET\n', 'следующий запуск неизвестен'),
    ('UnitFileState=disabled\nActiveState=active\nNextElapseUSecRealtime=Sun 2026-10-11 05:00:00 UTC\n', '⏹ Выключено'),
    ('UnitFileState=enabled\nActiveState=inactive\n', '⏹ Выключено'),
    ('UnitFileState=SECRET\nActiveState=SECRET\n', '⚠ Неизвестно'),
])
def test_timer_disabled_and_unknown_are_distinct(panel, app, monkeypatch, timer, label):
    base = docker_runner([])
    def run(args, **kwargs):
        if args[0] == 'systemctl':
            return SimpleNamespace(returncode=0 if timer is not None else 1, stdout=timer or '', stderr='')
        return base(args, **kwargs)
    monkeypatch.setattr(panel.subprocess, 'run', run)
    text = rows(panel.snapshot(app))['Продление']
    assert label in text and 'SECRET' not in text


def test_empty_tls_cache_is_unchecked(panel, app):
    app._menu_tls_check = {}
    text = rows(panel.snapshot(app))['HTTPS']
    assert 'Не проверен' in text and 'устарела' not in text


def test_stalled_docker_leaves_timer_budget(panel, app, monkeypatch):
    elapsed = [100.0]
    calls = []
    monkeypatch.setattr(panel.time, 'monotonic', lambda: elapsed[0])
    def run(args, **kwargs):
        calls.append(args)
        if args[0] == 'docker':
            elapsed[0] += kwargs['timeout']
            raise subprocess.TimeoutExpired(args, kwargs['timeout'])
        return docker_runner([])(args, **kwargs)
    monkeypatch.setattr(panel.subprocess, 'run', run)
    value = panel.snapshot(app)
    assert calls[-1][0] == 'systemctl'
    assert '✅ Включено' in rows(value)['Продление']


def test_remaining_budget_limits_last_timeout(panel, monkeypatch):
    elapsed = [100.0]
    monkeypatch.setattr(panel.time, 'monotonic', lambda: elapsed[0])
    budget = panel._Budget()
    timeouts = []
    def run(args, **kwargs):
        timeouts.append(kwargs['timeout'])
        return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(panel.subprocess, 'run', run)
    elapsed[0] = 101.9
    budget.run(['systemctl', 'show'])
    elapsed[0] = 102.0
    budget.run(['systemctl', 'show'])
    assert timeouts == pytest.approx([0.1])
