"""Offline diagnostic safety checks; never contact Docker, DNS or a server."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def diagnostics(monkeypatch):
    spec = importlib.util.spec_from_file_location('tenant_diagnostics_test', Path(__file__).resolve().parents[1] / 'diagnostics.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.shutil, 'which', lambda name: '/usr/bin/' + name)
    monkeypatch.delenv('DOCKER_HOST', raising=False)
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    monkeypatch.setattr(module, '_run', lambda args: None)
    return module


def codes(report):
    return {row['code']: row['status'] for row in report['checks']}


@pytest.fixture
def client_report():
    vpn = dict(address='*', port=443, source='ss', processes=[], container='remnanode', network_mode='host', owned=False)
    https = dict(address='127.0.0.1', port=9443, source='ss', processes=[], container='tenant-selfsteal-caddy-1', network_mode='host', owned=True)
    unrelated = dict(address='127.0.0.53', port=53, source='ss', processes=[dict(name='systemd-resolve', pid=42)])
    report = dict(os=dict(id='ubuntu', version='26.04', architecture='x86_64', system='Linux'),
                  dependencies={name: True for name in ('bash', 'curl', 'wget', 'python3', 'ss', 'docker', 'ufw')},
                  docker=dict(available=True, local=True, inventory_complete=True, containers=[
                      dict(name='tenant-selfsteal-caddy-1', image='caddy:2.11.4@sha256:abcdef', running=True, network_mode='host', owned=True),
                      dict(name='remnanode', image='node:latest', running=True, network_mode='host', owned=False),
                      dict(name='unrelated-db', image='postgres:17', running=True, network_mode='host', owned=False)]),
                  firewall={'ufw': 'inactive'}, listeners=[unrelated, vpn, https], web_servers=[],
                  dns=dict(domain='node.example.com', addresses=['8.8.8.8']),
                  selected_ports=dict(vpn=dict(port=443, address=None, listeners=[vpn]),
                                      challenge=dict(port=8080, address=None, listeners=[]),
                                      local=dict(port=9443, address='127.0.0.1', listeners=[https])),
                  installation=dict(configured=True, certificate=dict(state='present', days_remaining=89)),
                  checks=[], pending=[])
    for code, state in [('OS_SUPPORTED', 'ok'), ('SYSTEMD_RUNNING', 'ok'), ('SYSTEM_CLOCK', 'ok'),
                        ('DISK_SPACE', 'ok'), ('DOCKER_LOCAL', 'ok'), ('COMPOSE_AVAILABLE', 'ok'),
                        ('HTTP_PORT_AVAILABLE', 'ok'), ('HTTPS_OWN_LISTENER', 'ok'), ('CERT_SERVED', 'ok'),
                        ('DNS_RESOLVED', 'unknown'), ('VPN_LISTENER_PRESENT', 'warning'),
                        ('EXISTING_WEB_SERVER', 'warning'), ('OTHER_WEB_PORT_LISTENER', 'unknown')]:
        report['checks'].append(dict(code=code, status=state, message='technical ' + code))
    return report


def test_summary_uses_selected_ports_and_hides_technical_successes(diagnostics, client_report, capsys):
    diagnostics.display(client_report)
    output = capsys.readouterr().out
    for value in ('ubuntu 26.04', 'UFW: ⚠️ выключен', 'VPN 443', 'remnanode', 'HTTP 8080: ✅ свободен',
                  'HTTPS 127.0.0.1:9443', 'обслуживает наш Caddy', '89 дней', 'Проверка HTTPS'):
        assert value in output
    for value in ('127.0.0.53', 'systemd-resolve', 'unrelated-db', 'sha256:', 'technical', '[OS_SUPPORTED]',
                  'Требует внимания', 'bridge'):
        assert value not in output
    assert output.count('Доступ с релея') == 1 and output.count('remnanode') == 1
    diagnostics.display(client_report, full=True)
    full = capsys.readouterr().out
    assert '127.0.0.53:53' in full and 'unrelated-db' in full and 'sha256:' in full and '[OS_SUPPORTED]' in full


@pytest.mark.parametrize('code', ['DISK_SPACE', 'SYSTEM_CLOCK', 'SYSTEMD_RUNNING', 'COMPOSE_AVAILABLE',
                                 'RENEW_TIMER_INACTIVE', 'LISTENER_INVENTORY_UNAVAILABLE', 'DOCKER_UNAVAILABLE',
                                 'OS_SUPPORTED', 'VPN_CONTAINER_TARGET'])
def test_summary_keeps_actionable_or_unknown_findings(diagnostics, client_report, capsys, code):
    client_report['checks'] = [item for item in client_report['checks'] if item['code'] != code]
    client_report['checks'].append(dict(code=code, status='warning', message='Требуется проверка компонента'))
    diagnostics.display(client_report)
    output = capsys.readouterr().out
    assert 'Требует внимания' in output and 'Требуется проверка компонента' in output
    assert '[' + code + ']' not in output


@pytest.mark.parametrize('available,response,expected', [(False, None, 'missing'), (True, None, 'unknown'),
                                                       (True, 'Status: inactive', 'inactive'), (True, 'Status: active', 'active')])
def test_ufw_states_are_distinct(diagnostics, monkeypatch, available, response, expected):
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda name: '/usr/bin/' + name if name != 'ufw' or available else None)
    monkeypatch.setattr(diagnostics, '_run', lambda args: response if args == ['ufw', 'status'] else None)
    assert diagnostics.collect()['firewall']['ufw'] == expected


@pytest.mark.parametrize('mode,warn', [('host', False), ('bridge', True), (None, True)])
def test_host_node_does_not_get_bridge_warning(diagnostics, monkeypatch, mode, warn):
    monkeypatch.setattr(diagnostics, '_run', lambda args: 'LISTEN 0 4 *:443 *:*' if args[0] == 'ss' else None)
    def attribute(report):
        report['listeners'][0]['network_mode'] = mode
    monkeypatch.setattr(diagnostics, '_attribute_processes', attribute)
    report = diagnostics.collect()
    assert ('VPN_CONTAINER_TARGET' in codes(report)) == warn


def test_unknown_port_inventory_does_not_claim_ports_are_free(diagnostics, client_report, capsys):
    client_report['checks'] = [dict(code='HTTP_PORT_AVAILABLE', status='unknown', message='неизвестно'),
                               dict(code='VPN_LISTENER_MISSING', status='unknown', message='неизвестно')]
    client_report['selected_ports']['vpn']['listeners'] = []
    diagnostics.display(client_report)
    output = capsys.readouterr().out
    assert 'HTTP 8080: ❔ не удалось проверить' in output
    assert 'VPN 443: ❔ не удалось проверить' in output
    assert 'свободен' not in output


def test_summary_preserves_conflict_and_tls_errors(diagnostics, client_report, capsys):
    selected = client_report['selected_ports']['local']['listeners'][0]
    selected['owned'], selected['container'] = False, 'foreign-web'
    client_report['checks'] = [dict(code='HTTPS_PORT_BUSY', status='error', message='Занят чужим процессом'),
                               dict(code='CERT_NOT_APPLIED', status='error', message='HTTPS недоступен')]
    diagnostics.display(client_report)
    output = capsys.readouterr().out
    assert 'конфликт · foreign-web' in output and 'HTTPS недоступен' in output
    assert 'обслуживает наш Caddy' not in output


def test_summary_warns_about_expiring_certificate(diagnostics, client_report, capsys):
    client_report['installation']['certificate']['days_remaining'] = 7
    diagnostics.display(client_report)
    assert 'SSL: ⚠️ скоро истекает (на диске) · осталось 7 дней' in capsys.readouterr().out


def test_ipv6_specific_bind_does_not_block_ipv4_loopback(diagnostics):
    rows = diagnostics.parse_ss('LISTEN 0 4096 [2001:db8::1]:9443 [::]:* users:(("nginx",pid=123,fd=4))\n'
                        'LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("caddy",pid=456,fd=5))')
    assert rows[0]['processes'] == [dict(name='nginx', pid=123)]
    assert diagnostics.listeners_for_port(rows, 9443, '127.0.0.1') == []
    assert diagnostics.listeners_for_port(rows, 8080) == [rows[1]]
    wildcard = diagnostics.parse_ss('LISTEN 0 4096 [::]:9443 [::]:*')
    assert diagnostics.listeners_for_port(wildcard, 9443, '127.0.0.1')


def test_missing_dependencies_accumulate_unknown_not_false_success(diagnostics, monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda name: None)
    report = diagnostics.collect()
    assert codes(report)['LISTENER_INVENTORY_UNAVAILABLE'] == 'unknown'
    assert codes(report)['HTTP_PORT_AVAILABLE'] == 'unknown'
    assert codes(report)['HTTPS_PORT_AVAILABLE'] == 'unknown'
    assert codes(report)['DOCKER_MISSING'] == 'warning'
    assert codes(report)['RELAY_REACHABILITY_UNPROVEN'] == 'unknown'
    json.dumps(report)


@pytest.mark.parametrize('endpoint', ['ssh://root:secret@other', 'tcp://127.0.0.1:2375', 'tcp://other:2375', 'npipe:////./pipe/docker_engine'])
def test_remote_docker_never_contacts_daemon(diagnostics, monkeypatch, endpoint):
    calls = []
    monkeypatch.setenv('DOCKER_HOST', endpoint)
    monkeypatch.setattr(diagnostics, '_run', lambda args: calls.append(args))
    report = diagnostics.collect()
    assert codes(report)['DOCKER_CONTEXT_UNSAFE'] == 'error'
    assert all(args[0] != 'docker' for args in calls)
    assert endpoint not in json.dumps(report)
    assert diagnostics.local_docker_error()


def test_context_override_is_respected_and_inspected_before_daemon(diagnostics, monkeypatch):
    monkeypatch.setenv('DOCKER_HOST', 'ssh://remote')
    monkeypatch.setenv('DOCKER_CONTEXT', 'desktop-linux')
    calls = []

    def run(args):
        calls.append(args)
        if args[:3] == ['docker', 'context', 'inspect']:
            return json.dumps('unix:///run/user/1000/docker.sock')
        return None

    monkeypatch.setattr(diagnostics, '_run', run)
    assert diagnostics.docker_local_context()['local'] is True
    assert calls == [['docker', 'context', 'inspect', 'desktop-linux', '--format', '{{json .Endpoints.docker.Host}}']]


def test_default_context_unknown_blocks_daemon(diagnostics, monkeypatch):
    calls = []

    def run(args):
        calls.append(args)
        return 'remote\n' if args == ['docker', 'context', 'show'] else json.dumps('ssh://user:password@remote') if args[:3] == ['docker', 'context', 'inspect'] else None

    monkeypatch.setattr(diagnostics, '_run', run)
    report = diagnostics.collect()
    assert codes(report)['DOCKER_CONTEXT_UNSAFE'] == 'error'
    assert not any(args[:2] in (['docker', 'info'], ['docker', 'ps']) for args in calls)
    assert 'password' not in json.dumps(report)


def test_publication_detected_without_userland_proxy_and_no_secret_fields(diagnostics, monkeypatch):
    calls = []
    container_id = 'abc123456789'

    def run(args):
        calls.append(args)
        if args == ['ss', '-H', '-lntp']:
            return ''
        if args == ['docker', 'context', 'show']:
            return 'default\n'
        if args[:3] == ['docker', 'context', 'inspect']:
            return json.dumps('unix:///var/run/docker.sock')
        if args[:2] == ['docker', 'info']:
            return '27.5.1\n'
        if args[:2] == ['docker', 'ps']:
            return container_id + '\n'
        if args[:2] == ['docker', 'inspect']:
            return '|'.join(json.dumps(item) for item in [{'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}], '443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '443'}]}, 'bridge', '/vpn-node', 'xray:stable', True, None, None])
        return None

    monkeypatch.setattr(diagnostics, '_run', run)
    report = diagnostics.collect()
    assert codes(report)['HTTP_PORT_BUSY'] == 'error'
    assert codes(report)['VPN_LISTENER_PRESENT'] == 'warning'
    assert codes(report)['VPN_LOOPBACK_ONLY'] == 'error'
    assert codes(report)['DOCKER_LOOPBACK_PUBLICATION'] == 'warning'
    assert report['selected_ports']['challenge']['listeners'][0]['container'] == 'vpn-node'
    assert all('Env' not in ' '.join(args) and 'Args' not in ' '.join(args) for args in calls)
    assert not any(word in ' '.join(args) for args in calls for word in ('pull', 'kill', 'stop', 'restart', 'apt', 'enable'))


def test_existing_server_and_conflicts_are_reported_together(diagnostics, monkeypatch):
    def run(args):
        if args[0] == 'ss':
            return ('LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=42,fd=4))\n'
                    'LISTEN 0 4096 127.0.0.1:9443 0.0.0.0:* users:(("other",pid=43,fd=5))')
        if args == ['systemctl', 'is-active', 'nginx.service']:
            return 'active\n'
        if args[:3] == ['systemctl', 'show', 'nginx.service']:
            return 'loaded\n'
        return None

    monkeypatch.setattr(diagnostics, '_run', run)
    report = diagnostics.collect()
    assert codes(report)['HTTP_PORT_BUSY'] == 'error'
    assert codes(report)['HTTPS_PORT_BUSY'] == 'error'
    assert codes(report)['EXISTING_WEB_SERVER'] == 'warning'
    nginx = next(row for row in report['web_servers'] if row['name'] == 'nginx')
    assert nginx['active'] and nginx['installed'] and nginx['unit'] == 'nginx.service'


def test_node_listener_on_443_is_not_reported_as_web_server(diagnostics, monkeypatch, capsys):
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda name: None)
    report = {
        'checks': [], 'systemd': {'available': False},
        'docker': {'containers': []}, 'web_servers': [],
        'listeners': diagnostics.parse_ss('LISTEN 0 4096 *:443 *:* users:(("rw-core",pid=41829,fd=7))'),
        'os': {'id': 'ubuntu', 'version': '26.04', 'architecture': 'x86_64'},
        'firewall': {'ufw': 'inactive'},
    }
    diagnostics._web_inventory(report)
    assert 'EXISTING_WEB_SERVER' not in codes(report)
    assert 'OTHER_WEB_PORT_LISTENER' in codes(report)
    diagnostics.display_compact(report)
    output = capsys.readouterr().out
    assert 'rw-core' not in output and 'EXISTING_WEB_SERVER' not in output
    assert 'UFW: выключен' in output


def test_unavailable_docker_cannot_prove_port_available_via_empty_ss(diagnostics, monkeypatch):
    monkeypatch.setattr(diagnostics, '_run', lambda args: '' if args[0] == 'ss' else None)
    report = diagnostics.collect()
    assert codes(report)['HTTP_PORT_AVAILABLE'] == 'unknown'
    assert codes(report)['HTTPS_PORT_AVAILABLE'] == 'unknown'


@pytest.mark.parametrize('saved_id,label_id,expected_owned', [
    ('a' * 32, 'a' * 32, True), ('a' * 32, 'b' * 32, False),
    ('a' * 32, None, False), (None, 'a' * 32, False)])
def test_owned_listener_requires_exact_saved_install_id(diagnostics, monkeypatch, saved_id, label_id, expected_owned):
    def run(args):
        if args[0] == 'ss':
            return ''
        if args == ['docker', 'context', 'show']:
            return 'default\n'
        if args[:3] == ['docker', 'context', 'inspect']:
            return json.dumps('unix:///var/run/docker.sock')
        if args[:2] == ['docker', 'info']:
            return '28.0.0\n'
        if args[:2] == ['docker', 'ps']:
            return 'abc123456789\n'
        if args[:2] == ['docker', 'inspect']:
            return '|'.join(json.dumps(item) for item in [{'9443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '9443'}]}, 'bridge', '/caddy', 'caddy:2.11.4', True, 'true', label_id])
        return None

    monkeypatch.setattr(diagnostics, '_run', run)
    report = diagnostics.collect(dict(install_id=saved_id))
    assert report['docker']['containers'][0]['owned'] is expected_owned
    assert ('HTTPS_OWN_LISTENER' in codes(report)) is expected_owned
    assert label_id is None or label_id not in json.dumps(report)


def test_stopped_caddy_detected_without_claiming_active_or_port_busy(diagnostics, monkeypatch):
    def run(args):
        if args[0] == 'ss':
            return ''
        if args == ['docker', 'context', 'show']:
            return 'default\n'
        if args[:3] == ['docker', 'context', 'inspect']:
            return json.dumps('unix:///var/run/docker.sock')
        if args[:2] == ['docker', 'info']:
            return '28.0.0\n'
        if args[:2] == ['docker', 'ps']:
            return 'abc123456789\n'
        if args[:2] == ['docker', 'inspect']:
            return '|'.join(json.dumps(item) for item in [{'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}, 'bridge', '/old-caddy', 'caddy:2.11.4', False, 'true', None])
        return None

    monkeypatch.setattr(diagnostics, '_run', run)
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda name: '/usr/bin/' + name if name != 'caddy' else None)
    report = diagnostics.collect()
    caddy = next(row for row in report['web_servers'] if row['name'] == 'caddy')
    assert caddy['installed'] and not caddy['active']
    assert not report['listeners']
    assert codes(report)['HTTP_PORT_AVAILABLE'] == 'ok'


def test_legacy_unknown_vpn_and_bridge_do_not_invent_conflicts(diagnostics, monkeypatch):
    monkeypatch.setattr(diagnostics, '_run', lambda args: 'LISTEN 0 4096 127.0.0.1:9443 0.0.0.0:*' if args[0] == 'ss' else None)
    report = diagnostics.collect(dict(vpn_port=None, docker_network='private-vpn'))
    assert codes(report)['VPN_PORT_UNKNOWN'] == 'unknown'
    assert 'PORT_INVALID' not in codes(report)
    assert 'HTTPS_PORT_BUSY' not in codes(report)
    assert codes(report)['HTTPS_DOCKER_TARGET'] == 'unknown'


def test_dns_all_aaaa_checked_and_failure_does_not_abort(diagnostics, monkeypatch):
    monkeypatch.setattr(diagnostics, '_resolve_dns', lambda *args: ['8.8.8.8', '2606:4700:4700::1111'])
    report = diagnostics.collect(dict(domain='site.example', relay_ip='8.8.8.8'))
    assert codes(report)['DNS_RELAY_MISMATCH'] == 'error'
    monkeypatch.setattr(diagnostics, '_resolve_dns', lambda *args: None)
    report = diagnostics.collect(dict(domain='site.example'))
    assert codes(report)['DNS_LOOKUP_FAILED'] == 'error'
    assert 'SECRET' not in json.dumps(report)


def test_raw_subprocess_errors_and_control_characters_are_not_exposed(diagnostics, monkeypatch, capsys):
    monkeypatch.setattr(diagnostics.subprocess, 'run', lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, 'TOKEN=secret', 'PASSWORD=secret'))
    assert diagnostics._run(['ss']) is None
    rows = diagnostics.parse_ss('LISTEN 0 4 0.0.0.0:443 *:* users:(("bad\x1b[2J",pid=11,fd=2))')
    assert rows[0]['processes'][0]['name'] == 'unknown'
    monkeypatch.setattr(diagnostics, '_run', lambda args: None)
    diagnostics.display(diagnostics.collect())
    printed = capsys.readouterr().out
    assert 'TOKEN=' not in printed and 'PASSWORD=' not in printed and '\x1b' not in printed
