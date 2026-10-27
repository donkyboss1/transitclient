"""Offline tests of real lifecycle/cleanup/rollback paths. Never install anything."""
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

PACKAGE = Path(__file__).resolve().parents[1]


@pytest.fixture
def app(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('tenant_selfsteal_test', PACKAGE / 'selfsteal.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = tmp_path / 'state'
    state.mkdir()
    monkeypatch.setattr(module, 'STATE', state)
    monkeypatch.setattr(module, 'CONFIG', tmp_path / 'config.json')
    monkeypatch.setattr(module, 'INSTALL', tmp_path / 'install')
    monkeypatch.setattr(module, 'UNITS', tmp_path / 'units')
    monkeypatch.setattr(module, 'LOCK', tmp_path / 'lock')
    return module


@pytest.fixture
def config(app):
    return {'domain': 'bob.example.com', 'challenge_port': 8080, 'local_port': 9443,
            'relay_ip': '8.8.8.8', 'firewall': 'ufw', 'ca': app.PRODUCTION,
            'staging_ca_file': None}


def result(code=0, output=b''):
    return SimpleNamespace(returncode=code, stdout=output, stderr=b'')


@pytest.mark.parametrize('value', ['bad host', 'a;touch.example.com', 'a.example.com:80',
                                  'https://example.com', '*.example.com', '-x.example.com',
                                  '127.0.0.1', 'a..example.com', 'x\n.example.com'])
def test_domain_rejects_injection(app, value):
    with pytest.raises(app.Failure):
        app.domain_value(value)


@pytest.mark.parametrize('value', ['80', '443', '0', '65536', '8080;id', '-1', '8e3', '8080\n'])
def test_ports_are_order_parameters_not_shell(app, value):
    with pytest.raises(app.Failure):
        app.port_value(value)


def test_defaults_and_same_port_validation(app, config):
    assert app.validate_config(config)['challenge_port'] == 8080
    config['local_port'] = 8080
    with pytest.raises(app.Failure):
        app.validate_config(config)


def test_first_setup_only_asks_domain_and_three_ports(app, monkeypatch):
    answers = iter(['node.example.com', '', '', ''])
    prompts = []
    def respond(prompt):
        prompts.append(prompt)
        return next(answers)
    monkeypatch.setattr('builtins.input', respond)
    saved = app.interactive_config(SimpleNamespace(staging_ca_file=None))
    assert len(prompts) == 4
    assert not any(word in ' '.join(prompts) for word in ('IP', 'Docker', 'Firewall', 'контейнер'))
    assert saved['vpn_port'] == 443 and saved['challenge_port'] == 8080 and saved['local_port'] == 9443
    assert saved['firewall'] == 'auto' and saved['relay_ip'] == ''


@pytest.mark.parametrize('answer,approved', [('', False), ('n', False), ('N', False),
                                          ('no', False), ('да', False), ('y', True), ('Y', True), ('yes', False)])
def test_install_confirmation_defaults_to_no(app, config, monkeypatch, answer, approved):
    prompts = []
    def reply(prompt):
        prompts.append(prompt)
        return answer
    monkeypatch.setattr('builtins.input', reply)
    assert app.installation_plan(config) == approved
    assert prompts == ['Установить? [y/N]: ']


def test_explicit_random_template_needs_no_input_and_no_catalog_dump(app, monkeypatch, capsys):
    monkeypatch.setattr('builtins.input', lambda *_: pytest.fail('Default random selection needs no prompt'))
    selected = app.select_template('random')
    assert selected in [str(i) for i in range(1, 12)]
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('output,expected', [
    (b'permission denied; token=PRIVATE', 'Доступ запрещён'),
    (b'OCI runtime create failed; password=PRIVATE', 'OCI runtime'),
    (b'Error adapting config; secret=PRIVATE', 'отклонил конфигурацию'),
    (b'unknown error; -----BEGIN PRIVATE KEY-----', 'Причина не распознана'),
])
def test_compose_failure_identifies_stage_without_echoing_output(app, monkeypatch, output, expected):
    monkeypatch.setattr(app, 'assert_compose_owned', lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: SimpleNamespace(returncode=255, stdout=b'', stderr=output))
    with pytest.raises(app.Failure) as error:
        app.compose('run', '--rm', '--no-deps', 'caddy', 'caddy', 'validate')
    assert error.value.code == 'CADDY_VALIDATE_FAILED'
    assert expected in str(error.value)
    assert '255' in str(error.value) and 'PRIVATE' not in str(error.value)
    assert 'token=' not in str(error.value) and 'password=' not in str(error.value) and 'secret=' not in str(error.value)


def test_compose_cleanup_can_return_nonzero_without_masking_initial_failure(app, monkeypatch):
    monkeypatch.setattr(app, 'assert_compose_owned', lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: result(code=255))
    assert app.compose('down', check=False).returncode == 255


def test_host_node_is_attributed_without_network_questions(app, config, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda *_: pytest.fail('Host node needs no network questions'))
    monkeypatch.setattr(app, 'run', lambda *_: pytest.fail('Do not inspect or change host container'))
    config.update(vpn_port=443)
    report = {'docker': {'containers': [{'name': 'remnanode', 'running': True, 'network_mode': 'host'}]},
              'selected_ports': {'vpn': {'listeners': [{'container': 'remnanode'}]}}}
    app.detect_vpn_network(config, report)
    assert config['vpn_container'] == 'remnanode' and not config.get('docker_network')


def test_unattributed_container_is_not_guessed_from_its_image(app, config):
    report = {'docker': {'containers': [{'name': 'node', 'running': True, 'network_mode': 'host'}]},
              'selected_ports': {'vpn': {'listeners': [{'processes': [{'name': 'unknown'}]}]}}}
    app.detect_vpn_network(config, report)
    assert not config.get('vpn_container')


def test_single_existing_bridge_network_is_selected_without_modifying_node(app, config, monkeypatch):
    import json
    calls = []
    monkeypatch.setattr(app, 'assert_local_docker', lambda: None)
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or result(output=json.dumps({'vpn-net': {}}).encode()))
    config.update(vpn_port=443)
    report = {'docker': {'containers': [{'name': 'node', 'running': True, 'network_mode': 'vpn-net'}]},
              'selected_ports': {'vpn': {'listeners': [{'container': 'node'}]}}}
    app.detect_vpn_network(config, report)
    assert config['docker_network'] == 'vpn-net'
    assert all(call[:2] == ['docker', 'inspect'] for call in calls)


def test_busy_challenge_keeps_order_port_and_suggests_bot(app, config, monkeypatch):
    monkeypatch.setattr(app, 'free_port', lambda port, *a: port == 8081)
    with pytest.raises(app.Failure, match='Измените порт в боте'):
        app.check_challenge_port(config)
    assert config['challenge_port'] == 8080


def test_dns_compares_relay_and_blocks_wrong_aaaa(app, config, monkeypatch):
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('8.8.8.8', 0)),
               (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('2001:4860:4860::8888', 0, 0, 0))]
    monkeypatch.setattr(app.socket, 'getaddrinfo', lambda *a: answers)
    with pytest.raises(app.Failure, match='A/AAAA'):
        app.check_dns(config)
    config['relay_ip'] = ''
    app.check_dns(config)
    answers.append((socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0)))
    with pytest.raises(app.Failure, match='публичные'):
        app.check_dns(config)


def test_firewall_intent_persisted_before_add_and_cleanup_number_changes(app, config, monkeypatch):
    firewall = app.firewall_module()
    monkeypatch.setattr(firewall, '_vendor_configuration', lambda _: None)
    monkeypatch.setattr(app, 'firewall_module', lambda: firewall)
    calls, rules = [], []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args == ['ufw', 'status']:
            return result(output=b'Status: active\n')
        if args[:2] == ['systemd-run', '--unit=tenant-selfsteal-watchdog']:
            assert (app.STATE / 'firewall.json').exists()
            return result()
        if args[:3] == ['ufw', 'prepend', 'allow']:
            tag = args[-1]
            assert app.read_json(app.STATE / 'firewall.json')['tag'] == tag
            rules.extend([f'[ 2] 8080/tcp ALLOW IN Anywhere # {tag}',
                          f'[ 4] 8080/tcp (v6) ALLOW IN Anywhere (v6) # {tag}'])
            return result()
        if args == ['ufw', 'status', 'numbered']:
            return result(output=('\n'.join(['[ 1] 22/tcp ALLOW IN Anywhere # ssh',
                                           '[ 3] 8080/tcp ALLOW IN Anywhere # prior', *rules])).encode())
        if args[:3] == ['ufw', '--force', 'delete']:
            rules.pop()  # highest owned number removed first; next read re-resolves
        return result()

    monkeypatch.setattr(app, 'run', fake_run)
    monkeypatch.setattr(app, 'check_challenge_port', lambda c: None)
    app.open_firewall(config)
    assert app.read_json(app.STATE / 'firewall.json')['port'] == 8080
    app.cleanup_firewall()
    assert not (app.STATE / 'firewall.json').exists()
    deletions = [call[-1] for call in calls if call[:3] == ['ufw', '--force', 'delete']]
    assert deletions == ['4', '2']
    assert not rules


def test_existing_allow_not_removed_when_ufw_skips_duplicate(app, config, monkeypatch):
    firewall = app.firewall_module()
    monkeypatch.setattr(firewall, '_vendor_configuration', lambda _: None)
    monkeypatch.setattr(app, 'firewall_module', lambda: firewall)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return result(output=b'Status: active\n[ 1] 8080/tcp ALLOW IN Anywhere # prior\n')

    monkeypatch.setattr(app, 'run', fake_run)
    monkeypatch.setattr(app, 'check_challenge_port', lambda c: None)
    app.open_firewall(config)
    app.cleanup_firewall()
    assert any(c[:3] == ['ufw', 'prepend', 'allow'] for c in calls)
    assert not any(c[:3] == ['ufw', '--force', 'delete'] for c in calls)


def test_firewall_delete_failure_retains_marker_for_boot_recovery(app, monkeypatch):
    tag = 'tenant-selfsteal-' + 'a' * 32
    app.atomic_json(app.STATE / 'firewall.json', {'tag': tag, 'mode': 'ufw', 'port': 8080})

    def fake_run(args, **kwargs):
        if args[:3] == ['ufw', '--force', 'delete']:
            raise app.Failure('ufw failure')
        return result(output=f'[ 1] 8080/tcp ALLOW # {tag}'.encode())

    monkeypatch.setattr(app, 'run', fake_run)
    with pytest.raises(app.Failure):
        app.cleanup_firewall()
    assert (app.STATE / 'firewall.json').exists()


def test_add_failure_marker_can_be_reconciled_after_kill(app, config, monkeypatch):
    firewall = app.firewall_module()
    monkeypatch.setattr(firewall, '_vendor_configuration', lambda _: None)
    monkeypatch.setattr(app, 'firewall_module', lambda: firewall)
    monkeypatch.setattr(app, 'check_challenge_port', lambda c: None)

    def fake_run(args, **kwargs):
        if args == ['ufw', 'status']:
            return result(output=b'Status: active')
        if args[:3] == ['ufw', 'prepend', 'allow']:
            raise app.Failure('killed after intent')
        return result()

    monkeypatch.setattr(app, 'run', fake_run)
    with pytest.raises(app.Failure):
        app.open_firewall(config)
    assert (app.STATE / 'firewall.json').exists()
    app.abort_acme()
    assert not (app.STATE / 'firewall.json').exists()


def test_no_ufw_enable_or_manual_rule_mutation(app, config, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kwargs: calls.append(args) or result(output=b'Status: inactive'))
    monkeypatch.setattr(app, 'check_challenge_port', lambda c: None)
    with pytest.raises(app.Failure) as error:
        app.open_firewall(config)
    assert error.value.code == 'UFW_INACTIVE'
    config['firewall'] = 'manual'
    app.open_firewall(config)
    assert calls == [['ufw', 'status']]


def test_ca_failure_preserves_old_files_and_stops_own_listener(app, config, monkeypatch):
    old = app.STATE / 'certs/current'
    old.mkdir(parents=True)
    (old / 'fullchain.pem').write_text('OLD CERT')
    monkeypatch.setattr(app, 'check_dns', lambda c: None)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ['systemctl', 'show'] and any(command[0] == 'systemd-run' for command in calls):
            identifier = app._operation_id
            return result(output=('LoadState=loaded\nDescription=Transitclient acme ' + config['install_id'] + ' ' + identifier + '\nExecStart=' +
                                 str(app.INSTALL / 'vendor/acme.sh') + ' --home ' + str(app.STATE / 'acme') + '\n').encode())
        return result(code=1 if args[0] == 'systemd-run' else 0)

    monkeypatch.setattr(app, 'run', fake_run)
    with pytest.raises(app.Failure, match='ACME-проверка'):
        app.renew(config)
    assert (old / 'fullchain.pem').read_text() == 'OLD CERT'
    assert any(call[:2] == ['systemctl', 'stop'] and call[2].startswith('tenant-selfsteal-acme-') for call in calls)
    assert not (app.STATE / 'result.json').exists()


def test_renew_skip_checks_served_without_opening_port(app, config, monkeypatch):
    domain = app.STATE / 'acme/bob.example.com_ecc'
    domain.mkdir(parents=True)
    (domain / 'bob.example.com.conf').write_text('due=next')
    (domain / 'fullchain.cer').write_bytes(b'CERT')
    (domain / 'bob.example.com.key').write_bytes(b'KEY')
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    (current / 'key.pem').write_bytes(b'KEY')
    monkeypatch.setattr(app, 'check_dns', lambda c: None)
    calls, served = [], []
    monkeypatch.setattr(app, 'run', lambda args, **kwargs: calls.append(args) or
                        result(code=2 if args[0] == 'systemd-run' else 0))
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'DER')
    monkeypatch.setattr(app, 'verify_served', lambda *a: served.append(a))
    monkeypatch.setattr(app, 'apply_certificate', lambda *a: pytest.fail('Skipped cert reapplied'))
    app.renew(config)
    assert len(served) == 1
    assert app.read_json(app.STATE / 'result.json')['renewal_due'] is False
    assert not any(args[0] == 'ufw' for args in calls)
    acme = next(command for command in calls if command[0] == 'systemd-run')
    assert '--renew' in acme and '--force' not in acme and '--cron' not in acme
    assert '--property=RuntimeMaxSec=15min' in acme


def test_configure_then_renew_uses_agreed_port_preserves_account_cert(app, config, monkeypatch):
    domain = app.STATE / 'acme/bob.example.com_ecc'
    domain.mkdir(parents=True)
    domain_conf = domain / 'bob.example.com.conf'
    domain_conf.write_text("Le_HTTPPort='8080'\nLe_NextRenewTime='9999999999'\n"
                           "Le_PreHook='obsolete hook'\nLe_PostHook='obsolete hook'\n")
    account = app.STATE / 'acme/account.conf'
    account.write_text("ACCOUNT_KEY_PATH='private'\nAUTO_UPGRADE='0'\n")
    (domain / 'fullchain.cer').write_bytes(b'CERT')
    (domain / 'bob.example.com.key').write_bytes(b'KEY')
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    (current / 'key.pem').write_bytes(b'KEY')
    answers = iter(['1', '8091', 'y'])
    monkeypatch.setattr('builtins.input', lambda *a: next(answers))
    monkeypatch.setattr(app, 'check_challenge_port', lambda c: None)
    monkeypatch.setattr(app, 'check_dns', lambda c: None)
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or
                        result(code=2 if args[0] == 'systemd-run' else 0))
    updated = app.configure(config)
    assert not calls  # configuration never calls ACME
    assert updated['domain'] == 'bob.example.com'
    assert app.read_json(app.CONFIG)['challenge_port'] == 8091
    assert config['challenge_port'] == 8080
    assert account.read_text() == "ACCOUNT_KEY_PATH='private'\nAUTO_UPGRADE='0'\n"
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'DER')
    monkeypatch.setattr(app, 'verify_served', lambda *a: None)
    app.renew(updated)
    command = next(command for command in calls if command[0] == 'systemd-run')
    assert command[command.index('--httpport') + 1] == '8091'
    assert '--force' not in command
    text = domain_conf.read_text()
    assert "Le_HTTPPort='8091'" in text and "Le_NextRenewTime='9999999999'" in text
    assert 'obsolete hook' not in text
    assert '__ACME_BASE64__START_' in text
    assert (current / 'fullchain.pem').read_bytes() == b'CERT'


def test_ufw_disabled_mid_operation_retains_marker(app, monkeypatch):
    tag = 'tenant-selfsteal-' + 'a' * 32
    app.atomic_json(app.STATE / 'firewall.json', {'tag': tag, 'mode': 'ufw', 'port': 8080})
    monkeypatch.setattr(app, 'run', lambda *a, **kw: result(output=b'Status: inactive'))
    with pytest.raises(app.Failure, match='отключён'):
        app.cleanup_firewall()
    assert (app.STATE / 'firewall.json').exists()


def test_recovery_stable_helper_restores_update_rename_gap(app, monkeypatch):
    identifier = 'b' * 32
    old_source = app.INSTALL.with_name('tenant-selfsteal.previous-' + identifier)
    old_source.mkdir()
    (old_source / 'VERSION').write_text('1.0.0')
    snapshot = app.STATE / ('update-backup-' + identifier)
    snapshot.mkdir()
    (snapshot / 'compose.yaml').write_text('old image')
    (app.STATE / 'compose.yaml').write_text('new image')
    app.atomic_json(app.STATE / 'update-transaction.json', {'id': identifier})
    monkeypatch.setattr(app, 'compose', lambda *a, **kw: pytest.fail('No cert: must not start a container'))
    assert not app.INSTALL.exists()
    app.recover_update()
    assert (app.INSTALL / 'VERSION').read_text() == '1.0.0'
    assert (app.STATE / 'compose.yaml').read_text() == 'old image'
    assert not (app.STATE / 'update-transaction.json').exists()


def test_unit_preparation_never_activates_timer_under_parent_lock(app, monkeypatch):
    app.UNITS.mkdir()
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return result(output=b'')

    monkeypatch.setattr(app, 'run', fake_run)
    app.install_units()
    assert not any('--now' in call for call in calls)
    assert (app.STATE / 'schedule-pending.json').exists()
    assert (app.STATE / 'recover.py').exists()


def symlink_or_skip(path, target):
    try:
        path.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip('OS denied symlink creation; run rollback acceptance on Linux')


def test_caddy_wrong_served_cert_rolls_back_actual_paths(app, config, tmp_path, monkeypatch):
    certs = app.STATE / 'certs'
    prior = 'a' * 32
    old = certs / prior
    old.mkdir(parents=True)
    (old / 'fullchain.pem').write_bytes(b'OLD')
    (old / 'key.pem').write_bytes(b'OLDKEY')
    symlink_or_skip(certs / 'current', prior)
    chain, key = tmp_path / 'new.pem', tmp_path / 'new.key'
    chain.write_bytes(b'NEW')
    key.write_bytes(b'NEWKEY')
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'new der')
    commands = []
    monkeypatch.setattr(app, 'compose', lambda *args, **kw: commands.append(args) or result())
    monkeypatch.setattr(app, 'verify_served', lambda *a: (_ for _ in ()).throw(app.Failure('wrong served cert')))
    with pytest.raises(app.Failure):
        app.apply_certificate(config, chain, key)
    assert os.readlink(certs / 'current') == prior
    assert (certs / 'current/fullchain.pem').read_bytes() == b'OLD'
    assert not (app.STATE / 'certificate-transaction.json').exists()
    assert commands[-1][:5] == ('exec', '-T', 'caddy', 'caddy', 'reload')
    assert not (app.STATE / 'result.json').exists()


def test_reboot_restores_uncommitted_generation(app, monkeypatch):
    certs = app.STATE / 'certs'
    old, new = 'a' * 32, 'b' * 32
    (certs / old).mkdir(parents=True)
    (certs / new).mkdir()
    symlink_or_skip(certs / 'current', new)
    app.atomic_json(app.STATE / 'certificate-transaction.json', {'old': old, 'new': new})
    calls = []
    monkeypatch.setattr(app, 'compose', lambda *a, **kw: calls.append(a) or result())
    app.recover_certificate()
    assert os.readlink(certs / 'current') == old
    assert calls[-1][:5] == ('exec', '-T', 'caddy', 'caddy', 'reload')


def test_first_apply_failure_stops_only_own_compose(app, config, tmp_path, monkeypatch):
    symlink_or_skip(tmp_path / 'symlink-check', 'nonexistent')
    chain, key = tmp_path / 'new.pem', tmp_path / 'new.key'
    chain.write_bytes(b'NEW')
    key.write_bytes(b'KEY')
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'DER')
    monkeypatch.setattr(app, 'verify_served', lambda *a: (_ for _ in ()).throw(app.Failure('unreachable')))
    calls = []
    monkeypatch.setattr(app, 'compose', lambda *a, **kw: calls.append(a) or result())
    with pytest.raises(app.Failure):
        app.apply_certificate(config, chain, key)
    assert calls[-1] == ('down',)
    assert not (app.STATE / 'certs/current').exists()


def test_tar_traversal_rejected_before_update_mutation(app, config, tmp_path, monkeypatch):
    release = tmp_path / 'release.tar.gz'
    source = tmp_path / 'attack'
    source.write_text('payload')
    with tarfile.open(release, 'w:gz') as archive:
        archive.add(source, arcname='../outside')
    monkeypatch.setattr(app, 'verified_download', lambda url, digest, destination:
                        shutil.copyfile(release, destination))
    args = SimpleNamespace(package_url='https://owner.example/release.tar.gz',
                           sha256='a' * 64, version='1.1.0')
    with pytest.raises(app.Failure, match='Небезопасный'):
        app.update(config, args)
    assert not app.INSTALL.exists()


def test_update_requires_schedule_module_before_host_calls(app, config, tmp_path, monkeypatch):
    source = tmp_path / 'source'
    app.copy_package(PACKAGE, source)
    (source / 'VERSION').write_text('1.5.0')
    (source / 'renewal_schedule.py').unlink()
    release = tmp_path / 'release.tar.gz'
    with tarfile.open(release, 'w:gz') as archive:
        for path in source.rglob('*'):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
    monkeypatch.setattr(app, 'verified_download', lambda _, __, destination: shutil.copyfile(release, destination))
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Incomplete update touched host'))
    with pytest.raises(app.Failure, match='модуль расписания'):
        app.update(config, SimpleNamespace(package_url='https://owner.example/release.tar.gz', sha256='a' * 64, version='1.5.0'))
    assert not app.INSTALL.exists()


def test_unpublished_update_has_no_network_fallback(app, config, monkeypatch):
    monkeypatch.setattr(app, 'verified_download', lambda *a: pytest.fail('unexpected network'))
    args = SimpleNamespace(package_url=None, sha256=None, version=None)
    with pytest.raises(app.Failure, match='URL ещё не настроен'):
        app.update(config, args)


@pytest.mark.parametrize('outcome', ['success', 'decline', 'failure'])
def test_update_menu_launch_instruction_only_after_success(app, config, monkeypatch, tmp_path, capsys, outcome):
    """Exercise the real local archive/update transaction, never a host command."""
    release_source = tmp_path / 'release-source'
    app.copy_package(PACKAGE, release_source)
    (release_source / 'VERSION').write_text('1.4.3')
    release = tmp_path / 'release.tar.gz'
    with tarfile.open(release, 'w:gz') as archive:
        for path in release_source.rglob('*'):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(release_source).as_posix(), recursive=False)
    app.INSTALL.mkdir()
    (app.INSTALL / 'VERSION').write_text('1.4.2')
    (app.INSTALL / 'selfsteal.py').write_text('retained test controller')
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'verified_download', lambda _, __, destination: shutil.copyfile(release, destination))
    monkeypatch.setattr(app, 'check_install_resources', lambda: None)
    monkeypatch.setattr(app, 'assert_compose_owned', lambda: None)
    monkeypatch.setattr(app, 'confirm', lambda _: outcome != 'decline')
    calls = []
    def apply(command, **_):
        if command[:2] == ['systemctl', 'show']:
            return result(output=b'UnitFileState=disabled\nActiveState=inactive\n')
        if command == ['systemctl', 'daemon-reload']:
            return result()
        calls.append(command)
        assert '_update-apply' in command, 'Only the offline update application may be requested'
        if outcome == 'failure':
            raise app.Failure('Simulated apply failure')
        return result()
    monkeypatch.setattr(app, 'run', apply)
    selected = SimpleNamespace(package_url='https://owner.example/release.tar.gz', sha256='a' * 64, version='1.4.3')
    if outcome == 'success':
        app.update(config, selected)
        assert len(calls) == 1
    else:
        with pytest.raises(app.Failure):
            app.update(config, selected)
    output = capsys.readouterr().out
    assert ('Для запуска меню: transitclient' in output) == (outcome == 'success')
    assert (app.INSTALL / 'VERSION').read_text() == ('1.4.3' if outcome == 'success' else '1.4.2')


def test_staging_requires_explicit_trust(app, config):
    config['ca'] = app.STAGING
    with pytest.raises(app.Failure, match='trust bundle'):
        app.validate_config(config)


def test_fixed_vendored_acme_integrity(app):
    import hashlib
    lock = app.dependency_lock()
    assert hashlib.sha256((PACKAGE / 'vendor/acme.sh').read_bytes()).hexdigest() == lock['acme']['sha256']


def test_certificate_crypto_san_key_chain_with_real_openssl(app, config, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    openssl = shutil.which('openssl')
    if not openssl and Path('C:/Program Files/Git/usr/bin/openssl.exe').exists():
        monkeypatch.setenv('PATH', 'C:/Program Files/Git/usr/bin;' + os.environ['PATH'])
        openssl = shutil.which('openssl')
    if not openssl:
        pytest.skip('openssl missing: crypto runtime verification needs openssl')
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Offline test root')])
    root_cert = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                 .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=2))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                 .sign(root_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, config['domain'])]))
            .issuer_name(root_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(config['domain'])]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(root_key, hashes.SHA256()))
    trust, chain, key = tmp_path / 'trust.pem', tmp_path / 'chain.pem', tmp_path / 'key.pem'
    trust.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    chain.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + trust.read_bytes())
    key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    config.update(ca=app.STAGING, staging_ca_file=str(trust))
    expected = app.validate_certificate(config, chain, key)
    assert expected == leaf.public_bytes(serialization.Encoding.DER)
    config['domain'] = 'mallory.example.com'
    with pytest.raises(app.Failure, match='SAN'):
        app.validate_certificate(config, chain, key)
    config['domain'] = 'bob.example.com'
    key.write_bytes(root_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    with pytest.raises(app.Failure, match='не соответствует'):
        app.validate_certificate(config, chain, key)


def test_local_tls_verifies_actual_served_certificate_and_sni(app, config, tmp_path, monkeypatch):
    """Real loopback TLS, local CA only; no DNS/CA/provider/network services."""
    from datetime import datetime, timedelta, timezone
    import ssl
    import threading
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Offline loopback CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                        key_encipherment=False, data_encipherment=False, key_agreement=False,
                        key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, config['domain'])]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=4))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(config['domain'])]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    trust, chain, key = tmp_path / 'root.pem', tmp_path / 'fullchain.pem', tmp_path / 'private.pem'
    trust.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + trust.read_bytes())
    key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    config.update(ca=app.STAGING, staging_ca_file=str(trust))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(chain), str(key))
    context.set_alpn_protocols(['h2', 'http/1.1'])
    names = []
    context.set_servername_callback(lambda sock, name, ctx: names.append(name))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(16)
    listener.settimeout(0.2)
    config['local_port'] = listener.getsockname()[1]
    finished = threading.Event()

    def serve():
        while not finished.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(3)
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except OSError:
                    continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(app.time, 'sleep', lambda *a: None)
    try:
        expected = cert.public_bytes(serialization.Encoding.DER)
        app.verify_served(config, expected, attempts=1)
        assert names == ['bob.example.com']
        with pytest.raises(app.Failure, match='сертификат действующего Caddy'):
            app.verify_served(config, b'wrong generation', attempts=2)
        assert len(names) == 3
    finally:
        finished.set()
        listener.close()
        thread.join(timeout=2)


def test_bash_syntax_offline():
    bash = shutil.which('bash')
    if Path('C:/Program Files/Git/bin/bash.exe').exists():
        bash = 'C:/Program Files/Git/bin/bash.exe'
    if not bash:
        pytest.skip('bash unavailable')
    subprocess.run([bash, '-n', str(PACKAGE / 'selfsteal.sh')], check=True, capture_output=True)


def test_three_ports_and_legacy_vpn_unknown(app, config):
    assert app.validate_config(config)['vpn_port'] is None
    config['vpn_port'] = '443'
    assert app.validate_config(config)['vpn_port'] == 443
    config['vpn_port'] = 8080
    with pytest.raises(app.Failure, match='разных портов'):
        app.validate_config(config)


def test_remote_docker_rejected_even_before_dependency_install(app, monkeypatch):
    monkeypatch.setenv('DOCKER_HOST', 'ssh://private-user:SECRET@foreign.example')
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    monkeypatch.setattr(app.shutil, 'which', lambda _: None)
    monkeypatch.setattr(app, 'run', lambda *a, **k: pytest.fail('No daemon/package operations allowed'))
    with pytest.raises(app.Failure, match='удалённый') as caught:
        app.dependencies()
    assert 'SECRET' not in str(caught.value)


def test_host_and_bridge_render_never_publish_https(app, config):
    config.update(install_id='a' * 32, vpn_port=443)
    app.render_caddy(config)
    text = (app.STATE / 'compose.yaml').read_text()
    caddy = (app.STATE / 'Caddyfile').read_text()
    assert 'network_mode: host' in text and 'ports:' not in text
    assert 'cap_drop: [ALL]' in text and 'cap_add: [NET_BIND_SERVICE]' in text
    assert 'security_opt: [no-new-privileges:true]' in text and 'read_only: true' in text
    assert 'privileged:' not in text and 'NET_ADMIN' not in text and 'SYS_ADMIN' not in text
    assert 'bind 127.0.0.1' in caddy and app.ADMIN in caddy
    config.update(docker_network='vpn-private', local_port=9543)
    app.render_caddy(config)
    text = (app.STATE / 'compose.yaml').read_text()
    assert 'network_mode:' not in text and 'ports:' not in text
    assert 'external: true' in text and 'name: vpn-private' in text
    assert 'transitclient-selfsteal' in text
    assert app.target(config) == 'transitclient-selfsteal:9543'
    assert 'cap_add: [NET_BIND_SERVICE]' in text


def test_caddy_exec_failure_is_detected_before_issuance_and_hides_output(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or
                        SimpleNamespace(returncode=255, stdout=b'', stderr=b'exec /usr/bin/caddy: operation not permitted; token=PRIVATE'))
    with pytest.raises(app.Failure) as error:
        app.validate_caddy_runtime('pinned-image')
    assert error.value.code == 'CADDY_RUNTIME_FAILED' and 'PRIVATE' not in str(error.value)
    assert len(calls) == 1 and calls[0][-2:] == ['caddy', 'version']
    assert '--network' in calls[0] and 'none' in calls[0] and '--cap-add' in calls[0]
    assert not any(value in calls[0] for value in ('--privileged', '--mount', '-v', '--publish'))


def test_update_apply_of_partial_install_never_issues_cert_or_starts_caddy(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    app.atomic_json(app.STATE / 'update-transaction.json', {'id': 'a' * 32, 'parent_pid': os.getppid()})
    for name in ('require_host', 'check_install_resources', 'assert_compose_owned', 'dependencies',
                 'install_units', 'install_launcher', 'mark_package'):
        monkeypatch.setattr(app, name, lambda *_: None)
    monkeypatch.setattr(app, 'validate_network', lambda _: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: result())
    monkeypatch.setattr(app, 'renew', lambda _: pytest.fail('Update must not issue a certificate'))
    monkeypatch.setattr(app, 'reload_caddy', lambda: pytest.fail('Partial install has no running Caddy'))
    calls = []
    monkeypatch.setattr(app, 'compose', lambda *args, **_: calls.append(args) or result())
    assert app.dispatch(SimpleNamespace(command='_update-apply', operation_id='a' * 32)) == 0
    assert calls == [('config', '--quiet')]


def test_update_apply_missing_certificate_does_not_touch_existing_caddy(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    app.atomic_json(app.STATE / 'update-transaction.json', {'id': 'a' * 32, 'parent_pid': os.getppid()})
    monkeypatch.setattr(app, 'require_host', lambda: None)
    monkeypatch.setattr(app, 'check_install_resources', lambda: None)
    monkeypatch.setattr(app, 'assert_compose_owned', lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: result(output=b'existing-owned-caddy'))
    monkeypatch.setattr(app, 'dependencies', lambda: pytest.fail('Conflicting state must fail before mutation'))
    with pytest.raises(app.Failure) as error:
        app.dispatch(SimpleNamespace(command='_update-apply', operation_id='a' * 32))
    assert error.value.code == 'UPDATE_CERT_MISSING'


def test_certificate_reload_forces_file_reread_on_own_socket(app, monkeypatch):
    (app.STATE / 'Caddyfile').write_text('admin ' + app.ADMIN)
    calls = []
    monkeypatch.setattr(app, 'compose', lambda *a, **k: calls.append(a))
    app.reload_caddy()
    assert '--force' in calls[0]
    assert calls[0][calls[0].index('--address') + 1] == app.ADMIN


def test_launcher_conflict_does_not_overwrite_foreign_command(app, tmp_path, monkeypatch):
    launcher = tmp_path / 'transitclient'
    launcher.write_text('foreign')
    monkeypatch.setattr(app, 'LAUNCHER', launcher)
    monkeypatch.setattr(app.shutil, 'which', lambda _: None)
    with pytest.raises(app.Failure, match='чужим'):
        app.install_launcher()
    assert launcher.read_text() == 'foreign'


def test_launcher_absolute_path_survives_working_directory(app, tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'LAUNCHER', tmp_path / 'transitclient')
    monkeypatch.setattr(app.shutil, 'which', lambda _: None)
    app.install_launcher()
    assert 'exec /usr/bin/python3 ' in app.LAUNCHER.read_text()
    assert str(app.INSTALL / 'selfsteal.py') in app.LAUNCHER.read_text()


def test_status_before_install_has_no_lifecycle_or_recovery(app, monkeypatch, capsys):
    args = SimpleNamespace(command='diagnose', http01=False, vpn=False, json=True)
    monkeypatch.setattr(app, 'run', lambda *a, **k: result())
    monkeypatch.setattr(app, 'require_host', lambda: pytest.fail('Read-only diagnostics should work without root'))
    monkeypatch.setattr(app, 'lifecycle_lock', lambda: pytest.fail('Status must not wait on renew lock'))
    assert app.dispatch(args) == 0
    import json
    report = json.loads(capsys.readouterr().out)
    assert report['installation']['configured'] is False
    assert not app.CONFIG.exists() and not app.LOCK.exists()


@pytest.mark.parametrize('stage,pending', [('installing', True), ('installed', False)])
def test_status_reports_interrupted_ufw_package_preparation(app, monkeypatch, stage, pending):
    app.atomic_json(app.STATE / 'ufw-package-preparation.json', {'status': stage})
    monkeypatch.setattr(app, 'diagnostic_module', lambda: SimpleNamespace(collect=lambda _: {'checks': []}))
    monkeypatch.setattr(app, 'run', lambda *a, **k: result())
    report = app.status(None, json_output=True)
    assert ('ufw-package-preparation.json' in report['pending']) == pending
    assert any(row['code'] == 'UFW_PACKAGE_PREPARATION_PENDING' for row in report['checks']) == pending


def test_abort_never_stops_foreign_transient_unit(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or
                        result(output=b'LoadState=loaded\nDescription=Foreign administrator task\n'))
    with pytest.raises(app.Failure, match='не остановлен'):
        app.abort_acme()
    assert not any('stop' in call for call in calls)


def test_owned_transient_stop_is_explicit(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or
                        result(output=('LoadState=loaded\nDescription=Transitclient ACME\nExecStart=' +
                                       str(app.INSTALL / 'vendor/acme.sh') + ' --home ' + str(app.STATE / 'acme') + '\n').encode()))
    app.abort_acme()
    assert ['systemctl', 'stop', 'tenant-selfsteal-acme.service'] in calls


def test_docker_publication_blocks_http_even_without_socket(app, config, monkeypatch):
    module = SimpleNamespace(collect=lambda _: {'listeners': [{'source': 'docker', 'address': '0.0.0.0', 'port': 8080}]},
                             listeners_for_port=lambda rows, _: rows)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: module)
    monkeypatch.setattr(app, 'free_port', lambda *_: True)
    with pytest.raises(app.Failure, match='опубликован Docker'):
        app.check_challenge_port(config)


def test_new_install_does_not_adopt_legacy_labeled_container_without_config(app, monkeypatch):
    monkeypatch.setattr(app, 'assert_local_docker', lambda: None)
    monkeypatch.setattr(app, 'run', lambda args, **kw: result(output=b'abc\n' if 'ps' in args else
                        b'{"org.tenant-selfsteal.package":"true"}\n'))
    with pytest.raises(app.Failure, match='чужими'):
        app.assert_compose_owned()


def test_bridge_alias_collision_blocks_foreign_network_member(app, config, monkeypatch):
    import json
    config.update(docker_network='vpn-net', install_id='a' * 32)
    monkeypatch.setattr(app, 'assert_local_docker', lambda: None)
    def fake(args, **kw):
        if args[1:3] == ['network', 'inspect']:
            value = {'Driver': 'bridge', 'Name': 'vpn-net', 'Scope': 'local', 'Containers': {'b' * 64: {}}, 'Options': {}}
        elif 'Networks' in args[args.index('--format') + 1]:
            value = {'vpn-net': {'Aliases': ['transitclient-selfsteal']}}
        else:
            value = {'foreign': 'true'}
        return result(output=json.dumps(value).encode())
    monkeypatch.setattr(app, 'run', fake)
    with pytest.raises(app.Failure, match='Alias'):
        app.validate_network(config)


def test_configure_cancel_preserves_config_and_cert(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    before = app.CONFIG.read_bytes()
    answers = iter(['1', '8091', 'no'])
    monkeypatch.setattr('builtins.input', lambda *_: next(answers))
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    with pytest.raises(app.Failure, match='не изменены'):
        app.configure(config)
    assert app.CONFIG.read_bytes() == before


def test_failed_probe_launch_does_not_stop_competing_unit(app, config, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app, 'open_firewall', lambda _: None)
    monkeypatch.setattr(app, 'cleanup_firewall', lambda *args: calls.append('cleanup'))
    monkeypatch.setattr(app, 'stop_probe', lambda: pytest.fail('Failed launch does not prove unit ownership'))
    monkeypatch.setattr(app, 'run', lambda *a, **k: (_ for _ in ()).throw(app.Failure('Unit collision')))
    with pytest.raises(app.Failure):
        app.http_self_test(config)
    assert calls == ['cleanup', 'cleanup']


def test_reconfigure_failure_restores_previous_runtime_and_config(app, config, monkeypatch):
    config.update(vpn_port=443)
    app.render_caddy(config)
    app.atomic_json(app.CONFIG, config)
    originals = {name: (app.STATE / name).read_text() for name in ('Caddyfile', 'compose.yaml')}
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    (current / 'key.pem').write_bytes(b'KEY')
    answers = iter(['3', '9543', 'y'])
    monkeypatch.setattr('builtins.input', lambda *_: next(answers))
    monkeypatch.setattr(app, 'free_port', lambda *_: True)
    calls = []
    monkeypatch.setattr(app, 'compose', lambda *a, **k: calls.append(a) or result())
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'DER')
    def verify(candidate, *_):
        if candidate['local_port'] == 9543:
            raise app.Failure('new port unreachable')
    monkeypatch.setattr(app, 'verify_served', verify)
    with pytest.raises(app.Failure, match='unreachable'):
        app.configure(config)
    assert app.read_json(app.CONFIG)['local_port'] == 9443
    assert {name: (app.STATE / name).read_text() for name in originals} == originals
    assert not (app.STATE / 'configuration-transaction.json').exists()
    assert '--force' in calls[-1]


def test_transient_description_alone_is_not_ownership(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or
                        result(output=b'LoadState=loaded\nDescription=Transitclient ACME\nExecStart=/usr/local/bin/foreign\n'))
    with pytest.raises(app.Failure, match='не остановлен'):
        app.abort_acme()
    assert not any('stop' in call for call in calls)


def test_install_docker_nat_conflict_is_read_only(app, config, monkeypatch):
    from types import SimpleNamespace
    diagnostics = SimpleNamespace(collect=lambda *_: {'checks': [{'code': 'HTTP_PORT_BUSY', 'status': 'error', 'message': 'Docker DNAT conflict'}]},
                                  display_compact=lambda *_, **__: None)
    monkeypatch.setattr(app, 'check_install_resources', lambda: None)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: diagnostics)
    monkeypatch.setattr(app, 'interactive_config', lambda _: config)
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'free_port', lambda *_: True)
    monkeypatch.setattr('builtins.input', lambda *_: '1')
    monkeypatch.setattr(app, 'dependencies', lambda: pytest.fail('Preflight must fail before apt/pull'))
    with pytest.raises(app.Failure, match='DNAT'):
        app.install(SimpleNamespace())
    assert not app.CONFIG.exists() and list(app.STATE.iterdir()) == []


def test_http_probe_nonce_success_stops_only_owned_unit_and_never_ca(app, config, monkeypatch):
    events = []
    monkeypatch.setattr(app, 'check_dns', lambda _: ['8.8.8.8'])
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app.uuid, 'uuid4', lambda: SimpleNamespace(hex='a' * 32))
    monkeypatch.setattr(app, 'open_firewall', lambda _: events.append('open'))
    monkeypatch.setattr(app, 'stop_probe', lambda: events.append('stop-owned'))
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or result())
    class Response:
        status = 200

        def read(self, *_):
            return b'transitclient-check:' + b'a' * 32
    class Connection:
        def request(self, method, path, headers):
            assert method == 'GET' and path.startswith('/.well-known/acme-challenge/')
            assert headers['Host'] == config['domain']

        def getresponse(self):
            return Response()

        def close(self):
            pass
    monkeypatch.setattr(app.http.client, 'HTTPConnection', lambda *_, **__: Connection())
    app.http_self_test(config)
    assert events == ['open', 'stop-owned']
    launches = [call for call in calls if call[0] == 'systemd-run']
    assert len(launches) == 1 and '--unit=tenant-selfsteal-probe-' + 'a' * 32 in launches[0]
    assert '--property=RuntimeMaxSec=120s' in launches[0]
    assert not any('acme.sh' in str(value) for call in calls for value in call)


def test_install_copy_does_not_copy_clone_secrets_or_cache(app, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    for name in ('selfsteal.sh', 'VERSION', 'dependencies.json', 'templates.json', 'README.md', 'LICENSE', 'NOTICE.md', 'selfsteal.py', 'diagnostics.py'):
        (source / name).write_text(name)
    for name in ('.env', '.git/config', 'tests/__pycache__/cached.pyc', 'docs/integration.md'):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    app.copy_package(source, app.INSTALL)
    assert (app.INSTALL / 'selfsteal.py').exists()
    assert (app.INSTALL / 'docs/integration.md').exists()
    assert not (app.INSTALL / '.env').exists() and not (app.INSTALL / '.git').exists()
    assert not (app.INSTALL / 'tests/__pycache__').exists()


def test_saved_own_package_is_reusable_but_changed_controller_is_not(app, config, monkeypatch):
    app.INSTALL.mkdir()
    (app.INSTALL / 'selfsteal.py').write_text('owned controller')
    (app.INSTALL / 'VERSION').write_text('1.1.0')
    app.mark_package(config)
    assert app.package_owned()
    monkeypatch.setattr(app, 'check_launcher', lambda: None)
    app.check_install_resources()
    (app.INSTALL / 'selfsteal.py').write_text('foreign replacement')
    assert not app.package_owned()
    with pytest.raises(app.Failure, match='не перезаписаны'):
        app.check_install_resources()


@pytest.fixture
def retained_install(app, config, monkeypatch, tmp_path):
    monkeypatch.setattr(app, '_test_original_install_launcher', app.install_launcher, raising=False)
    source = tmp_path / 'incoming'
    source.mkdir()
    for name in ('selfsteal.sh', 'selfsteal.py', 'VERSION', 'dependencies.json', 'templates.json', 'README.md', 'LICENSE', 'NOTICE.md',
                 'diagnostics.py', 'site_templates.py', 'firewall_setup.py'):
        (source / name).write_text('1.4.1' if name == 'VERSION' else 'incoming ' + name)
    app.INSTALL.mkdir()
    (app.INSTALL / 'selfsteal.py').write_text('retained controller')
    (app.INSTALL / 'selfsteal.sh').write_text('retained shell')
    (app.INSTALL / 'VERSION').write_text('1.3.3')
    app.mark_package(config)
    monkeypatch.setattr(app, 'PACKAGE', source)
    config.update(install_id='a' * 32)
    report = SimpleNamespace(collect=lambda *_: {'checks': []}, display_compact=lambda *_, **__: None)
    firewall = SimpleNamespace(plan=lambda *_: {'changes': []}, apply=lambda *_: None, FirewallError=RuntimeError)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: report)
    monkeypatch.setattr(app, 'firewall_module', lambda: firewall)
    monkeypatch.setattr(app, 'check_launcher', lambda: None)
    monkeypatch.setattr(app, 'ask', lambda *_: '1')
    monkeypatch.setattr(app, 'interactive_config', lambda _: config.copy())
    for name in ('detect_vpn_network', 'check_dns', 'check_challenge_port', 'assert_local_docker', 'assert_compose_owned',
                 'validate_network', 'dependencies', 'install_launcher', 'render_caddy', 'install_units', 'change_template', 'renew'):
        monkeypatch.setattr(app, name, lambda *_, **__: None)
    monkeypatch.setattr(app, 'http_self_test', lambda *_, **__: None)
    monkeypatch.setattr(app, 'free_port', lambda *_: True)
    monkeypatch.setattr(app, 'select_template', lambda *_: 'builtin')
    monkeypatch.setattr(app.shutil, 'which', lambda _: '/bin/docker')
    monkeypatch.setattr(app, 'run', lambda *_, **__: result())
    monkeypatch.setattr(app, 'installation_plan', lambda _: True)
    return source


def test_reinstall_cancel_preserves_incoming_package_selection_and_retained_files(app, retained_install, monkeypatch):
    monkeypatch.setattr(app, 'installation_plan', lambda _: False)
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None))
    assert error.value.code == 'CANCELLED'
    assert app.PACKAGE == retained_install
    assert (app.INSTALL / 'VERSION').read_text() == '1.3.3'
    assert not app.CONFIG.exists() and list(app.STATE.iterdir()) == []


def test_reinstall_uses_incoming_version_and_preserves_previous_package(app, retained_install):
    app.install(SimpleNamespace(template=None))
    assert app.PACKAGE == app.INSTALL
    assert (app.INSTALL / 'VERSION').read_text() == '1.4.1'
    assert (app.INSTALL / 'selfsteal.py').read_text() == 'incoming selfsteal.py'
    assert app.package_owned()
    previous = list(app.INSTALL.parent.glob('tenant-selfsteal.previous-*'))
    assert len(previous) == 1 and (previous[0] / 'VERSION').read_text() == '1.3.3'
    assert not (app.STATE / 'update-transaction.json').exists()


def test_reinstall_initialization_failure_restores_retained_package(app, retained_install, monkeypatch):
    def fail():
        raise KeyboardInterrupt
    monkeypatch.setattr(app, 'install_launcher', fail)
    with pytest.raises(KeyboardInterrupt):
        app.install(SimpleNamespace(template=None))
    assert app.PACKAGE == app.INSTALL
    assert (app.INSTALL / 'VERSION').read_text() == '1.3.3'
    assert list(app.INSTALL.parent.glob('tenant-selfsteal.failed-*'))
    assert not (app.STATE / 'update-transaction.json').exists()


def test_reinstall_rename_gap_keeps_stable_helper_and_journal_for_recovery(app, retained_install, monkeypatch):
    replace = app.os.replace
    def interrupted(source, target):
        if Path(target) == app.INSTALL and Path(source).name == 'package':
            raise SystemExit('simulated SIGKILL')
        return replace(source, target)
    monkeypatch.setattr(app.os, 'replace', interrupted)
    # Prevent the in-process exception handler to model a hard process exit.
    monkeypatch.setattr(app, 'recover_update', lambda: None)
    with pytest.raises(SystemExit):
        app.install(SimpleNamespace(template=None))
    assert not app.INSTALL.exists()
    pointer = app.read_json(app.STATE / 'recovery-current.json')
    assert (app.STATE / 'recovery' / pointer['generation'] / 'selfsteal.py').read_text() == 'incoming selfsteal.py'
    assert (app.STATE / 'update-transaction.json').exists()


def test_install_with_config_cannot_replace_different_version(app, retained_install, config):
    app.atomic_json(app.CONFIG, config)
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None))
    assert error.value.code == 'UPDATE_REQUIRED'
    assert (app.INSTALL / 'VERSION').read_text() == '1.3.3'


def _repeat_install_diagnostics(app, config, monkeypatch, published_port, identifier):
    """Use real ownership/port diagnostics against an entirely fake local CLI."""
    spec = importlib.util.spec_from_file_location('repeat_install_diagnostics', PACKAGE / 'diagnostics.py')
    diagnostics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostics)
    monkeypatch.delenv('DOCKER_HOST', raising=False)
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    import json
    container_id = 'b' * 12
    inspect = '|'.join(json.dumps(value) for value in (
        {'9443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(published_port)}]},
        'bridge', '/tenant-selfsteal-caddy', 'caddy:2', True, 'true', identifier))

    def cli(command):
        if command[:3] == ['docker', 'context', 'show']:
            return 'default'
        if command[:3] == ['docker', 'context', 'inspect']:
            return json.dumps('unix:///var/run/docker.sock')
        if command[:2] == ['docker', 'info']:
            return '29.8.2'
        if command[:3] == ['docker', 'compose', 'version']:
            return '5.0.0'
        if command[:2] == ['docker', 'ps']:
            return container_id
        if command[:2] == ['docker', 'inspect']:
            return inspect
        if command[0] == 'ss':
            return 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*'
        if command[:2] == ['ufw', 'status']:
            return 'Status: inactive'
        return None

    monkeypatch.setattr(diagnostics, '_run', cli)
    monkeypatch.setattr(diagnostics, '_resolve_dns', lambda _: ['8.8.8.8'])
    monkeypatch.setattr(diagnostics, '_attribute_processes', lambda _: None)
    monkeypatch.setattr(diagnostics, '_web_inventory', lambda _: None)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: diagnostics)
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'PACKAGE', app.INSTALL)
    return diagnostics


@pytest.mark.parametrize('local_port,challenge_port', [(9443, 8080), (9543, 8180)])
def test_repeat_install_initial_inventory_uses_saved_ownership_and_ports(
        app, retained_install, config, monkeypatch, capsys, local_port, challenge_port):
    config.update(local_port=local_port, challenge_port=challenge_port, vpn_port=443)
    diagnostics = _repeat_install_diagnostics(app, config, monkeypatch, local_port, config['install_id'])
    collect = diagnostics.collect
    reports = []

    def record(candidate=None):
        report = collect(candidate)
        reports.append(report)
        return report

    monkeypatch.setattr(diagnostics, 'collect', record)
    monkeypatch.setattr(app, 'installation_plan', lambda _: False)
    monkeypatch.setattr(app, 'dependencies', lambda: pytest.fail('Cancellation precedes mutations'))
    monkeypatch.setattr(app, 'free_port', lambda *_: pytest.fail('Own installed listener must not be bound again'))
    before = app.CONFIG.read_bytes()
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None))
    assert error.value.code == 'CANCELLED'
    assert reports[0]['docker']['containers'][0]['owned'] is True
    assert reports[0]['selected_ports']['local']['port'] == local_port
    assert reports[0]['selected_ports']['challenge']['port'] == challenge_port
    assert '[HTTPS_PORT_BUSY]' not in capsys.readouterr().out
    assert app.CONFIG.read_bytes() == before and list(app.STATE.iterdir()) == []


def test_repeat_install_foreign_listener_still_blocks_final_guard_without_mutations(
        app, retained_install, config, monkeypatch):
    config.update(vpn_port=443)
    _repeat_install_diagnostics(app, config, monkeypatch, config['local_port'], 'c' * 32)
    monkeypatch.setattr(app, 'installation_plan', lambda _: pytest.fail('Foreign listener blocks before confirmation'))
    monkeypatch.setattr(app, 'dependencies', lambda: pytest.fail('Foreign listener blocks before mutations'))
    before = app.CONFIG.read_bytes()
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None))
    assert error.value.code == 'HTTPS_PORT_BUSY'
    assert app.CONFIG.read_bytes() == before and list(app.STATE.iterdir()) == []


def test_reinstall_foreign_package_never_replaced(app, retained_install):
    (app.INSTALL / 'selfsteal.py').write_text('foreign replacement')
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None))
    assert error.value.code == 'OWNERSHIP_UNKNOWN'
    assert (app.INSTALL / 'selfsteal.py').read_text() == 'foreign replacement'


@pytest.mark.parametrize('mode', ['0', '2'])
def test_reinstall_exit_or_guide_does_not_override_incoming_package(app, retained_install, monkeypatch, mode):
    monkeypatch.setattr(app, 'ask', lambda *_: mode)
    monkeypatch.setattr(app, 'guide', lambda *_: None)
    if mode == '0':
        with pytest.raises(app.Failure) as error:
            app.install(SimpleNamespace())
        assert error.value.code == 'CANCELLED'
    else:
        app.install(SimpleNamespace())
    assert app.PACKAGE == retained_install and (app.INSTALL / 'VERSION').read_text() == '1.3.3'
    assert not app.CONFIG.exists()


def test_reinstall_actual_launcher_and_controller_report_incoming_version(app, retained_install, monkeypatch, tmp_path):
    import sys
    (retained_install / 'selfsteal.py').write_bytes((PACKAGE / 'selfsteal.py').read_bytes())
    launcher = tmp_path / 'transitclient'
    monkeypatch.setattr(app, 'LAUNCHER', launcher)
    # Exercise real atomic launcher creation, bypassing only the host's PATH.
    monkeypatch.setattr(app, 'install_launcher', app._test_original_install_launcher)
    app.install(SimpleNamespace(template=None))
    assert str(app.INSTALL / 'selfsteal.py') in launcher.read_text()
    result = subprocess.run([sys.executable, str(app.INSTALL / 'selfsteal.py'), 'version'], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == 'transitclient 1.4.1'


def test_reinstall_pending_package_replacement_blocks_without_prompt(app, retained_install, monkeypatch):
    app.atomic_json(app.STATE / 'update-transaction.json', {'id': 'b' * 32})
    # CONFIG would already exist when the replacement's journal is persisted.
    app.atomic_json(app.CONFIG, {'domain': 'bob.example.com'})
    monkeypatch.setattr(app, 'ask', lambda *_: pytest.fail('Recovery required before prompting'))
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace())
    assert error.value.code == 'UPDATE_RECOVERY_REQUIRED'
    assert (app.INSTALL / 'VERSION').read_text() == '1.3.3'


def test_reinstall_issuance_failure_keeps_committed_new_package(app, retained_install, monkeypatch):
    def fail(_):
        raise app.Failure('ACME unsuccessful')
    monkeypatch.setattr(app, 'renew', fail)
    with pytest.raises(app.Failure, match='ACME'):
        app.install(SimpleNamespace(template=None))
    assert (app.INSTALL / 'VERSION').read_text() == '1.4.1' and app.PACKAGE == app.INSTALL
    assert not (app.STATE / 'update-transaction.json').exists()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX directory permissions')
def test_install_secures_existing_state_directory(app, retained_install):
    app.STATE.chmod(0o755)
    app.install(SimpleNamespace(template=None))
    assert app.STATE.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name == 'nt', reason='POSIX directory permissions')
def test_uninstall_backup_is_root_only_and_retains_account_certificate_and_config(app, config, monkeypatch, tmp_path):
    app.STATE.chmod(0o755)
    app.atomic_json(app.CONFIG, config)
    (app.STATE / 'acme').mkdir()
    (app.STATE / 'acme/account.key').write_bytes(b'PRIVATE account')
    (app.STATE / 'certs').mkdir()
    (app.STATE / 'certs/key.pem').write_bytes(b'PRIVATE certificate')
    monkeypatch.setattr(app, 'LAUNCHER', tmp_path / 'transitclient')
    for name in ('check_install_resources', 'assert_compose_owned', 'cleanup_firewall'):
        monkeypatch.setattr(app, name, lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: result())
    monkeypatch.setattr(app, 'compose', lambda *_, **__: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    app.uninstall()
    backups = list(app.STATE.parent.glob('tenant-selfsteal-backup-*'))
    assert len(backups) == 1 and backups[0].stat().st_mode & 0o777 == 0o700
    assert (backups[0] / 'acme/account.key').read_bytes() == b'PRIVATE account'
    assert (backups[0] / 'certs/key.pem').read_bytes() == b'PRIVATE certificate'
    assert app.read_json(backups[0] / 'config-backup.json')['domain'] == config['domain']
    assert not app.CONFIG.exists()


def test_ctrl_c_during_reconfiguration_rolls_back_before_propagating(app, config, monkeypatch):
    config.update(vpn_port=443)
    app.render_caddy(config)
    app.atomic_json(app.CONFIG, config)
    original = {name: (app.STATE / name).read_bytes() for name in ('Caddyfile', 'compose.yaml')}
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    (current / 'key.pem').write_bytes(b'KEY')
    answers = iter(['9543', 'y'])
    monkeypatch.setattr('builtins.input', lambda *_: next(answers))
    monkeypatch.setattr(app, 'free_port', lambda *_: True)
    interrupted = [False]
    def compose(*args, **kwargs):
        if args[0] == 'run' and not interrupted[0]:
            interrupted[0] = True
            raise KeyboardInterrupt
        return result()
    monkeypatch.setattr(app, 'compose', compose)
    monkeypatch.setattr(app, 'validate_certificate', lambda *_: b'DER')
    monkeypatch.setattr(app, 'verify_served', lambda *_: None)
    with pytest.raises(KeyboardInterrupt):
        app.configure(config, '3')
    assert app.read_json(app.CONFIG)['local_port'] == 9443
    assert {name: (app.STATE / name).read_bytes() for name in original} == original
    assert not (app.STATE / 'configuration-transaction.json').exists()


@pytest.mark.parametrize('interruption', [KeyboardInterrupt, EOFError])
def test_http_test_cleans_owned_probe_before_interrupt(app, config, monkeypatch, interruption):
    monkeypatch.setattr(app, 'check_dns', lambda _: ['8.8.8.8'])
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    events = []
    monkeypatch.setattr(app, 'open_firewall', lambda _: events.append('open'))
    monkeypatch.setattr(app, 'run', lambda args, **k: (events.append('launch') if args[0] == 'systemd-run' else None) or result())
    monkeypatch.setattr(app, 'stop_probe', lambda: events.append('stop-owned'))
    class Response:
        status = 200

        def read(self, *_):
            raise interruption
    class Connection:
        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            events.append('connection-closed')
    monkeypatch.setattr(app.http.client, 'HTTPConnection', lambda *_, **__: Connection())
    with pytest.raises(interruption):
        app.http_self_test(config)
    assert events == ['open', 'launch', 'connection-closed', 'stop-owned']


def test_renew_interrupt_aborts_acme_and_does_not_apply_certificate(app, config, monkeypatch):
    events = []
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'synchronize_acme_parameters', lambda *_: None)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app, 'acme_command', lambda *_: ['fake-acme'])
    monkeypatch.setattr(app, 'apply_certificate', lambda *_: pytest.fail('Cancelled renew must stop'))
    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(app, 'run', interrupt)
    monkeypatch.setattr(app, 'abort_acme', lambda *args: events.append('abort'))
    with pytest.raises(KeyboardInterrupt):
        app.renew(config)
    assert events == ['abort', 'abort']


@pytest.mark.parametrize('success', [True, False])
def test_explicit_local_tls_check_records_only_verified_current_identity(app, config, monkeypatch, success):
    import client_panel
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    monkeypatch.setattr(app, 'validate_certificate', lambda *_: b'DER')
    def verify(candidate, expected, attempts):
        assert candidate == config and expected == b'DER' and attempts == 1
        if not success:
            raise app.Failure('HTTPS не подтверждён')
    monkeypatch.setattr(app, 'verify_served', verify)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: pytest.fail('TLS check is not a full inventory'))
    if success:
        app.local_self_test(config)
    else:
        with pytest.raises(app.Failure):
            app.local_self_test(config)
    assert app._menu_tls_check['success'] == success
    assert app._menu_tls_check['identity'] == client_panel.tls_identity(app, config)


def test_perform_eof_propagates_without_error_history(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    def dispatch(_):
        raise EOFError
    monkeypatch.setattr(app, 'dispatch', dispatch)
    with pytest.raises(EOFError):
        app.perform(SimpleNamespace(command='configure'))
    assert not (app.STATE / 'result.json').exists()


def test_declined_action_has_no_failure_history(app, config, monkeypatch, capsys):
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'ask', lambda *_: '1')
    def dispatch(_):
        raise app.Failure('Установка отменена', 'CANCELLED')
    monkeypatch.setattr(app, 'dispatch', dispatch)
    assert app.perform(SimpleNamespace(command='install', _menu_mode=True)) == 0
    assert not (app.STATE / 'result.json').exists()
    output = capsys.readouterr()
    assert 'Действие отменено' in output.out and output.err == ''


def test_cli_decline_retains_nonzero_exit_code(app, monkeypatch):
    def dispatch(_):
        raise app.Failure('Отмена', 'CANCELLED')
    monkeypatch.setattr(app, 'dispatch', dispatch)
    assert app.perform(SimpleNamespace(command='install')) == 1


def test_declining_uninstall_is_a_cancellation_before_mutations(app, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: '')
    monkeypatch.setattr(app, 'check_install_resources', lambda: pytest.fail('No mutations on decline'))
    with pytest.raises(app.Failure) as error:
        app.uninstall()
    assert error.value.code == 'CANCELLED'


def test_setting_confirmation_shows_old_and_new_before_decline(app, config, monkeypatch, capsys):
    app.atomic_json(app.CONFIG, config)
    before = app.CONFIG.read_bytes()
    answers = iter(['8091', 'no'])
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    def read(prompt):
        if '[y/N]' in prompt:
            assert 'HTTP-порт для сертификата: 8080 → 8091' in capsys.readouterr().out
        return next(answers)
    monkeypatch.setattr('builtins.input', read)
    with pytest.raises(app.Failure):
        app.configure(config, '1')
    assert app.CONFIG.read_bytes() == before


def test_diagnose_does_not_cache_replaced_unverified_certificate(app, config, monkeypatch):
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    chain = current / 'fullchain.pem'
    chain.write_bytes(b'OLD')
    monkeypatch.setattr(app, 'certificate_status', lambda _: {'state': 'present'})
    monkeypatch.setattr(app, 'diagnostic_module', lambda: SimpleNamespace(
        collect=lambda _: {'checks': []}, display=lambda *a, **k: None))
    monkeypatch.setattr(app, 'run', lambda *a, **k: result())
    monkeypatch.setattr(app, 'validate_certificate', lambda *_: b'OLD-DER')
    monkeypatch.setattr(app, 'verify_served', lambda *a, **k: chain.write_bytes(b'NEW'))
    app.diagnose(config, interactive=True)
    assert app._menu_tls_check['success'] is False


def test_full_diagnostics_keep_site_provenance_in_json_only(app, config, monkeypatch, capsys):
    commit = '24134e23a438217cd52373ecdb0fcf7983e0e72c'
    app.atomic_json(app.STATE / 'site-template.json', dict(id='2', name='Convertit', commit=commit))
    monkeypatch.setattr(app, 'diagnostic_module', lambda: SimpleNamespace(
        collect=lambda _: {'checks': []}, display=lambda *a, **k: None))
    monkeypatch.setattr(app, 'run', lambda *a, **k: result())
    monkeypatch.setattr(app, 'verify_served', lambda *a, **k: None)
    monkeypatch.setattr(app, 'validate_certificate', lambda *a: b'CERT')
    report = app.diagnose(config, full=True)
    text = capsys.readouterr().out
    assert 'Сайт: Convertit' in text and commit not in text
    assert report['installation']['site']['commit'] == commit


def test_local_tls_rejects_certificate_change_during_check(app, config, monkeypatch):
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    chain = current / 'fullchain.pem'
    chain.write_bytes(b'OLD')
    monkeypatch.setattr(app, 'validate_certificate', lambda *_: b'OLD-DER')
    monkeypatch.setattr(app, 'verify_served', lambda *a, **k: chain.write_bytes(b'NEW'))
    with pytest.raises(app.Failure):
        app.local_self_test(config)
    assert app._menu_tls_check['success'] is False


@pytest.mark.parametrize('json_output', [False, True])
def test_status_only_reads_snapshot_and_preserves_tls_cache(app, config, monkeypatch, capsys, json_output):
    import client_panel
    app._menu_tls_check.update(at=123, success=True, identity={'domain': config['domain']})
    before = dict(app._menu_tls_check)
    calls = []
    monkeypatch.setattr(app, 'diagnostic_module', lambda: pytest.fail('status must not inventory host or resolve DNS'))
    monkeypatch.setattr(app, 'verify_served', lambda *a, **k: pytest.fail('status must not probe TLS'))
    monkeypatch.setattr(app, 'run', lambda *a, **k: pytest.fail('status must use the bounded snapshot'))
    monkeypatch.setattr(client_panel, 'snapshot', lambda proxy: calls.append(proxy.safe_config()) or {
        'rows': [('Сервер', 'Caddy · Работает'), ('Домен', config['domain']),
                 ('Порты', 'VPN 443 · HTTP 8080 · HTTPS 9443'), ('SSL', '89 дней'),
                 ('HTTPS', 'Не проверен'), ('Продление', 'Включено'), ('Заглушка', 'Convertit')],
        'installation': 'configured', 'hint': ''})
    report = app.status(config, json_output=json_output, no_color=True)
    output = capsys.readouterr().out
    assert calls == [config] and app._menu_tls_check == before
    assert list(report['summary']) == ['Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка']
    assert 'listeners' not in report and 'Диагностика' not in output and '\x1b' not in output
    assert 'Незавершённые' not in output


def test_status_warns_about_pending_operation_without_running_recovery(app, monkeypatch, capsys):
    import client_panel
    app.atomic_json(app.STATE / 'certificate-transaction.json', {'state': 'pending'})
    monkeypatch.setattr(client_panel, 'snapshot', lambda _: {
        'rows': [], 'installation': 'incomplete', 'hint': 'Установка не завершена.'})
    monkeypatch.setattr(app, 'recover_certificate', lambda: pytest.fail('status must not recover'))
    report = app.status(None)
    assert report['pending'] == ['certificate-transaction.json']
    assert 'Есть незавершённая операция' in capsys.readouterr().out


def test_ipv6_unavailable_is_not_reported_as_busy_http(app, monkeypatch):
    import errno
    binds = []
    class Socket:
        def bind(self, address):
            binds.append(address)
        def close(self):
            pass
    def socket_factory(family, *_):
        if family == app.socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, 'IPv6 disabled')
        return Socket()
    monkeypatch.setattr(app.socket, 'socket', socket_factory)
    monkeypatch.setattr(app.socket, 'has_ipv6', True)
    assert app.free_port(8080)
    assert binds == [('0.0.0.0', 8080)]


def test_https_bind_checks_only_selected_ipv4_loopback(app, monkeypatch):
    families = []
    class Socket:
        def bind(self, address):
            assert address == ('127.0.0.1', 9443)
        def close(self):
            pass
    monkeypatch.setattr(app.socket, 'socket', lambda family, *_: families.append(family) or Socket())
    monkeypatch.setattr(app.socket, 'has_ipv6', True)
    assert app.free_port(9443, '127.0.0.1')
    assert families == [app.socket.AF_INET]
