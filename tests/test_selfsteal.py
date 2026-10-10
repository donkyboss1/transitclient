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
    assert saved['firewall'] == 'ufw' and saved['relay_ip'] == ''


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
    with pytest.raises(app.Failure, match='не будет включён'):
        app.open_firewall(config)
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
            return result(output=('LoadState=loaded\nDescription=Transitclient ACME\nExecStart=' +
                                 str(app.INSTALL / 'vendor/acme.sh') + ' --home ' + str(app.STATE / 'acme') + '\n').encode())
        return result(code=1 if args[0] == 'systemd-run' else 0)

    monkeypatch.setattr(app, 'run', fake_run)
    with pytest.raises(app.Failure, match='ACME-проверка'):
        app.renew(config)
    assert (old / 'fullchain.pem').read_text() == 'OLD CERT'
    assert ['systemctl', 'stop', 'tenant-selfsteal-acme.service'] in calls
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
    answers = iter(['1', '8091', 'да'])
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


def test_timer_must_have_real_scheduled_next_run(app, monkeypatch):
    app.UNITS.mkdir()
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return result(output=b'')

    monkeypatch.setattr(app, 'run', fake_run)
    with pytest.raises(app.Failure, match='не назначен'):
        app.install_units()
    assert ['systemctl', 'is-active', '--quiet', 'tenant-selfsteal-renew.timer'] in calls
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


def test_unpublished_update_has_no_network_fallback(app, config, monkeypatch):
    monkeypatch.setattr(app, 'verified_download', lambda *a: pytest.fail('unexpected network'))
    args = SimpleNamespace(package_url=None, sha256=None, version=None)
    with pytest.raises(app.Failure, match='URL ещё не настроен'):
        app.update(config, args)


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
    assert 'bind 127.0.0.1' in caddy and app.ADMIN in caddy
    config.update(docker_network='vpn-private', local_port=9543)
    app.render_caddy(config)
    text = (app.STATE / 'compose.yaml').read_text()
    assert 'network_mode:' not in text and 'ports:' not in text
    assert 'external: true' in text and 'name: vpn-private' in text
    assert 'transitclient-selfsteal' in text
    assert app.target(config) == 'transitclient-selfsteal:9543'


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
    answers = iter(['1', '8091', 'нет'])
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
    monkeypatch.setattr(app, 'cleanup_firewall', lambda: calls.append('cleanup'))
    monkeypatch.setattr(app, 'stop_probe', lambda: pytest.fail('Failed launch does not prove unit ownership'))
    monkeypatch.setattr(app, 'run', lambda *a, **k: (_ for _ in ()).throw(app.Failure('Unit collision')))
    with pytest.raises(app.Failure):
        app.http_self_test(config)
    assert calls == ['cleanup']


def test_reconfigure_failure_restores_previous_runtime_and_config(app, config, monkeypatch):
    config.update(vpn_port=443)
    app.render_caddy(config)
    app.atomic_json(app.CONFIG, config)
    originals = {name: (app.STATE / name).read_text() for name in ('Caddyfile', 'compose.yaml')}
    current = app.STATE / 'certs/current'
    current.mkdir(parents=True)
    (current / 'fullchain.pem').write_bytes(b'CERT')
    (current / 'key.pem').write_bytes(b'KEY')
    answers = iter(['3', '9543', 'да'])
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
    from contextlib import nullcontext
    events = []
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app.uuid, 'uuid4', lambda: SimpleNamespace(hex='a' * 32))
    monkeypatch.setattr(app, 'open_firewall', lambda _: events.append('open'))
    monkeypatch.setattr(app, 'stop_probe', lambda: events.append('stop-owned'))
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **kw: calls.append(args) or result())
    class Response:
        def read(self, *_):
            return b'transitclient-check:' + b'a' * 32
    class Opener:
        def open(self, address, **_):
            assert address.startswith('http://bob.example.com/.well-known/acme-challenge/')
            return nullcontext(Response())
    monkeypatch.setattr(app.urllib.request, 'build_opener', lambda *_: Opener())
    app.http_self_test(config)
    assert events == ['open', 'stop-owned']
    assert len(calls) == 1 and '--unit=tenant-selfsteal-probe' in calls[0]
    assert '--property=RuntimeMaxSec=120s' in calls[0]
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
