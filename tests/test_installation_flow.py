"""Repeat installation, domain rollback and explicit certificate cleanup, offline."""
import os
import socket
from types import SimpleNamespace

import pytest

import installation_flow as flow
import test_selfsteal as fixtures


app = fixtures.app
config = fixtures.config
retained_install = fixtures.retained_install


@pytest.fixture(autouse=True)
def owned_paths(monkeypatch, root_path):
    monkeypatch.setattr(flow, 'Path', root_path)


def private_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value)
    path.chmod(0o600)
    return path


def generation(app, name, domain):
    path = app.STATE / 'certs' / (name * 32)
    private_file(path / 'fullchain.pem', domain)
    private_file(path / 'key.pem', 'private')
    return path


@pytest.fixture
def saved(app, config, monkeypatch):
    config.update(install_id='a' * 32, vpn_port=443)
    app.validate_config(config)
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'certificate_status', lambda _: dict(state='present', days_remaining=75))
    monkeypatch.setattr(app, 'check_dns', lambda _: pytest.fail('No DNS before choosing the domain'))
    return config


@pytest.mark.parametrize('choice', ['0', '1', '2'])
def test_entry_chooses_without_dns_or_lock(app, saved, monkeypatch, choice, capsys):
    monkeypatch.setattr(app, 'ask', lambda *_: choice)
    dispatched = []
    monkeypatch.setattr(app, 'dispatch', lambda args: dispatched.append(args._new_domain) or 0)
    monkeypatch.setattr(app, 'check_install_resources', lambda: None)
    monkeypatch.setattr(app, 'package_owned', lambda: True)
    launched = []
    monkeypatch.setattr(app.subprocess, 'call', lambda cmd: launched.append(cmd) or 0)
    assert app.perform(SimpleNamespace(command='install', no_color=True)) == 0
    assert dispatched == ([True] if choice == '2' else [])
    assert bool(launched) == (choice == '1')
    if launched:
        assert launched[0][1:] == [str(app.INSTALL / 'selfsteal.py'), 'menu', '--no-color']
    assert not app.LOCK.exists()
    assert saved['domain'] in capsys.readouterr().out


def test_existing_menu_install_can_resume_without_nested_menu(app, saved, monkeypatch):
    monkeypatch.setattr(app, 'ask', lambda *_: '1')
    monkeypatch.setattr(app, 'dispatch', lambda args: 0 if not args._new_domain else pytest.fail('Wrong action'))
    monkeypatch.setattr(app.subprocess, 'call', lambda _: pytest.fail('Nested menu'))
    assert app.perform(SimpleNamespace(command='install', _menu_mode=True)) == 0


@pytest.mark.parametrize('marker', ['configuration-transaction.json', 'certificate-transaction.json', 'operation.json'])
def test_pending_transaction_blocks_entry(app, saved, monkeypatch, marker):
    app.atomic_json(app.STATE / marker, {})
    monkeypatch.setattr(app, 'ask', lambda *_: pytest.fail('Recovery must come first'))
    with pytest.raises(app.Failure, match='восстановите'):
        flow.choose_existing(app, SimpleNamespace())


@pytest.fixture
def switching(app, retained_install, config, monkeypatch):
    if os.name == 'nt':
        pytest.skip('Certificate generation links require Linux/WSL')
    app.validate_config(config)
    app.atomic_json(app.CONFIG, config)
    app.STATE.chmod(0o700)
    old = generation(app, 'b', config['domain'])
    (old.parent / 'current').symlink_to(old.name, target_is_directory=True)
    private_file(app.STATE / 'Caddyfile', 'old-caddy')
    private_file(app.STATE / 'compose.yaml', 'old-compose')
    app.lifecycle_stage('ready', issuance_authorized=True)
    app.atomic_json(app.STATE / 'http-path.json', {'old': True})
    candidate = dict(config, domain='new.example.com', relay_ip='8.8.4.4')
    monkeypatch.setattr(app, 'interactive_config', lambda _: candidate.copy())
    checked = []
    monkeypatch.setattr(app, 'check_dns', lambda cfg: checked.append(cfg['domain']))
    monkeypatch.setattr(app, 'validate_certificate', lambda *args: b'old')
    monkeypatch.setattr(app, 'verify_served', lambda *args: None)
    monkeypatch.setattr(app, 'compose', lambda *args, **kwargs: None)
    monkeypatch.setattr(app, 'reload_caddy', lambda: None)
    def renew(cfg):
        new = generation(app, 'c', cfg['domain'])
        app.swap_current(new.name)
        app.lifecycle_stage('ready', issuance_authorized=True)
    monkeypatch.setattr(app, 'renew', renew)
    cleanup = []
    monkeypatch.setattr(flow, 'cleanup_old_data', lambda _, cfg: cleanup.append(cfg['domain']))
    return config.copy(), checked, cleanup


def test_new_domain_uses_incoming_package_and_commits_before_cleanup(app, switching):
    old, checked, cleanup = switching
    app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG)['domain'] == 'new.example.com'
    assert checked == ['new.example.com']
    assert cleanup == ['new.example.com']
    assert not (app.STATE / 'configuration-transaction.json').exists()
    assert (app.INSTALL / 'VERSION').read_text() == '1.4.1'
    assert not list(app.INSTALL.parent.glob('tenant-selfsteal.previous-*'))
    assert not list(app.STATE.glob('update-backup-*'))
    backups = list(app.STATE.parent.glob('tenant-selfsteal-backup-*'))
    assert len(backups) == 1 and flow.verified_backup(app, backups[0]) == old
    assert (backups[0] / 'certs' / ('b' * 32) / 'key.pem').exists()


@pytest.mark.parametrize('stage', ['dependencies', 'render_caddy', 'http_self_test', 'renew'])
def test_failed_new_domain_restores_old_configuration_certificate_and_metadata(app, switching, monkeypatch, stage):
    old, _, cleanup = switching
    before = app.read_json(app.STATE / 'lifecycle.json')
    def fail(*args, **kwargs):
        # Failure after a new certificate has replaced current must also roll back.
        if stage == 'renew':
            new = generation(app, 'c', 'new.example.com')
            app.swap_current(new.name)
        raise app.Failure('offline failure')
    monkeypatch.setattr(app, stage, fail)
    with pytest.raises(app.Failure):
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG) == old
    assert (app.STATE / 'certs/current').resolve().name == 'b' * 32
    assert (app.STATE / 'Caddyfile').read_text() == 'old-caddy'
    assert app.read_json(app.STATE / 'lifecycle.json') == before
    assert app.read_json(app.STATE / 'http-path.json') == {'old': True}
    assert not (app.STATE / 'configuration-transaction.json').exists()
    assert cleanup == []
    if stage in ('http_self_test', 'renew'):
        assert list(app.INSTALL.parent.glob('tenant-selfsteal.previous-*'))


def test_cancel_new_domain_has_no_backup_or_mutations(app, switching, monkeypatch):
    old, _, cleanup = switching
    monkeypatch.setattr(app, 'installation_plan', lambda _: False)
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert error.value.code == 'CANCELLED'
    assert app.read_json(app.CONFIG) == old
    assert not list(app.STATE.parent.glob('tenant-selfsteal-backup-*'))
    assert cleanup == []


@pytest.fixture
def certificates(app, saved, monkeypatch):
    if os.name == 'nt':
        pytest.skip('Certificate generation links require Linux/WSL')
    active = generation(app, 'b', saved['domain'])
    (active.parent / 'current').symlink_to(active.name, target_is_directory=True)
    same = generation(app, 'c', saved['domain'])
    first = generation(app, 'd', 'old.example.com')
    second = generation(app, 'e', 'old.example.com')
    another = generation(app, 'f', 'older.example.com')
    monkeypatch.setattr(flow.ssl._ssl, '_test_decode_cert', lambda filename: {
        'subjectAltName': [('DNS', flow.Path(filename).read_text())]})
    private_file(app.STATE / 'acme/old.example.com_ecc/fullchain.cer', 'old.example.com')
    private_file(app.STATE / 'acme/old.example.com_ecc/old.example.com.key', 'old-key')
    private_file(app.STATE / 'acme/account.conf', 'account')
    private_file(app.STATE / 'acme/account.key', 'account-key')
    return active, same, first, second, another


def test_cleanup_groups_old_domains_and_preserves_current_domain_and_account(app, saved, certificates, monkeypatch):
    assert {name: len(paths) for name, paths in flow.old_certificates(app, saved).items()} == {
        'old.example.com': 2, 'older.example.com': 1}
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    flow.cleanup_old_data(app, saved)
    active, same, *old = certificates
    assert active.exists() and same.exists() and not any(path.exists() for path in old)
    assert (app.STATE / 'certs/current').resolve() == active
    assert not (app.STATE / 'acme/old.example.com_ecc').exists()
    assert (app.STATE / 'acme/account.conf').read_text() == 'account'
    assert (app.STATE / 'acme/account.key').read_text() == 'account-key'


@pytest.mark.parametrize('answer', ['', 'n', 'no', 'yes'])
def test_cleanup_requires_literal_y_and_keeps_files_on_decline(app, saved, certificates, monkeypatch, answer):
    monkeypatch.setattr('builtins.input', lambda _: answer)
    flow.cleanup_old_data(app, saved)
    assert all(path.exists() for path in certificates)


def test_cleanup_rejects_changed_current_after_confirmation(app, saved, certificates, monkeypatch):
    def confirm(_):
        app.swap_current(certificates[2].name)
        return True
    monkeypatch.setattr(app, 'confirm', confirm)
    with pytest.raises(app.Failure):
        flow.cleanup_old_data(app, saved)
    assert all(path.exists() for path in certificates)


def test_backup_cleanup_is_separate_and_decline_reports_retained_keys(app, saved, certificates, monkeypatch, capsys):
    backup = flow.backup_installation(app, saved)
    candidate = dict(saved, domain='new.example.com')
    app.atomic_json(app.CONFIG, candidate)
    monkeypatch.setattr(app, 'confirm', lambda _: False)
    flow.cleanup_old_data(app, candidate)
    assert backup.exists()
    assert 'сертификаты и ключи остаются внутри' in capsys.readouterr().out


def test_backup_delete_cannot_follow_symlink_or_unverified_manifest(app, saved, certificates, monkeypatch, tmp_path):
    backup = flow.backup_installation(app, saved)
    untouched = tmp_path / 'foreign'
    private_file(untouched / 'important', 'keep')
    (backup / 'unexpected').symlink_to(untouched, target_is_directory=True)
    candidate = dict(saved, domain='new.example.com')
    app.atomic_json(app.CONFIG, candidate)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    flow.cleanup_old_data(app, candidate)
    assert backup.exists() and (untouched / 'important').read_text() == 'keep'
    with pytest.raises(app.Failure):
        flow.verified_backup(app, backup)


def test_verified_old_backup_is_deleted_only_after_its_own_confirmation(app, saved, certificates, monkeypatch):
    backup = flow.backup_installation(app, saved)
    candidate = dict(saved, domain='new.example.com')
    app.atomic_json(app.CONFIG, candidate)
    monkeypatch.setattr(app, 'confirm', lambda prompt: 'эту резервную копию' in prompt)
    flow.cleanup_old_data(app, candidate)
    assert not backup.exists()
    assert all(path.exists() for path in certificates)


def test_backup_path_escape_and_tampered_manifest_are_rejected(app, saved, certificates):
    backup = flow.backup_installation(app, saved)
    manifest = app.read_json(backup / 'backup-manifest.json')
    manifest['domain'] = 'unrelated.example.com'
    app.atomic_json(backup / 'backup-manifest.json', manifest)
    with pytest.raises(app.Failure):
        flow.verified_backup(app, backup)
    with pytest.raises(app.Failure):
        flow.verified_backup(app, backup / '..' / '..' / backup.name)


def test_recovery_after_process_exit_restores_old_domain_before_any_renewal(app, switching, monkeypatch):
    old, _, cleanup = switching
    recover = app.recover_configuration
    def interrupted(cfg):
        new = generation(app, 'c', cfg['domain'])
        app.swap_current(new.name)
        raise SystemExit(137)
    monkeypatch.setattr(app, 'renew', interrupted)
    monkeypatch.setattr(app, 'recover_configuration', lambda: None)
    with pytest.raises(SystemExit):
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG)['domain'] == 'new.example.com'
    assert (app.STATE / 'configuration-transaction.json').exists()
    recover()
    assert app.read_json(app.CONFIG) == old
    assert (app.STATE / 'certs/current').resolve().name == 'b' * 32
    assert app.read_json(app.STATE / 'http-path.json') == {'old': True}
    assert cleanup == []


def test_cleanup_interruption_does_not_rollback_verified_new_domain(app, switching, monkeypatch):
    def interrupted(*_):
        raise KeyboardInterrupt
    monkeypatch.setattr(flow, 'cleanup_old_data', interrupted)
    app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG)['domain'] == 'new.example.com'
    assert (app.STATE / 'certs/current').resolve().name == 'c' * 32
    assert not (app.STATE / 'configuration-transaction.json').exists()


def test_current_domain_backup_is_never_offered_for_deletion(app, saved, certificates, monkeypatch):
    backup = flow.backup_installation(app, saved)
    monkeypatch.setattr(app, 'confirm', lambda prompt: pytest.fail('Current-domain backup offered')
                        if 'резервную копию' in prompt else False)
    flow.cleanup_old_data(app, saved)
    assert backup.exists()


def test_acme_only_old_domain_is_found_and_removed(app, saved, certificates, monkeypatch):
    private_file(app.STATE / 'acme/extra.example.com_ecc/fullchain.cer', 'extra.example.com')
    private_file(app.STATE / 'acme/extra.example.com_ecc/extra.example.com.key', 'extra-key')
    assert flow.old_certificates(app, saved)['extra.example.com'] == []
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    flow.cleanup_old_data(app, saved)
    assert not (app.STATE / 'acme/extra.example.com_ecc').exists()
    assert (app.STATE / 'acme/account.key').exists()


def test_package_failure_can_restore_an_expired_old_certificate(app, switching, monkeypatch):
    old, _, _ = switching
    monkeypatch.setattr(app, 'validate_certificate', lambda *_: pytest.fail('Rollback must preserve even an expired old certificate'))
    monkeypatch.setattr(app, 'render_caddy', lambda _: (_ for _ in ()).throw(app.Failure('offline failure')))
    with pytest.raises(app.Failure, match='offline failure'):
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG) == old
    assert (app.STATE / 'certs/current').resolve().name == 'b' * 32
    assert not (app.STATE / 'update-transaction.json').exists()


@pytest.mark.skipif(os.name != 'posix', reason='Live Caddy uses a Unix admin socket')
def test_backup_excludes_live_caddy_socket_without_stopping_caddy(app, saved, monkeypatch):
    import tempfile
    # Linux sockaddr_un paths are limited; keep this independent of pytest's long temp name.
    with tempfile.TemporaryDirectory(prefix='tc-') as directory:
        monkeypatch.setattr(app, 'STATE', flow.Path(directory) / 'state')
        folder = app.STATE / 'caddy-config'
        folder.mkdir(parents=True, mode=0o700)
        with socket.socket(socket.AF_UNIX) as admin:
            admin.bind(str(folder / 'transitclient-admin.sock'))
            backup = flow.backup_installation(app, saved)
            assert (folder / 'transitclient-admin.sock').exists()
            assert not (backup / 'caddy-config/transitclient-admin.sock').exists()
            assert flow.verified_backup(app, backup) == saved


def test_failure_publishing_new_lifecycle_restores_config_immediately(app, switching, monkeypatch):
    old, _, _ = switching
    original = app.lifecycle_stage
    def fail(stage, **kwargs):
        if stage == 'preparing':
            raise OSError('offline write failure')
        return original(stage, **kwargs)
    monkeypatch.setattr(app, 'lifecycle_stage', fail)
    with pytest.raises(OSError):
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG) == old
    assert (app.STATE / 'certs/current').resolve().name == 'b' * 32
    assert not (app.STATE / 'configuration-transaction.json').exists()
