"""Legacy firewall policy and cleanup only after committed, verified installation."""
import hashlib
import os
from types import SimpleNamespace

import pytest

import installation_flow as flow
import test_installation_flow as flow_fixtures
import test_selfsteal as fixtures


app = fixtures.app
config = fixtures.config
retained_install = fixtures.retained_install
saved = flow_fixtures.saved
switching = flow_fixtures.switching
private_file = flow_fixtures.private_file
owned_paths = flow_fixtures.owned_paths


@pytest.mark.parametrize('policy', ['manual', 'preserve'])
@pytest.mark.parametrize('null_effective', [False, True])
def test_preserving_legacy_policy_never_contacts_ufw(app, config, monkeypatch, policy, null_effective):
    config['firewall'] = policy
    if null_effective:
        config['firewall_effective'] = None
    monkeypatch.setattr(app, 'run', lambda *_: pytest.fail('Preserve accessed UFW'))
    app._open_firewall_locked(config, None)


def test_explicit_ufw_policy_stays_blocked_when_ufw_inactive(app, config, monkeypatch):
    config['firewall_effective'] = None
    calls = []
    monkeypatch.setattr(app, 'run', lambda args: calls.append(args) or fixtures.result(output=b'Status: inactive'))
    with pytest.raises(app.Failure) as error:
        app._open_firewall_locked(config, None)
    assert error.value.code == 'UFW_INACTIVE'
    assert 'Настройки' in str(error.value) and 'preserve' in str(error.value)
    assert calls == [['ufw', 'status']]


def test_unresolved_auto_policy_does_not_silently_require_ufw(app, config, monkeypatch):
    config.update(firewall='auto', firewall_effective=None)
    monkeypatch.setattr(app, 'run', lambda *_: pytest.fail('Unresolved auto contacted UFW'))
    with pytest.raises(app.Failure) as error:
        app._open_firewall_locked(config, None)
    assert error.value.code == 'FIREWALL_MODE_REQUIRED'


@pytest.mark.parametrize('policy,effective', [('manual', 'preserve'), ('preserve', 'preserve'), ('ufw', 'ufw')])
@pytest.mark.parametrize('null_effective', [False, True])
def test_new_domain_persists_legacy_policy_instead_of_null(app, switching, monkeypatch, policy, effective, null_effective):
    initial = app.read_json(app.CONFIG)
    initial['firewall'] = policy
    if null_effective:
        initial['firewall_effective'] = None
    app.atomic_json(app.CONFIG, initial)
    def probe(cfg, **_):
        assert cfg['firewall_effective'] == effective
        if effective == 'preserve':
            app._open_firewall_locked(cfg, None)
    monkeypatch.setattr(app, 'http_self_test', probe)
    app.install(SimpleNamespace(template=None, _new_domain=True))
    assert app.read_json(app.CONFIG)['firewall_effective'] == effective


def test_unresolved_auto_stops_before_backup_or_config_replacement(app, switching):
    initial = app.read_json(app.CONFIG)
    initial.update(firewall='auto', firewall_effective=None)
    app.atomic_json(app.CONFIG, initial)
    with pytest.raises(app.Failure) as error:
        app.install(SimpleNamespace(template=None, _new_domain=True))
    assert error.value.code == 'FIREWALL_MODE_REQUIRED'
    assert app.read_json(app.CONFIG) == initial
    assert not list(app.STATE.parent.glob('tenant-selfsteal-backup-*'))


@pytest.fixture
def runtime(app, saved):
    app.INSTALL.mkdir(mode=0o700)
    private_file(app.INSTALL / 'selfsteal.py', 'new controller')
    private_file(app.INSTALL / 'VERSION', '1.5.3')
    app.mark_package(saved)
    app.lifecycle_stage('ready', issuance_authorized=True)
    path = app.INSTALL.with_name('tenant-selfsteal.previous-' + 'b' * 32)
    private_file(path / 'selfsteal.py', 'old controller')
    private_file(path / 'VERSION', '1.4.6')
    app.atomic_json(path / '.transitclient-package.json', {
        'install_id': 'a' * 32, 'version': '1.4.6',
        'controller_sha256': hashlib.sha256(b'old controller').hexdigest()})
    snapshot = app.STATE / ('update-backup-' + 'b' * 32)
    app.atomic_json(snapshot / 'config.json', saved)
    private_file(snapshot / 'Caddyfile', 'old config')
    return path, snapshot


def test_verified_success_removes_only_previous_runtime_and_its_snapshot(app, saved, runtime):
    package, snapshot = runtime
    private_file(app.STATE / 'recovery/current-code.py', 'keep recovery')
    backup = flow.backup_installation(app, saved)
    flow.cleanup_previous_packages(app, saved)
    assert not package.exists() and not snapshot.exists()
    assert (app.INSTALL / 'selfsteal.py').read_text() == 'new controller'
    assert (app.STATE / 'recovery/current-code.py').read_text() == 'keep recovery'
    assert backup.exists()


@pytest.mark.parametrize('stage', ['preparing', 'runtime_ready', 'awaiting_http', 'awaiting_firewall'])
def test_unfinished_install_keeps_previous_runtime(app, saved, runtime, stage):
    app.lifecycle_stage(stage)
    flow.cleanup_previous_packages(app, saved)
    assert all(path.exists() for path in runtime)


@pytest.mark.parametrize('marker', ['operation.json', 'configuration-transaction.json',
                                  'certificate-transaction.json', 'update-transaction.json'])
def test_pending_transaction_keeps_previous_runtime(app, saved, runtime, marker):
    app.atomic_json(app.STATE / marker, {})
    flow.cleanup_previous_packages(app, saved)
    assert all(path.exists() for path in runtime)


@pytest.mark.parametrize('damage', ['hash', 'version', 'unknown_file', 'snapshot_owner', 'snapshot_file'])
def test_unproven_previous_runtime_is_never_deleted(app, saved, runtime, damage):
    package, snapshot = runtime
    if damage == 'hash':
        private_file(package / 'selfsteal.py', 'foreign replacement')
    elif damage == 'version':
        private_file(package / 'VERSION', 'different version')
    elif damage == 'unknown_file':
        private_file(package / '.env', 'must remain')
    elif damage == 'snapshot_owner':
        app.atomic_json(snapshot / 'config.json', dict(saved, install_id='c' * 32))
    else:
        private_file(snapshot / 'unknown.json', 'must remain')
    flow.cleanup_previous_packages(app, saved)
    assert package.exists() and snapshot.exists()


@pytest.mark.skipif(os.name == 'nt', reason='Linux package directory links')
def test_symlinked_snapshot_cannot_delete_outside_state(app, saved, runtime, tmp_path):
    package, snapshot = runtime
    for path in snapshot.iterdir():
        path.unlink()
    snapshot.rmdir()
    target = tmp_path / 'foreign'
    private_file(target / 'keep', 'foreign')
    snapshot.symlink_to(target, target_is_directory=True)
    flow.cleanup_previous_packages(app, saved)
    assert package.exists() and (target / 'keep').read_text() == 'foreign'


def test_deferred_first_renew_cleans_runtime_after_operation_scope_closes(app, saved, runtime, monkeypatch):
    monkeypatch.setattr(app, '_renew', lambda _: app.lifecycle_stage('ready', issuance_authorized=True))
    monkeypatch.setattr(app, 'abort_acme', lambda *_: None)
    monkeypatch.setattr(app, 'stop_scoped_transient', lambda *_: None)
    app.renew(saved)
    assert not (app.STATE / 'operation.json').exists()
    assert not any(path.exists() for path in runtime)


@pytest.mark.skipif(os.name != 'posix', reason='Unix file ownership')
def test_foreign_file_owner_blocks_runtime_deletion(app, saved, runtime, monkeypatch, root_path):
    package, snapshot = runtime
    original = root_path.stat
    def stat(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == package / '.transitclient-package.json':
            return SimpleNamespace(**dict(vars(value), st_uid=1000))
        return value
    monkeypatch.setattr(root_path, 'stat', stat)
    flow.cleanup_previous_packages(app, saved)
    assert package.exists() and snapshot.exists()


def test_new_domain_message_and_menu_are_plain_client_copy(app, retained_install, monkeypatch, capsys):
    monkeypatch.setattr(app, 'ask', lambda *_: '0')
    with pytest.raises(app.Failure):
        app.install(SimpleNamespace())
    output = capsys.readouterr().out
    assert 'Будет обновлён Transit Client: 1.3.3 → 1.4.1.' in output
    assert 'Установить веб-сервер Caddy [Рекомендуем]' in output
    assert 'Свой веб-сервер [Инструкция]' in output
    assert 'собственный пакет' not in output and 'входящий пакет' not in output
