"""Failure, ownership and race regression tests. No host mutation or CA calls."""
from contextlib import contextmanager
import hashlib
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import test_selfsteal as fixtures


app = fixtures.app
config = fixtures.config
result = fixtures.result


def operation(app, config, identifier='a' * 32, **details):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    record = dict(operation_id=identifier, install_id=config['install_id'], resources=['acme', 'probe', 'watchdog'],
                  deadline=int(time.time()) + 100, state='active')
    record.update(details)
    app.atomic_json(app.STATE / 'operation.json', record)
    return record


def test_busy_does_not_overwrite_active_result(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    original = b'{"success": true, "operation_id": "active"}'
    (app.STATE / 'result.json').write_bytes(original)
    def busy(_):
        raise app.Failure('busy', 'OPERATION_BUSY')
    monkeypatch.setattr(app, 'dispatch', busy)
    assert app.perform(SimpleNamespace(command='renew')) == 75
    assert (app.STATE / 'result.json').read_bytes() == original


@pytest.mark.parametrize('hook', ['_cleanup', '_abort', '_open'])
def test_late_old_hook_never_touches_new_operation(app, config, monkeypatch, hook):
    record = operation(app, config)
    marker = dict(tag='tenant-selfsteal-' + 'c' * 32, mode='ufw', port=8080,
                  operation_id=record['operation_id'], install_id=config['install_id'])
    app.atomic_json(app.STATE / 'firewall.json', marker)
    before = (app.STATE / 'firewall.json').read_bytes()
    monkeypatch.setattr(app, 'require_host', lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Stale hook executed a host command'))
    args = SimpleNamespace(command=hook, operation_id='d' * 32)
    if hook == '_open':
        with pytest.raises(app.Failure) as error:
            app.dispatch(args)
        assert error.value.code == 'OPERATION_EXPIRED'
    else:
        assert app.dispatch(args) == 0
    assert (app.STATE / 'firewall.json').read_bytes() == before


@pytest.mark.parametrize('details', [{'deadline': 0}, {'state': 'closing'}, {'state': 'recovering'}])
def test_expired_or_closing_operation_cannot_reopen_firewall(app, config, monkeypatch, details):
    record = operation(app, config, **details)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Inactive lease mutated firewall'))
    with pytest.raises(app.Failure) as error:
        app.open_firewall(config, record['operation_id'])
    assert error.value.code == 'OPERATION_EXPIRED'
    assert not (app.STATE / 'firewall.json').exists()


def test_unscoped_legacy_cleanup_cannot_delete_new_lease(app, config, monkeypatch):
    record = operation(app, config)
    app.atomic_json(app.STATE / 'firewall.json', dict(operation_id=record['operation_id'],
                    tag='tenant-selfsteal-' + 'c' * 32, mode='ufw', port=8080))
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Legacy handler touched a new lease'))
    app.cleanup_firewall()
    app.abort_acme()
    assert (app.STATE / 'firewall.json').exists()


def test_resource_unit_requires_both_id_and_executable_proof(app, config, monkeypatch):
    record = operation(app, config)
    monkeypatch.setattr(app, 'transient_state', lambda _: dict(LoadState='loaded',
                        Description='Transitclient acme bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ' + record['operation_id'],
                        ExecStart='/usr/bin/foreign --home ' + str(app.STATE / 'acme')))
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Foreign service stopped'))
    with pytest.raises(app.Failure) as error:
        app.abort_acme(record['operation_id'])
    assert error.value.code == 'OWNERSHIP_UNKNOWN'
    assert (app.STATE / 'operation.json').exists()


@pytest.mark.parametrize('stage', ['preparing', 'awaiting_http', 'awaiting_firewall', 'uninstalling'])
def test_partial_installation_never_contacts_ca(app, config, monkeypatch, stage):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    app.lifecycle_stage(stage, issuance_authorized=True)
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Unprepared install contacted host/CA'))
    with pytest.raises(app.Failure):
        app.renew(config)
    assert not (app.STATE / 'operation.json').exists()


def test_cancelled_http_probe_does_not_create_operation_or_contact_host(app, config, monkeypatch):
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: False)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Cancelled test contacted host'))
    with pytest.raises(app.Failure) as error:
        app.http_self_test(config)
    assert error.value.code == 'CANCELLED'
    assert list(app.STATE.iterdir()) == []


def test_schedule_activation_runs_after_lock_release_and_accepts_running_timer(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    locked = [False]
    @contextmanager
    def lock(**_):
        locked[0] = True
        try:
            yield
        finally:
            locked[0] = False
    def install(_):
        app.atomic_json(app.CONFIG, config)
        app.lifecycle_stage('certificate_pending', issuance_authorized=True)
        app.atomic_json(app.STATE / 'schedule-pending.json', {'install_id': config['install_id']})
    def run(args, **_):
        assert not locked[0], 'Timer activated/awaited under its parent lock'
        if 'tenant-selfsteal-renew.timer' in args and 'show' in args:
            return result(output=b'UnitFileState=enabled\nActiveState=active\nSubState=running\nNextElapseUSecRealtime=n/a\n')
        if 'tenant-selfsteal-renew.service' in args:
            return result(output=b'ActiveState=activating\nResult=success\n')
        return result()
    monkeypatch.setattr(app, 'lifecycle_lock', lock)
    monkeypatch.setattr(app, 'install', install)
    monkeypatch.setattr(app, 'require_host', lambda: None)
    monkeypatch.setattr(app, 'run', run)
    assert app.dispatch(SimpleNamespace(command='install')) == 0
    assert not (app.STATE / 'schedule-pending.json').exists()


def test_incomplete_recovery_generation_never_replaces_working_pointer(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    app.install_recovery()
    pointer = (app.STATE / 'recovery-current.json').read_bytes()
    wrapper = (app.STATE / 'recover.py').read_bytes()
    copied = app.shutil.copyfile
    calls = [0]
    def fail(source, destination):
        calls[0] += 1
        if calls[0] == 2:
            raise OSError('Simulated interruption between helper copies')
        return copied(source, destination)
    monkeypatch.setattr(app.shutil, 'copyfile', fail)
    with pytest.raises(OSError):
        app.install_recovery()
    assert (app.STATE / 'recovery-current.json').read_bytes() == pointer
    assert (app.STATE / 'recover.py').read_bytes() == wrapper
    generation = app.read_json(app.STATE / 'recovery-current.json')['generation']
    assert (app.STATE / 'recovery' / generation / 'renewal_schedule.py').is_file()


def test_rollback_restores_unit_files_and_enabled_state_without_restarting_worker(app, monkeypatch):
    app.UNITS.mkdir()
    for name in ('renew.service', 'renew.timer', 'recover.service'):
        (app.UNITS / ('tenant-selfsteal-' + name)).write_text('new unit')
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or result())
    values = {name: dict(content='previous ' + name, enabled=name != 'renew.service', active=True)
              for name in ('renew.service', 'renew.timer', 'recover.service')}
    app.restore_units(values)
    assert (app.UNITS / 'tenant-selfsteal-renew.timer').read_text() == 'previous renew.timer'
    assert ['systemctl', 'enable', 'tenant-selfsteal-renew.timer'] in calls
    assert not any(call[:2] == ['systemctl', 'start'] for call in calls)
    assert (app.STATE / 'units-restore-pending.json').exists()
    assert ['systemctl', 'start', 'tenant-selfsteal-renew.service'] not in calls


@pytest.mark.skipif(os.name != 'posix', reason='Real flock process contention requires Linux/WSL')
def test_real_worker_lock_wait_is_bounded_and_releases_after_exception(app):
    program = 'import fcntl,sys,time; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX); print("ready",flush=True); time.sleep(1)'
    child = subprocess.Popen([sys.executable, '-c', program, str(app.LOCK)], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        start = time.monotonic()
        with pytest.raises(app.Failure) as error:
            with app.lifecycle_lock(wait=0.2):
                pytest.fail('Competing lock entered')
        assert error.value.code == 'OPERATION_BUSY'
        assert time.monotonic() - start < 0.8
    finally:
        child.wait(timeout=5)
    with app.lifecycle_lock():
        pass


def test_restore_rejects_foreign_or_tampered_backup_without_host_calls(app, config, monkeypatch):
    source = app.STATE.parent / 'tenant-selfsteal-backup-test'
    source.mkdir()
    config['install_id'] = 'b' * 32
    app.atomic_json(source / 'config-backup.json', config)
    app.atomic_json(source / 'backup-manifest.json', dict(kind='transitclient-backup', install_id='c' * 32,
                    domain=config['domain'], config_sha256=hashlib.sha256((source / 'config-backup.json').read_bytes()).hexdigest()))
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Untrusted restore contacted host'))
    with pytest.raises(app.Failure) as error:
        app.restore_backup(SimpleNamespace(backup=str(source), domain=None))
    assert error.value.code == 'BACKUP_UNTRUSTED'
    assert not app.CONFIG.exists()


@pytest.mark.parametrize('domain', [None, 'new.example.com'])
def test_explicit_restore_uses_trusted_runtime_and_never_requests_certificate(app, config, monkeypatch, domain):
    source = app.STATE.parent / 'tenant-selfsteal-backup-test'
    source.mkdir(mode=0o700)
    config.update(install_id='b' * 32, firewall='preserve')
    app.atomic_json(source / 'config-backup.json', config)
    app.atomic_json(source / 'backup-manifest.json', dict(kind='transitclient-backup', install_id=config['install_id'],
                    domain=config['domain'], config_sha256=hashlib.sha256((source / 'config-backup.json').read_bytes()).hexdigest()))
    (source / 'acme').mkdir(mode=0o700)
    (source / 'acme/account.key').write_bytes(b'original private account')
    (source / 'recover.py').write_text('raise RuntimeError("Must never run backup code")')
    for item in source.rglob('*'):
        item.chmod(0o700 if item.is_dir() else 0o600)
    app.INSTALL.mkdir()
    (app.INSTALL / 'selfsteal.py').write_text('trusted retained controller')
    (app.INSTALL / 'VERSION').write_text('1.5.0')
    app.mark_package(config)
    monkeypatch.setattr(app, 'PACKAGE', app.INSTALL)
    for name in ('check_install_resources', 'check_dns', 'check_challenge_port', 'assert_local_docker',
                 'dependencies', 'install_launcher', 'render_caddy', 'install_units'):
        monkeypatch.setattr(app, name, lambda *_, **__: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Restore contacted CA/host'))
    before = (source / 'config-backup.json').read_bytes()
    app.restore_backup(SimpleNamespace(backup=str(source), domain=domain, relay_ip=None))
    assert app.read_json(app.CONFIG)['domain'] == (domain or config['domain'])
    assert (app.STATE / 'acme/account.key').read_bytes() == b'original private account'
    assert not (app.STATE / 'recover.py').exists()
    assert (source / 'config-backup.json').read_bytes() == before
    assert app.read_json(app.STATE / 'lifecycle.json')['issuance_authorized'] is False


def test_busy_worker_queues_one_retry_and_preserves_current_result(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    original = b'{"success": true}'
    (app.STATE / 'result.json').write_bytes(original)
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or result())
    def busy(_):
        raise app.Failure('busy', 'OPERATION_BUSY')
    monkeypatch.setattr(app, 'dispatch', busy)
    for _ in range(3):
        assert app.perform(SimpleNamespace(command='renew', worker=True)) == 75
    launches = [call for call in calls if call[0] == 'systemd-run']
    assert len(launches) == 1 and '--on-active=5min' in launches[0]
    assert (app.STATE / 'result.json').read_bytes() == original
    assert app.read_json(app.STATE / 'retry.json')['state'] == 'pending'


def test_one_shot_retry_cannot_launch_a_second_worker_chain(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or result())
    monkeypatch.setattr(app, 'check_install_resources', lambda: None)
    app.queue_retry()
    retry_id = app.read_json(app.STATE / 'retry.json')['retry_id']
    app.retry_renew(config['install_id'], retry_id)
    app.retry_renew(config['install_id'], retry_id)
    app.queue_retry()
    assert len([call for call in calls if call[0] == 'systemd-run']) == 1
    assert calls.count(['systemctl', 'start', 'tenant-selfsteal-renew.service']) == 1
    assert app.read_json(app.STATE / 'retry.json')['state'] == 'fired'


def test_stale_retry_install_id_never_starts_renewal(app, config, monkeypatch):
    record = operation(app, config)
    app.atomic_json(app.STATE / 'retry.json', dict(install_id=record['install_id'], state='pending'))
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Stale retry touched host'))
    app.retry_renew('d' * 32)
    assert app.read_json(app.STATE / 'retry.json')['state'] == 'pending'


def test_existing_certificate_does_not_authorize_restored_account(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    (app.STATE / 'certs/current').mkdir(parents=True)
    (app.STATE / 'certs/current/fullchain.pem').write_bytes(b'saved cert')
    app.lifecycle_stage('ready', issuance_authorized=False)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Restore requested CA without consent'))
    monkeypatch.setattr(app, 'check_dns', lambda _: pytest.fail('Must stop before network checks'))
    with pytest.raises(app.Failure) as error:
        app.renew(config)
    assert error.value.code == 'ACME_NOT_AUTHORIZED'


def test_update_child_cannot_run_outside_own_transaction(app, config, monkeypatch):
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'require_host', lambda: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Unauthorized child changed host'))
    with pytest.raises(app.Failure) as error:
        app.dispatch(SimpleNamespace(command='_update-apply', operation_id='a' * 32))
    assert error.value.code == 'OPERATION_EXPIRED'


def test_service_recovery_never_starts_its_own_dependent_schedule(app, monkeypatch):
    monkeypatch.setenv('INVOCATION_ID', 'systemd-invocation')
    monkeypatch.setattr(app, '_dispatch', lambda _: 0)
    monkeypatch.setattr(app, 'activate_schedule', lambda: pytest.fail('Recovery started its own dependant'))
    assert app.dispatch(SimpleNamespace(command='_recover')) == 0


def test_firewall_mode_change_requires_confirmation_and_preserves_foreign_rules(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'diagnostic_module', lambda: SimpleNamespace(collect=lambda _: {}))
    monkeypatch.setattr(app, 'confirm', lambda _: False)
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Preserve plan touched firewall'))
    original = app.CONFIG.read_bytes()
    with pytest.raises(app.Failure):
        app.configure(config, '5', 'preserve')
    assert app.CONFIG.read_bytes() == original
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    changed = app.configure(config, '5', 'preserve')
    assert changed['firewall'] == changed['firewall_effective'] == 'preserve'
    assert app.read_json(app.CONFIG)['firewall_effective'] == 'preserve'


@pytest.mark.parametrize('confirmed', [False, True])
def test_hairpin_external_nonce_is_explicit_and_records_operator_scope(app, config, monkeypatch, confirmed):
    from contextlib import nullcontext
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app, 'open_firewall', lambda _: None)
    monkeypatch.setattr(app, 'confirm', lambda _: confirmed)
    calls = []
    monkeypatch.setattr(app, 'run', lambda args, **_: calls.append(args) or result())
    class Response:
        def read(self, *_):
            return b'wrong backend'
    class Opener:
        def open(self, *_args, **_kwargs):
            return nullcontext(Response())
    monkeypatch.setattr(app.urllib.request, 'build_opener', lambda *_: Opener())
    if confirmed:
        app.http_self_test(config, approved=True, external_check=True)
        record = app.read_json(app.STATE / 'http-path.json')
        assert record['scope'] == 'operator_reported'
    else:
        with pytest.raises(app.Failure) as error:
            app.http_self_test(config, approved=True, external_check=True)
        assert error.value.code == 'HTTP_PATH_UNCONFIRMED'
        assert not (app.STATE / 'http-path.json').exists()
    assert not any('acme.sh' in str(value) for call in calls for value in call)
    assert not (app.STATE / 'operation.json').exists()


def test_previous_retry_callback_cannot_launch_new_retry_for_same_install(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    monkeypatch.setattr(app, 'run', lambda *_, **__: result())
    app.queue_retry()
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Old retry touched the new installation'))
    app.retry_renew(config['install_id'], 'f' * 32)
    assert app.read_json(app.STATE / 'retry.json')['state'] == 'pending'


def test_uninstall_cleans_stamp_before_removing_units_and_retains_data_on_failure(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    app.UNITS.mkdir()
    for name in ('renew.timer', 'renew.service', 'recover.service'):
        (app.UNITS / ('tenant-selfsteal-' + name)).write_text('own unit')
    for name in ('check_install_resources', 'assert_compose_owned', 'recover_operation'):
        monkeypatch.setattr(app, name, lambda: None)
    monkeypatch.setattr(app, 'confirm', lambda _: True)
    monkeypatch.setattr(app, 'compose', lambda *_, **__: None)
    calls = []
    def run(args, **_):
        calls.append(args)
        if args[:2] == ['systemctl', 'clean']:
            assert (app.UNITS / 'tenant-selfsteal-renew.timer').exists()
            raise app.Failure('Simulated stamp cleanup failure')
        return result()
    monkeypatch.setattr(app, 'run', run)
    with pytest.raises(app.Failure, match='stamp'):
        app.uninstall()
    assert app.CONFIG.exists() and app.STATE.exists()
    assert (app.STATE / 'uninstall.json').exists()
    assert (app.UNITS / 'tenant-selfsteal-renew.timer').exists()
    assert ['systemctl', 'stop', 'tenant-selfsteal-renew.service'] in calls


def test_uninstall_resumes_after_state_rename_without_repeating_host_mutations(app, config, monkeypatch):
    config['install_id'] = 'b' * 32
    app.atomic_json(app.CONFIG, config)
    backup = app.STATE.with_name('tenant-selfsteal-backup-20261013090000-' + 'c' * 32)
    app.atomic_json(app.CONFIG.with_name('uninstall-transaction.json'), dict(
                    stage='resources_removed', install_id=config['install_id'], backup=str(backup)))
    app.prepare_uninstall_backup(backup, config)
    assert not app.STATE.exists() and app.CONFIG.exists()
    monkeypatch.setattr(app, 'run', lambda *_, **__: pytest.fail('Resume repeated host/CA operations'))
    monkeypatch.setattr(app, 'LAUNCHER', app.CONFIG.parent / 'nonexistent-launcher')
    assert app.resume_uninstall()
    assert not app.CONFIG.exists()
    assert not app.CONFIG.with_name('uninstall-transaction.json').exists()
    assert app.read_json(backup / 'config-backup.json')['install_id'] == config['install_id']
