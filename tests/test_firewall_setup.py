"""Offline tests: no actual firewall, package install or service operations."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fw(tmp_path, monkeypatch, root_path):
    spec = importlib.util.spec_from_file_location('tested_firewall_setup', Path(__file__).parents[1] / 'firewall_setup.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = tmp_path / 'ufw'
    directory.mkdir()
    for name in ('before.rules', 'before6.rules', 'after.rules', 'after6.rules'):
        (directory / name).write_text('standard ' + name)
    default = tmp_path / 'default-ufw'
    default.write_text('IPV6=yes\nMANAGE_BUILTINS=no\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_INPUT_POLICY="DROP"\n')
    monkeypatch.setattr(module, 'UFW_DIR', directory)
    monkeypatch.setattr(module, 'UFW_DEFAULT', default)
    monkeypatch.setattr(module, 'Path', root_path)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.delenv('SSH_CONNECTION', raising=False)
    return module


@pytest.fixture
def report():
    return dict(dependencies=dict(ufw=True), docker=dict(available=True, local=True, inventory_complete=True,
                containers=[dict(running=True, network_mode='host')]))


@pytest.fixture
def config():
    return dict(firewall='ufw', challenge_port=8080, vpn_port=443, install_id='a' * 32)


class Runner:
    def __init__(self, fw):
        self.calls = []
        self.status = 'inactive'
        self.added = 'Added user rules (see \'ufw status\' for running firewall):\n'
        self.tcp = ('LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=12,fd=3))\n'
                    'LISTEN 0 4096 *:443 *:* users:(("rw-core",pid=15,fd=7))\n')
        self.udp = 'UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolved",pid=3,fd=4))\n'
        self.saved = '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n'
        self.nft = '{"nftables":[]}'
        self.vendor = '\n'.join(' ' + str(p) + ' ' + hashlib.md5(p.read_bytes()).hexdigest() for p in fw.UFW_DIR.iterdir())
        self.rules = []
        self.fail_enable = False
        self.missing_ipv6 = False
        self.hide_permission = False

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        out = ''
        code = 0
        if args[0] == 'ss':
            out = self.tcp if args[-1] == '-lntp' else self.udp
        elif args[0] in ('iptables-save', 'ip6tables-save'):
            out = self.saved
        elif args[0] == 'nft':
            out = self.nft
        elif args[0] == 'dpkg-query':
            out = self.vendor
        elif args[:2] == ['systemctl', 'is-active']:
            out, code = 'inactive', 3
        elif args[:2] == ['ufw', 'status']:
            out = 'Status: ' + self.status + '\n'
            if args[-1] == 'numbered' and not self.hide_permission:
                for index, port in enumerate(self.rules, 1):
                    out += f'[{index}] {port} ALLOW IN Anywhere # transitclient-preserve\n'
                    if not self.missing_ipv6:
                        out += f'[{index+100}] {port} (v6) ALLOW IN Anywhere (v6) # transitclient-preserve\n'
        elif args[:3] == ['ufw', 'show', 'added']:
            out = self.added
        elif args[:3] == ['ufw', 'prepend', 'allow']:
            self.rules.append(args[3])
        elif args == ['ufw', '--force', 'enable']:
            if self.fail_enable:
                raise RuntimeError('enable failed')
            self.status = 'active'
        elif args == ['ufw', '--force', 'disable']:
            self.status = 'inactive'
        return SimpleNamespace(returncode=code, stdout=out.encode())


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def patch_collect(monkeypatch, report):
    import diagnostics
    monkeypatch.setattr(diagnostics, 'collect', lambda _: report)


def test_inactive_plan_only_opens_confirmed_ssh_and_selected_vpn(fw, config, report):
    run = Runner(fw)
    prepared = fw.plan(config, report, run)
    assert prepared['mode'] == 'inactive'
    assert prepared['rules'] == [dict(port=22, protocol='tcp'), dict(port=443, protocol='tcp')]
    assert not any(a[:2] == ['ufw', '--force'] or a[:2] == ['ufw', 'prepend'] for a in run.calls)


def test_active_plan_never_enables_or_adds_service_rules(fw, config, report, tmp_path):
    run = Runner(fw)
    run.status = 'active'
    prepared = fw.plan(config, report, run)
    assert fw.apply(prepared, config, tmp_path / 'state', run, atomic)['status'] == 'unchanged'
    assert run.calls == [['ufw', 'status'], ['iptables-save'], ['ip6tables-save'], ['nft', '--json', 'list', 'ruleset'],
                         ['dpkg-query', '-W', '-f=${Conffiles}', 'ufw'],
                         ['ufw', 'show', 'added']]


@pytest.mark.parametrize('rule', ['ufw deny 8080/tcp', 'ufw limit 8000:9000/tcp',
                                'ufw deny from 8.8.8.8 to any port 8080 proto tcp',
                                'ufw reject from 8.8.8.8', 'ufw deny in on eth0'])
def test_challenge_deny_is_not_overridden(fw, rule):
    run = Runner(fw)
    run.added += rule
    with pytest.raises(fw.FirewallError) as error:
        fw.check_challenge_rules(run, 8080)
    assert error.value.code == 'FIREWALL_RULE_CONFLICT'


@pytest.mark.parametrize('rule', ['ufw deny 443/tcp', 'ufw deny 8080/udp', 'ufw deny out 8080/tcp',
                                'ufw deny from 8.8.8.8 to any port 443 proto tcp'])
def test_unrelated_challenge_deny_allowed(fw, rule):
    run = Runner(fw)
    run.added += rule
    fw.check_challenge_rules(run, 8080)


def test_bridge_containers_block_activation(fw, config, report):
    report['docker']['containers'][0]['network_mode'] = 'bridge'
    with pytest.raises(fw.FirewallError, match='Docker-контейнер'):
        fw.plan(config, report, Runner(fw))


def test_missing_owner_and_missing_ssh_block(fw, config, report):
    run = Runner(fw)
    run.tcp = 'LISTEN 0 4096 *:443 *:*\n'
    with pytest.raises(fw.FirewallError, match='владельца'):
        fw.plan(config, report, run)
    run.tcp = 'LISTEN 0 4096 *:443 *:* users:(("core",pid=15,fd=7))\n'
    with pytest.raises(fw.FirewallError, match='SSH-слушатель'):
        fw.plan(config, report, run)


@pytest.mark.parametrize('port', [2022, 443, 2222])
def test_ssh_connection_port_must_match_ssh_inventory(fw, config, report, monkeypatch, port):
    monkeypatch.setenv('SSH_CONNECTION', f'8.8.8.8 45000 1.1.1.1 {port}')
    with pytest.raises(fw.FirewallError, match='SSH-порт'):
        fw.plan(config, report, Runner(fw))


def test_confirmed_nonstandard_ssh_port_is_preserved(fw, config, report, monkeypatch):
    run = Runner(fw)
    run.tcp = run.tcp.replace('0.0.0.0:22 ', '0.0.0.0:2022 ')
    monkeypatch.setenv('SSH_CONNECTION', '8.8.8.8 45000 1.1.1.1 2022')
    prepared = fw.plan(config, report, run)
    assert dict(port=2022, protocol='tcp') in prepared['rules']
    assert dict(port=22, protocol='tcp') not in prepared['rules']


def test_native_filters_and_modified_before_rules_block(fw, config, report):
    run = Runner(fw)
    run.saved += '-A INPUT -j DROP\n'
    with pytest.raises(fw.FirewallError):
        fw.plan(config, report, run)
    run = Runner(fw)
    (fw.UFW_DIR / 'before.rules').write_text('custom drops')
    with pytest.raises(fw.FirewallError, match='Изменённая'):
        fw.plan(config, report, run)


@pytest.mark.parametrize('rule', [
    '-A INPUT -p tcp -m multiport --dports 22 -m set --match-set f2b-sshd src -j REJECT --reject-with icmp-port-unreachable',
    '-A INPUT -p tcp --dport 22 -j f2b-sshd',
    '-A f2b-sshd -s 192.0.2.1/32 -j REJECT',
])
def test_fail2ban_reports_specific_cause_before_any_mutation(fw, config, report, rule):
    run = Runner(fw)
    run.saved += rule + '\n'
    with pytest.raises(fw.FirewallError) as error:
        fw.plan(config, report, run)
    assert error.value.code == 'FIREWALL_FAIL2BAN_PRESENT'
    assert '--firewall manual' in str(error.value)
    assert not any(a[0] in ('ufw', 'systemd-run', 'apt-get') and a[1:2] != ['status'] for a in run.calls)


@pytest.mark.parametrize('null_effective', [False, True])
def test_manual_mode_never_reads_or_changes_existing_fail2ban(fw, config, report, tmp_path, null_effective):
    config['firewall'] = 'manual'
    if null_effective:
        config['firewall_effective'] = None
    def unchanged(*_, **__):
        pytest.fail('Manual mode must not inspect, enable or change the host firewall')
    prepared = fw.plan(config, report, unchanged)
    assert prepared['mode'] == 'manual'
    assert fw.apply(prepared, config, tmp_path, unchanged, atomic)['status'] == 'unchanged'


def test_unknown_nft_chain_policy_blocks(fw, config, report):
    run = Runner(fw)
    run.nft = '{"nftables":[{"chain":{"table":"filter","hook":"input","policy":"drop"}}]}'
    with pytest.raises(fw.FirewallError, match='nftables'):
        fw.plan(config, report, run)


def test_docker_host_forwarding_rules_do_not_block(fw, config, report):
    run = Runner(fw)
    run.saved = ('*filter\n:INPUT ACCEPT [100:500]\n:OUTPUT ACCEPT [300:500]\n:FORWARD DROP [0:0]\n'
                 ':DOCKER-USER - [0:0]\n:DOCKER-FORWARD - [0:0]\n'
                 '-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n'
                 '-A DOCKER-USER -j RETURN\n-A DOCKER-FORWARD -j ACCEPT\nCOMMIT\n')
    run.nft = '{"nftables":[{"chain":{"family":"ip","table":"filter","name":"FORWARD","hook":"forward","policy":"drop"}},{"rule":{"family":"ip","table":"filter","chain":"FORWARD","expr":[{"jump":{"target":"DOCKER-USER"}}]}}]}'
    first = fw.plan(config, report, run)
    run.saved = run.saved.replace('[100:500]', '[500:10000]') + '# Completed at differenttime\n'
    assert fw.plan(config, report, run)['fingerprint'] == first['fingerprint']


def test_docker_user_custom_drop_blocks(fw, config, report):
    run = Runner(fw)
    run.saved += '-A DOCKER-USER -j DROP\n'
    with pytest.raises(fw.FirewallError, match='Пользовательские Docker'):
        fw.plan(config, report, run)


def test_active_custom_before_rules_block_challenge(fw):
    run = Runner(fw)
    (fw.UFW_DIR / 'before.rules').write_text('hidden drop8080')
    with pytest.raises(fw.FirewallError, match='Изменённая'):
        fw.check_challenge_rules(run, 8080)


def test_backup_rules_watchdog_enable_wait_for_new_ssh_order(fw, config, report, tmp_path, monkeypatch):
    patch_collect(monkeypatch, report)
    run = Runner(fw)
    prepared = fw.plan(config, report, run)
    state = tmp_path / 'state'
    result = fw.apply(prepared, config, state, run, atomic)
    assert result['status'] == 'awaiting-confirmation'
    assert (Path(result['backup']) / 'ufw' / 'before.rules').read_bytes() == (fw.UFW_DIR / 'before.rules').read_bytes()
    assert (state / 'ufw-activation.json').exists()
    calls = run.calls
    first_rule = next(i for i, a in enumerate(calls) if a[:3] == ['ufw', 'prepend', 'allow'])
    arm = next(i for i, a in enumerate(calls) if a[0] == 'systemd-run')
    enable = calls.index(['ufw', '--force', 'enable'])
    assert first_rule < arm < enable
    assert not any(a[:2] == ['systemctl', 'stop'] for a in calls)
    assert '--on-active=180s' in calls[arm]
    assert '8080/tcp' not in run.rules
    assert not any('reset' in a or 'default' in a or 'delete' in a for a in calls)


@pytest.mark.parametrize('failure', ['enable', 'verify', 'ipv6'])
def test_enable_or_verify_failure_disables_and_retains_marker(fw, config, report, tmp_path, monkeypatch, failure):
    patch_collect(monkeypatch, report)
    run = Runner(fw)
    prepared = fw.plan(config, report, run)
    run.fail_enable = failure == 'enable'
    run.hide_permission = failure == 'verify'
    run.missing_ipv6 = failure == 'ipv6'
    with pytest.raises((fw.FirewallError, RuntimeError)):
        fw.apply(prepared, config, tmp_path / 'state', run, atomic)
    assert run.status == 'inactive'
    assert (tmp_path / 'state' / 'ufw-activation.json').exists()
    assert run.rules  # Permanent SSH/service allowances are never deleted.


def test_service_change_after_confirmation_blocks_without_mutation(fw, config, report, tmp_path, monkeypatch):
    patch_collect(monkeypatch, report)
    run = Runner(fw)
    prepared = fw.plan(config, report, run)
    run.tcp += 'LISTEN 0 128 *:2022 *:* users:(("sshd",pid=30,fd=3))\n'
    with pytest.raises(fw.FirewallError) as error:
        fw.apply(prepared, config, tmp_path / 'state', run, atomic)
    assert error.value.code == 'FIREWALL_PLAN_CHANGED'
    assert not run.rules


def test_recovery_disables_incomplete_activation_keeps_rules(fw, tmp_path):
    state = tmp_path / 'state'
    atomic(state / 'ufw-activation.json', dict(unit='transitclient-ufw-rollback-' + 'a' * 32,
                                           original='inactive', status='enabling'))
    run = Runner(fw)
    run.status = 'active'
    fw.recover_activation(state, run, atomic)
    assert run.status == 'inactive'
    assert not (state / 'ufw-activation.json').exists()
    assert not any('delete' in a for a in run.calls)


def test_missing_package_backed_up_before_install_and_replanned(fw, config, report, tmp_path, monkeypatch):
    patch_collect(monkeypatch, report)
    report['dependencies']['ufw'] = False
    run = Runner(fw)
    state = tmp_path / 'state'
    def installing(args, **kwargs):
        if args[:2] == ['apt-get', 'install']:
            record = json.loads((state / 'ufw-package-preparation.json').read_text())
            assert (Path(record['backup']) / 'default-ufw').exists()
            report['dependencies']['ufw'] = True
        return run(args, **kwargs)
    prepared = fw.plan(config, report, installing)
    assert prepared['mode'] == 'missing'
    result = fw.apply(prepared, config, state, installing, atomic)
    assert result['status'] == 'awaiting-confirmation'
    assert result['before_install_backup']


def test_interrupted_enable_leaves_watchdog_and_recovery_marker(fw, config, report, tmp_path, monkeypatch):
    patch_collect(monkeypatch, report)
    run = Runner(fw)
    def interrupted(args, **kwargs):
        if args == ['ufw', '--force', 'enable']:
            raise KeyboardInterrupt
        return run(args, **kwargs)
    prepared = fw.plan(config, report, interrupted)
    with pytest.raises(KeyboardInterrupt):
        fw.apply(prepared, config, tmp_path / 'state', interrupted, atomic)
    assert any(a[0] == 'systemd-run' for a in run.calls)
    assert not any(a[:2] == ['systemctl', 'stop'] for a in run.calls)
    journal = json.loads((tmp_path / 'state' / 'ufw-activation.json').read_text())
    assert journal['status'] == 'needs-review'
    assert (Path(journal['backup']) / 'rollback.sh').exists()


def test_builtin_flush_setting_is_refused(fw, config, report):
    fw.UFW_DEFAULT.write_text('IPV6=yes\nMANAGE_BUILTINS=yes\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
    with pytest.raises(fw.FirewallError):
        fw.plan(config, report, Runner(fw))


@pytest.mark.parametrize('active', [False, True])
def test_auto_preserves_native_inet_even_when_named_sets_are_empty(fw, config, report, active):
    config['firewall'] = 'auto'
    run = Runner(fw)
    run.status = 'active' if active else 'inactive'
    run.nft = json.dumps({'nftables': [
        {'set': {'family': 'inet', 'table': 'remna', 'name': 'whitelist', 'elem': []}},
        {'chain': {'family': 'inet', 'table': 'remna', 'name': 'input', 'hook': 'input', 'prio': -1, 'policy': 'accept'}},
        {'rule': {'family': 'inet', 'table': 'remna', 'chain': 'input', 'expr': [{'drop': None}]}}]})
    prepared = fw.plan(config, report, run)
    assert prepared['mode'] == prepared['effective'] == 'preserve'
    assert not any(a[0] in ('apt-get', 'systemd-run') or a[:2] == ['ufw', 'prepend'] for a in run.calls)


@pytest.mark.parametrize('active', [False, True])
def test_auto_fail2ban_never_aborts_install_or_overrides_bans(fw, config, report, active):
    config['firewall'] = 'auto'
    run = Runner(fw)
    run.status = 'active' if active else 'inactive'
    run.saved += '-A INPUT -m set --match-set f2b-sshd src -j REJECT\n'
    prepared = fw.plan(config, report, run)
    assert prepared['mode'] == 'preserve'
    assert prepared['reason'] == 'FIREWALL_FAIL2BAN_PRESENT'
    assert not run.rules


def test_auto_bridge_uses_preserve(fw, config, report):
    config['firewall'] = 'auto'
    report['docker']['containers'][0]['network_mode'] = 'bridge'
    assert fw.plan(config, report, Runner(fw))['mode'] == 'preserve'


@pytest.mark.parametrize('port', [80, 2222, 9443, 51820])
def test_unknown_public_listener_is_never_permanently_allowed(fw, config, report, port):
    config['firewall'] = 'auto'
    run = Runner(fw)
    run.tcp += f'LISTEN 0 128 *:{port} *:* users:(("unknown",pid=50,fd=3))\n'
    prepared = fw.plan(config, report, run)
    assert prepared['mode'] == 'preserve' and prepared['rules'] == []
    assert prepared['reason'] == 'FIREWALL_LISTENER_UNCLASSIFIED'


def test_saved_effective_policy_is_not_reselected_on_cleaner_host(fw, config, report):
    config.update(firewall='auto', firewall_effective='preserve')
    def forbidden(*_, **__):
        pytest.fail('Saved preserve mode must not reconsider firewall activation')
    assert fw.plan(config, report, forbidden)['effective'] == 'preserve'


@pytest.mark.parametrize('fresh', [False, True])
def test_only_fresh_ssh_proof_can_cancel_activation_rollback(fw, config, report, tmp_path, monkeypatch, fresh):
    patch_collect(monkeypatch, report)
    run = Runner(fw)
    state = tmp_path / 'state'
    journal = fw.apply(fw.plan(config, report, run), config, state, run, atomic)
    monkeypatch.setattr(fw, 'fresh_ssh', lambda *args: fresh)
    before = len(run.calls)
    if fresh:
        fw.confirm_activation(state, config, journal['token'], run, atomic)
        assert not (state / 'ufw-activation.json').exists()
        assert json.loads((state / 'ufw-setup.json').read_text())['status'] == 'active'
    else:
        with pytest.raises(fw.FirewallError) as error:
            fw.confirm_activation(state, config, journal['token'], run, atomic)
        assert error.value.code == 'FIREWALL_FRESH_SSH_REQUIRED'
        assert (state / 'ufw-activation.json').exists()
        assert not any(a[:2] == ['systemctl', 'stop'] for a in run.calls[before:])


@pytest.mark.parametrize('old_transport', [False, True])
def test_fresh_ssh_rejects_new_channel_on_existing_controlmaster(fw, tmp_path, monkeypatch, old_transport):
    proc = tmp_path / 'proc'
    proc.mkdir()
    for pid, parent, started in [(300, 200, 110000), (200, 100, 90000), (100, 1, 100)]:
        directory = proc / str(pid)
        directory.mkdir()
        values = ['S', str(parent)] + ['0'] * 17 + [str(started)]
        (directory / 'stat').write_text(str(pid) + ' (sshd) ' + ' '.join(values))
        (directory / 'comm').write_text('sshd\n')
    monkeypatch.setattr(fw, 'Path', lambda value: proc if value == '/proc' else Path(value))
    monkeypatch.setattr(fw.os, 'getppid', lambda: 300)
    monkeypatch.setattr(fw.os, 'sysconf', lambda _: 100, raising=False)
    monkeypatch.setenv('SSH_CONNECTION', '8.8.8.8 50000 1.1.1.1 2022')
    owners = 'pid=300' + (',pid=200' if old_transport else '')
    def run(*_, **__):
        return SimpleNamespace(returncode=0, stdout=('0 0 1.1.1.1:2022 8.8.8.8:50000 users:((' + owners + '))').encode())
    journal = dict(activated_uptime=1000, rules=[dict(port=2022, protocol='tcp')])
    assert fw.fresh_ssh(journal, run) is not old_transport


def test_activation_still_rejects_non_root_before_mutations(fw, config, report, tmp_path, monkeypatch):
    run = Runner(fw)
    prepared = fw.plan(config, report, run)
    monkeypatch.setattr(fw.os, 'geteuid', lambda: 1000)
    calls = len(run.calls)
    with pytest.raises(fw.FirewallError, match='root'):
        fw.apply(prepared, config, tmp_path / 'state', run, atomic)
    assert len(run.calls) == calls
    assert not (tmp_path / 'state').exists()
