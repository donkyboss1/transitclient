"""Delayed HTTP listener startup through a relay, without host or CA operations."""
from types import SimpleNamespace

import pytest

import test_selfsteal as fixtures


app = fixtures.app
config = fixtures.config


@pytest.fixture
def probe(app, config, monkeypatch):
    responses, requests, sleeps, events = [], [], [], []
    monkeypatch.setattr(app, 'check_dns', lambda _: ['8.8.8.8'])
    monkeypatch.setattr(app, 'check_challenge_port', lambda _: None)
    monkeypatch.setattr(app, 'assert_transient_available', lambda _: None)
    monkeypatch.setattr(app, 'open_firewall', lambda _: None)
    monkeypatch.setattr(app, 'run', lambda *_, **__: fixtures.result())
    monkeypatch.setattr(app.time, 'sleep', sleeps.append)
    monkeypatch.setattr(app, 'stop_probe', lambda: events.append('stopped'))
    monkeypatch.setattr(app, 'abort_acme', lambda *_: None)
    monkeypatch.setattr(app, 'stop_scoped_transient', lambda *_: None)
    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ('8.8.8.8', 80)
            assert 0 < timeout <= 5

        def request(self, method, path, headers):
            assert method == 'GET' and headers['Host'] == config['domain']
            self.token = path.rsplit('/', 1)[-1]
            requests.append(path)

        def getresponse(self):
            outcome = responses.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            if outcome == 'wrong_body':
                return SimpleNamespace(status=200, read=lambda _: b'PRIVATE UNEXPECTED BACKEND BODY')
            return SimpleNamespace(status=outcome, read=lambda _: ('transitclient-check:' + self.token).encode())

        def close(self):
            events.append('closed')
    monkeypatch.setattr(app.http.client, 'HTTPConnection', Connection)
    return SimpleNamespace(responses=responses, requests=requests, sleeps=sleeps, events=events)


@pytest.mark.parametrize('status', [502, 503, 504])
def test_gateway_error_before_listener_ready_is_retried(app, config, probe, status):
    probe.responses.extend([status, 200])
    app.http_self_test(config, approved=True)
    assert len(probe.requests) == 2
    assert len(probe.sleeps) == 1 and 0 < probe.sleeps[0] <= 1
    assert app.read_json(app.STATE / 'http-path.json')['addresses'] == [
        dict(address='8.8.8.8', confirmed=True)]
    assert probe.events == ['closed', 'closed', 'stopped']
    assert not (app.STATE / 'operation.json').exists()


def test_listener_can_start_on_last_attempt(app, config, probe):
    probe.responses.extend([503] * 4 + [200])
    app.http_self_test(config, approved=True)
    assert len(probe.requests) == 5 and len(probe.sleeps) == 4


def test_persistent_gateway_error_reports_status_and_keeps_ca_blocked(app, config, probe, capsys):
    probe.responses.extend([503] * 5)
    with pytest.raises(app.Failure) as error:
        app.http_self_test(config, approved=True)
    assert error.value.code == 'HTTP_PATH_UNCONFIRMED'
    assert len(probe.requests) == 5 and len(probe.sleeps) == 4
    output = capsys.readouterr().out
    assert '8.8.8.8:80' in output and 'HTTP 503' in output
    assert not (app.STATE / 'http-path.json').exists()
    assert probe.events[-1] == 'stopped'
    assert not (app.STATE / 'operation.json').exists()


def test_wrong_body_does_not_retry_or_disclose_body(app, config, probe, capsys):
    probe.responses.append('wrong_body')
    with pytest.raises(app.Failure):
        app.http_self_test(config, approved=True)
    output = capsys.readouterr().out
    assert 'неверный контрольный ответ' in output
    assert 'PRIVATE' not in output
    assert len(probe.requests) == 1 and probe.sleeps == []


@pytest.mark.parametrize('failure,reason', [(TimeoutError(), 'таймаут'),
                                           (ConnectionRefusedError(), 'отказ в соединении')])
def test_network_failures_have_safe_diagnostics(app, config, probe, capsys, failure, reason):
    probe.responses.extend([failure] * 5)
    with pytest.raises(app.Failure):
        app.http_self_test(config, approved=True)
    assert reason in capsys.readouterr().out
    assert len(probe.requests) == 5 and len(probe.sleeps) == 4


def test_gateway_retries_respect_total_time_budget(app, config, probe, monkeypatch):
    clock = SimpleNamespace(now=0)
    monkeypatch.setattr(app.time, 'monotonic', lambda: clock.now)
    original = app.http.client.HTTPConnection
    class SlowConnection(original):
        def getresponse(self):
            clock.now = 120
            return super().getresponse()
    monkeypatch.setattr(app.http.client, 'HTTPConnection', SlowConnection)
    probe.responses.append(503)
    with pytest.raises(app.Failure):
        app.http_self_test(config, approved=True)
    assert len(probe.requests) == 1 and probe.sleeps == []
