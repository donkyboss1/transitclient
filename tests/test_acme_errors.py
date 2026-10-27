"""Classify ACME failures without disclosing output or changing issuance policy."""
from types import SimpleNamespace

import pytest

import test_selfsteal as fixtures


app = fixtures.app
config = fixtures.config


@pytest.mark.parametrize('text,expected', [
    ('urn:ietf:params:acme:error:rateLimited', 'ACME_RATE_LIMITED'),
    ('The account key has been deactivated', 'ACME_ACCOUNT_ERROR'),
    ('urn:ietf:params:acme:error:caa', 'ACME_CAA_ERROR'),
    ('DNS problem: NXDOMAIN', 'ACME_DNS_ERROR'),
    ('urn:ietf:params:acme:error:connection', 'ACME_HTTP_ERROR'),
    ('Invalid response from http://domain.example/path: 503', 'ACME_HTTP_ERROR'),
    ('Invalid status. Verification error details', 'ACME_VALIDATION_FAILED'),
    ('socat: Address already in use', 'ACME_LISTENER_ERROR'),
    ('Please install socat or python tools first.', 'ACME_TOOL_MISSING'),
    ('Error occurred when running pre hook.', 'ACME_PRE_HOOK_FAILED'),
    ('Error encountered while running post hook.', 'ACME_POST_HOOK_FAILED'),
    ('Error creating domain key.', 'ACME_KEY_ERROR'),
    ('curl: SSL certificate problem', 'ACME_API_TLS_ERROR'),
    ('acme.sh is using ZeroSSL as default CA now.', 'ACME_CA_CONFIGURATION'),
    ('Error registering account', 'ACME_REGISTRATION_FAILED'),
    ('Cannot init API for URL', 'ACME_API_ERROR'),
    ('Permission denied', 'ACME_PROCESS_ERROR'),
    ('unrecognized client error', 'ACME_CLIENT_FAILED'),
])
def test_failure_classification_never_discloses_captured_output(app, text, expected):
    result = SimpleNamespace(returncode=1, stdout=(text + '\nTOKEN=PRIVATE_VALUE').encode(),
                             stderr=b'-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY_DATA\n')
    code, message = app.acme_failure(result)
    assert code == expected
    assert 'PRIVATE_VALUE' not in message and 'PRIVATE_KEY_DATA' not in message
    assert 'BEGIN PRIVATE KEY' not in message


def test_rate_limit_is_not_hidden_by_registration_wrapper(app):
    result = fixtures.result(code=1, output=b'Error registering account: urn:ietf:params:acme:error:rateLimited')
    assert app.acme_failure(result)[0] == 'ACME_RATE_LIMITED'


def test_missing_output_has_safe_unknown_category(app):
    assert app.acme_failure(SimpleNamespace(stdout=None, stderr=None))[0] == 'ACME_CLIENT_FAILED'


def test_renew_preserves_certificate_and_returns_classified_failure(app, config, monkeypatch):
    old = app.STATE / 'certs/current'
    old.mkdir(parents=True)
    (old / 'fullchain.pem').write_text('OLD CERTIFICATE')
    (old / 'key.pem').write_text('OLD PRIVATE KEY')
    monkeypatch.setattr(app, 'check_dns', lambda _: None)
    cleanup, calls = [], []
    monkeypatch.setattr(app, 'abort_acme', lambda *_: cleanup.append('abort'))
    def run(args, **kwargs):
        calls.append(args)
        if args[0] == 'systemd-run':
            return SimpleNamespace(returncode=1, stdout=b'Error occurred when running pre hook.',
                                   stderr=b'TOKEN=PRIVATE_VALUE')
        return fixtures.result()
    monkeypatch.setattr(app, 'run', run)
    with pytest.raises(app.Failure) as error:
        app.renew(config)
    assert error.value.code == 'ACME_PRE_HOOK_FAILED'
    assert 'ACME-проверка' in str(error.value)
    assert 'PRIVATE_VALUE' not in str(error.value)
    assert 'повтор через таймер' not in str(error.value)
    assert (old / 'fullchain.pem').read_text() == 'OLD CERTIFICATE'
    assert (old / 'key.pem').read_text() == 'OLD PRIVATE KEY'
    assert not (app.STATE / 'operation.json').exists()
    assert cleanup
    assert sum(args[0] == 'systemd-run' for args in calls) == 1
