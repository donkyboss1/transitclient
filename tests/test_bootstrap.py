"""Exercise the actual embedded verifier offline; no downloads or installation."""
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile

import pytest

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPT = (PACKAGE / 'selfsteal.sh').read_text(encoding='utf-8')


@pytest.fixture
def extractor():
    source = SCRIPT.split("<<'EXTRACT'\n", 1)[1].split('\nEXTRACT\n', 1)[0]
    namespace = {'__name__': 'bootstrap_tests'}
    exec(compile(source, str(PACKAGE / 'selfsteal.sh') + ':extractor', 'exec'), namespace)
    return namespace['safe_extract'], namespace


def release(tmp_path, additions=(), omit=(), version='1.2.3', bad_acme=False,
            controller=b'raise SystemExit(0)\n'):
    acme = b'#!/bin/sh\nexit 0\n'
    files = {'selfsteal.py': controller, 'selfsteal.sh': b'#!/bin/bash\n',
             'diagnostics.py': b'# diagnostics\n', 'site_templates.py': b'# templates\n',
             'firewall_setup.py': b'# firewall\n', 'templates.json': b'{}',
             'terminal_ui.py': b'# ui\n', 'client_panel.py': b'# panel\n',
             'docs/integration.md': b'# Integration\n',
             'VERSION': version.encode(), 'LICENSE': b'MIT', 'NOTICE.md': b'DigneZzZ',
             'site/index.html': b'<p>Hello</p>', 'vendor/acme.sh': acme,
             'dependencies.json': json.dumps({'acme': {'sha256':
                 '0' * 64 if bad_acme else hashlib.sha256(acme).hexdigest()}}).encode()}
    path = tmp_path / 'release.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        for name, content in files.items():
            if name in omit:
                continue
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o777, len(content)
            archive.addfile(entry, io.BytesIO(content))
        for entry, data in additions:
            archive.addfile(entry, io.BytesIO(data))
    return path, tmp_path / 'unpacked', version, hashlib.sha256(path.read_bytes()).hexdigest()


def test_complete_pinned_release_can_be_extracted(extractor, tmp_path):
    args = release(tmp_path)
    extractor[0](*args)
    assert (args[1] / 'NOTICE.md').read_bytes() == b'DigneZzZ'
    assert (args[1] / 'vendor/acme.sh').is_file()


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'vendor/../../escape',
                                 r'vendor\escape', 'C:/escape', './dot',
                                 'double//slash', 'line\nbreak', 'selfsteal.py'])
def test_bad_tar_paths_and_duplicates_fail_before_writes(extractor, tmp_path, name):
    entry = tarfile.TarInfo(name)
    entry.size = 1
    args = release(tmp_path, [(entry, b'x')])
    with pytest.raises(ValueError):
        extractor[0](*args)
    assert not args[1].exists()


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                                tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_archive_links_devices_and_fifo_are_rejected(extractor, tmp_path, kind):
    entry = tarfile.TarInfo('unsafe')
    entry.type, entry.linkname = kind, '../elsewhere'
    args = release(tmp_path, [(entry, b'')])
    with pytest.raises(ValueError):
        extractor[0](*args)
    assert not args[1].exists()


def test_parent_file_cannot_be_replaced_with_directory(extractor, tmp_path):
    entry = tarfile.TarInfo('selfsteal.py/payload')
    entry.size = 1
    args = release(tmp_path, [(entry, b'x')])
    with pytest.raises(ValueError, match='родительский'):
        extractor[0](*args)
    assert not args[1].exists()


def test_pinned_hash_failure_cannot_write_or_run_payload(extractor, tmp_path):
    args = release(tmp_path)
    with pytest.raises(ValueError, match='SHA256'):
        extractor[0](*args[:-1], '0' * 64)
    assert not args[1].exists()


@pytest.mark.parametrize('omit', ['vendor/acme.sh', 'site/index.html', 'LICENSE', 'NOTICE.md', 'site_templates.py', 'firewall_setup.py', 'templates.json'])
def test_incomplete_release_rejected(extractor, tmp_path, omit):
    args = release(tmp_path, omit=[omit])
    with pytest.raises(ValueError, match='неполон'):
        extractor[0](*args)
    assert not args[1].exists()


def test_wrong_release_version_rejected(extractor, tmp_path):
    args = release(tmp_path, version='2.0.0')
    args = (*args[:2], '1.2.3', args[3])
    with pytest.raises(ValueError, match='Версия'):
        extractor[0](*args)
    assert not args[1].exists()


@pytest.mark.parametrize('helper', ['terminal_ui.py', 'client_panel.py'])
def test_ui_release_requires_both_terminal_helpers(extractor, tmp_path, helper):
    args = release(tmp_path, version='1.4.0', omit=[helper])
    with pytest.raises(ValueError, match='неполон'):
        extractor[0](*args)
    assert not args[1].exists()


def test_dependency_manifest_checked_even_after_outer_hash(extractor, tmp_path):
    with pytest.raises(ValueError, match='acme.sh'):
        extractor[0](*release(tmp_path, bad_acme=True))


@pytest.mark.parametrize('limit', ['MAX_ARCHIVE', 'MAX_EXPANDED', 'MAX_MEMBERS'])
def test_archive_resource_limits(extractor, tmp_path, limit):
    extractor[1][limit] = 1
    args = release(tmp_path)
    with pytest.raises(ValueError):
        extractor[0](*args)
    assert not args[1].exists()


def test_existing_destination_untouched(extractor, tmp_path):
    args = release(tmp_path)
    args[1].mkdir()
    original = args[1] / 'original'
    original.write_text('keep')
    with pytest.raises(ValueError, match='существует'):
        extractor[0](*args)
    assert original.read_text() == 'keep'


@pytest.mark.parametrize('url', ['http://example.test/file', 'https://user:secret@example.test/file',
                                'https://@example.test/file', 'https://example.test/file#fragment',
                                'https://example.test:80/file', 'https://example.test/line\nbreak'])
def test_bootstrap_metadata_rejected_before_network(url):
    source = SCRIPT.split("<<'VALIDATE'\n", 1)[1].split('\nVALIDATE\n', 1)[0]
    result = subprocess.run([sys.executable, '-c', source, url, '1.2.3', 'a' * 64],
                            capture_output=True, timeout=5)
    assert result.returncode != 0
    assert b'secret' not in result.stderr


def test_bootstrap_metadata_accepts_explicit_release():
    source = SCRIPT.split("<<'VALIDATE'\n", 1)[1].split('\nVALIDATE\n', 1)[0]
    result = subprocess.run([sys.executable, '-c', source,
                             'https://example.test/v1.2.3/package.tar.gz', '1.2.3', 'a' * 64],
                            capture_output=True, timeout=5)
    assert result.returncode == 0


def bash_path(path):
    """Git Bash maps drive paths; POSIX CI uses unchanged absolute paths."""
    value = Path(path).resolve().as_posix()
    if os.name == 'nt':
        return '/' + value[0].lower() + value[2:]
    return value


@pytest.fixture
def bash():
    executable = (Path('C:/Program Files/Git/bin/bash.exe') if os.name == 'nt'
                  else Path(shutil.which('bash') or '/nonexistent'))
    if not executable.is_file():
        pytest.skip('Bash runtime is unavailable; extractor tests still run.')
    return str(executable)


def shell_environment(tmp_path):
    binary = tmp_path / 'bin'
    binary.mkdir()
    python = binary / 'python3'
    python.write_text('#!/usr/bin/env bash\nexec ' + shlex.quote(bash_path(sys.executable))
                      + ' "$@"\n', encoding='utf-8')
    python.chmod(0o700)
    temp = tmp_path / 'temp'
    temp.mkdir()
    environment = dict(os.environ, TMPDIR=bash_path(temp))
    return binary, environment, temp


def run_shell(bash, binary, script, environment, args=()):
    return subprocess.run([bash, '-c', 'export PATH="$1:$PATH"; shift; exec bash "$@"',
                           'transitclient-test', bash_path(binary), bash_path(script), *args],
                          env=environment, input=b'', capture_output=True, timeout=15)


def test_actual_bash_launches_local_controller_without_downloading(bash, tmp_path):
    binary, environment, temp = shell_environment(tmp_path)
    script = tmp_path / 'selfsteal.sh'
    script.write_text(SCRIPT, encoding='utf-8')
    log = tmp_path / 'controller.json'
    (tmp_path / 'selfsteal.py').write_text(
        'import json, sys\nfrom pathlib import Path\n'
        f'Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n', encoding='utf-8')
    (tmp_path / 'dependencies.json').write_text('{}')
    result = run_shell(bash, binary, script, environment, ['diagnose', '--vpn-port', '8443'])
    assert result.returncode == 0, result.stderr
    assert json.loads(log.read_text()) == ['diagnose', '--vpn-port', '8443']
    assert not list(temp.iterdir())


@pytest.mark.parametrize('good_hash', [True, False])
def test_actual_bash_downloads_verifies_launches_and_cleans(bash, tmp_path, good_hash):
    binary, environment, temp = shell_environment(tmp_path)
    script = tmp_path / 'selfsteal.sh'
    script.write_text(SCRIPT, encoding='utf-8')
    log = tmp_path / 'controller.json'
    payload = ('import json, sys\nfrom pathlib import Path\n'
               f'Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n').encode()
    package, _, version, digest = release(tmp_path, controller=payload)
    curl_log = tmp_path / 'curl.args'
    mock = binary / 'curl'
    mock.write_text('#!/usr/bin/env bash\nprintf \'%s\\n\' "$@" > '
                    + shlex.quote(bash_path(curl_log)) + '\n'
                    + 'while (($#)); do if [[ "$1" == --output ]]; then shift; destination=$1; fi; shift; done\n'
                    + 'cp -- ' + shlex.quote(bash_path(package)) + ' "$destination"\n', encoding='utf-8')
    mock.chmod(0o700)
    result = run_shell(bash, binary, script, environment,
                       ['--package-url', 'https://example.test/release.tar.gz', '--version', version,
                        '--sha256', digest if good_hash else '0' * 64, '--', 'status'])
    assert (result.returncode == 0) == good_hash, result.stderr
    if good_hash:
        assert json.loads(log.read_text()) == ['status']
    else:
        assert not log.exists()
    args = curl_log.read_text().splitlines()
    assert args[args.index('--proto') + 1] == '=https'
    assert args[args.index('--proto-redir') + 1] == '=https'
    assert not list(temp.iterdir())


def test_actual_bash_stdin_without_public_metadata_stops_cleanly(bash, tmp_path):
    binary, environment, temp = shell_environment(tmp_path)
    result = subprocess.run([bash, '-c', 'export PATH="$1:$PATH"; exec bash -s',
                             'transitclient-test', bash_path(binary)], env=environment,
                            input=SCRIPT.encode(), capture_output=True, timeout=15)
    assert result.returncode == 1
    assert b'--package-url' in result.stderr
    assert b'unbound variable' not in result.stderr
    assert not list(temp.iterdir())


@pytest.mark.parametrize('command', ['install', 'menu', 'configure', 'template', 'update', 'uninstall'])
def test_sudo_pipe_interactive_command_fails_before_prompt_or_download(bash, tmp_path, command):
    binary, environment, temp = shell_environment(tmp_path)
    environment['SUDO_COMMAND'] = '/usr/bin/bash -s -- ' + command
    result = subprocess.run([bash, '-c', 'export PATH="$1:$PATH"; exec bash -s -- "$2"',
                             'transitclient-test', bash_path(binary), command],
                            env=environment, input=SCRIPT.encode(), capture_output=True, timeout=5)
    assert result.returncode == 1
    assert 'pipe + sudo'.encode() in result.stderr
    assert not list(temp.iterdir())
