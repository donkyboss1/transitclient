"""Verify public bootstrap pins and source export without network or installation."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


@pytest.fixture
def publication_module(monkeypatch, tmp_path):
    package = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(package))
    spec = importlib.util.spec_from_file_location('transitclient_publication', package / 'build_publication.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / 'source'
    shutil.copytree(package, source, ignore=shutil.ignore_patterns('.git', '.cache', '.tools', '__pycache__',
                                                                 '.test-tmp*', '.ruff_cache', 'dist'))
    monkeypatch.setattr(module, '__file__', str(source / 'build_publication.py'))
    return module


def test_publication_bootstrap_pins_complete_export(publication_module, tmp_path):
    destination = tmp_path / 'public'
    destination.mkdir()
    (destination / 'LICENSE').write_text('initial owner license')
    bundle, digest = publication_module.prepare(destination)
    script = (destination / 'install.sh').read_text(encoding='utf-8')
    assert digest == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert f"RELEASE_SHA256='{digest}'" in script
    assert f"RELEASE_URL='https://raw.githubusercontent.com/donkyboss1/transitclient/main/dist/{bundle.name}'" in script
    assert 'bootstrap=true' in script
    assert 'Публичный адрес пока не назначен' not in script
    assert not any((destination / name).exists() for name in ('.env', 'AGENTS.MD', 'backend', '.git'))
    assert {'install.sh', 'selfsteal.py', 'diagnostics.py', 'README.md'} <= {path.name for path in destination.iterdir()}
    assert 'Copyright (c) 2026 donkyboss1' in (destination / 'LICENSE').read_text()
    assert 'Copyright (c) 2025-2026 DigneZzZ' in (destination / 'LICENSE').read_text()
    # Exercise the real extractor against the publication, not a synthetic tar.
    source = script.split("<<'EXTRACT'\n", 1)[1].split('\nEXTRACT\n', 1)[0]
    namespace = {'__name__': 'publication_test'}
    exec(compile(source, 'install.sh:extractor', 'exec'), namespace)
    version = (destination / 'VERSION').read_text().strip()
    namespace['safe_extract'](bundle, tmp_path / 'verified', version, digest)
    assert (tmp_path / 'verified/diagnostics.py').is_file()
    assert (destination / '.gitattributes').read_text() == '* text=auto eol=lf\n*.tar.gz -text\n'


def test_publication_refuses_source_destination(publication_module):
    root = Path(publication_module.__file__).resolve().parent
    for destination in (root / 'public', root.parent):
        with pytest.raises(ValueError, match='separate'):
            publication_module.prepare(destination)


def test_publication_refreshes_this_repo_without_touching_git(publication_module):
    root = Path(publication_module.__file__).resolve().parent
    (root / '.git').mkdir()
    (root / '.git/config').write_text('preserve owner remote')
    before = (root / 'selfsteal.py').read_bytes()
    bundle, digest = publication_module.prepare(root)
    assert bundle.parent == root / 'dist'
    assert (root / '.git/config').read_text() == 'preserve owner remote'
    assert (root / 'selfsteal.py').read_bytes() == before
    assert digest in (root / 'install.sh').read_text(encoding='utf-8')


def test_publication_pipe_uses_embedded_metadata(publication_module, tmp_path):
    executable = (Path('C:/Program Files/Git/bin/bash.exe') if os.name == 'nt'
                  else Path(shutil.which('bash') or '/nonexistent'))
    if not executable.is_file():
        pytest.skip('Bash runtime is unavailable')
    destination = tmp_path / 'public'
    bundle, _ = publication_module.prepare(destination)
    binary, temporary = tmp_path / 'bin', tmp_path / 'temporary'
    binary.mkdir()
    temporary.mkdir()

    def shell_path(path):
        value = Path(path).resolve().as_posix()
        return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

    import sys
    python = binary / 'python3'
    python.write_text('#!/usr/bin/env bash\nexec ' + shlex.quote(shell_path(sys.executable)) + ' "$@"\n')
    python.chmod(0o700)
    curl = binary / 'curl'
    curl.write_text('#!/usr/bin/env bash\n'
                    'while (($#)); do if [[ "$1" == --output ]]; then shift; target=$1; fi; shift; done\n'
                    'cp -- ' + shlex.quote(shell_path(bundle)) + ' "$target"\n')
    curl.chmod(0o700)
    script = (destination / 'install.sh').read_bytes()
    result = subprocess.run([str(executable), '-c',
                             'export PATH="$1:$PATH"; exec bash -s -- version',
                             'public-bootstrap-test', shell_path(binary)], input=script,
                            env=dict(os.environ, TMPDIR=shell_path(temporary)),
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    version = (destination / 'VERSION').read_text().strip().encode()
    assert b'transitclient ' + version in result.stdout
    assert not list(temporary.iterdir())
