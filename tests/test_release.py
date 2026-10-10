"""Offline release checks: complete runtime, safe sources and reproducibility."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile

import pytest


@pytest.fixture
def builder(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / 'build_release.py'
    spec = importlib.util.spec_from_file_location('transitclient_release', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / 'source'
    source.mkdir()
    for name in ('selfsteal.sh', 'selfsteal.py', 'diagnostics.py', 'build_release.py',
                 'terminal_ui.py', 'client_panel.py',
                 'VERSION', 'dependencies.json', 'templates.json', 'README.md', 'LICENSE', 'NOTICE.md'):
        (source / name).write_text(name, encoding='utf-8')
    for name in ('docs/integration.md', 'docs/operations.md', 'vendor/acme.sh',
                 'site/index.html', 'tests/test_release.py', 'tests/__pycache__/cached.pyc'):
        path = source / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(name, encoding='utf-8')
    (source / '.env').write_text('never-export', encoding='utf-8')
    monkeypatch.setattr(module, '__file__', str(source / 'build_release.py'))
    return module, source


def test_release_includes_helpers_docs_and_pins_without_state(builder, tmp_path):
    module, source = builder
    destination = tmp_path / 'release.tar.gz'
    module.build(destination)
    with tarfile.open(destination) as archive:
        names = set(archive.getnames())
        assert {'selfsteal.py', 'diagnostics.py', 'docs/integration.md',
                'terminal_ui.py', 'client_panel.py',
                'docs/operations.md', 'vendor/acme.sh', 'dependencies.json'} <= names
        assert '.env' not in names
        assert not any('__pycache__' in name or name.endswith('.pyc') for name in names)
        assert archive.getmember('selfsteal.sh').mode == 0o755
        assert all(member.isfile() for member in archive.getmembers())
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    assert destination.with_name('release.tar.gz.sha256').read_text() == digest + '  release.tar.gz\n'
    other = tmp_path / 'other-name.tar.gz'
    module.build(other)
    assert other.read_bytes() == destination.read_bytes()


def test_release_refuses_output_inside_package(builder):
    module, source = builder
    with pytest.raises(ValueError, match='outside'):
        module.build(source / 'release.tar.gz')


def test_release_refuses_linked_runtime(builder, tmp_path):
    module, source = builder
    outsider = tmp_path / 'outside.py'
    outsider.write_text('foreign runtime', encoding='utf-8')
    try:
        (source / 'foreign.py').symlink_to(outsider)
    except OSError:
        pytest.skip('Host does not permit creating symlinks')
    with pytest.raises(ValueError, match='linked source'):
        module.build(tmp_path / 'release.tar.gz')
