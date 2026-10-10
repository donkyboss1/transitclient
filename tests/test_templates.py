"""Offline real-file tests of catalog integrity, site switching and recovery."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

import pytest


@pytest.fixture
def themes(tmp_path):
    package = tmp_path / 'package'
    package.mkdir()
    (package / 'site').mkdir()
    (package / 'site/index.html').write_bytes(b'fallback')
    payloads = {'index.html': b'new index', 'assets/app.js': b'static script'}
    data = {'source': {'repository': 'DigneZzZ/remnawave-scripts', 'commit': 'a' * 40},
            'templates': [{'id': str(i), 'folder': 'theme-' + str(i), 'name': 'Theme ' + str(i),
                           'files': [{'path': path, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
                                     for path, content in payloads.items()]} for i in range(1, 12)]}
    (package / 'templates.json').write_text(json.dumps(data))
    path = Path(__file__).resolve().parents[1] / 'site_templates.py'
    spec = importlib.util.spec_from_file_location('site_templates_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = tmp_path / 'state'
    state.mkdir()

    def fetch(url, digest, target):
        assert '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sni-templates/theme-1/' in url
        target.write_bytes(payloads[url.split('/theme-1/')[1]])

    def atomic(path, value):
        candidate = path.with_suffix('.tmp')
        candidate.write_text(json.dumps(value))
        os.replace(candidate, path)

    return module, state, package, fetch, atomic


def test_real_catalog_has_eleven_complete_pinned_sites():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('real_catalog_test', root / 'site_templates.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = module.catalog(root)
    assert len(data['templates']) == 11
    assert data['source']['commit'] == '24134e23a438217cd52373ecdb0fcf7983e0e72c'


@pytest.mark.parametrize('path', ['../escape', '/absolute', 'a//b', r'a\b', 'C:/escape', '.env', 'a/../b', 'a\nb'])
def test_download_catalog_rejects_unsafe_paths_without_fetch(themes, path):
    module, state, package, _, atomic = themes
    data = json.loads((package / 'templates.json').read_text())
    data['templates'][0]['files'][1]['path'] = path
    (package / 'templates.json').write_text(json.dumps(data))
    module.ensure_site(state, package)
    with pytest.raises(module.TemplateError):
        module.apply(state, package, '1', lambda *_: pytest.fail('unsafe fetch'), atomic, lambda _: None)
    assert (state / 'site/current/index.html').read_bytes() == b'fallback'


def test_failed_download_keeps_live_site_and_cleans_partial_files(themes):
    module, state, package, _, atomic = themes
    def corrupt(url, digest, target):
        target.write_bytes(b'corrupt')
    with pytest.raises(module.TemplateError):
        module.apply(state, package, '1', corrupt, atomic, lambda _: pytest.fail('must not verify bad files'))
    assert (state / 'site/current/index.html').read_bytes() == b'fallback'
    assert not list((state / 'site/staged').iterdir())
    assert not (state / 'site-transaction.json').exists()


def test_change_preserves_backup_and_explicit_rollback_does_not_download(themes):
    module, state, package, fetch, atomic = themes
    verified = []
    metadata = module.apply(state, package, '1', fetch, atomic, lambda path: verified.append(path.read_bytes()))
    assert verified == [b'new index']
    assert (state / 'site/current/assets/app.js').is_file()
    saved = json.loads((state / 'site-template.json').read_text())
    assert saved['id'] == metadata['id'] == '1'
    assert (state / 'site/backups' / saved['previous'] / 'index.html').read_bytes() == b'fallback'
    module.apply(state, package, 'rollback', lambda *_: pytest.fail('rollback must be local'), atomic, lambda _: None)
    assert (state / 'site/current/index.html').read_bytes() == b'fallback'
    assert not (state / 'site/current/assets/app.js').exists()


def test_http_verification_failure_restores_site_and_metadata(themes):
    module, state, package, fetch, atomic = themes
    module.ensure_site(state, package)
    atomic(state / 'site-template.json', {'id': 'custom', 'name': 'Preserved custom site'})
    def reject(_):
        raise RuntimeError('HTTP served different bytes')
    with pytest.raises(RuntimeError, match='different bytes'):
        module.apply(state, package, '1', fetch, atomic, reject)
    assert (state / 'site/current/index.html').read_bytes() == b'fallback'
    assert json.loads((state / 'site-template.json').read_text())['id'] == 'custom'
    assert not (state / 'site-transaction.json').exists()


@pytest.mark.parametrize('new_site_visible', [False, True])
def test_boot_recovery_after_interrupted_directory_swap(themes, new_site_visible):
    module, state, package, _, atomic = themes
    module.ensure_site(state, package)
    site = state / 'site'
    backup, staged = site / 'backups' / ('a' * 32), site / 'staged' / ('b' * 32)
    backup.parent.mkdir()
    staged.mkdir(parents=True)
    (staged / 'index.html').write_bytes(b'interrupted site')
    atomic(state / 'site-transaction.json', {'id': 'a' * 32, 'staged': 'b' * 32,
                                           'old_metadata': {'id': 'previous'}})
    os.replace(site / 'current', backup)
    if new_site_visible:
        os.replace(staged, site / 'current')
    module.recover(state)
    module.recover(state)
    assert (site / 'current/index.html').read_bytes() == b'fallback'
    assert json.loads((state / 'site-template.json').read_text()) == {'id': 'previous'}
    assert not staged.exists() and not (state / 'site-transaction.json').exists()


def test_legacy_custom_site_is_preserved_when_changing_root(themes):
    module, state, package, _, _ = themes
    (state / 'site').mkdir()
    (state / 'site/index.html').write_bytes(b'custom site')
    (state / 'site/asset.txt').write_bytes(b'custom asset')
    module.ensure_site(state, package)
    assert (state / 'site/current/index.html').read_bytes() == b'custom site'
    assert (state / 'site/current/asset.txt').read_bytes() == b'custom asset'


def test_symlink_cannot_redirect_site_changes_outside_state(themes, tmp_path):
    module, state, package, fetch, atomic = themes
    module.ensure_site(state, package)
    current = state / 'site/current'
    shutil.rmtree(current)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'index.html').write_bytes(b'foreign site')
    try:
        current.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Host does not permit symlinks')
    with pytest.raises(module.TemplateError):
        module.apply(state, package, '1', fetch, atomic, lambda _: None)
    assert (outside / 'index.html').read_bytes() == b'foreign site'
