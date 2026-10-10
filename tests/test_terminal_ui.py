"""Acceptance tests for navigation and terminal rendering; no host mutations."""
import argparse
import importlib.util
import io
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def app(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('ui_app_test', ROOT / 'selfsteal.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(module, 'CONFIG', tmp_path / 'config.json')
    return module


@pytest.fixture
def ui(monkeypatch):
    import terminal_ui
    import client_panel
    monkeypatch.setattr(client_panel, 'snapshot', lambda _: {
        'rows': [('Сервер', 'node · Ubuntu 26.04'), ('Caddy', '✅ Работает'),
                 ('Домен', 'example.com'), ('Порты', 'VPN 443 · HTTP 8080 · HTTPS 127.0.0.1:9443'),
                 ('SSL', '✅ Действителен · 25 дней · issuer'), ('HTTPS', 'Не подтверждён'),
                 ('Продление', '✅ Таймер включён'), ('Сайт', 'Встроенная страница')],
        'hint': 'HTTPS не подтверждён → Самопроверка (9).',
        'config': {'domain': 'example.com', 'challenge_port': 8080, 'vpn_port': 443,
                   'local_port': 9443}})
    monkeypatch.setattr(sys, 'stdin', type('TTY', (), {'isatty': lambda _: True})())
    return terminal_ui


def args():
    return argparse.Namespace(command='menu', no_color=True, json=False, http01=False,
                              vpn=False, template=None)


def inputs(monkeypatch, values):
    answers = iter(values)
    def read(_):
        value = next(answers)
        if isinstance(value, BaseException):
            raise value
        return value
    monkeypatch.setattr('builtins.input', read)


@pytest.mark.parametrize('submenu', ['2', '9', '10'])
def test_view_and_back_never_perform(app, ui, monkeypatch, submenu):
    monkeypatch.setattr(app, 'perform', lambda _: pytest.fail('Browsing cannot perform'))
    inputs(monkeypatch, [submenu, '0', '0'])
    assert ui.run(app, args()) == 0


def test_nested_settings_and_cancel_return_one_level(app, ui, monkeypatch, capsys):
    monkeypatch.setattr(app, 'perform', lambda _: pytest.fail('Browsing cannot perform'))
    inputs(monkeypatch, ['2', '4', KeyboardInterrupt(), '0', '0'])
    assert ui.run(app, args()) == 0
    assert 'Действие отменено' in capsys.readouterr().out


def test_invalid_and_empty_remain_on_screen(app, ui, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(app, 'perform', lambda selected: calls.append(selected.command) or 0)
    inputs(monkeypatch, ['', 'bad', '9', '', 'bad', '0', '0'])
    ui.run(app, args())
    assert calls == []
    assert capsys.readouterr().out.count('Неизвестный пункт') == 4


@pytest.mark.parametrize('sequence', [
    [EOFError()], ['2', EOFError()], ['9', '1', EOFError()],
    ['3', EOFError()], ['10', EOFError()]])
def test_eof_exits_once(app, ui, monkeypatch, sequence):
    monkeypatch.setattr(app, 'perform', lambda _: 0)
    inputs(monkeypatch, sequence)
    assert ui.run(app, args()) == 0


def test_action_result_waits_for_enter(app, ui, monkeypatch):
    events = []
    monkeypatch.setattr(app, 'perform', lambda selected: events.append(selected.command) or 1)
    answers = iter(['3', '', '0'])
    def read(prompt):
        events.append(prompt)
        return next(answers)
    monkeypatch.setattr('builtins.input', read)
    ui.run(app, args())
    assert events == ['Выберите действие: ', 'status',
                      'Нажмите Enter для возврата…', 'Выберите действие: ']


def test_operation_interrupt_finishes_cleanup_then_returns_parent(app, ui, monkeypatch, capsys):
    events = []
    def operation(_):
        try:
            raise KeyboardInterrupt
        finally:
            events.append('cleanup')
    monkeypatch.setattr(app, 'perform', operation)
    inputs(monkeypatch, ['2', '1', '0'])
    ui.run(app, args())
    assert events == ['cleanup']
    assert 'Действие отменено' in capsys.readouterr().out


def test_site_aliases_do_not_change_cli_mapping(app, ui, monkeypatch):
    choices = []
    monkeypatch.setattr(app, 'perform', lambda selected: choices.append(selected.template) or 0)
    inputs(monkeypatch, ['10', 'i', '', 'r', '', 'b', '', '11', '', '0', '0'])
    ui.run(app, args())
    assert choices == ['builtin', 'random', 'rollback', '11']
    assert app.select_template('0') == 'builtin'


def test_selftest_flags_are_isolated(app, ui, monkeypatch):
    choices = []
    monkeypatch.setattr(app, 'perform', lambda selected:
                        choices.append((selected.command, selected.http01, selected.vpn)) or 0)
    inputs(monkeypatch, ['9', '2', '', '3', '', '1', '', '0', '3', '', '0'])
    ui.run(app, args())
    assert choices == [('self-test', True, False), ('self-test', False, True),
                       ('self-test', False, False), ('status', False, False)]


def test_many_transitions_use_constant_call_depth(app, ui, monkeypatch):
    depths = []
    def read(_):
        frame, depth = sys._getframe(), 0
        while frame:
            frame, depth = frame.f_back, depth + 1
        depths.append(depth)
        return next(answers)
    answers = iter(['2', '0', '9', '0', '10', '0'] * 50 + ['0'])
    monkeypatch.setattr('builtins.input', read)
    monkeypatch.setattr(app, 'perform', lambda _: pytest.fail('Browsing must not mutate'))
    assert ui.run(app, args()) == 0
    assert max(depths) == min(depths)


def test_interrupt_while_loading_submenu_returns_to_parent(app, ui, monkeypatch, capsys):
    import client_panel
    original = client_panel.snapshot
    calls = [0]
    def panel(module):
        calls[0] += 1
        if calls[0] == 2:
            raise KeyboardInterrupt
        return original(module)
    monkeypatch.setattr(client_panel, 'snapshot', panel)
    inputs(monkeypatch, ['2', '0'])
    assert ui.run(app, args()) == 0
    assert calls[0] == 3
    assert 'Действие отменено' in capsys.readouterr().out


class Output(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize('environment,no_color,colors,clear', [
    ({'TERM': 'xterm-256color'}, False, True, True),
    ({'TERM': 'xterm', 'NO_COLOR': '1'}, False, False, True),
    ({'TERM': 'xterm'}, True, False, True),
    ({'TERM': 'dumb'}, False, False, False)])
def test_terminal_capabilities(ui, monkeypatch, environment, no_color, colors, clear):
    monkeypatch.delenv('NO_COLOR', raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    terminal = ui.Terminal(no_color=no_color)
    terminal.clear()
    terminal.line('Название', 'heading')
    text = output.getvalue()
    assert ('\x1b[2J\x1b[H' in text) == clear
    assert ('\x1b[36m' in text) == colors
    assert '\x1b[3J' not in text


def test_redirected_output_contains_no_ansi(ui, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', output)
    terminal = ui.Terminal()
    terminal.clear()
    terminal.line('Название', 'heading')
    assert output.getvalue() == 'Название\n'


@pytest.mark.parametrize('screen', ['main', 'sites'])
@pytest.mark.parametrize('notice', ['', 'Неизвестный пункт. Выберите действие из списка.'])
@pytest.mark.parametrize('width,height', [(80, 40), (48, 20)])
def test_menu_fits_and_all_actions_remain(ui, app, monkeypatch, width, height, screen, notice):
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setattr(ui.shutil, 'get_terminal_size', lambda *_: (width, height))
    terminal = ui.Terminal(no_color=True)
    ui.draw(terminal, app, screen, notice)
    text = output.getvalue().replace('\x1b[2J\x1b[H', '')
    assert len(text.splitlines()) + 1 <= height
    assert all(ui.display_width(line) <= width for line in text.splitlines())
    for number in range(12 if screen == 'sites' else 11):
        assert str(number) + ')' in text


def test_unicode_width_and_hostile_metadata(ui):
    assert ui.display_width('⚙️') == 2
    assert ui.display_width('🚀') == 2
    assert ui.display_width('е\u0301') == 1
    assert '\x1b' not in ui.clean('\x1b[31mHOST\n\u202eSECRET')
    assert '\n' not in ui.clean('a\nb')


@pytest.mark.parametrize('error', [KeyboardInterrupt(), EOFError()])
def test_confirmation_preserves_interrupt_signal(app, monkeypatch, error):
    inputs(monkeypatch, [error])
    with pytest.raises(type(error)):
        app.confirm('Подтвердить?')
