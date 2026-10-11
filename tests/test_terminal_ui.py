"""Acceptance tests for navigation and terminal rendering; no host mutations."""
import argparse
import importlib.util
import io
from pathlib import Path
import re
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
        'rows': [('Сервер', 'Caddy · ✅ Работает'),
                 ('Домен', 'example.com'), ('Порты', 'VPN 443 · HTTP 8080 · HTTPS 127.0.0.1:9443'),
                 ('SSL', '✅ Действителен · 25 дней · issuer'), ('HTTPS', 'Не подтверждён'),
                 ('Продление', '✅ Включено'), ('Заглушка', 'Встроенная страница')],
        'hint': 'HTTPS не подтверждён → Самопроверка (5).',
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


@pytest.mark.parametrize('submenu', ['2', '5', '6'])
def test_view_and_back_never_perform(app, ui, monkeypatch, submenu):
    monkeypatch.setattr(app, 'perform', lambda _: pytest.fail('Browsing cannot perform'))
    inputs(monkeypatch, [submenu, '0', '0'])
    assert ui.run(app, args()) == 0


def test_docker_settings_cancel_returns_to_main(app, ui, monkeypatch, capsys):
    calls = []
    def cancel(selected):
        calls.append((selected.command, selected._configure_choice))
        raise KeyboardInterrupt
    monkeypatch.setattr(app, 'perform', cancel)
    inputs(monkeypatch, ['2', '4', '0'])
    assert ui.run(app, args()) == 0
    assert calls == [('configure', '4')]
    assert 'Действие отменено' in capsys.readouterr().out


def test_invalid_and_empty_remain_on_screen(app, ui, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(app, 'perform', lambda selected: calls.append(selected.command) or 0)
    inputs(monkeypatch, ['', 'bad', '5', '', 'bad', '0', '0'])
    ui.run(app, args())
    assert calls == []
    assert capsys.readouterr().out.count('Неизвестный пункт') == 4


@pytest.mark.parametrize('sequence', [
    [EOFError()], ['2', EOFError()], ['5', '1', EOFError()],
    ['3', EOFError()], ['6', EOFError()]])
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
    inputs(monkeypatch, ['6', 'i', '', 'r', '', 'b', '', '11', '', '0', '0'])
    ui.run(app, args())
    assert choices == ['builtin', 'random', 'rollback', '11']
    assert app.select_template('0') == 'builtin'


def test_selftest_flags_are_isolated(app, ui, monkeypatch):
    choices = []
    monkeypatch.setattr(app, 'perform', lambda selected:
                        choices.append((selected.command, selected.http01, selected.vpn)) or 0)
    inputs(monkeypatch, ['5', '2', '', '3', '', '1', '', '0', '3', '', '0'])
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
    answers = iter(['2', '0', '5', '0', '6', '0'] * 50 + ['0'])
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
    assert ('\x1b[1;36m' in text) == colors
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


@pytest.mark.parametrize('choice,command', [('1', 'install'), ('3', 'status'), ('4', 'diagnose'),
                                          ('7', 'guide'), ('8', 'renew'), ('9', 'update'), ('10', 'uninstall')])
def test_main_number_dispatch_matches_visual_order(app, ui, monkeypatch, choice, command):
    called = []
    monkeypatch.setattr(app, 'perform', lambda selected: called.append(selected.command) or 0)
    inputs(monkeypatch, [choice, '', '0'])
    ui.run(app, args())
    assert called == [command]


@pytest.mark.parametrize('size', [(80, 40), (48, 20)])
def test_main_menu_numbers_are_sequential_in_row_major_order(app, ui, monkeypatch, size):
    import re
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setattr(ui.shutil, 'get_terminal_size', lambda *_: size)
    ui.draw(ui.Terminal(no_color=True), app, 'main')
    text = output.getvalue()
    option_lines = [line for line in text.splitlines() if re.search(r'\b\d+\)', line)]
    option_lines = [line for line in option_lines if re.match(r'^\s*\d+\)', line)]
    assert re.findall(r'\b(\d+)\)', '\n'.join(option_lines)) == [str(number) for number in range(1, 11)] + ['0']
    assert all(line[:4].endswith(')') for line in option_lines)


def test_summary_fragment_styles_keep_values_neutral_and_domain_bold_cyan(app, ui, monkeypatch):
    import re
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setenv('TERM', 'xterm-256color')
    monkeypatch.delenv('NO_COLOR', raising=False)
    ui.draw(ui.Terminal(), app, 'main')
    text = output.getvalue()
    for label in ('Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка'):
        assert '\x1b[1m' + label + ':\x1b[0m' in text
    assert '\x1b[1;36mexample.com\x1b[0m' in text
    assert '\x1b[32m' not in text and '\x1b[33m' not in text and '\x1b[31m' not in text
    assert 'node · Ubuntu' not in text
    for heading, _ in ui.GROUPS:
        assert '\x1b[1m' + ui.clean(heading) + '\x1b[0m' in text
    assert re.search(r'\x1b\[1m\s*10\x1b\[0m\)', text)


@pytest.mark.parametrize('value,expected', [('⚙️Настройки', '⚙️ Настройки'), ('🗑️Удаление', '🗑️ Удаление'),
                                           ('☁️Облако', '☁️ Облако'), ('Текст✅Готово', 'Текст ✅ Готово'),
                                           ('⚙️  Настройки', '⚙️ Настройки'), ('☁️   Облако', '☁️ Облако')])
def test_emoji_always_has_text_separator(ui, value, expected):
    assert ui.clean(value) == expected
    assert ui.clean(ui.clean(value)) == expected


def test_fragment_clipping_preserves_bold_and_cyan_without_overflow(ui, monkeypatch):
    import re
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setenv('TERM', 'xterm')
    monkeypatch.delenv('NO_COLOR', raising=False)
    terminal = ui.Terminal()
    terminal.width = 20
    terminal.fragments([('Домен:', 'bold'), (' ', None), ('very-long-domain.example.com', 'domain')])
    text = output.getvalue().rstrip('\n')
    assert text.startswith('\x1b[1mДомен:\x1b[0m ')
    assert '\x1b[1;36m' in text and text.endswith('…\x1b[0m')
    assert ui.display_width(re.sub(r'\x1b\[[0-9;]*m', '', text)) == 20


SUMMARY_LABELS = ('Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка')


def summary_lines(text):
    plain = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', text)
    return [line for line in plain.splitlines() if any(line.startswith(label + ':') for label in SUMMARY_LABELS)]


@pytest.mark.parametrize('size', [(80, 40), (48, 20)])
def test_same_summary_is_kept_on_every_submenu(app, ui, monkeypatch, size):
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setattr(ui.shutil, 'get_terminal_size', lambda *_: size)
    terminal = ui.Terminal(no_color=True)
    ui.draw(terminal, app, 'main')
    expected = summary_lines(output.getvalue())
    assert [line.split(':', 1)[0] for line in expected] == list(SUMMARY_LABELS)
    for screen in ('settings', 'tests', 'sites'):
        output.seek(0)
        output.truncate()
        ui.draw(terminal, app, screen)
        assert summary_lines(output.getvalue()) == expected, screen


@pytest.mark.parametrize('size', [(80, 40), (48, 20)])
@pytest.mark.parametrize('path', [('1',), ('3',), ('4',), ('7',), ('8',), ('9',), ('10',),
                                ('2', '1'), ('2', '4'), ('5', '1'), ('5', '2'), ('5', '3'), ('6', 'i')])
def test_operation_keeps_shared_header_before_action(app, ui, monkeypatch, size, path):
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setenv('TERM', 'xterm')
    monkeypatch.setattr(ui.shutil, 'get_terminal_size', lambda *_: size)
    seen = []
    def operation(_):
        visible = output.getvalue().rsplit('\x1b[2J\x1b[H', 1)[-1]
        seen.append(visible)
    monkeypatch.setattr(app, 'perform', operation)
    # EOF after the action also proves it cannot redraw before acknowledging the result.
    inputs(monkeypatch, list(path) + [EOFError()])
    assert ui.run(app, args()) == 0
    assert len(seen) == 1
    visible = seen[0]
    assert 'Transit Client · ' + (app.PACKAGE / 'VERSION').read_text().strip() in visible
    assert [line.split(':', 1)[0] for line in summary_lines(visible)] == list(SUMMARY_LABELS)
    assert not re.search(r'\b(?:1|2|3|10)\)', visible), 'Action header must not include the menu list'


def test_settings_explains_port_purpose_and_exposes_docker_directly(app, ui, monkeypatch):
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    ui.draw(ui.Terminal(no_color=True), app, 'settings')
    text = output.getvalue()
    for number, label in [('1', 'HTTP-порт для сертификата'), ('2', 'Порт для проксирования трафика'),
                          ('3', 'Локальный HTTPS-порт веб-сервера'), ('4', 'Docker-сеть')]:
        assert re.search(r'\b' + number + r'\) ' + re.escape(label), text)
    assert 'Дополнительные настройки' not in text


def test_settings_four_performs_configure_without_intermediate_screen(app, ui, monkeypatch):
    calls = []
    monkeypatch.setattr(app, 'perform', lambda selected: calls.append((selected.command, selected._configure_choice)) or 0)
    inputs(monkeypatch, ['2', '4', '', '0', '0'])
    assert ui.run(app, args()) == 0
    assert calls == [('configure', '4')]


def test_operation_stream_uses_one_emoji_space_preserves_lines_ansi_and_payload(app, ui, monkeypatch):
    output, errors = Output(), Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setattr(sys, 'stderr', errors)
    def operation(_):
        print('✅  Готово')
        sys.stdout.write('☁️')
        sys.stdout.flush()
        sys.stdout.write('   Облако\n')
        print('PATH=/root/a  b/key.pem')
        print('{"target":"127.0.0.1:9443", "note":"a  b"}')
        sys.stderr.write('⚠️\x1b[33m  Ошибка\x1b[0m\n')
        return 1
    monkeypatch.setattr(app, 'perform', operation)
    inputs(monkeypatch, ['3', '', '0'])
    assert ui.run(app, args()) == 0
    text = output.getvalue()
    assert '✅ Готово\n☁️ Облако\n' in text
    assert 'PATH=/root/a  b/key.pem\n' in text
    assert '{"target":"127.0.0.1:9443", "note":"a  b"}\n' in text
    assert re.sub(r'\x1b\[[0-9;]*m', '', errors.getvalue()) == '⚠️ Ошибка\n'
    assert '\x1b[33m' in errors.getvalue() and '\x1b[0m' in errors.getvalue()
    assert sys.stdout is output and sys.stderr is errors, 'Stream wrappers must be restored on return'


@pytest.mark.parametrize('error', [KeyboardInterrupt(), EOFError()])
def test_operation_stream_is_restored_after_cancel_or_eof(app, ui, monkeypatch, error):
    output, errors = Output(), Output()
    monkeypatch.setattr(sys, 'stdout', output)
    monkeypatch.setattr(sys, 'stderr', errors)
    def operation(_):
        sys.stdout.write('☁️')
        raise error
    monkeypatch.setattr(app, 'perform', operation)
    inputs(monkeypatch, ['3', '0'])
    assert ui.run(app, args()) == 0
    assert sys.stdout is output and sys.stderr is errors
    assert '☁️' in output.getvalue(), 'Partial output must not be lost on cancel'


@pytest.mark.parametrize('raw,expected', [('🇷🇺  RU', '🇷🇺 RU'), ('👩🏽‍💻  Код', '👩🏽‍💻 Код'),
                                        ('🛠️Инструменты', '🛠️ Инструменты')])
def test_operation_stream_preserves_emoji_clusters_across_write_boundaries(app, ui, monkeypatch, raw, expected):
    output = Output()
    monkeypatch.setattr(sys, 'stdout', output)
    def operation(_):
        for char in raw + '\n':
            sys.stdout.write(char)
            sys.stdout.flush()
    monkeypatch.setattr(app, 'perform', operation)
    inputs(monkeypatch, ['3', '', '0'])
    assert ui.run(app, args()) == 0
    assert expected + '\n' in output.getvalue()
