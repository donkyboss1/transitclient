"""Small Russian terminal UI. Operations stay in the existing controller."""
import argparse
import builtins
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import re
import os
import shutil
import sys
import unicodedata
from types import SimpleNamespace

import client_panel


def clean(value):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value))
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)
    text = ''.join(char for char in text
                   if not unicodedata.category(char).startswith('C') or char == '\u200d')
    groups = list(clusters(text))
    result = ''
    skip_spaces = False
    for index, group in enumerate(groups):
        if skip_spaces and group.isspace():
            continue
        skip_spaces = False
        emoji = ('\ufe0f' in group or any('\U0001f000' <= char <= '\U0001faff'
                 or '\u2600' <= char <= '\u27bf' for char in group))
        if result and not result[-1].isspace() and emoji:
            result += ' '
        result += group
        if emoji and index + 1 < len(groups):
            result += ' '
            skip_spaces = True
    return result


def clusters(value):
    """Enough grapheme handling for combining text, emoji/VS16/ZWJ and flags."""
    group = ''
    for char in value:
        regional_pair = (len(group) == 1 and '\U0001f1e6' <= group <= '\U0001f1ff'
                         and '\U0001f1e6' <= char <= '\U0001f1ff')
        if group and (unicodedata.combining(char) or char in ('\ufe0e', '\ufe0f', '\u200d')
                      or group.endswith('\u200d') or '\U0001f3fb' <= char <= '\U0001f3ff'
                      or regional_pair):
            group += char
        else:
            if group:
                yield group
            group = char
    if group:
        yield group


def cluster_width(group):
    widths = [2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
              for char in group if not unicodedata.combining(char)
              and char not in ('\ufe0e', '\ufe0f', '\u200d')
              and not '\U0001f3fb' <= char <= '\U0001f3ff']
    return max([2] if '\ufe0f' in group else [0]) if not widths else max(
        max(widths), 2 if '\ufe0f' in group or '\U0001f1e6' <= group[0] <= '\U0001f1ff' else 0)


def display_width(value):
    return sum(cluster_width(group) for group in clusters(value))


def fit_fragments(fragments, width):
    """Clip plain graphemes with their roles, before any ANSI is generated."""
    prepared = [(clean(value), role) for value, role in fragments]
    truncated = sum(display_width(value) for value, _ in prepared) > width
    budget = max(0, width - int(truncated))
    result, used = [], 0
    for value, role in prepared:
        portion = ''
        for group in clusters(value):
            size = cluster_width(group)
            if used + size > budget:
                if width:
                    portion += '…'
                result.append((portion, role))
                return result
            portion += group
            used += size
        result.append((portion, role))
    return result


class CellStream:
    """Place the gap after a two-cell emoji even when the terminal advances one."""
    positioned = True

    def __init__(self, stream, width, cursor=None):
        self.stream, self.width = stream, width
        self.cursor = cursor or SimpleNamespace(column=1, group='', pending=False)
        self.escape = ''

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def reset(self):
        self.cursor.column, self.cursor.group, self.cursor.pending = 1, '', False

    def write(self, text):
        output = []
        state = self.cursor
        for char in text:
            if self.escape or char == '\x1b':
                output.append(char)
                self.escape += char
                if len(self.escape) > 2 and self.escape[1] == '[' and '@' <= char <= '~':
                    match = re.fullmatch(r'\x1b\[([0-9;]*)([GCHfD])', self.escape)
                    if match:
                        values = [int(value or '1') for value in match[1].split(';')]
                        command = match[2]
                        if command == 'G':
                            state.column = max(1, min(self.width, values[0]))
                        elif command in ('H', 'f'):
                            state.column = max(1, min(self.width, values[1] if len(values) > 1 else 1))
                        else:
                            state.column = max(1, min(self.width, state.column + values[0] * (1 if command == 'C' else -1)))
                        state.group, state.pending = '', False
                    self.escape = ''
                elif len(self.escape) == 2 and self.escape[1] != '[':
                    self.escape = ''
                continue
            if char in ('\r', '\n'):
                output.append(char)
                self.reset()
                continue
            if char == '\b':
                output.append(char)
                state.column = max(1, state.column - 1)
                state.group, state.pending = '', False
                continue
            regional_pair = (len(state.group) == 1 and '\U0001f1e6' <= state.group <= '\U0001f1ff'
                             and '\U0001f1e6' <= char <= '\U0001f1ff')
            extension = (unicodedata.combining(char) or char in ('\ufe0e', '\ufe0f', '\u200d')
                         or state.group.endswith('\u200d') or '\U0001f3fb' <= char <= '\U0001f3ff' or regional_pair)
            if extension and state.group:
                before = cluster_width(state.group)
                state.group += char
                state.column += cluster_width(state.group) - before
            else:
                size = 8 - (state.column - 1) % 8 if char == '\t' else cluster_width(char)
                # VS16 may arrive in the next write. Keep a possible emoji base
                # off the final cell before its presentation selector arrives.
                possible_emoji = ('\u2190' <= char <= '\u27bf'
                                  or '\u2b00' <= char <= '\u2bff'
                                  or '\U0001f000' <= char <= '\U0001faff')
                reserve = max(size, 2) if possible_emoji else size
                if state.column + reserve - 1 > self.width:
                    output.append('\r\n')
                    self.reset()
                    size = 8 if char == '\t' else size
                if state.pending:
                    output.append(f'\x1b[{state.column}G')
                state.group = char
                state.column += size
            state.pending = ('\ufe0f' in state.group or any('\U0001f000' <= item <= '\U0001faff'
                             or '\u2600' <= item <= '\u27bf' for item in state.group))
            output.append(char)
        self.stream.write(''.join(output))
        # Both TTY streams share the cursor. Emit each positioned write before
        # the other stream can write, including stdout without a newline.
        self.stream.flush()
        return len(text)


class Terminal:
    palette = {'heading': '1;36', 'bold': '1', 'domain': '1;36', 'label': None,
               'value': None, 'success': '32', 'warning': '33', 'error': '31'}

    def __init__(self, no_color=False):
        self.controls = (sys.stdin.isatty() and sys.stdout.isatty()
                         and os.environ.get('TERM', '') not in ('', 'dumb'))
        self.colors = self.controls and not no_color and 'NO_COLOR' not in os.environ
        self.width, self.height = shutil.get_terminal_size((80, 40))

    def clear(self):
        if self.controls:
            # ED2 clears the visible area only; never use ED3, RIS or `clear`.
            print('\x1b[2J\x1b[H', end='', flush=True)

    def line(self, value='', role='value'):
        self.fragments([(value, role)])

    def fragments(self, values):
        parts = []
        for value, role in fit_fragments(values, self.width):
            code = self.palette.get(role)
            parts.append('\x1b[' + code + 'm' + value + '\x1b[0m'
                         if self.colors and code and value else value)
        value = ''.join(parts) + '\n'
        if self.controls and not getattr(sys.stdout, 'positioned', False):
            CellStream(sys.stdout, self.width).write(value)
        else:
            sys.stdout.write(value)


class EmojiStream:
    """Normalize human operation output as it arrives, including input prompts."""

    def __init__(self, stream, state=None):
        self.stream = stream
        self.state = state or SimpleNamespace(after_emoji=False, separator=False,
                                              previous='', escape='', regional_pending=False)

    def reset(self):
        self.state.after_emoji = self.state.separator = False
        self.state.previous = self.state.escape = ''
        self.state.regional_pending = False

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def write(self, text):
        output = []
        state = self.state
        for char in text:
            # Preserve controller ANSI verbatim; it is not printable text.
            if state.escape or char == '\x1b':
                output.append(char)
                state.escape += char
                if len(state.escape) > 1 and (state.escape[1] != '[' or
                                             len(state.escape) > 2 and '@' <= char <= '~'):
                    state.escape = ''
                continue
            if char in ('\n', '\r'):
                output.append(char)
                state.after_emoji = state.separator = False
                state.regional_pending = False
                state.previous = char
                continue
            if char in ('\ufe0e', '\ufe0f', '\u200d') or unicodedata.combining(char) or '\U0001f3fb' <= char <= '\U0001f3ff':
                output.append(char)
                if char == '\ufe0f':
                    state.after_emoji, state.separator = True, False
                state.previous = char
                continue
            regional = '\U0001f1e6' <= char <= '\U0001f1ff'
            joined = state.previous == '\u200d' or regional and state.regional_pending
            emoji = '\U0001f000' <= char <= '\U0001faff' or '\u2600' <= char <= '\u27bf'
            if state.after_emoji and not joined:
                if not state.separator:
                    output.append(' ')
                    state.separator = True
                    state.previous = ' '
                if char == ' ':
                    state.regional_pending = False
                    continue
                state.after_emoji = state.separator = False
            if emoji and not joined and state.previous and not state.previous.isspace():
                if not output or output[-1] != ' ':
                    output.append(' ')
            output.append(char)
            state.previous = char
            state.regional_pending = regional and not joined
            if emoji:
                state.after_emoji, state.separator = True, False
        self.stream.write(''.join(output))
        return len(text)


@contextmanager
def operation_output(terminal, header_lines):
    """Keep the summary above the scrolling operation body in a real terminal."""
    pinned = terminal.controls and header_lines + 2 < terminal.height
    if pinned:
        print(f'\x1b[{header_lines + 1};{terminal.height}r\x1b[{header_lines + 1};1H', end='', flush=True)
    original_input = builtins.input
    cursor = SimpleNamespace(column=1, group='', pending=False)
    stdout = CellStream(sys.stdout, terminal.width, cursor) if terminal.controls else sys.stdout
    stderr = CellStream(sys.stderr, terminal.width, cursor) if terminal.controls else sys.stderr
    output = EmojiStream(stdout)
    errors = EmojiStream(stderr, output.state)

    def spaced_input(prompt=''):
        # CPython's real TTY readline may bypass sys.stdout.write for prompts.
        buffer = io.StringIO()
        EmojiStream(buffer, output.state).write(prompt)
        value = buffer.getvalue()
        if terminal.controls:
            buffer = io.StringIO()
            CellStream(buffer, terminal.width, cursor).write(value)
            value = buffer.getvalue()
        try:
            return original_input(value)
        finally:
            # Readline echoes the entered text and newline outside our stream.
            cursor.column, cursor.group, cursor.pending = 1, '', False
            output.reset()

    try:
        builtins.input = spaced_input
        with redirect_stdout(output), redirect_stderr(errors):
            yield
    finally:
        builtins.input = original_input
        if pinned:
            print(f'\x1b[r\x1b[{terminal.height};1H', end='', flush=True)


GROUPS = [
    ('🔧 Установка и настройки', [('1', '🚀 Установка', 'install'), ('2', '⚙️ Настройки', 'settings')]),
    ('🔍 Проверки', [('3', '🔍 Диагностика', 'diagnose'), ('4', '🧪 Самопроверка', 'tests')]),
    ('🎨 Сайт и подключение', [('5', '🎨 Сайт-заглушка', 'sites'), ('6', '📖 Инструкция подключения', 'guide')]),
    ('🔐 Обслуживание', [('7', '🔐 Проверить продление', 'renew'), ('8', '🔄 Обновить', 'update'), ('9', '🗑️ Удаление', 'uninstall')])]
MENU = {number: (label, action) for _, options in GROUPS for number, label, action in options}
OPERATIONS = {number: action for number, (_, action) in MENU.items() if action not in ('settings', 'tests', 'sites')}
COMPACT_LABELS = {'guide': '📖 Подключение', 'renew': '🔐 Продление'}
TITLES = {'settings': '⚙️ Настройки',
          'tests': '🧪 Самопроверка', 'sites': '🎨 Сайт-заглушка'}


def option(number, label):
    return [(' ', None), (str(number).rjust(2), 'bold'), (') ', None), (label, None)]


def columns(terminal, options):
    half = max(1, (terminal.width - 1) // 2)
    for offset in range(0, len(options), 2):
        left = fit_fragments(option(*options[offset]), half)
        if offset + 1 < len(options):
            padding = half - sum(display_width(value) for value, _ in left) + 1
            left += [(' ' * padding, None)] + fit_fragments(option(*options[offset + 1]), terminal.width - half - 1)
        terminal.fragments(left)


def draw_rows(terminal, rows):
    compact = terminal.width < 70 or terminal.height < 36
    for label, value in rows:
        padding = ' ' if compact else ' ' * max(1, 14 - display_width(label + ':'))
        terminal.fragments([(label + ':', 'bold'), (padding, None), (value, 'domain' if label == 'Домен' else None)])


def draw_header(terminal, app):
    terminal.width, terminal.height = shutil.get_terminal_size((80, 40))
    panel = client_panel.snapshot(app)
    compact = terminal.width < 70 or terminal.height < 36
    terminal.clear()
    version = (app.PACKAGE / 'VERSION').read_text().strip()
    terminal.line('🚀 Transit Client · ' + version, 'heading')
    if not compact:
        terminal.line('─' * min(60, terminal.width), 'label')
    rows = panel['rows']
    if terminal.height < 18:
        rows = [row for row in rows if row[0] in ('Сервер', 'Домен', 'SSL', 'HTTPS')]
    draw_rows(terminal, rows)
    terminal.line('─' * min(60, terminal.width), 'label')
    return panel, 2 + len(rows) + int(not compact)


def draw(terminal, app, screen, notice=''):
    panel, _ = draw_header(terminal, app)
    compact = terminal.width < 70 or terminal.height < 36
    config = panel.get('config')
    if screen == 'main':
        if compact:
            columns(terminal, [(number, COMPACT_LABELS.get(action, label)) for number, (label, action) in MENU.items()]
                    + [('0', '⬅️ Выход')])
        else:
            for heading, options in GROUPS:
                terminal.line(heading, 'bold')
                for number, label, _ in options:
                    terminal.fragments(option(number, label))
                terminal.line()
            terminal.fragments(option('0', '⬅️ Выход'))
            terminal.line()
        terminal.line(notice or 'Подсказка: ' + panel['hint'], 'warning' if notice else 'label')
    else:
        terminal.line(TITLES[screen], 'bold')
        if screen == 'settings':
            for number, key, label in [('1', 'challenge_port', 'HTTP-порт для сертификата'),
                                       ('2', 'vpn_port', 'Порт для проксирования трафика'),
                                       ('3', 'local_port', 'Локальный HTTPS-порт веб-сервера')]:
                terminal.fragments(option(number, f"{label}: {(config or {}).get(key) or 'неизвестно'}"))
            terminal.fragments(option('4', 'Docker-сеть: ' + ((config or {}).get('docker_network') or 'host / loopback')))
        elif screen == 'tests':
            terminal.fragments(option('1', 'Локальная HTTPS — без изменений'))
            terminal.fragments(option('2', 'HTTP через релей — временный тест'))
            terminal.fragments(option('3', 'Из контейнера ноды — без изменений'))
        elif screen == 'sites':
            try:
                themes = app.template_module().catalog(app.PACKAGE)['templates']
            except (OSError, ValueError, KeyError, TypeError):
                themes = []
                terminal.line('Каталог недоступен → Диагностика (3).', 'error')
            if compact:
                columns(terminal, [(theme['id'], theme['name']) for theme in themes])
            else:
                for theme in themes:
                    terminal.fragments(option(theme['id'], theme['name']))
            terminal.fragments(option('r', 'Случайный') + [(' · ', None), ('i', 'bold'), (') Встроенный · ', None), ('b', 'bold'), (') Откат', None)])
        terminal.fragments(option('0', '⬅️ Назад'))
        if notice:
            terminal.line(notice, 'warning')
    return panel


def run(app, args):
    if not sys.stdin.isatty():
        raise app.Failure('Для меню нужен терминал. Укажите команду status/diagnose либо откройте интерактивный Bash.', 'TTY_REQUIRED')
    terminal = Terminal(no_color=getattr(args, 'no_color', False))
    stack, notice = ['main'], ''
    try:
        while stack:
            screen = stack[-1]
            try:
                draw(terminal, app, screen, notice)
            except KeyboardInterrupt:
                if screen == 'main':
                    print('\nВыход.')
                    return 0
                stack.pop()
                notice = 'Действие отменено.'
                continue
            notice = ''
            try:
                choice = input('Выберите действие: ').strip().lower()
            except KeyboardInterrupt:
                if screen == 'main':
                    print('\nВыход.')
                    return 0
                stack.pop()
                notice = 'Действие отменено.'
                continue
            if choice == '0':
                stack.pop()
                continue
            action = MENU.get(choice, (None, None))[1] if screen == 'main' else None
            destination = action if action in ('settings', 'tests', 'sites') else None
            if destination:
                stack.append(destination)
                continue
            selected = argparse.Namespace(**vars(args))
            selected._menu_mode = True
            selected.json, selected.http01, selected.vpn = False, False, False
            selected.full = False
            if screen == 'main' and choice in OPERATIONS:
                selected.command = OPERATIONS[choice]
            elif screen == 'settings' and choice in ('1', '2', '3', '4'):
                selected.command, selected._configure_choice = 'configure', choice
            elif screen == 'tests' and choice in ('1', '2', '3'):
                selected.command = 'self-test'
                selected.http01, selected.vpn = choice == '2', choice == '3'
            elif screen == 'sites' and choice in [str(i) for i in range(1, 12)] + ['r', 'i', 'b']:
                selected.command = 'template'
                selected.template = {'r': 'random', 'i': 'builtin', 'b': 'rollback'}.get(choice, choice)
            else:
                notice = 'Неизвестный пункт. Выберите действие из списка.'
                continue
            try:
                _, header_lines = draw_header(terminal, app)
                with operation_output(terminal, header_lines):
                    draw_title = TITLES.get(screen) or MENU[choice][0]
                    terminal.line(draw_title, 'bold')
                    app.perform(selected)
                    if selected.command == 'diagnose':
                        terminal.fragments(option('1', 'Подробный отчёт') + [(' · Enter — назад', None)])
                        while True:
                            detail = input('Нажмите Enter для возврата или 1 для подробного отчёта: ').strip()
                            if not detail:
                                break
                            if detail != '1':
                                terminal.line('Неизвестный пункт. Нажмите Enter или 1.', 'warning')
                                continue
                            selected.full = True
                            app.perform(selected)
                            input('Нажмите Enter для возврата…')
                            break
                        continue
                    input('Нажмите Enter для возврата…')
            except KeyboardInterrupt:
                if len(stack) > 1:
                    stack.pop()
                notice = 'Действие отменено.'
    except EOFError:
        print('\nВыход.')
    return 0
