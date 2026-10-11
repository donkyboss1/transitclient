"""Small Russian terminal UI. Operations stay in the existing controller."""
import argparse
import re
import os
import shutil
import sys
import unicodedata

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
            # Some SSH fonts draw VS16 emoji wider than the grid cell. Leave a
            # real two-space gap, independent of ANSI and idempotent on redraw.
            result += '  '
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


def fit(value, width):
    text = clean(value)
    if display_width(text) <= width:
        return text
    result, used = '', 0
    for group in clusters(text):
        size = cluster_width(group)
        if used + size > max(0, width - 1):
            break
        result += group
        used += size
    return result + ('…' if width else '')


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
        print(''.join(parts))


GROUPS = [
    ('🔧 Установка и настройки', [('1', '🚀 Установка', 'install'), ('2', '⚙️ Настройки', 'settings')]),
    ('📊 Состояние и проверки', [('3', '📊 Статус', 'status'), ('4', '🔍 Диагностика', 'diagnose'), ('5', '🧪 Самопроверка', 'tests')]),
    ('🎨 Сайт и подключение', [('6', '🎨 Сайт-заглушка', 'sites'), ('7', '📖 Инструкция подключения', 'guide')]),
    ('🔐 Обслуживание', [('8', '🔐 Проверить продление', 'renew'), ('9', '🔄 Обновить', 'update'), ('10', '🗑️ Удаление', 'uninstall')])]
MENU = {number: (label, action) for _, options in GROUPS for number, label, action in options}
OPERATIONS = {number: action for number, (_, action) in MENU.items() if action not in ('settings', 'tests', 'sites')}
COMPACT_LABELS = {'guide': '📖 Подключение', 'renew': '🔐 Продление'}
TITLES = {'settings': '⚙️ Настройки', 'advanced': '⚙️ Дополнительные настройки',
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


def draw(terminal, app, screen, notice=''):
    terminal.width, terminal.height = shutil.get_terminal_size((80, 40))
    panel = client_panel.snapshot(app)
    compact = terminal.width < 70 or terminal.height < 36
    terminal.clear()
    version = (app.PACKAGE / 'VERSION').read_text().strip()
    terminal.line('🚀 Transit Client · ' + version, 'heading')
    if not compact:
        terminal.line('─' * min(60, terminal.width), 'label')
    rows = panel['rows']
    if compact and screen == 'sites':
        rows = [row for row in rows if row[0] != 'Продление']
    if terminal.height < 18:
        rows = [row for row in rows if row[0] in ('Сервер', 'Домен', 'SSL', 'HTTPS')]
    for label, value in rows:
        padding = ' ' if compact else ' ' * max(1, 14 - display_width(label + ':'))
        terminal.fragments([(label + ':', 'bold'), (padding, None), (value, 'domain' if label == 'Домен' else None)])
    terminal.line('─' * min(60, terminal.width), 'label')
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
            for number, key, label in [('1', 'challenge_port', 'HTTP-порт'), ('2', 'vpn_port', 'VPN-порт'),
                                        ('3', 'local_port', 'Локальный HTTPS-порт')]:
                terminal.fragments(option(number, f"{label}: {(config or {}).get(key) or 'неизвестно'}"))
            terminal.fragments(option('4', 'Дополнительные настройки'))
        elif screen == 'advanced':
            terminal.fragments(option('1', 'Docker-сеть: ' + ((config or {}).get('docker_network') or 'host / loopback')))
        elif screen == 'tests':
            terminal.fragments(option('1', 'Локальная HTTPS — без изменений'))
            terminal.fragments(option('2', 'HTTP через релей — временный тест'))
            terminal.fragments(option('3', 'Из контейнера ноды — без изменений'))
        elif screen == 'sites':
            try:
                themes = app.template_module().catalog(app.PACKAGE)['templates']
            except (OSError, ValueError, KeyError, TypeError):
                themes = []
                terminal.line('Каталог недоступен → Диагностика (4).', 'error')
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
            if screen == 'settings' and choice == '4':
                destination = 'advanced'
            if destination:
                stack.append(destination)
                continue
            selected = argparse.Namespace(**vars(args))
            selected._menu_mode = True
            selected.json, selected.http01, selected.vpn = False, False, False
            if screen == 'main' and choice in OPERATIONS:
                selected.command = OPERATIONS[choice]
            elif screen == 'settings' and choice in ('1', '2', '3'):
                selected.command, selected._configure_choice = 'configure', choice
            elif screen == 'advanced' and choice == '1':
                selected.command, selected._configure_choice = 'configure', '4'
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
                terminal.clear()
                draw_title = TITLES.get(screen) or MENU[choice][0]
                terminal.line('🚀 Transit Client · ' + draw_title, 'heading')
                app.perform(selected)
                input('Нажмите Enter для возврата…')
            except KeyboardInterrupt:
                if len(stack) > 1:
                    stack.pop()
                notice = 'Действие отменено.'
    except EOFError:
        print('\nВыход.')
    return 0
