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
    return ''.join(char for char in text
                   if not unicodedata.category(char).startswith('C') or char == '\u200d')


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


class Terminal:
    palette = {'heading': '36', 'label': '90', 'value': '37', 'success': '32',
               'warning': '33', 'error': '31'}

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
        text = fit(value, self.width)
        if self.colors and text:
            text = '\x1b[' + self.palette[role] + 'm' + text + '\x1b[0m'
        print(text)


GROUPS = [
    ('🔧 Установка и настройки', [('1', '🚀 Установка'), ('2', '⚙️ Настройки')]),
    ('📊 Состояние и проверки', [('3', '📊 Статус'), ('4', '🔍 Диагностика'), ('9', '🧪 Самопроверка')]),
    ('🎨 Сайт и подключение', [('10', '🎨 Сайт-заглушка'), ('7', '📖 Инструкция подключения')]),
    ('🔐 Обслуживание', [('5', '🔐 Проверить продление'), ('6', '🔄 Обновить'), ('8', '🗑️ Удаление')])]
OPERATIONS = {'1': 'install', '3': 'status', '4': 'diagnose', '5': 'renew',
              '6': 'update', '7': 'guide', '8': 'uninstall'}
TITLES = {'settings': '⚙️ Настройки', 'advanced': '⚙️ Дополнительные настройки',
          'tests': '🧪 Самопроверка', 'sites': '🎨 Сайт-заглушка'}


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
        rows = [row for row in rows if row[0] in ('Сервер', 'Caddy', 'SSL', 'HTTPS')]
    for label, value in rows:
        role = 'error' if '❌' in value else 'warning' if '⚠' in value else 'success' if '✅' in value else 'value'
        text = label + ': ' if compact else label + ':' + ' ' * max(1, 14 - display_width(label + ':'))
        terminal.line(text + value, role)
    terminal.line('─' * min(60, terminal.width), 'label')
    config = panel.get('config')
    if screen == 'main':
        if compact:
            options = [('1', 'Установка'), ('2', 'Настройки'), ('3', 'Статус'),
                       ('4', 'Диагностика'), ('9', 'Самопроверка'), ('10', 'Сайт-заглушка'),
                       ('7', 'Подключение'), ('5', 'Продление'), ('6', 'Обновить'),
                       ('8', 'Удаление'), ('0', 'Выход')]
            half = max(1, (terminal.width - 1) // 2)
            for offset in range(0, len(options), 2):
                left = fit(options[offset][0] + ') ' + options[offset][1], half)
                right = '' if offset + 1 == len(options) else options[offset + 1][0] + ') ' + options[offset + 1][1]
                terminal.line(left + ' ' * (half - display_width(left) + 1) + right)
        else:
            for heading, options in GROUPS:
                terminal.line(heading, 'heading')
                for number, label in options:
                    terminal.line(f' {number:>2}) {label}')
                terminal.line()
            terminal.line('  0) ⬅️ Выход')
            terminal.line()
        terminal.line(notice or 'Подсказка: ' + panel['hint'], 'warning' if notice else 'label')
    else:
        terminal.line(TITLES[screen], 'heading')
        if screen == 'settings':
            for number, key, label in [('1', 'challenge_port', 'HTTP-порт'), ('2', 'vpn_port', 'VPN-порт'),
                                        ('3', 'local_port', 'Локальный HTTPS-порт')]:
                terminal.line(f"  {number}) {label}: {(config or {}).get(key) or 'неизвестно'}")
            terminal.line('  4) Дополнительные настройки')
        elif screen == 'advanced':
            terminal.line('  1) Docker-сеть: ' + ((config or {}).get('docker_network') or 'host / loopback'))
        elif screen == 'tests':
            terminal.line('  1) Локальная HTTPS — без изменений')
            terminal.line('  2) HTTP через релей — временный тест')
            terminal.line('  3) Из контейнера ноды — без изменений')
        elif screen == 'sites':
            try:
                themes = app.template_module().catalog(app.PACKAGE)['templates']
            except (OSError, ValueError, KeyError, TypeError):
                themes = []
                terminal.line('Каталог недоступен → Диагностика (4).', 'error')
            if compact:
                half = max(1, (terminal.width - 1) // 2)
                for offset in range(0, len(themes), 2):
                    left = fit(themes[offset]['id'] + ') ' + themes[offset]['name'], half)
                    right = '' if offset + 1 == len(themes) else themes[offset + 1]['id'] + ') ' + themes[offset + 1]['name']
                    terminal.line(left + ' ' * (half - display_width(left) + 1) + right)
            else:
                for theme in themes:
                    terminal.line(f" {theme['id']:>2}) {theme['name']}")
            terminal.line('  r) Случайный · i) Встроенный · b) Откат')
        terminal.line('  0) ⬅️ Назад')
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
            destination = {'2': 'settings', '9': 'tests', '10': 'sites'}.get(choice) if screen == 'main' else None
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
                draw_title = TITLES.get(screen) or next(label for _, options in GROUPS
                                                       for number, label in options if number == choice)
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
