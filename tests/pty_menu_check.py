#!/usr/bin/env python3
"""Offline acceptance of the real menu in a Linux controlling PTY.

Run: python3 tests/pty_menu_check.py (stdlib only; no pytest required).
Assertions fixed before implementation: 0/back, real keyboard SIGINT and EOF,
empty/invalid selection, Enter-gated results, cancel before installation mutation,
all self-test modes, template navigation, incomplete/Docker-unknown summaries,
80x40/48x20 layouts, clear/home without clearing scrollback, NO_COLOR/no-color,
TERM=dumb and redirected output. Every host operation/network call is forbidden.
The fake dispatcher exercises navigation; lifecycle rollback remains covered by
the separate offline pytest suite, not by the fake operation below.
"""
import argparse
import errno
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
PROMPT = 'Выберите действие:'
PAUSE = 'Нажмите Enter'
SGR = re.compile(r'\x1b\[[0-9;]*m')
CSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


class NarrowEmojiTerminal:
    """Independent VT replay: SSH draws these VS16 glyphs in two cells,
    with either one- or two-cell native cursor advance. This models terminal behavior,
    rather than calling the renderer's width or placement implementation.
    """

    narrow_bases = {'⚙', '☁', '🗑', '⬅'}

    def __init__(self, columns=80, lines=40, native_emoji_advance=1):
        self.columns, self.lines = columns, lines
        self.native_emoji_advance = native_emoji_advance
        self.row = self.column = 0
        self.top, self.bottom = 0, lines - 1
        self.saved = (0, 0)
        self.draws = []

    def feed(self, data):
        index = 0
        while index < len(data):
            if data[index] == '\x1b':
                command = re.match(r'\x1b\[([0-9;?]*)([A-Za-z])', data[index:])
                assert command, 'Unsupported VT sequence in acceptance oracle: ' + repr(data[index:index + 20])
                parameters, final = command.groups()
                numbers = [int(number or '0') for number in parameters.lstrip('?').split(';')]
                amount = numbers[0] or 1
                if final in ('H', 'f'):
                    self.row = amount - 1
                    self.column = (numbers[1] or 1) - 1 if len(numbers) > 1 else 0
                elif final in ('G',):
                    self.column = amount - 1
                elif final in ('C', 'a'):
                    self.column += amount
                elif final == 'D':
                    self.column = max(0, self.column - amount)
                elif final in ('A', 'B'):
                    self.row += amount * (1 if final == 'B' else -1)
                elif final in ('E', 'F'):
                    self.row += amount * (1 if final == 'E' else -1)
                    self.column = 0
                elif final == 'd':
                    self.row = amount - 1
                elif final == 's':
                    self.saved = self.row, self.column
                elif final == 'u':
                    self.row, self.column = self.saved
                elif final == 'r':
                    self.top = amount - 1
                    self.bottom = (numbers[1] or self.lines) - 1 if len(numbers) > 1 else self.lines - 1
                    self.row = self.column = 0
                elif final == 'J' and numbers[0] == 2:
                    self.draws.clear()
                else:
                    assert final in ('m', 'J', 'K', 'h', 'l'), 'Unknown VT command: ' + command.group(0)
                index += len(command.group(0))
                continue
            char = data[index]
            index += 1
            if char == '\r':
                self.column = 0
                continue
            if char == '\n':
                # Default SSH PTY OPOST/ONLCR resets the column on a newline.
                self.column = 0
                if self.row == self.bottom:
                    self.draws = [dict(item, row=item['row'] - 1) if self.top < item['row'] <= self.bottom else item
                                  for item in self.draws if item['row'] != self.top]
                else:
                    self.row += 1
                continue
            if char in ('\ufe0e', '\ufe0f') or unicodedata.combining(char):
                if self.draws:
                    self.draws[-1]['glyph'] += char
                    if char == '\ufe0f':
                        if self.draws[-1]['glyph'][0] in self.narrow_bases:
                            self.column += self.native_emoji_advance - 1
                        self.draws[-1]['width'] = 2
                continue
            if char == '\b':
                self.column = max(0, self.column - 1)
                continue
            if char == '\t':
                self.column = (self.column // 8 + 1) * 8
                continue
            if ord(char) < 32:
                continue
            native = 1 if char in self.narrow_bases else 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
            if self.column >= self.columns:
                self.column = 0
                self.row += 1
            self.draws.append(dict(glyph=char, row=self.row, column=self.column, width=native))
            self.column += native
        return self

    def assert_gap(self, glyph):
        occurrences = 0
        for index, icon in enumerate(self.draws):
            if icon['glyph'] != glyph:
                continue
            following = next((item for item in self.draws[index + 1:]
                              if item['row'] == icon['row'] and not item['glyph'].isspace()), None)
            if following is None:
                continue
            occurrences += 1
            assert icon['column'] + icon['width'] <= self.columns, ('Glyph extends beyond terminal', icon)
            gap = following['column'] - icon['column'] - icon['width']
            assert gap == 1, (glyph, 'effective blank cells', gap, 'icon', icon, 'next text', following)
        assert occurrences, 'No visible ' + repr(glyph) + ' followed by text'


def assert_vs16_geometry(raw, glyph, columns=80, lines=40, native_emoji_advance=None):
    for advance in (1, 2) if native_emoji_advance is None else (native_emoji_advance,):
        NarrowEmojiTerminal(columns, lines, advance).feed(raw).assert_gap(glyph)
    plain = CSI.sub('', raw)
    assert glyph + ' ' in plain and glyph + '  ' not in plain, 'Exactly one literal ASCII separator required'


def line_width(text):
    """Independent width estimate for menu emoji, Cyrillic and variation selectors."""
    widths = []
    joined = False
    for char in text:
        if char == '\u200d':
            joined = True
            continue
        if char == '\ufe0f':
            if widths:
                widths[-1] = max(2, widths[-1])
            continue
        if unicodedata.combining(char) or char == '\ufe0e':
            continue
        width = 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
        if joined and widths:
            widths[-1] = max(widths[-1], width)
            joined = False
        else:
            widths.append(width)
    return sum(widths)


def child(scenario, no_color):
    sys.path.insert(0, str(ROOT))
    import selfsteal as app
    import client_panel
    real_install = app.install

    def forbidden(*args, **kwargs):
        raise AssertionError('FORBIDDEN_REAL_OPERATION')

    def audit(event, args):
        if event in ('subprocess.Popen', 'socket.connect', 'socket.getaddrinfo',
                     'urllib.Request', 'os.system'):
            forbidden()

    sys.addaudithook(audit)
    for name in ('run', 'dependencies', 'install', 'renew', 'update', 'uninstall',
                 'verified_download', 'abort_acme', 'open_firewall', 'cleanup_firewall',
                 'require_host', 'http_self_test', 'vpn_self_test'):
        setattr(app, name, forbidden)
    config = dict(domain='node.example.com', vpn_port=443, challenge_port=8080,
                  local_port=9443, docker_network='', vpn_container='', relay_ip='',
                  ca=app.PRODUCTION, staging_ca_file=None, firewall='manual')
    with tempfile.TemporaryDirectory(prefix='transitclient-pty-') as directory:
        folder = Path(directory)
        app.STATE = folder / 'state'
        app.STATE.mkdir()
        app.CONFIG = folder / 'config.json'
        app.INSTALL = folder / 'install'
        app.UNITS = folder / 'units'
        app.LOCK = folder / 'lock'
        app.safe_config = lambda: dict(config)
        state = 'Установка не завершена' if scenario == 'incomplete' else 'Работает'
        docker = 'Docker недоступен · неизвестно' if scenario == 'docker' else state
        rows = [('Сервер', 'Caddy · ' + docker),
                ('Домен', config['domain']), ('Порты', 'VPN 443 · HTTP 8080 · HTTPS 127.0.0.1:9443'),
                ('SSL', 'Действителен на диске · 30 дней · Test issuer'),
                ('HTTPS', 'Не подтверждён · Самопроверка'),
                ('Продление', 'Включено · следующий запуск завтра'), ('Заглушка', '☁️Тестовый сайт')]
        client_panel.snapshot = lambda *a, **k: dict(rows=rows, hint='HTTPS не подтверждён → Самопроверка',
                                                    config=dict(config), installation=state)
        if scenario == 'install-mode':
            app.check_install_resources = lambda: None
            app.diagnostic_module = lambda: SimpleNamespace(collect=lambda *_: {'checks': []},
                                                            display_compact=lambda *_, **__: None)
            app.guide = lambda *_: print('MODE_GUIDE', flush=True)

        def fake_perform(args):
            command = args.command
            if scenario in ('vs16-output', 'vs16-buffered'):
                for chunk in ('☁', '\ufe0f'):
                    sys.stdout.write(chunk)
                    if scenario == 'vs16-output':
                        sys.stdout.flush()
                sys.stderr.write(' ')
                sys.stderr.flush()
                sys.stdout.write('Облако\n')
                sys.stdout.flush()
                print('🗑️ Удаление', file=sys.stderr, flush=True)
                input('⚙️ Введите значение: ')
            if scenario == 'vs16-edge':
                columns = os.get_terminal_size().columns
                for glyph in ('⚙️', '☁️', '🗑️', '⬅️'):
                    for chunk in ('x' * (columns - 2) + ' ', glyph[0], glyph[1], ' A\n'):
                        sys.stdout.write(chunk)
                        sys.stdout.flush()
            if scenario == 'stream-output':
                print('✅  Готово', flush=True)
                sys.stdout.write('☁️')
                sys.stdout.flush()
                sys.stdout.write('   Облако\n')
                sys.stdout.flush()
                print('⚠️  Ошибка', file=sys.stderr, flush=True)
                print('PATH=/root/a  b/key.pem', flush=True)
                input('⚙️  Введите значение: ')
            if scenario == 'long-output':
                for index in range(75):
                    print('REPORT_LINE=' + str(index), flush=True)
            if command == 'install':
                if scenario == 'install-mode':
                    try:
                        real_install(args)
                    except app.Failure as exc:
                        assert exc.code == 'CANCELLED', exc.code
                        print('MODE_CANCELLED', flush=True)
                    return 0
                approved = app.installation_plan(config)
                print('INSTALL_APPROVED' if approved else 'INSTALL_CANCELLED', flush=True)
                if approved:
                    forbidden()
                return 0
            if scenario == 'interrupt-operation' and command == 'renew':
                try:
                    print('OPERATION_RUNNING', flush=True)
                    while True:
                        # A cancellable polling wait models subprocess supervision;
                        # pause() can miss the readiness-to-wait signal window.
                        time.sleep(0.05)
                finally:
                    print('ROLLBACK_FINISHED', flush=True)
            if command == 'configure':
                print('CONFIG_CHOICE=' + str(getattr(args, '_configure_choice', '?')), flush=True)
                input('Новое значение: ')
            if command == 'diagnose':
                print('TEST_ERROR: безопасная тестовая ошибка', flush=True)
                return 1
            if command == 'self-test':
                print('SELF_TEST=' + ('http01' if args.http01 else 'vpn' if args.vpn else 'local'), flush=True)
            if command == 'template':
                print('TEMPLATE=' + str(args.template), flush=True)
            print('TEST_SUCCESS=' + command, flush=True)
            return 0

        app.perform = fake_perform
        args = SimpleNamespace(command='menu', no_color=no_color, http01=False, vpn=False,
                               template=None, json=False)
        code = app.menu(args)
        print('HARNESS_EXIT=' + str(code), flush=True)


class Session:
    def __init__(self, scenario='normal', *, columns=80, lines=40, no_color=False, env=None):
        import fcntl
        import pty
        import termios
        pid, fd = pty.fork()
        if pid == 0:
            variables = dict(os.environ, TERM='xterm-256color', PYTHONUNBUFFERED='1')
            if scenario == 'vs16-buffered':
                variables.pop('PYTHONUNBUFFERED', None)
            variables.pop('NO_COLOR', None)
            variables.update(env or {})
            argv = [sys.executable, str(Path(__file__).resolve()), '--child', scenario]
            if no_color:
                argv.append('--no-color')
            os.execve(sys.executable, argv, variables)
        self.pid, self.fd = pid, fd
        self.output = ''
        self.offset = 0
        self.closed = False
        self.status = None
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', lines, columns, 0, 0))

    def send(self, value):
        os.write(self.fd, value.encode('utf-8'))

    def read(self, seconds=0.1):
        if self.closed:
            return ''
        ready, _, _ = select.select([self.fd], [], [], seconds)
        if not ready:
            return ''
        try:
            data = os.read(self.fd, 65536)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            data = b''
        if not data:
            self.closed = True
            return ''
        # A read may split a multibyte character. Keep raw bytes until complete.
        pending = getattr(self, '_pending', b'') + data
        try:
            decoded = pending.decode('utf-8')
            self._pending = b''
        except UnicodeDecodeError as exc:
            decoded = pending[:exc.start].decode('utf-8')
            self._pending = pending[exc.start:]
        self.output += decoded
        return decoded

    def expect(self, text, seconds=5):
        deadline = time.monotonic() + seconds
        while True:
            found = self.output.find(text, self.offset)
            if found >= 0:
                self.offset = found + len(text)
                return
            if self.closed or time.monotonic() >= deadline:
                raise AssertionError('Expected ' + repr(text) + '\n' + repr(self.output[-3000:]))
            self.read(0.1)

    def finish(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.read(0.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                while not self.closed:
                    self.read(0.1)
                assert self.status == 0, self.output
                assert 'Traceback' not in self.output, self.output
                assert 'Выход без подтверждения' not in self.output, self.output
                assert 'FORBIDDEN_REAL_OPERATION' not in self.output, self.output
                return
        raise AssertionError('Child did not exit; possible EOF loop\n' + self.output[-2000:])

    def close(self):
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except ProcessLookupError:
                pass
        os.close(self.fd)

    def __enter__(self):
        self.expect(PROMPT)
        return self

    def __exit__(self, *args):
        self.close()


def back_and_cancel():
    for option, title in [('2', 'Настройки'), ('5', 'Самопроверка'), ('6', 'Сайт')]:
        with Session() as session:
            session.send(option + '\n')
            session.expect(title)
            session.expect(PROMPT)
            session.send('0\n')
            session.expect(PROMPT)
            session.send(option + '\n')
            session.expect(PROMPT)
            session.send('\x03')
            session.expect('Действие отменено')
            session.expect(PROMPT)
            session.send('0\n')
            session.finish()
    with Session() as session:
        session.send('\x03')
        session.finish()


def invalid_and_results():
    with Session() as session:
        for option in ('', 'invalid', '99'):
            session.send(option + '\n')
            session.expect('Неизвестный')
            session.expect(PROMPT)
        for option, marker in [('3', 'TEST_SUCCESS=status'), ('4', 'TEST_ERROR')]:
            session.send(option + '\n')
            session.expect(marker)
            session.expect(PAUSE)
            start = len(session.output)
            session.read(0.2)
            assert '\x1b[2J' not in session.output[start:], 'Result cleared before Enter'
            session.send('\n')
            session.expect(PROMPT)
        session.send('0\n')
        session.finish()
    for menu in ('2', '5', '6'):
        with Session() as session:
            session.send(menu + '\n')
            session.expect(PROMPT)
            for option in ('', 'invalid', '99'):
                session.send(option + '\n')
                session.expect('Неизвестный')
                session.expect(PROMPT)
            assert 'TEST_SUCCESS=' not in session.output
            assert 'TEMPLATE=' not in session.output
            session.send('0\n')
            session.expect(PROMPT)
            session.send('0\n')
            session.finish()


def sequential_main_actions():
    with Session() as session:
        for option, command in [('3', 'status'), ('7', 'guide'), ('8', 'renew'), ('9', 'update'), ('10', 'uninstall')]:
            session.send(option + '\n')
            session.expect('TEST_SUCCESS=' + command)
            session.expect(PAUSE)
            session.send('\n')
            session.expect(PROMPT)
        session.send('0\n')
        session.finish()


def operation_modes():
    with Session() as session:
        session.send('5\n')
        session.expect(PROMPT)
        for option, marker in [('1', 'local'), ('2', 'http01'), ('3', 'vpn')]:
            session.send(option + '\n')
            session.expect('SELF_TEST=' + marker)
            session.expect(PAUSE)
            session.send('\n')
            session.expect(PROMPT)
        session.send('0\n')
        session.expect(PROMPT)
        session.send('6\n')
        session.expect(PROMPT)
        assert '11' in session.output
        for option, marker in [('i', 'builtin'), ('r', 'random'), ('b', 'rollback')]:
            session.send(option + '\n')
            session.expect('TEMPLATE=' + marker)
            session.expect(PAUSE)
            session.send('\n')
            session.expect(PROMPT)
        session.send('0\n')
        session.expect(PROMPT)
        session.send('0\n')
        session.finish()


def input_cancel_and_operation_interrupt():
    with Session() as session:
        session.send('2\n')
        session.expect(PROMPT)
        session.send('1\n')
        session.expect('Новое значение:')
        session.send('\x03')
        session.expect('Действие отменено')
        session.expect(PROMPT)
        session.send('0\n')
        session.finish()
    with Session() as session:
        session.send('2\n')
        session.expect(PROMPT)
        session.send('4\n')
        session.expect('CONFIG_CHOICE=4')
        session.expect('Новое значение:')
        session.send('\x03')
        session.expect('Действие отменено')
        session.expect(PROMPT)
        session.send('0\n')
        session.finish()
    with Session('interrupt-operation') as session:
        session.send('8\n')
        session.expect('OPERATION_RUNNING')
        session.send('\x03')
        session.expect('ROLLBACK_FINISHED')
        session.expect('Действие отменено')
        session.expect(PROMPT)
        assert '\x1b[r' in session.output, 'Scroll region must reset after interrupt'
        session.send('0\n')
        session.finish()


def eof_at_every_level():
    for path in ([], ['2'], ['5'], ['6'], ['2', '1'], ['2', '4'], ['3'], ['1']):
        with Session() as session:
            for index, option in enumerate(path):
                session.send(option + '\n')
                if path in (['2', '1'], ['2', '4']) and index == 1:
                    session.expect('Новое значение:')
                elif option == '3':
                    session.expect(PAUSE)
                elif option == '1':
                    session.expect('[y/N]')
                else:
                    session.expect(PROMPT)
            session.send('\x04')
            session.finish()
            if path in (['2', '1'], ['2', '4'], ['3'], ['1']):
                assert '\x1b[r' in session.output, 'Scroll region must reset after EOF'


def confirmation_defaults_to_no():
    with Session() as session:
        session.send('1\n')
        session.expect('[y/N]')
        session.send('\n')
        session.expect('INSTALL_CANCELLED')
        session.expect(PAUSE)
        session.send('\n')
        session.expect(PROMPT)
        assert 'INSTALL_APPROVED' not in session.output
        session.send('0\n')
        session.finish()


def terminal_capabilities_and_layout():
    for kwargs in ({}, {'columns': 48, 'lines': 20}, {'no_color': True},
                   {'env': {'NO_COLOR': '1'}}, {'env': {'TERM': 'dumb'}}):
        with Session(**kwargs) as session:
            for _ in range(2):
                session.send('5\n')
                session.expect(PROMPT)
                session.send('0\n')
                session.expect(PROMPT)
            session.send('0\n')
            session.finish()
            output = session.output
            assert '\x1b[3J' not in output and '\x1bc' not in output
            if kwargs.get('env', {}).get('TERM') == 'dumb':
                assert '\x1b' not in output
            else:
                assert '\x1b[2J' in output and '\x1b[H' in output
                screen = output.rsplit('\x1b[2J', 1)[1]
                screen = CSI.sub('', screen).replace('\r', '')
                assert screen.count('Transit Client') == 1, screen
                assert len(screen.splitlines()) <= kwargs.get('lines', 40), screen
                for line in screen.splitlines():
                    assert line_width(line) <= kwargs.get('columns', 80), repr(line)
                for number in ('1)', '2)', '3)', '4)', '5)', '6)', '7)', '8)', '9)', '10)', '0)'):
                    assert number in screen, screen
                options = [line for line in screen.splitlines() if re.match(r'^\s*\d+\)', line)]
                assert re.findall(r'\b(\d+)\)', '\n'.join(options)) == [str(i) for i in range(1, 11)] + ['0'], options
                assert 'pty-host' not in screen and 'Ubuntu' not in screen, screen
                assert 'Сервер:' in screen and 'Caddy ·' in screen and 'Заглушка:' in screen, screen
                assert 'Таймер включён' not in screen and 'Включено' in screen, screen
                assert '☁️ Тестовый сайт' in screen, screen
                if not kwargs.get('no_color') and not kwargs.get('env', {}).get('NO_COLOR'):
                    raw_screen = output.rsplit('\x1b[2J', 1)[1]
                    for label in ('Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка'):
                        assert '\x1b[1m' + label + ':\x1b[0m' in raw_screen, raw_screen
                    assert '\x1b[1;36mnode.example.com\x1b[0m' in raw_screen, raw_screen
                    assert '\x1b[32m' not in raw_screen and '\x1b[31m' not in raw_screen, raw_screen
            if kwargs.get('no_color') or kwargs.get('env', {}).get('NO_COLOR'):
                assert not SGR.search(output), 'Color emitted with no-color'
    for scenario, marker in [('incomplete', 'Установка не завершена'), ('docker', 'Docker недоступен')]:
        with Session(scenario) as session:
            assert marker in session.output
            session.send('0\n')
            session.finish()


def redirected_output():
    import pty
    master, slave = pty.openpty()
    with tempfile.TemporaryFile() as output:
        # Use a PTY input but ordinary redirected output in a separate subprocess.
        try:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child', 'normal'],
                                       stdin=slave, stdout=output, stderr=output,
                                       env=dict(os.environ, TERM='xterm-256color', PYTHONUNBUFFERED='1'))
            os.write(master, b'0\n')
            process.wait(timeout=5)
            output.seek(0)
            captured = output.read()
            assert b'\x1b' not in captured
            assert b'Traceback' not in captured, captured
        finally:
            if 'process' in locals() and process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)


SUMMARY_LABELS = ('Сервер', 'Домен', 'Порты', 'SSL', 'HTTPS', 'Продление', 'Заглушка')


def current_screen(session):
    return session.output.rsplit('\x1b[2J\x1b[H', 1)[-1]


def assert_shared_header(raw, columns):
    plain = CSI.sub('', raw).replace('\r', '')
    found = [line.split(':', 1)[0] for line in plain.splitlines()
             if any(line.startswith(label + ':') for label in SUMMARY_LABELS)]
    assert found == list(SUMMARY_LABELS), plain
    assert 'Transit Client · ' in plain and 'node.example.com' in plain, plain
    assert all(line_width(line) <= columns for line in plain.splitlines()), plain
    assert not re.search(r'[\U0001f300-\U0001faff\u2600-\u27bf]\ufe0f? {2,}\S', plain), plain


def shared_headers_direct_docker_and_operation_regions():
    for columns, lines in ((80, 40), (48, 20)):
        with Session(columns=columns, lines=lines) as session:
            assert_shared_header(current_screen(session), columns)
            for option in ('2', '5', '6'):
                session.send(option + '\n')
                session.expect(PROMPT)
                screen = current_screen(session)
                assert_shared_header(screen, columns)
                assert len(CSI.sub('', screen).replace('\r', '').splitlines()) <= lines, screen
                session.send('0\n')
                session.expect(PROMPT)
            session.send('2\n')
            session.expect(PROMPT)
            settings = CSI.sub('', current_screen(session))
            assert '4) Docker-сеть' in settings and 'Дополнительные' not in settings, settings
            session.send('4\n')
            session.expect('CONFIG_CHOICE=4')
            session.expect('Новое значение:')
            assert_shared_header(current_screen(session), columns)
            session.send('\n')
            session.expect(PAUSE)
            session.send('\n')
            session.expect(PROMPT)
            assert '\x1b[r' in session.output, 'Scroll region must reset before returning to settings'
            session.send('0\n')
            session.expect(PROMPT)
            for choice, marker in [('3', 'TEST_SUCCESS=status'), ('4', 'TEST_ERROR'), ('7', 'TEST_SUCCESS=guide'),
                                   ('8', 'TEST_SUCCESS=renew'), ('9', 'TEST_SUCCESS=update'), ('10', 'TEST_SUCCESS=uninstall')]:
                session.send(choice + '\n')
                session.expect(marker)
                session.expect(PAUSE)
                raw = current_screen(session)
                assert_shared_header(raw, columns)
                assert re.search(r'\x1b\[\d+;\d+r', raw), 'No protected operation scroll region: ' + repr(raw)
                begin = len(session.output)
                session.read(0.1)
                assert '\x1b[2J' not in session.output[begin:], 'Operation result cleared before Enter'
                session.send('\n')
                session.expect(PROMPT)
                assert '\x1b[r' in session.output[begin:], 'Scroll region must reset after Enter'
            session.send('0\n')
            session.finish()


def operation_stream_and_long_report():
    for columns, lines in ((80, 40), (48, 20)):
        with Session('stream-output', columns=columns, lines=lines) as session:
            session.send('3\n')
            session.expect('Введите значение:')
            screen = CSI.sub('', current_screen(session)).replace('\r', '')
            assert '✅ Готово\n☁️ Облако\n⚠️ Ошибка\n' in screen, screen
            assert 'PATH=/root/a  b/key.pem' in screen, screen
            session.send('\n')
            session.expect(PAUSE)
            session.send('\n')
            session.expect(PROMPT)
            session.send('0\n')
            session.finish()
        with Session('long-output', columns=columns, lines=lines) as session:
            session.send('3\n')
            session.expect('REPORT_LINE=74')
            session.expect(PAUSE)
            raw = current_screen(session)
            assert_shared_header(raw, columns)
            region = re.search(r'\x1b\[(\d+);(\d+)r', raw)
            assert region and 8 < int(region.group(1)) < int(region.group(2)) <= lines, repr(raw)
            session.send('\x03')
            session.expect(PROMPT)
            assert '\x1b[r' in session.output, 'Long output cancellation left restricted scroll region'
            session.send('0\n')
            session.finish()


def narrow_vs16_cursor_cells():
    for columns, lines in ((80, 40), (48, 20)):
        for capability in ({}, {'no_color': True}, {'env': {'NO_COLOR': '1'}}):
            with Session('vs16-output', columns=columns, lines=lines, **capability) as session:
                for glyph in ('⚙️', '🗑️', '☁️', '⬅️'):
                    assert_vs16_geometry(current_screen(session), glyph, columns, lines)
                session.send('6\n')
                session.expect(PROMPT)
                assert_vs16_geometry(current_screen(session), '☁️', columns, lines)
                session.send('0\n')
                session.expect(PROMPT)
                session.send('3\n')
                session.expect('Введите значение:')
                raw = current_screen(session)
                for glyph in ('⚙️', '🗑️', '☁️'):
                    assert_vs16_geometry(raw, glyph, columns, lines)
                if capability:
                    assert not SGR.search(session.output), 'Color emitted in no-color mode'
                session.send('\n')
                session.expect(PAUSE)
                session.send('\n')
                session.expect(PROMPT)
                session.send('0\n')
                session.finish()


def vertical_install_modes():
    for columns, lines in ((80, 40), (48, 20)):
        for mode, marker in (('0', 'MODE_CANCELLED'), ('2', 'MODE_GUIDE')):
            with Session('install-mode', columns=columns, lines=lines) as session:
                session.send('1\n')
                session.expect('Режим')
                session.expect('[1]:')
                raw = current_screen(session)
                plain = CSI.sub('', raw).replace('\r', '')
                assert 'Режим установки' in plain, plain
                options = [line for line in plain.splitlines() if re.match(r'^\s*[120]\)', line)]
                assert [re.match(r'^\s*([120])\)', line).group(1) for line in options] == ['1', '2', '0'], plain
                for number in ('1', '2', '0'):
                    assert re.search(r'\x1b\[1m\s*' + number + r'\x1b\[0m\)', raw), raw
                assert_shared_header(raw, columns)
                session.send(mode + '\n')
                session.expect(marker)
                session.expect(PAUSE)
                session.send('\n')
                session.expect(PROMPT)
                session.send('0\n')
                session.finish()


def streaming_vs16_edge_and_buffer_order():
    for columns, lines in ((80, 40), (48, 20)):
        for scenario in ('vs16-edge', 'vs16-buffered'):
            with Session(scenario, columns=columns, lines=lines) as session:
                session.send('3\n')
                if scenario == 'vs16-buffered':
                    session.expect('Введите значение:')
                else:
                    session.expect(PAUSE)
                raw = current_screen(session)
                glyphs = ('⚙️', '☁️', '🗑️', '⬅️') if scenario == 'vs16-edge' else ('⚙️', '☁️', '🗑️')
                for glyph in glyphs:
                    assert_vs16_geometry(raw, glyph, columns, lines)
                if scenario == 'vs16-buffered':
                    assert '☁️ Облако' in CSI.sub('', raw), 'Interleaved streams reordered buffered bytes'
                    session.send('\n')
                    session.expect(PAUSE)
                session.send('\n')
                session.expect(PROMPT)
                assert '\x1b[r' in session.output
                session.send('0\n')
                session.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', help=argparse.SUPPRESS)
    parser.add_argument('--no-color', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        child(args.child, args.no_color)
        return
    if os.name != 'posix':
        parser.error('Run in Linux/WSL: python3 tests/pty_menu_check.py')
    checks = [back_and_cancel, invalid_and_results, sequential_main_actions, operation_modes,
              input_cancel_and_operation_interrupt, eof_at_every_level,
              confirmation_defaults_to_no, terminal_capabilities_and_layout, redirected_output,
              shared_headers_direct_docker_and_operation_regions, operation_stream_and_long_report,
              narrow_vs16_cursor_cells, vertical_install_modes, streaming_vs16_edge_and_buffer_order]
    for check in checks:
        check()
        print('PASS ' + check.__name__, flush=True)
    print('PASS offline PTY acceptance: no installation, ACME or host mutations')


if __name__ == '__main__':
    main()
