#!/usr/bin/env bash
# Tenant selfsteal, adapted from Selfsteal 2.10.0.
# Original author: DigneZzZ (https://github.com/DigneZzZ), project gig.ovh.
# MIT; see LICENSE and NOTICE.md. No upstream self-update endpoint.
set -euo pipefail
umask 077

# Publication fills these three values together. Never guess a repository URL.
RELEASE_URL=''
RELEASE_VERSION=''
RELEASE_SHA256=''

fail() { printf '\n❌ %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
🚀 transitclient — автономный установщик арендатора
Локальный пакет: sudo bash ./selfsteal.sh [команда]
Проверенный релиз:
  bash selfsteal.sh --package-url HTTPS_URL --version VERSION --sha256 SHA256 [-- команда]
Без команды открывается меню. Публичный адрес пока не назначен.
Bootstrap только проверяет и запускает пакет; изменения подтверждаются в меню.
HELP
}

bootstrap=false
while (($#)); do
    case "$1" in
        --package-url|--version|--sha256)
            (($# >= 2)) || fail "Для $1 нужно значение."
            case "$1" in
                --package-url) RELEASE_URL=$2 ;;
                --version) RELEASE_VERSION=$2 ;;
                --sha256) RELEASE_SHA256=$2 ;;
            esac
            bootstrap=true
            shift 2 ;;
        --bootstrap-help) usage; exit 0 ;;
        --) shift; break ;;
        *) break ;;
    esac
done

# sudo can give a piped Bash a separate PTY whose input is not forwarded.
# Fail before the controller waits on /dev/tty; use a downloaded file instead.
if [[ ! -t 0 && -n "${SUDO_COMMAND:-}" ]]; then
    case "${1:-menu}" in
        menu|install|configure|template|update|uninstall)
            fail 'Интерактивный запуск через pipe + sudo не поддерживается. Скачайте install.sh в файл и запустите sudo bash ./install.sh install; от root запускайте bash без sudo.' ;;
    esac
fi

command -v python3 >/dev/null 2>&1 || fail 'Нужен Python ≥3.10. На Ubuntu сначала выполните sudo apt-get update && sudo apt-get install python3, затем повторите запуск.'
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || fail 'Нужен Python ≥3.10; существующий Python не заменён.'

# Bash stdin may contain the bootstrap text when invoked through a pipe.
# Read interactive answers only from the terminal, never from script contents.
controller() {
    if [[ ! -t 0 && -r /dev/tty ]] && (: </dev/tty) 2>/dev/null; then
        python3 "$1" "${@:2}" </dev/tty
    else
        python3 "$1" "${@:2}"
    fi
}

SOURCE_DIR=''
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || SOURCE_DIR=''
fi
if [[ "$bootstrap" == false && -n "$SOURCE_DIR" && -f "$SOURCE_DIR/selfsteal.py" && -f "$SOURCE_DIR/dependencies.json" ]]; then
    controller "$SOURCE_DIR/selfsteal.py" "$@"
    exit $?
fi

[[ -n "$RELEASE_URL" && -n "$RELEASE_VERSION" && -n "$RELEASE_SHA256" ]] || fail 'Публичный релиз ещё не настроен. Используйте полный локальный пакет либо укажите --package-url, --version и --sha256 из проверенного релиза владельца.'

# Validate before even contacting the network; do not echo URL credentials.
python3 - "$RELEASE_URL" "$RELEASE_VERSION" "$RELEASE_SHA256" <<'VALIDATE'
import re
import sys
from urllib.parse import urlsplit
try:
    url = urlsplit(sys.argv[1])
    valid = (url.scheme == 'https' and url.hostname and '@' not in url.netloc and not url.username
             and not url.password and not url.fragment and url.port in (None, 443)
             and not any(ord(c) < 33 or ord(c) == 127 for c in sys.argv[1])
             and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?', sys.argv[2])
             and re.fullmatch(r'[0-9a-fA-F]{64}', sys.argv[3]))
except ValueError:
    valid = False
if not valid:
    sys.exit('❌ Нужны HTTPS URL без авторизации/fragment, точная версия и SHA256 (64 hex).')
VALIDATE

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/transitclient-bootstrap.XXXXXXXX") || fail 'Не удалось создать временный каталог.'
cleanup() { rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
printf '\n📦 Загрузка и проверка релиза %s…\n' "$RELEASE_VERSION"
if command -v curl >/dev/null 2>&1; then
    (ulimit -f 32768; curl --fail --silent --location --proto '=https' --proto-redir '=https' \
        --tlsv1.2 --connect-timeout 15 --max-time 180 --max-filesize 16777216 \
        --output "$TMP_DIR/package.tar.gz" -- "$RELEASE_URL") || fail 'Не удалось получить релиз по HTTPS. Проверьте адрес и сеть.'
elif command -v wget >/dev/null 2>&1; then
    # --https-only also applies to redirect targets. Hash/extraction limits below
    # reject oversized archives, even on wget without a download-size option.
    (ulimit -f 32768; wget --quiet --https-only --timeout=30 --tries=1 --max-redirect=10 \
        --output-document="$TMP_DIR/package.tar.gz" -- "$RELEASE_URL") || fail 'Не удалось получить релиз по HTTPS. Проверьте адрес и сеть.'
else
    fail 'Нужен curl или wget. Установите выбранный инструмент и повторите запуск.'
fi

# BEGIN SAFE_EXTRACTOR (also exercised by offline tests)
python3 - "$TMP_DIR/package.tar.gz" "$TMP_DIR/package" "$RELEASE_VERSION" "$RELEASE_SHA256" <<'EXTRACT'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_MEMBERS = 2048


def safe_extract(archive_path, destination, version, digest):
    archive_path, destination = Path(archive_path), Path(destination)
    if archive_path.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Архив превышает разрешённый размер.')
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != digest.lower():
        raise ValueError('SHA256 релиза не совпадает; запуск запрещён.')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Каталог распаковки уже существует.')
    required = {'selfsteal.sh', 'selfsteal.py', 'diagnostics.py', 'site_templates.py', 'firewall_setup.py', 'templates.json', 'docs/integration.md', 'dependencies.json', 'VERSION',
                'LICENSE', 'NOTICE.md', 'vendor/acme.sh', 'site/index.html'}
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries, names, total = [], set(), 0
        for entry in archive:
            parts = PurePosixPath(entry.name).parts
            if (not parts or entry.name.startswith('/') or '\\' in entry.name
                    or any(p in ('.', '..') or ':' in p for p in parts)
                    or any(ord(c) < 32 or ord(c) == 127 for c in entry.name)
                    or entry.name != '/'.join(parts)
                    or entry.name in names or not (entry.isfile() or entry.isdir())):
                raise ValueError('Небезопасный путь/тип/дубликат в архиве.')
            names.add(entry.name)
            if entry.size < 0 or entry.size > MAX_EXPANDED:
                raise ValueError('Недопустимый размер файла.')
            total += entry.size
            entries.append(entry)
            if len(entries) > MAX_MEMBERS or total > MAX_EXPANDED:
                raise ValueError('Архив превышает лимиты распаковки.')
        files = {entry.name for entry in entries if entry.isfile()}
        if not required <= files:
            raise ValueError('Релиз неполон: отсутствуют обязательные файлы.')
        if (archive.getmember('VERSION').size > 128
                or archive.extractfile('VERSION').read(128).decode('ascii').strip() != version):
            raise ValueError('Версия архива не совпадает с запрошенной.')
        for entry in entries:
            for parent in PurePosixPath(entry.name).parents:
                if str(parent) != '.' and str(parent) in files:
                    raise ValueError('Файл используется как родительский каталог.')
        # No extractall: links, devices, permissions and owner metadata are ignored.
        destination.mkdir(mode=0o700)
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.name).parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(entry) as source, target.open('xb') as output:
                    remaining = entry.size
                    while remaining:
                        block = source.read(min(65536, remaining))
                        if not block:
                            raise ValueError('Оборванный файл в архиве.')
                        output.write(block)
                        remaining -= len(block)
                target.chmod(0o700 if entry.name == 'selfsteal.sh' else 0o600)
        deps = json.loads((destination / 'dependencies.json').read_text(encoding='utf-8'))
        acme_digest = deps['acme']['sha256']
        if (not re.fullmatch(r'[0-9a-f]{64}', acme_digest)
                or hashlib.sha256((destination / 'vendor/acme.sh').read_bytes()).hexdigest() != acme_digest):
            raise ValueError('Встроенный acme.sh не соответствует манифесту.')


if __name__ == '__main__':
    try:
        safe_extract(*sys.argv[1:])
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError):
        sys.exit('❌ Проверка релиза не пройдена: SHA256, версия, структура или зависимости. Ничего не установлено.')
EXTRACT
# END SAFE_EXTRACTOR
printf '✅ Релиз проверен. Запуск установщика…\n'
controller "$TMP_DIR/package/selfsteal.py" "$@"
