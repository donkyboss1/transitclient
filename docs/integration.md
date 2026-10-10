# 📖 Подключение selfsteal к существующей инфраструктуре

В 1.1.0 установщик управляет только своим изолированным Caddy через Docker
Compose. Фрагменты ниже — ручная альтернативная интеграция для владельца,
а не готовый режим автоматического продления. Нельзя просто добавить их
рядом с уже работающим selfsteal на том же адресе/порту.

## VPN target

Для ноды в host network/на host используйте `127.0.0.1:9443` или выбранный
HTTPS-порт. В bridge-контейнере loopback указывает на сам контейнер: выбирайте
существующую user-defined bridge-сеть и target
`transitclient-selfsteal:<HTTPS-порт>`. Подключается только Caddy; VPN уже должна
принадлежать этой сети. Не переводите работающую ноду на host network и
не публикуйте HTTPS наружу ради обхода изоляции.

REALITY: `serverNames` содержит выданный домен, `target` — выбранный адрес,
`xver: 0`. Конфигурацию проверьте своей версией Xray; старые версии могут
использовать `dest`. UUID/privateKey остаются средствами панели.
Пример: [официальный REALITY](https://github.com/XTLS/REALITY/blob/main/README.en.md).
Обычный TLS inbound требует отдельной настройки certificate/private-key.
После локальной проверки нажмите в боте «Готово, проверить backend» и проверьте
VPN реальным клиентом. Открытый TCP-порт не подтверждает REALITY.

## Перед ручной интеграцией

1. Определите экземпляр: службу/контейнер, конфигурационный файл, include/prefix
   и web worker. Команды ниже для стандартных служб Ubuntu; custom/container
   требуют путей и команд своего экземпляра. Установщик чужой `exec` не запускает.
2. Выберите свободный локальный HTTPS-порт. `ss -lntp` дополните проверкой
   опубликованных Docker-портов: NAT может не иметь процесса в `ss`.
3. Сделайте защищённую backup только затрагиваемых файлов с metadata,
   запишите SHA256, подготовьте отдельный include. Не выводите ключ в терминал.
4. `DOMAIN`, `CERT_PATH`, `KEY_PATH`, `SITE_PATH` — placeholders: подставьте
   настоящий домен и абсолютные пути. Web worker должен читать ключ через
   ограниченную группу/ACL; не делайте ключ общедоступным и не расширяйте
   права всего state. Эти фрагменты нельзя копировать без правки.
5. Проверьте полную итоговую конфигурацию. При ошибке оставьте работающую службу
   и уберите неприменённый фрагмент. Reload согласуйте с владельцем.

Backup-пример для уже определённого include-файла:

```bash
sudo install -d -m 700 /root/transitclient-manual-backup
sudo cp -a /ПОЛНЫЙ/ПУТЬ/К/ФАЙЛУ /root/transitclient-manual-backup/
sudo sha256sum /ПОЛНЫЙ/ПУТЬ/К/ФАЙЛУ
```

Если создаёте фрагмент, отметьте отсутствие прежнего файла. Не занимайте имя
другого сайта. Backup с ключом/account храните закрыто.

## Caddy

Добавьте отдельный site block в согласованный include, не меняя глобальные
`auto_https`, admin endpoint и другие сайты:

```caddyfile
https://DOMAIN:9443 {
    bind 127.0.0.1
    tls CERT_PATH KEY_PATH
    root * SITE_PATH
    file_server
}
```

Validate всей конфигурации, затем reload конкретного экземпляра с принудительным
перечитыванием TLS-файлов:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo caddy reload --force --config /etc/caddy/Caddyfile --adapter caddyfile
```

Для custom admin socket укажите его адрес согласно конфигурации экземпляра.
Не обращайтесь к TCP 2019, не выяснив владельца.
Документация: [Caddy CLI](https://caddyserver.com/docs/command-line).

## Nginx

```nginx
server {
    listen 127.0.0.1:9443 ssl;
    server_name DOMAIN;
    ssl_certificate CERT_PATH;
    ssl_certificate_key KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    root SITE_PATH;
    location / { try_files $uri $uri/ =404; }
}
```

HTTP/2 настройте по своей версии Nginx: директивы менялись. Сначала полная
проверка, затем согласованный reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Custom config требует своих `-c`/`-p` и точной службы.
Документация: [Nginx](https://nginx.org/en/docs/beginners_guide.html).

## Apache

Нужные TLS-модули должны быть доступны; изменение модулей и глобальных настроек
согласуется отдельно. `Listen` добавляется ровно один раз:

```apache
Listen 127.0.0.1:9443
<VirtualHost 127.0.0.1:9443>
    ServerName DOMAIN
    SSLEngine on
    SSLCertificateFile CERT_PATH
    SSLCertificateKeyFile KEY_PATH
    DocumentRoot SITE_PATH
    <Directory "SITE_PATH">
        Require all granted
    </Directory>
</VirtualHost>
```

Проверка/reload стандартного экземпляра:

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Документация: [Apache apachectl](https://httpd.apache.org/docs/2.4/programs/apachectl.html).

## Проверка и откат

Проверьте реально выдаваемый сертификат с SNI, trust, SAN, сроком, TLS 1.3/h2,
затем HTTPS из сети VPN. Успех на host не доказывает доступность из bridge.
При отсутствии инструмента в ноде не меняйте её образ; используйте свой
диагностический контейнер с pinned образом и явно выбранной сетью.

```bash
openssl s_client -connect 127.0.0.1:9443 -servername DOMAIN \
  -verify_hostname DOMAIN -verify_return_error -alpn h2 -tls1_3 </dev/null
```

Для отката сравните текущий фрагмент с записанной версией после интеграции.
Позднейшие правки клиента не затирайте backup: восстановите согласованный diff.
Удалите созданный фрагмент либо верните его копию, повторите validate/configtest
и лишь затем reload. Проверьте прежние сайты/selfsteal. Общую службу не останавливайте.

HTTP-01 требует отдельного свободного порта: занятый 8080 согласуйте сначала
в боте. Webroot и произвольные root-shell renewal hooks в 1.1.0 не поддерживаются.
Timer установщика проверяет свой Caddy; он не знает, как безопасно reload чужой
сервер. До проверенного adapter выпуск, применение и проверка сертификата
внешней интеграции остаются обязанностью владельца.
