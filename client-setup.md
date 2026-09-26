# TyProxy — Полное руководство по настройке клиента

Документ описывает **полный** цикл настройки клиентской машины: от получения бинарника и редактирования `config.toml` до тонкой настройки приложений (браузер, Telegram, Proxifier/proxychains), автозапуска в разных ОС, защиты от утечек и диагностики. Это «парная» часть к [`deployment.md`](deployment.md): там подробно разобрана сторона сервера/хостинга, здесь — сторона пользователя. Разобранный код: `src/main.rs`, `src/client.rs`, `src/config.rs`, `src/crypto.rs`, `src/modules/socks5.rs`, `src/modules/tun.rs`.

Для установки вам понадобится только две вещи от владельца сервера: **адрес `IP:порт`** и, если порт нестандартный, просто номер. Никаких токенов, паролей и сертификатов настраивать не нужно (почему — см. раздел 11).

---

## Содержание

1. [Что настраивается на стороне клиента](#1-что-настраивается-на-стороне-клиента)
2. [Получение бинарника](#2-получение-бинарника)
3. [Формат конфигурации `config.toml` для клиента](#3-формат-конфигурации-configtoml-для-клиента)
4. [Настройка клиента Linux: SOCKS5](#4-настройка-клиента-linux-socks5)
5. [Настройка клиента Linux: режим TUN (VPN на весь трафик)](#5-настройка-клиента-linux-режим-tun-vpn-на-весь-трафик)
6. [Настройка клиента Windows (только SOCKS5)](#6-настройка-клиента-windows-только-socks5)
7. [Настройка клиента macOS (только SOCKS5)](#7-настройка-клиента-macos-только-socks5)
8. [Привязка приложений к SOCKS5](#8-привязка-приложений-к-socks5)
9. [Как использовать SOCKS5 как глобальный VPN, если хостер выключил TUN?](#9-как-использовать-socks5-как-глобальный-vpn-если-хостер-выключил-tun)
10. [Автозапуск клиента как сервиса](#10-автозапуск-клиента-как-сервиса)
11. [Что нужно знать о приватности](#11-что-нужно-знать-о-приватности)
12. [Диагностика типовых проблем клиента](#12-диагностика-типовых-проблем-клиента)
13. [Удаление / полная отмена настроек](#13-удаление--полная-отмена-настроек)
14. [Приложение A. Чек-лист настройки клиента](#14-приложение-a-чек-лист-настройки-клиента)
15. [Приложение B. Эталонные клиентские конфиги](#15-приложение-b-эталонные-клиентские-конфиги)

---

## 1. Что настраивается на стороне клиента

Клиент TyProxy — это **тот же самый бинарник**, что и сервер; роль выбирается полем `mode = "client"` в `config.toml` (или интерактивным выбором при `mode = "ask"`). После запуска клиент:

1. Устанавливает **одно** TLS 1.3 соединение с сервером (`server_host`), с ALPN `typroxy` и **отключенной верификацией сертификата** (`NoCertificateVerification` в `crypto.rs`) — поэтому никаких CA/отпечатков настраивать не нужно.
2. Поднимает локальную точку входа в туннель — один из двух взаимозаменяемых модулей (поле `routing_mode`):
   * `socks5` — локальный SOCKS5-прокси на `socks_bind_addr` (по умолчанию `127.0.0.1:1080`), поддерживает TCP CONNECT и UDP ASSOCIATE;
   * `tun` — виртуальный L3-интерфейс, перехватывающий **весь** трафик ОС (**только Linux**, требует root).
3. Мультиплексирует все сессии поверх единственного TLS-канала.

### Ключевые особенности кода, влияющие на настройку

1. **Нет автоматического переподключения.** При обрыве TLS-канала клиент печатает `[-] Потеряно соединение с сервером.` и завершает цикл чтения. Для надежной работы нужен systemd/Task Scheduler с рестартом (раздел 10).
2. **Первый запуск «холостой».** Если `config.toml` нет рядом с рабочей директорией, бинарник создает его с комментариями и **завершается с кодом 0**. Нужно отредактировать файл и запустить повторно.
3. **TUN существует только на Linux.** На Windows/macOS/FreeBSD режим `tun` вернет ошибку `UnsupportedPlatform` — клиентам доступен только SOCKS5.
4. **Секция `[server]` обязательна в конфиге клиента** даже при `mode = "client"` — сериализация `Config` требует наличия обеих секций, иначе парсинг упадет с ошибкой.
5. **Поле `wallet_path` ни на что не влияет** — оно читается, но нигде в коде не используется.
6. **DNS в TUN-режиме** переключается на 1.1.1.1/8.8.8.8 автоматически **только при наличии `systemd-resolved`**; иначе DNS остается прежним и может утекать наружу (раздел 5).

---

## 2. Получение бинарника

### 2.1. Готовый бинарник (рекомендуется)

Готовые бинарники лежат **прямо в репозитории GitHub**: <https://github.com/lohrrrr/TyProxy.git> (клонировать не обязательно — можно скачать нужный файл через веб-интерфейс, кнопка *Download raw file*; либо целиком: `git clone https://github.com/lohrrrr/TyProxy.git`). Скачайте файл под свою платформу и переименуйте в `typroxy` (Windows — `typroxy.exe`):

| Платформа | Файл в `./dist/` | Примечание |
|---|---|---|
| Linux x86_64 | `typroxy-linux-amd64` | оба режима (SOCKS5 + TUN) |
| Windows x64 | `typroxy-windows-amd64.exe` | только SOCKS5 |
| macOS Apple Silicon | `typroxy-darwin-arm64` | только SOCKS5 |
| macOS Intel | `typroxy-darwin-amd64` | только SOCKS5 |
| FreeBSD | `typroxy-freebsd-amd64` | только SOCKS5 |

Проверьте целостность — **SHA256-суммы лежат в репозитории рядом с каждым бинарником** (в `./dist/`, файл вида `typroxy-linux-amd64.sha256`; на странице файла на GitHub сумма показана прямо над кнопкой *Download raw file*):

```bash
# Linux/macOS — скачайте .sha256 рядом с бинарником и проверьте:
sha256sum -c typroxy-linux-amd64.sha256        # или сверить вручную:
sha256sum typroxy-linux-amd64
# Windows:
certUtil -hashfile typroxy-windows-amd64.exe SHA256
```

### 2.2. Сборка самому

```bash
git clone https://github.com/lohrrrr/TyProxy.git
cd TyProxy
cargo build --release            # результат: target/release/typroxy
# либо конкретный таргет:
make linux        # dist/typroxy-linux-amd64
make windows      # dist/typroxy-windows-amd64.exe (нужен mingw-w64)
make darwin       # dist/typroxy-darwin-arm64 (нужны zig + cargo-zigbuild)
```

Подробно тулчейн и кросс-компиляция разобраны в разделах 4–5 `deployment.md`.

### 2.3. Размещение файлов

Бинарник и `config.toml` должны лежать **в одной рабочей директории** (либо указывайте путь через `-c`):

* **Linux:** `/usr/local/bin/typroxy` + конфиг `/etc/typroxy/config.toml` (запуск `sudo typroxy -c /etc/typroxy/config.toml`); либо простая папка `~/typroxy/`.
* **Windows:** `C:\typroxy\typroxy.exe` + `C:\typroxy\config.toml`.
* **macOS:** `~/Applications/typroxy` + `config.toml` рядом; снимите карантин (раздел 7).

---

## 3. Формат конфигурации `config.toml` для клиента

Файл ищется **в текущей рабочей директории** под именем `config.toml` (или по пути из флага `-c/--config`). Если его нет — программа создаст шаблон и завершится. Клиентские поля (ровно как в `src/config.rs`):

```toml
mode = "client"                 # без этого бинарник поднимет сервер (или спросит в "ask")

[server]
bind_addr   = "0.0.0.0:8888"    # на клиенте игнорируется, но секция обязательна для валидации
wallet_path = "server.wallet"   # декоративное поле, кодом не используется
tun_enabled = false             # на клиенте игнорируется
tun_name    = "typroxy-srv"     # на клиенте игнорируется
tun_ip      = "10.8.0.1"        # на клиенте игнорируется

[client]
server_host     = "SERVER_IP:8888"   # ЕДИНСТВЕННОЕ, что нужно узнать у хостера
routing_mode    = "socks5"           # "socks5" или "tun" (tun — только Linux)
socks_bind_addr = "127.0.0.1:1080"   # локальный SOCKS5 (TCP + UDP ASSOCIATE)
tun_name        = "typroxy-tun"      # имя TUN-интерфейса (режим tun)
tun_ip          = "10.8.0.2"         # адрес клиента внутри туннеля
tun_gateway     = "10.8.0.1"         # «виртуальный» шлюз (= tun_ip сервера)
```

Важные детали семантики (из кода):

* **`server_host` — только IPv4 или домен с A-записью.** Логика исключения сервера из туннеля (`resolve_all_ipv4`) работает лишь с IPv4; для SOCKS5-режима это не критично, но для TUN — обязательно.
* **Не меняйте `tun_ip`/`tun_gateway` без необходимости.** Сервер жестко назначает себе destination `10.8.0.2` на своем TUN и строит NAT для подсети `10.8.0.0/24`. Сломаете адресацию — маршрутизация перестанет работать.
* **`socks_bind_addr = "127.0.0.1:1080"`** — безопасно держать локальным. Привязка к `0.0.0.0` откроет открытый прокси всей вашей сети/LAN.
* Значения `tun_*` имеют смысл только при `routing_mode = "tun"`, а `socks_bind_addr` — только при `"socks5"`.

---

## 4. Настройка клиента Linux: SOCKS5

Самый простой способ, не требует root, работает на любой платформе.

1. Первый запуск создаст конфиг и выйдет:

```bash
mkdir -p ~/typroxy && cd ~/typroxy
cp /путь/к/typroxy-linux-amd64 ./typroxy && chmod +x ./typroxy
./typroxy                      # создаст config.toml и завершится (код 0)
nano config.toml               # mode="client", server_host="IP:ПОРТ", routing_mode="socks5"
```

2. Запуск:

```bash
./typroxy
```

Ожидаемый вывод (ровно эти строки печатает `src/client.rs` / `src/modules/socks5.rs`):

```
[*] Подключение к TLS TyProxy серверу (SERVER_IP:8888)
[+] Защищенное TLS-соединение установлено!
[*] Выбран режим перехвата трафика: SOCKS5
[+] Модуль SOCKS5 запущен на 127.0.0.1:1080
```

3. Проверка из терминала:

```bash
curl -x socks5h://127.0.0.1:1080 -s https://ifconfig.me   # должен вернуть IP СЕРВЕРА
```

`socks5h` — чтобы DNS-имена разрешались на стороне сервера (иначе домен резолвится локально и утекает).

4. Дальше — привязка приложений (раздел 8).

Минус режима: через туннель идет только трафик явно настроенных приложений; системный DNS и приложения без поддержки прокси работают напрямую.

---

## 5. Настройка клиента Linux: режим TUN (VPN на весь трафик)

Перехват **всего** трафика ОС. Требует root.

1. Конфиг:

```toml
mode = "client"

[client]
server_host  = "SERVER_IP:8888"
routing_mode = "tun"
tun_name     = "typroxy-tun"
tun_ip       = "10.8.0.2"
tun_gateway  = "10.8.0.1"
```

2. Запуск:

```bash
sudo ./typroxy -c ./config.toml
```

Ожидаемый вывод:

```
[*] Подключение к TLS TyProxy серверу (SERVER_IP:8888)
[+] Защищенное TLS-соединение установлено!
[*] Выбран режим перехвата трафика: TUN
[+] Защита от утечек IPv6 активна (unreachable default ::/0)
[+] DNS-серверы (1.1.1.1, 8.8.8.8) настроены через systemd-resolved для 'typroxy-tun'
```

Строка про DNS появится **только если** в системе работает `systemd-resolved` (код проверяет наличие команды `resolvectl`). Если её нет — DNS останется прежним и будет утекать наружу: пропишите DNS вручную или поставьте resolved/dnscrypt.

3. Что код делает автоматически (функция `setup_routes` в `src/modules/tun.rs`):

   * резолвит `server_host` и добавляет **прямые маршруты до IP сервера через реальный шлюз** — трафик до самого сервера не попадает в туннель (защита от петли);
   * создает интерфейс `typroxy-tun` с адресом `10.8.0.2/24`;
   * добавляет маршруты `0.0.0.0/1` и `128.0.0.0/1` через туннель — **default-шлюз системы не затирается**;
   * ставит `net.ipv4.conf.typroxy-tun.rp_filter=2`;
   * добавляет `ip -6 route add unreachable default metric 1` — профилактика IPv6-утечек (приложения быстро падают на IPv4-туннель);
   * при наличии `systemd-resolved`: `resolvectl dns typroxy-tun 1.1.1.1 8.8.8.8`, `resolvectl domain typroxy-tun ~.`, `resolvectl default-route typroxy-tun true`.

4. Проверка:

```bash
curl -s ifconfig.me                     # должен вернуть IP сервера
ip route show match 0.0.0.0/1           # два /1-маршрута через typroxy-tun
dig +short myip.opendns.com @resolver1.opendns.com   # проверка отсутствия DNS-утечки
```

5. **Остановка — только корректная** (`Ctrl+C` или `systemctl stop`). Структура `RouteGuard` в деструкторе удаляет все добавленные маршруты, правила IPv6 и настройки DNS — сеть возвращается в исходное состояние. **Не убивайте процесс через `kill -9` (SIGKILL)** — после него маршруты останутся висеть и интернет «перестанет работать» до ручной чистки:

```bash
sudo ip route del 0.0.0.0/1 dev typroxy-tun
sudo ip route del 128.0.0.0/1 dev typroxy-tun
sudo ip -6 route del unreachable default metric 1
sudo resolvectl revert typroxy-tun   # если DNS настраивался
```

6. Автозапуск как сервис — раздел 10.1.

---

## 6. Настройка клиента Windows (только SOCKS5)

1. Создайте папку `C:\typroxy`, положите в нее `typroxy-windows-amd64.exe`, переименуйте в `typroxy.exe`.
2. Запустите двойным кликом — окно мелькнет и закроется? Это нормально: первый запуск только создает `config.toml` и завершается. Откройте `C:\typroxy\config.toml` блокнотом и отредактируйте:

```toml
mode = "client"

[client]
server_host     = "SERVER_IP:8888"
routing_mode    = "socks5"
socks_bind_addr = "127.0.0.1:1080"
```

3. Запустите `typroxy.exe` снова. В консольном окне (cmd) ожидаемое то же, что в разделе 4.
4. **Windows Defender Firewall** при первом запросе разрешите исходящие соединения для программы (исходящие обычно не блокируются; проблема возникает редко).
5. Перехват «всего системного трафика» в Windows делается сторонним **Proxifier** с правилом на `127.0.0.1:1080` (SOCKS5) — см. раздел 8.3.
6. Автозапуск — раздел 10.2.

> Режим `tun` на Windows нерабочий: вспомогательные функции маршрутизации (`route add/delete`) в коде есть, но само TUN-устройство не создаётся (`UnsupportedPlatform`).

---

## 7. Настройка клиента macOS (только SOCKS5)

1. Скачайте `typroxy-darwin-arm64` (Apple Silicon) или `typroxy-darwin-amd64` (Intel), положите в `~/typroxy/`, `chmod +x`.
2. Первый запуск в Terminal: `./typroxy` — создаст конфиг и выйдет. Отредактируйте `config.toml` (как в разделе 6, п.2).
3. Gatekeeper может заблокировать неподписанный бинарник («не удается открыть, так как разработчик не проверен»). Снимите блокировку одним из способов:
   * System Settings → Privacy & Security → «Все равно открыть»;
   * либо `xattr -d com.apple.quarantine ./typroxy`.
4. Запустите снова — дождитесь строк `[+] Модуль SOCKS5 запущен на 127.0.0.1:1080`.
5. Системный SOCKS-прокси (действует на большинство приложений, включая браузеры):

```bash
networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 1080
# отключение:
networksetup -setsocksfirewallproxystate Wi-Fi off
```

6. Автозапуск — раздел 10.3 (launchd).

---

## 8. Привязка приложений к SOCKS5

Локальная точка входа — `127.0.0.1:1080` (SOCKS5, TCP + UDP).

### 8.1. Браузеры

* **Firefox (нативно):** Settings → General → Network Settings → Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `1080`, SOCKS v5; поставьте галочку **Proxy DNS when using SOCKS v5** (резолвинг доменов уйдет через туннель).
* **Chromium:** встроенных настроек нет — расширение SwitchyOmega / FoxyProxy (SOCKS5 `127.0.0.1:1080`), либо запуск с флагом:

```bash
chromium --proxy-server="socks5://127.0.0.1:1080" \
         --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost"
```

(без `~NOTFOUND` Chromium будет резолвить домены напрямую — утечка DNS.)

### 8.2. Мессенджеры и отдельные приложения

* **Telegram Desktop:** Settings → Connection type → Proxy → Add → SOCKS5, сервер `127.0.0.1`, порт `1080`.
* **Discord / Steam / другие:** поддерживают системный прокси или сторонние обертки (см. 8.3).

### 8.3. Приложения без поддержки прокси

* **Linux:** `proxychains4` (конфиг `/etc/proxychains.conf`: `socks5 127.0.0.1 1080`):

```bash
sudo apt-get install -y proxychains4
proxychains4 curl -v https://example.com
proxychains4 some-app
```

* **Windows / macOS:** **Proxifier** — профиль SOCKS/HTTPS `127.0.0.1:1080`, правило «Applications» на нужные `.exe`/.app (или на всё). Именно так получают «VPN на весь компьютер» там, где недоступен TUN-режим.

### 8.4. Только терминал

```bash
export ALL_PROXY=socks5h://127.0.0.1:1080   # curl, wget, git (через сокет), pip...
git config --global http.proxy socks5h://127.0.0.1:1080
```

UDP (голосовые звонки, игры) работает через SOCKS5 UDP ASSOCIATE поверх того же TLS-канала — дополнительных настроек не требуется.

---

## 9. Как использовать SOCKS5 как глобальный VPN, если хостер выключил TUN?

Режим `tun` требует прав на создание виртуального интерфейса — на VPS/облачных машинах хостеры часто его запрещают, а на Windows/macOS он недоступен в принципе (раздел 1, п. 3). Но **глобальный VPN можно собрать на самой клиентской машине**: TyProxy поднимает локальный SOCKS5 на `127.0.0.1:1080`, а любой «VPN-клиент» с поддержкой прокси-аплинка (nekoray, v2rayN, NekoBox, Xray-core) перехватит весь трафик ОС в свой локальный TUN/системный прокси и **перельёт его в SOCKS5 TyProxy**. Цепочка выглядит так:

```
приложения → TUN nekoray (172.16.0.2) → SOCKS5 127.0.0.1:1080 (TyProxy client) → TLS → сервер TyProxy → интернет
```

### 9.1. Шаг 1. Запустите TyProxy-клиент в режиме SOCKS5

Убедитесь, что в `config.toml` стоит `routing_mode = "socks5"` (см. разделы 3–4), и прокси отвечает локально:

```bash
curl -x socks5h://127.0.0.1:1080 https://ipinfo.io/ip   # должен вернуть IP вашего TyProxy-сервера
```

Дальше TyProxy — это просто «локальный SOCKS5-прокси», который нужно куда-то подключить.

### 9.2. Шаг 2. Nekoray (кроссплатформенно: Windows / Linux)

1. Установите nekoray с релизов: <https://github.com/MatsuriDayo/nekoray/releases>.
2. Включите режим **advanced mode** (переключатель внизу окна настроек).
3. Профиль → **Add custom outbound** (Добавить пользовательский исходящий) → тип **socks**, заполните:

| Поле | Значение |
|---|---|
| tag | `typroxy` |
| address | `127.0.0.1` |
| port | `1080` |
| network / protocol | `tcp` / `socks` |
| username / password | оставить пустыми (TyProxy не требует аутентификации) |

4. Сделайте этот outbound **default outlet** (по умолчанию для всего трафика) — в списке аутбаундов выберите `typroxy` как основной.
5. Включите **TUN mode** в настройках nekoray (режим `system` или `gvisor`; на Linux для TUN нужны права — запускайте от root или выдайте бинарнику capabilities, как в разделе 5). Если TUN на самом клиенте тоже недоступен, вместо него включите **System Proxy** (правый клик по профилю → Set system proxy) — перехват будет на уровне системных настроек прокси (без UDP-трафика).
6. Нажмите кнопку подключения. Проверка: откройте `https://2ip.ru` — должен отображаться IP TyProxy-сервера.

Если nekoray ругается, что «нет ни одного сервера»: добавьте любой dummy- inbound-профиль (например, пустой shadowsocks) — при default outlet `typroxy` он не будет использоваться, но клиенту нужна хотя бы одна запись для активации.

### 9.3. Альтернатива: Xray-core напрямую (`freedom` + `socks` outbound)

Тот же трюк без GUI — минимальный `config.json` Xray, где весь трафик уходит в SOCKS5 TyProxy, а TUN поднимает `tun2socks` (входит в состав Xray Panel / nekoray-ядра):

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 10808, "protocol": "dokodemo-door", "settings": { "network": "tcp,udp" } }
  ],
  "outbounds": [
    {
      "tag": "typroxy",
      "protocol": "socks",
      "settings": {
        "servers": [{ "address": "127.0.0.1", "port": 1080 }]
      },
      "streamSettings": { "network": "tcp" }
    }
  ],
  "routing": { "balancers": [], "rules": [], "domainStrategy": "IPOnDemand" }
}
```

Подключите к этому же `127.0.0.1:1080` любой TUN-инструмент (sing-box `tun` inbound c outbound-ом `socks`, tun2socks, WireGuard→local proxy) — принцип идентичен.

### 9.4. v2rayN (Windows)

Профиль → **Add custom transmission link / BLK** либо «Добавить SOCKS-сервер» с адресом `127.0.0.1:1080`, затем выбрать его единственным сервером и включить **TUN mode** (меню «Режим» → «Глобальный PAC» не подходит — нужен именно TUN или «Системный прокси»). Трафик приложения → TUN v2rayN → SOCKS5 TyProxy.

### 9.5. Proxifier (Windows/macOS) — самый простой вариант

В Proxifier достаточно добавить правило «Все приложения → SOCKS `127.0.0.1:1080`» (раздел 6) — он делает то же самое, что TUN-клиенты, только через LSP/WFP-перехват. Это полноценная замена «глобального VPN» для приложений, кроме трафика, идущего мимо стека Winsock (некоторые игры, raw-сокеты).

### 9.6. Ограничения такой схемы

* **Двойной прокси-хоп:** TyProxy-сервер выходит в интернет сам — убедитесь, что ему хватает пропускной способности; лишняя задержка вносит TUN-слой (~несколько мс).
* **DNS:** держите DNS-запросы внутри перехвата (TUN-режим nekoray перекрывает DNS по умолчанию; при «системном прокси» — настройте DoH в браузере, см. раздел 11).
* **Без kill-switch:** если TyProxy упадёт (автопереподключения нет — раздел 1), TUN-клиент начнёт стучаться в мёртвый `127.0.0.1:1080` или, хуже, уйдёт трафик напрямую. Держите сервис TyProxy под systemd/автозапуском (раздел 10) и не отключайте «Block outside»/«Bypass”-правила без нужды.
* Сам TyProxy при этом остаётся без аутентификации — локальный SOCKS5 слушает на `127.0.0.1`, поэтому доступ к туннелю имеют только процессы вашей машины (раздел 11).

---

## 10. Автозапуск клиента как сервиса

Поскольку автопереподключения нет (раздел 1), для стабильной работы процесса нужен менеджер служб с рестартом.

### 10.1. Linux (systemd)

`/etc/systemd/system/typroxy-client.service` (SOCKS5-режим):

```ini
[Unit]
Description=TyProxy TLS tunnel client (SOCKS5)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/YOU/typroxy
ExecStart=/home/YOU/typroxy/typroxy -c /home/YOU/typroxy/config.toml
Restart=on-failure
RestartSec=3
User=YOU

[Install]
WantedBy=multi-user.target
```

Активация:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now typroxy-client
journalctl -u typroxy-client -f
```

Для **TUN-режима**: `User=root` (создание интерфейса/route/rp_filter требуют root), остальное идентично. Учитывайте: при обрыве TLS-канала процесс завершится штатно — `RouteGuard` очистит маршруты, а systemd поднимет клиента заново.

> Важно: убедитесь, что `config.toml` уже отредактирован и содержит `mode = "client"`. Иначе systemd зациклит «запустился–создал конфиг–вышел» (см. раздел 1, п.2).

### 10.2. Windows (автозапуск)

Простейший вариант — ярлык в `shell:startup` (Win+R → `shell:startup`). Для скрытого запуска с рестартом — планировщик:

```powershell
schtasks /Create /TN "TyProxyClient" /TR "C:\typroxy\typroxy.exe" `
  /SC ONSTART /RU SYSTEM /F
```

(Консольное окно можно свернуть запуском через `wscript`-обертку или NSSM как службу.)

### 10.3. macOS (launchd)

`~/Library/LaunchAgents/com.typroxy.client.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.typroxy.client</string>
  <key>ProgramArguments</key><array>
    <string>/Users/YOU/typroxy/typroxy</string>
    <string>-c</string><string>/Users/YOU/typroxy/config.toml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/typroxy.log</string>
</dict></plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.typroxy.client.plist
```

Не забудьте вместе с клиентом включить системный SOCKS-прокси (`networksetup`, раздел 7, п.5) — launchd сам прокси не настраивает.

---

## 11. Что нужно знать о приватности

Эти свойства — следствия реализации, их нельзя «настроить», их нужно учитывать:

1. **Туннель шифруется, но не аутентифицируется.** Клиент использует `NoCertificateVerification` и принимает любой сертификат сервера. Теоретически возможен MITM: тот, кто перехватит маршрут, сможет деанонимизировать ваш трафик. Для личного использования риск обычно приемлем, но знать об этом обязательно.
2. **Сервер — открытый relay.** Доступ к серверу имеет любой, кто знает `IP:порт`. Ваша приватность целиком зависит от того, насколько вы доверяете хостеру (если сервер не ваш — владелец видит метаданные подключений).
3. **DNS в SOCKS5-режиме** не защищен автоматически: он уходит через туннель только если приложение резолвит имена через прокси (`socks5h`, «Proxy DNS» в Firefox) или если вы включили системный прокси/DNS самостоятельно.
4. **IPv6 в TUN-режиме** блокируется best-effort (`unreachable default`), но если команда не прошла — возможны утечки; проверьте тестами на утечки.
5. **Отсутствие автопереподключения** означает: при обрыве трафик клиента пойдет **напрямую** (fail-open). Если это неприемлемо — держите сервис с `Restart=` (раздел 10) и/или kill-switch на уровне фаервола.

---

## 12. Диагностика типовых проблем клиента

| Симптом | Причина | Решение |
|---|---|---|
| `[-] Ошибка привязки SOCKS5 к 127.0.0.1:1080` | Порт занят (другой прокси/старый процесс) | `ss -ltnp \| grep 1080`, смените `socks_bind_addr` или завершите конфликтующий процесс |
| `[-] Потеряно соединение с сервером.` сразу или через время | Обрыв TLS-канала; автопереподключения нет | Перезапуск; systemd-сервис (раздел 10); проверьте доступность сервера у хостера |
| `[-] Ошибка модуля TUN: ... Проверьте root/sudo права!` | TUN без root / нет `/dev/net/tun` | `sudo`; в контейнере пробросьте `/dev/net/tun` и `NET_ADMIN` |
| `UnsupportedPlatform` при `routing_mode = "tun"` | Windows/macOS/FreeBSD | Используйте SOCKS5 + Proxifier (разделы 6–8) |
| TUN поднялся, но интернета нет | Сервер не настроил NAT/iptables, либо сервер упал после ребута | Обратитесь к хостеру: разделы 8–9 `deployment.md` |
| После `kill -9` сеть «сломана» | Маршруты остались висеть | Ручная чистка из раздела 5, п.5 |
| `curl ifconfig.me` возвращает домашний IP | Приложение не через прокси / резолвится локально | Используйте `socks5h`, проверьте привязку приложения (раздел 8) |
| Chrome не ходит через прокси | Chromium не берет системный прокси так, как ожидается | Расширение SwitchyOmega или флаги из раздела 8.1 |
| macOS: «программа не может быть открыта» | Gatekeeper/карантин | `xattr -d com.apple.quarantine ./typroxy` (раздел 7) |
| Конфиг не создан / ошибка парсинга TOML | Не удалена секция `[server]`, опечатка | Сверьтесь с эталоном раздела 14 |

Полезные проверки связности:

```bash
nc -vz SERVER_IP 8888                 # TCP-порт сервера доступен?
openssl s_client -connect SERVER_IP:8888 -alpn typroxy   # TLS-хендшейк проходит?
curl -x socks5h://127.0.0.1:1080 -sv https://example.com -o /dev/null
```

---

## 13. Удаление / полная отмена настроек

**Linux (SOCKS5):** остановите сервис (`sudo systemctl disable --now typroxy-client`), удалите юнит и файлы (`rm -rf ~/typroxy`). Системных следов нет.

**Linux (TUN):** корректно остановите процесс (`Ctrl+C`/`systemctl stop`) — `RouteGuard` сам уберет маршруты, IPv6-правило и DNS. Затем удалите файлы. Если остались висеть: команды ручной чистки из раздела 5, п.5.

**Windows:** завершите `typroxy.exe`, удалите папку `C:\typroxy`, задачу из планировщика (`schtasks /Delete /TN TyProxyClient /F`), запись автозагрузки; в Proxifier удалите профиль/правило.

**macOS:** `launchctl unload ~/Library/LaunchAgents/com.typroxy.client.plist`, `networksetup -setsocksfirewallproxystate Wi-Fi off`, удалите файлы.

---

## 14. Приложение A. Чек-лист настройки клиента

- [ ] Бинарник скачан/собран под платформу, проверен SHA256-суммой из репозитория (раздел 2.1)
- [ ] `config.toml` создан первым «холостым» запуском и отредактирован
- [ ] `mode = "client"`; секции `[server]` и `[client]` обе присутствуют
- [ ] `server_host` = `IP:порт` от хостера (IPv4 или домен с A-записью)
- [ ] `routing_mode = "socks5"` (все ОС) или `"tun"` (только Linux + root)
- [ ] Локальная точка входа отвечает: `curl -x socks5h://127.0.0.1:1080 -s https://ifconfig.me` → IP сервера
- [ ] Приложения привязаны (браузер/Telegram/proxychains/Proxifier)
- [ ] (TUN) Проверка утечек: DNS и IPv6
- [ ] (Опционально) Автозапуск с рестартом настроен (systemd / Task Scheduler / launchd)
- [ ] Владелец понимает ограничения: нет автопереподключения, нет аутентификации сервера

---

## 15. Приложение B. Эталонные клиентские конфиги

### B.1. Клиент SOCKS5 (Windows / macOS / Linux)

```toml
mode = "client"

[server]
bind_addr   = "0.0.0.0:8888"
wallet_path = "server.wallet"
tun_enabled = false
tun_name    = "typroxy-srv"
tun_ip      = "10.8.0.1"

[client]
server_host     = "SERVER_IP:8888"
routing_mode    = "socks5"
socks_bind_addr = "127.0.0.1:1080"
tun_name        = "typroxy-tun"
tun_ip          = "10.8.0.2"
tun_gateway     = "10.8.0.1"
```

### B.2. Клиент «VPN на весь компьютер» (Linux)

```toml
mode = "client"

[server]
bind_addr   = "0.0.0.0:8888"
wallet_path = "server.wallet"
tun_enabled = false
tun_name    = "typroxy-srv"
tun_ip      = "10.8.0.1"

[client]
server_host  = "SERVER_IP:8888"
routing_mode = "tun"
tun_name     = "typroxy-tun"
tun_ip       = "10.8.0.2"
tun_gateway  = "10.8.0.1"
```

---

*Документ составлен по состоянию кода версии 0.1.0. Сопутствующие руководства: [README.md](README.md) (обзор проекта) и [deployment.md](deployment.md) (сторона сервера/хостинга).*
