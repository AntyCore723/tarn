<p align="center">
  <img src="mascot/wave.png" width="110" alt="Tarn mascot">
</p>

<a name="en"></a>

# Tarn — Network Research Tool for Chromium

**[English](#en) · [Русский](#ru) · [简体中文](#zh)**

A Chromium extension that runs a tunnel **inside the browser**: import a `.conf` (a configuration *you* already have), click Connect, and browser traffic flows through a real tunnel via a local `wireproxy` instance — no system VPN, no account, no servers.

The repo also ships **DPI research tooling** (a port of the well-known zapret engine family): desync strategies and connectivity diagnostics for studying traffic behavior on your network. All probe targets and domain lists are **user-configurable**; nothing is pre-configured for any specific service — the IP-range table (`engine\conf\ip.lst`) ships with the engine's plain upstream ipset baseline (unlabelled CIDR ranges, no service targeting; see `engine\bins\ATTRIBUTION.md`) and can be trimmed or replaced like any other list.

> **Note**: this project does **not** operate VPN servers, does not sell subscriptions, and provides no ready-to-use endpoint. You bring your own tunnel configuration. The author is not a service provider of any kind. Users are responsible for acquiring or setting up their own servers and for complying with applicable laws in their jurisdiction when using this software.

> **Export notice**: this software contains cryptographic functionality and may be
> subject to export control regulations. See `EXPORT_CONTROL.md` for details.
> Users in embargoed destinations (Cuba, Iran, North Korea, Syria, Crimea Region)
> must ensure compliance with applicable sanctions before downloading or using
> this software.

> **Antivirus notice**: WinDivert and winws are legitimate open-source tools that
> are routinely flagged by antivirus engines (Kaspersky, Windows Defender, ESET).
> These are heuristic detections based on tool capability, not malicious behavior.
> See `SECURITY.md` for details and false-positive reporting guidance.

> **Legal**: Tarn is a network research tool, not a VPN service. See `LEGAL.md`
> for full disclaimer. Users are responsible for compliance with applicable laws.

**Highlights**

<p align="center">
  <img src="mascot/shield1.png" width="80" alt="Shield mascot">
</p>

- **Deterministic extension ID**: `jiadcegfgdohggekdciecfialalkbnpo` — pinned via the `"key"` field in `manifest.json`, so the ID is identical on every machine and never breaks native messaging, no matter where you unpack the folder
- **Zero-touch installer**: double-click `install.bat` — no Admin (one optional UAC prompt creates the `tarndpi` service), no downloads, everything is bundled. It **derives the ID automatically** from `manifest.json` (via `tools/ext_id.py`) — nothing to hardcode or edit. Load the extension first, run `install.bat`, and the popup flips from *"tunnel unavailable"* to *"available"* **by itself** — no reload, no Chrome restart
- MV3 service worker, native-messaging host in Python; no kernel driver needed for the tunnel itself
- Optional packet filter via `winws.exe` + WinDivert
- **Auto strategy selection**: 10 DPI desync strategies ported from the flowseal/zapret family (`fake+fakedsplit` (ALT), `simple fake`, `fake+multisplit` (ALT11), `hostfakesplit` (ALT9), `EXP`, `fake TLS auto` ×2, `multisplit`, `syndata+multidisorder` (ALT5), `fake badseq`); on start the host probes real connectivity to the **configured probe targets** (HTTP, any status = reachable, weighted pass ≥3/5 hosts; targets are user-editable in Settings → Packet filter → "Probe targets"), picks the strategy that works, caches it in `%USERPROFILE%\.tarn-tunnel\dpi_strategy.txt` and reuses it next time. Manual strategy pick + one-click **"Full strategy test"** in Settings → Packet filter: runs every config N times (1–5 passes each), shows a live progress bar with % and per-run log, supports pause/resume/stop, ranks the results and auto-saves the best config. Every file ships inside the zip; bundled binaries are verified against pinned SHA-256 hashes before use (see *Security*).
- **No-UAC DPI service**: `install.bat` creates the `tarndpi` Windows service (via one UAC prompt) with `start= demand` — winws runs **only** while the tunnel is active and never persists across reboots. The service SDDL grants **normal users** the rights to start and stop it (start right = generic-execute `GX` in the SDDL, re-encoded by Windows as `RP`; without it `sc start` fails with "Access is denied (5)" and DPI never comes up), while `SERVICE_CHANGE_CONFIG` (rewriting the strategy ImagePath) is granted **only to the installing user** — not to all Authenticated Users (see *Security*). The host rewrites the service ImagePath for each strategy using the exact quoting format of the DPI service manager (verified with `sc qc` after every change) and probes real connectivity before accepting a strategy. Game-filter flag (`engine\game_filter.enabled`, default `all`) mirrors the validated upstream setup.

---

## Install (3 minutes)

1. **Get the files**
   - **Easy**: download `Tarn-vX.Y.Z.zip` from GitHub Releases → right-click → *Extract All…* to any folder
   - **Dev**: `git clone https://github.com/AntyCore723/tarn.git` — the repo itself is the ready folder, no build step

2. **Load the extension in Chrome**
   - Open `chrome://extensions/`
   - Toggle **Developer mode** (top-right)
   - Click **Load unpacked** → select the folder you just extracted/cloned
   - Tarn appears in your toolbar (pin it)

3. **Install the native host**
   - Open the Tarn popup (toolbar icon) — it shows **"tunnel unavailable"** until the native host is installed. **That is expected.**
   - Double-click `install.bat` **in the extracted folder** (the same folder you loaded in step 2)
   - Seconds after install.bat registers the host, the popup flips to **"available" by itself** — no reload, no Chrome restart (Chrome reads the native-host registry on every connection attempt, so a running extension picks up the install instantly)
   - Either way it: detects Python 3 (`py` / `python` / `python3`) **or falls back to the bundled embedded Python — no Python install needed**; copies `wireproxy.exe`, `winws.exe`, `WinDivert`, DPI bins → `%USERPROFILE%\.tarn-tunnel\`; writes the native-messaging manifest **with your exact extension ID** and registers it for Chrome, Edge, Brave (HKCU, no Admin); **creates the `tarndpi` DPI service** (one UAC prompt — click "Yes"; the service SDDL lets normal users start/stop it, so DPI never prompts again). Everything is logged to `%USERPROFILE%\.tarn-tunnel\install.log`.

4. **Connect** — click the Tarn icon. For the **packet filter** no config is needed: open the "Packet filter" tab → **Full strategy test** → enable the filter. For the **tunnel**: paste a `.conf` → click **Connect**. Popup shows "External IP: …"

**Upgrades**: in `chrome://extensions/` click **Update**, then double-click `install.bat` again (idempotent). The popup re-verifies the host on every open — the status flips back to "available" by itself, **no Chrome restart needed**.

**DPI configuration**: the engine's domain lists (`engine\conf\dom.lst`, `tgt.lst`) ship **empty by design** — add the sites you care about via Settings → Packet filter → "Additional domains" (stored in `dom.user`, which is never overwritten by updates), and adjust the **probe targets** used to verify strategies in Settings → Packet filter → "Probe targets". The exclusion lists ship **empty by design** too (`exc.lst` is a commented template; an optional `exc.default-template` profile can be copied into it for the full starter set) plus `ipexc.lst` for private/link-local IP ranges, which is pre-filled. Your own never-touch entries go to Settings → Packet filter → "Excluded domains" (stored in `exc.user`).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Native host not installed. Run install.bat" | install.bat not run / registry missing | Double-click `install.bat` from the folder |
| "Error when communicating with the native messaging host" in chrome://extensions | `allowed_origins` does not match the loaded extension ID, or Chrome was started before the host manifest was fixed | Re-run `install.bat` — the popup re-verifies the host on its own |
| host.log shows `host started` then `stdin closed, exiting` | Same origin mismatch (Chrome drops the connection) | Re-run `install.bat`; reopen the popup |
| "This extension contains key files" warning | A `.pem`/private key sits inside the loaded folder | Official zips never contain keys. If you see it, delete `tools/extension_key.*` from your folder |
| Popup shows an ID like `mAMkZ…` in logs | Old broken builds hardcoded a wrong ID | Use a current release; ID is now derived automatically |
| "Filter service failed to start" / filter toggle stays on | The `tarndpi` service is missing or misconfigured (e.g. SDDL from a pre-1.6.0 install, or a corrupted ImagePath) | Re-run `install.bat` (v1.6.1+ recreates the service with the hardened SDDL and demand start) — no Chrome restart needed |
| host.log shows `hosts update failed: Permission denied …drivers\etc\hosts.bak.wgbt` | Editing the hosts file needs elevation; the non-admin host cannot write it | Non-critical: the packet filter works without the hosts entries. Blocked CDN subdomains may still fail — enable `dpiForceDoh` in Settings → Packet filter for a DNS-level workaround |
| Filter fails to start on Windows 11 24H2+ | Microsoft changed cross-signed kernel driver trust (March 2026); WinDivert64.sys may not load | Enable test-signing mode (`bcdedit /set testsigning on`) or wait for upstream WinDivert update. See Security section |

Deep diagnostics: Settings → Packet filter → "Full diagnostics" (engine files, `tarndpi` service + SDDL, DNS resolution, real internet probes, host log tail — one click, copyable report), or `powershell -File native-host\diagnose.ps1`

---

## Why deterministic ID? (root cause of "tunnel unavailable")

Chrome derives an unpacked extension's ID **either** from the `"key"` field in `manifest.json` **or**, without it, from the SHA-256 of the absolute folder path. Without a `"key"`:

- copy / move / re-unpack the folder → new path → **new ID**;
- the native host's `allowed_origins` (pinned to the old ID) stops matching;
- Chrome refuses to launch the host → *"Error when communicating with the native messaging host"* / *"tunnel unavailable"*.

With the pinned `"key"` (public key, base64 DER SPKI), the ID is computed as:

```
ID = nibble-map-a..p( SHA-256( public_key_DER_SPKI )[:16] )   # 32 chars
```

…and is the same for **every user, every machine, every folder path**. `install.bat` derives it from `manifest.json` at install time, so it can never drift out of sync. Verify on your machine:

```
python tools/ext_id.py manifest.json   → jiadcegfgdohggekdciecfialalkbnpo
```

The private key is **not** distributed (see `tools/gen_key.py`); it is only needed if you ever publish to the Chrome Web Store.

---

## Security

**What this software does** (be aware before installing):

- Creates a `tarndpi` Windows service running `winws.exe` as **SYSTEM** (`install.bat`, one UAC prompt) and a `WinDivert` kernel driver. The tunnel itself runs as your user.
- The service starts on demand (`start= demand`): winws runs **only while the filter is enabled** and stops on tunnel disconnect. Nothing survives a reboot.
- The native host (`tarn_host.py`) may edit `C:\Windows\System32\drivers\etc\hosts` (packet filter host entries) and, when "Force DoH" is on, the system DNS/DoH registry settings. On disable, **only** the interfaces and values this code changed are restored — user DNS (DHCP or static) is put back exactly as it was; the hosts file backup is only restored if the file still matches what Tarn wrote (otherwise only the DPI marker block is removed, keeping your edits).

**Measures in place:**

- **No local privilege escalation**: the `tarndpi` service SDDL grants Authenticated Users start/stop rights **only** — `SERVICE_CHANGE_CONFIG` is granted solely to the user who ran `install.bat` (via their SID). Granting it to all users would let any local account run arbitrary code as SYSTEM through `sc config tarndpi binPath= …` + `sc start tarndpi`. (v1.6.0 and earlier had this flaw; re-run `install.bat` after upgrading to 1.6.1+ to harden the SDDL.)
- **Scoped process control**: winws instances are stopped only when their command line points into `%USERPROFILE%\.tarn-tunnel\engine` — instances owned by other software or other users are never killed. The legacy `zapret` service is only removed when its ImagePath points into this tunnel's app dir.
- **Supply-chain**: `wireproxy.exe` and the packet filter engine (`winws.exe`,
  `WinDivert64.sys`, `WinDivert.dll`, `cygwin1.dll`) are verified against
  pinned SHA-256 hashes at copy time **and** right before every launch —
  the engine runs as SYSTEM, so a tampered binary in the user-writable app
  dir would be a privilege escalation. Only the pinned bundled `wireproxy`
  is ever executed (no PATH fallback); downloaded binaries are refused
  unless they match the pin. The extension's private signing key is never
  distributed.
- **Host hardening**: system-proxy values from the extension are
  charset-validated before interpolation into PowerShell; the host only
  binds SOCKS/HTTP listeners to loopback; inbound native-messaging messages
  are size-capped and parsed strictly; backup imports are whitelisted
  (unknown keys dropped, values type-checked, `socksHost` locked to
  loopback).
- **Privacy**: no Google Fonts CDN — all fonts are bundled; no telemetry, no network calls beyond the tunnel/IP-check endpoints (`api.ipify.org`, `ifconfig.me`, `api.myip.com`) and the packet filter connectivity probes.

**Residual risks** (not fixable in an extension): WinDivert and winws run with SYSTEM privileges because the filter must process system-wide traffic; a vulnerability in either binary is a privilege boundary. Update the bundle when a new release ships.

---

## Project layout

```
tarn/
├── manifest.json            # MV3 + pinned "key" → deterministic ID
├── background.js            # service worker, native-messaging logic
├── popup.html popup.js popup.css
├── options.html options.js options.css
├── lib/                     # parser, proxy, storage, i18n, adblock, antitrack
├── icons/ fonts/ mascot/    # static assets
├── native-host/
│   ├── tarn_host.py             # Python stdio native host
│   ├── tarn_host_wrapper.bat    # cmd shim (generated with ABS python path)
│   ├── com.tarn.host.json      # template (install.bat fills ABS path)
│   ├── diagnose.ps1                  # sanity checker
│   └── install.sh                    # Linux/macOS installer
├── engine/
│   ├── bins/                # wireproxy.exe + winws.exe + WinDivert + bins
│   └── conf/                # packet filter domain/IP lists (editable)
├── install.bat              # double-click me (Windows, no Admin)
├── install_service.bat      # elevated helper (WinDivert + tarndpi service + SDDL)
├── uninstall.bat            # removes registry keys, service, app dir
├── tools/
│   ├── ext_id.py            # derives extension ID from manifest.json
│   ├── gen_key.py           # one-shot keypair generator (maintainer only)
│   └── build_release.py     # release zip builder (maintainer only)
├── LICENSES/                # third-party licenses
└── THIRD_PARTY_NOTICES.md
```

---

### Troubleshooting: tunnel drops when DPI filter is also enabled

**Symptom**: The tunnel disconnects randomly when the DPI packet filter is active.

**Cause**: The DPI filter (WinDivert) can interfere with the tunnel's UDP traffic when the game filter is in "all" or "udp" mode, causing keepalive timeouts.

**Fix**: The tunnel's default port (51820) is automatically excluded from the game filter's UDP port range. If you use a custom tunnel port, add it to the DPI exclusion list:
1. Open the extension Options → Packet filter
2. Add your tunnel endpoint port to the "Excluded domains" field as a port number (e.g., `51820`)
3. Restart the DPI filter

Alternatively, switch the game filter to "tcp" mode (Settings → Packet filter → Game filter mode).

---

## Licenses

GPL-3.0 (see `LICENSE`). Bundled third-party components keep their licenses under `LICENSES/` (see `THIRD_PARTY_NOTICES.md`): wireproxy (ISC — windtf fork of pufferffish/wireproxy), packet filter engine (MIT — flowseal/zapret family), WinDivert (LGPL-3.0/GPL-2.0 dual), cygwin1.dll (LGPL-3.0+ with Cygwin Linking Exception), embedded Python (PSF License), Press Start 2P / Share Tech Mono (OFL-1.1).

---

Users are responsible for acquiring or setting up their own servers and for complying with applicable laws in their jurisdiction when using this software.

<p align="center">
  <img src="mascot/joy.png" width="80" alt="Tarn mascot">
</p>

---

### Git LFS (for contributors)

This repository contains large binary files (`engine/bins/*.exe`, `engine/bins/*.sys`,
`engine/bins/*.dll`, `python-embed-amd64.zip`). When contributing, use
[Git LFS](https://git-lfs.com/) to avoid bloating the git history:

```bash
git lfs install
git lfs track "engine/bins/*.exe" "engine/bins/*.sys" "engine/bins/*.dll" "python-embed-amd64.zip"
git add .gitattributes
```

Binary releases are distributed via GitHub Releases, not through git clone.

---

### Localization

This README is a single file with three versions: English, Russian
(Русский), and Chinese (简体中文). Use the navigation links at the top
to jump between them. The English version is canonical.

---

<a name="ru"></a>

<p align="center">
  <img src="mascot/wave.png" width="110" alt="Тарн-маскот">
</p>

# Tarn — инструмент сетевых исследований для Chromium

**[English](#en) · [Русский](#ru) · [简体中文](#zh)**

Расширение Chromium, которое запускает туннель **прямо в браузере**: импортируйте `.conf` (конфигурацию, которая *у вас уже есть*), нажмите Connect — и трафик браузера пойдёт через настоящий туннель через локальный экземпляр `wireproxy`. Без системного VPN, без аккаунта, без серверов.

В репозитории также есть **инструментарий для исследований DPI** (порт известного семейства движков zapret): desync-стратегии и диагностика связности для изучения поведения трафика в вашей сети. Все цели для проверки и списки доменов **настраиваются пользователем**; ничего не пред-сконфигурировано под какой-либо конкретный сервис — таблица IP-диапазонов (`engine\conf\ip.lst`) поставляется с простым базовым ipset-набором движка (немаркированные CIDR-диапазоны, без нацеливания на сервисы; см. `engine\bins\ATTRIBUTION.md`) и может быть сокращена или заменена, как любой другой список.

> **Примечание**: этот проект **не** управляет VPN-серверами, не продаёт подписки и не предоставляет готовых конечных точек. Вы приносите свою собственную конфигурацию туннеля. Автор не является поставщиком услуг какого-либо рода. Пользователи сами отвечают за приобретение или настройку своих серверов и за соблюдение законов своей юрисдикции при использовании этого ПО.

> **Экспортное уведомление**: это ПО содержит криптографические функции и может
> подпадать под правила экспортного контроля. См. `EXPORT_CONTROL.md`.
> Пользователи в эмбарго-зонах (Куба, Иран, Северная Корея, Сирия, Крым)
> обязаны убедиться в соблюдении применимых санкций до загрузки или
> использования этого ПО.

> **Антивирусное уведомление**: WinDivert и winws — легитимные инструменты с
> открытым исходным кодом, которые регулярно помечаются антивирусами
> (Kaspersky, Windows Defender, ESET). Это эвристические срабатывания на
> основе возможностей инструмента, а не вредоносное поведение. Подробности
> и инструкции по ложным срабатываниям — в `SECURITY.md`.

> **Юридически**: Tarn — инструмент сетевых исследований, а не VPN-сервис.
> Полный дисклеймер — в `LEGAL.md`. Пользователи отвечают за соблюдение
> применимых законов.

**Ключевые особенности**

<p align="center">
  <img src="mascot/shield1.png" width="80" alt="Маскот со щитом">
</p>

- **Детерминированный ID расширения**: `jiadcegfgdohggekdciecfialalkbnpo` — закреплён через поле `"key"` в `manifest.json`, поэтому ID одинаков на каждой машине и никогда не ломает native messaging, где бы вы ни распаковали папку
- **Установка в один клик**: двойной клик по `install.bat` — без прав администратора (одно необязательное UAC-окно создаёт службу `tarndpi`), без загрузок, всё упаковано. ID **вычисляется автоматически** из `manifest.json` (через `tools/ext_id.py`) — ничего не нужно прописывать или править. Сначала загрузите расширение, затем запустите `install.bat` — и попап сам переключится с *«туннель недоступен»* на *«доступен»* — без перезагрузки, без перезапуска Chrome
- MV3 service worker, native-messaging хост на Python; для самого туннеля не нужен драйвер ядра
- Опциональный пакетный фильтр через `winws.exe` + WinDivert
- **Автовыбор стратегии**: 10 DPI desync-стратегий, портированных из семейства flowseal/zapret (`fake+fakedsplit` (ALT), `simple fake`, `fake+multisplit` (ALT11), `hostfakesplit` (ALT9), `EXP`, `fake TLS auto` ×2, `multisplit`, `syndata+multidisorder` (ALT5), `fake badseq`); при старте хост проверяет реальную связность с **настроенными целями проверки** (HTTP, любой статус = доступно, взвешенный проход ≥3/5 хостов; цели редактируются в Настройки → Пакетный фильтр → «Цели проверки»), выбирает рабочую стратегию, кэширует её в `%USERPROFILE%\.tarn-tunnel\dpi_strategy.txt` и использует в следующий раз. Ручной выбор стратегии + кнопка **«Полное тестирование стратегий»** в Настройки → Пакетный фильтр: прогоняет каждую конфигурацию N раз (по 1–5 проходов), показывает живой прогресс-бар с % и логом каждого прогона, поддерживает паузу/возобновление/остановку, ранжирует результаты и автосохраняет лучшую конфигурацию. Все файлы лежат внутри zip; встроенные бинарники проверяются по закреплённым SHA-256 хешам перед использованием (см. *Безопасность*).
- **DPI-служба без UAC**: `install.bat` создаёт службу Windows `tarndpi` (через одно UAC-окно) с `start= demand` — winws работает **только** пока туннель активен и никогда не переживает перезагрузку. SDDL службы даёт **обычным пользователям** права запуска и остановки (право запуска = generic-execute `GX` в SDDL, перекодируется Windows в `RP`; без него `sc start` падает с "Access is denied (5)" и DPI не запускается), а `SERVICE_CHANGE_CONFIG` (перезапись ImagePath стратегии) выдаётся **только пользователю, запускавшему `install.bat`** — не всем Authenticated Users (см. *Безопасность*). Хост переписывает ImagePath службы для каждой стратегии, используя точный формат кавычек DPI-менеджера службы (проверяется через `sc qc` после каждого изменения), и проверяет реальную связность перед принятием стратегии. Флаг игрового фильтра (`engine\game_filter.enabled`, по умолчанию `all`) повторяет проверенную настройку апстрима.

---

## Установка (3 минуты)

1. **Получите файлы**
   - **Просто**: скачайте `Tarn-vX.Y.Z.zip` из GitHub Releases → правый клик → *Извлечь всё…* в любую папку
   - **Для разработки**: `git clone https://github.com/AntyCore723/tarn.git` — сам репозиторий уже готовая папка, сборка не нужна

2. **Загрузите расширение в Chrome**
   - Откройте `chrome://extensions/`
   - Включите **Режим разработчика** (справа сверху)
   - Нажмите **Загрузить распакованное** → выберите папку, которую вы извлекли/склонировали
   - Tarn появится на панели инструментов (закрепите)

3. **Установите native host**
   - Откройте попап Tarn (иконка на панели) — он показывает **«туннель недоступен»**, пока native host не установлен. **Это нормально.**
   - Дважды кликните `install.bat` **в извлечённой папке** (та же папка, что вы загрузили на шаге 2)
   - Через несколько секунд после регистрации хоста попап сам переключится на **«доступен»** — без перезагрузки, без перезапуска Chrome (Chrome читает реестр native-host при каждой попытке соединения, поэтому работающее расширение мгновенно подхватывает установку)
   - Скрипт: определяет Python 3 (`py` / `python` / `python3`) **или переключается на встроенный embedded Python — установка Python не нужна**; копирует `wireproxy.exe`, `winws.exe`, `WinDivert`, DPI-бинарники → `%USERPROFILE%\.tarn-tunnel\`; записывает native-messaging манифест **с вашим точным ID расширения** и регистрирует его для Chrome, Edge, Brave (HKCU, без администратора); **создаёт DPI-службу `tarndpi`** (одно UAC-окно — нажмите «Да»; SDDL службы позволяет обычным пользователям запускать/останавливать её, так что DPI больше никогда не спрашивает). Всё логируется в `%USERPROFILE%\.tarn-tunnel\install.log`.

4. **Подключение** — нажмите на иконку Tarn. Для **пакетного фильтра** конфигурация не нужна: вкладка «Пакетный фильтр» → **Полное тестирование стратегий** → включите фильтр. Для **туннеля**: вставьте `.conf` → нажмите **Connect**. В попапе появится «External IP: …»

**Обновления**: в `chrome://extensions/` нажмите **Обновить**, затем снова дважды кликните `install.bat` (идемпотентно). Попап перепроверяет хост при каждом открытии — статус сам вернётся на «доступен», **перезапуск Chrome не нужен**.

**Конфигурация DPI**: списки доменов движка (`engine\conf\dom.lst`, `tgt.lst`) поставляются **пустыми по дизайну** — добавьте нужные сайты через Настройки → Пакетный фильтр → «Дополнительные домены» (хранятся в `dom.user`, который никогда не перезаписывается при обновлениях) и настройте **цели проверки** в Настройки → Пакетный фильтр → «Цели проверки». Списки исключений тоже **пустые по дизайну** (`exc.lst` — шаблон с комментариями; опциональный профиль `exc.default-template` можно скопировать в него для полного стартового набора), плюс `ipexc.lst` для частных/link-local IP-диапазонов — предзаполнен. Свои «не трогать никогда» записи — через Настройки → Пакетный фильтр → «Исключённые домены» (хранятся в `exc.user`).

---

## Решение проблем

| Симптом | Причина | Решение |
|---|---|---|
| «Native host not installed. Run install.bat» | install.bat не запускался / нет записи в реестре | Дважды кликните `install.bat` из папки |
| «Error when communicating with the native messaging host» в chrome://extensions | `allowed_origins` не совпадает с ID загруженного расширения, или Chrome был запущен до исправления манифеста хоста | Перезапустите `install.bat` — попап сам перепроверит хост |
| В host.log: `host started`, затем `stdin closed, exiting` | Несовпадение origin (Chrome обрывает соединение) | Перезапустите `install.bat`; откройте попап заново |
| Предупреждение «This extension contains key files» | Внутри загруженной папки лежит `.pem`/приватный ключ | В официальных zip ключей нет. Если видите — удалите `tools/extension_key.*` из папки |
| В логах попапа ID вида `mAMkZ…` | Старые сломанные сборки зашивали неправильный ID | Используйте актуальный релиз; ID теперь вычисляется автоматически |
| «Filter service failed to start» / фильтр не включается | Служба `tarndpi` отсутствует или повреждена (например, SDDL от установки до 1.6.0, битый ImagePath) | Перезапустите `install.bat` (v1.6.1+ пересоздаёт службу с усиленным SDDL и demand start) — перезапуск Chrome не нужен |
| В host.log: `hosts update failed: Permission denied …drivers\etc\hosts.bak.wgbt` | Для правки hosts нужны права администратора; хост без них писать не может | Некритично: пакетный фильтр работает и без hosts-записей. Заблокированные CDN-поддомены могут не работать — включите `dpiForceDoh` в Настройки → Пакетный фильтр как обходной путь на уровне DNS |
| Фильтр не стартует на Windows 11 24H2+ | Microsoft изменила доверие к кросс-подписанным драйверам ядра (март 2026); WinDivert64.sys может не загрузиться | Включите тестовую подпись (`bcdedit /set testsigning on`) или ждите обновления WinDivert. См. раздел «Безопасность» |

Глубокая диагностика: Настройки → Пакетный фильтр → «Полная диагностика» (файлы движка, служба `tarndpi` + SDDL, разрешение DNS, реальные интернет-проверки, хвост лога хоста — одним кликом, отчёт можно скопировать), или `powershell -File native-host\diagnose.ps1`

---

## Зачем детерминированный ID? (корень «туннель недоступен»)

Chrome вычисляет ID распакованного расширения **либо** из поля `"key"` в `manifest.json`, **либо**, без него, из SHA-256 абсолютного пути к папке. Без `"key"`:

- скопировали / перенесли / заново распаковали папку → новый путь → **новый ID**;
- `allowed_origins` native host (закреплённый за старым ID) перестаёт совпадать;
- Chrome отказывается запускать хост → *"Error when communicating with the native messaging host"* / *«туннель недоступен»*.

С закреплённым `"key"` (публичный ключ, base64 DER SPKI) ID вычисляется как:

```
ID = nibble-map-a..p( SHA-256( public_key_DER_SPKI )[:16] )   # 32 символа
```

…и одинаков для **каждого пользователя, каждой машины, каждого пути**. `install.bat` вычисляет его из `manifest.json` при установке, поэтому он никогда не рассинхронизируется. Проверьте у себя:

```
python tools/ext_id.py manifest.json   → jiadcegfgdohggekdciecfialalkbnpo
```

Приватный ключ **не распространяется** (см. `tools/gen_key.py`); он нужен только если вы когда-нибудь опубликуете расширение в Chrome Web Store.

---

## Безопасность

**Что делает это ПО** (знайте перед установкой):

- Создаёт службу Windows `tarndpi`, запускающую `winws.exe` от имени **SYSTEM** (`install.bat`, одно UAC-окно), и драйвер ядра `WinDivert`. Сам туннель работает от вашего пользователя.
- Служба запускается по требованию (`start= demand`): winws работает **только пока фильтр включён** и останавливается при отключении туннеля. Ничего не переживает перезагрузку.
- Native host (`tarn_host.py`) может править `C:\Windows\System32\drivers\etc\hosts` (записи пакетного фильтра) и, при включённом «Force DoH», системные настройки DNS/DoH в реестре. При отключении восстанавливаются **только** те интерфейсы и значения, которые менял этот код — пользовательский DNS (DHCP или статический) возвращается в точности как был; бэкап hosts восстанавливается только если файл всё ещё совпадает с тем, что записал Tarn (иначе удаляется только блок DPI-маркера, сохраняя ваши правки).

**Принятые меры:**

- **Нет локальной эскалации привилегий**: SDDL службы `tarndpi` даёт Authenticated Users **только** права запуска/остановки — `SERVICE_CHANGE_CONFIG` выдаётся исключительно пользователю, запускавшему `install.bat` (по его SID). Выдача этого права всем позволила бы любому локальному аккаунту запускать произвольный код от имени SYSTEM через `sc config tarndpi binPath= …` + `sc start tarndpi`. (В v1.6.0 и ранее эта дыра была; после обновления до 1.6.1+ перезапустите `install.bat` для усиления SDDL.)
- **Ограниченное управление процессами**: winws-процессы останавливаются только если их командная строка указывает в `%USERPROFILE%\.tarn-tunnel\engine` — экземпляры, принадлежащие другому ПО или другим пользователям, никогда не убиваются. Легаси-служба `zapret` удаляется только когда её ImagePath указывает в папку приложения этого туннеля.
- **Цепочка поставок**: `wireproxy.exe` и движок пакетного фильтра (`winws.exe`,
  `WinDivert64.sys`, `WinDivert.dll`, `cygwin1.dll`) проверяются по
  закреплённым SHA-256 хешам при копировании **и** непосредственно перед
  каждым запуском — движок работает от имени SYSTEM, поэтому подменённый
  бинарник в пользовательской папке был бы эскалацией привилегий.
  Выполняется только закреплённый встроенный `wireproxy` (без fallback на
  PATH); скачанные бинарники отклоняются, если не совпадают с пином.
  Приватный ключ подписи расширения никогда не распространяется.
- **Усиление хоста**: значения системного прокси из расширения
  валидируются по кодировке перед подстановкой в PowerShell; хост
  связывает SOCKS/HTTP-слушатели только с loopback; входящие
  native-messaging сообщения ограничены по размеру и строго парсятся;
  импорт бэкапов — по белому списку (неизвестные ключи отбрасываются,
  значения проверяются по типам, `socksHost` зафиксирован на loopback).
- **Приватность**: никакого Google Fonts CDN — все шрифты встроены; никакой
  телеметрии, никаких сетевых вызовов, кроме проверок туннеля/IP
  (`api.ipify.org`, `ifconfig.me`, `api.myip.com`) и проверок связности
  пакетного фильтра.

**Остаточные риски** (неустранимые в расширении): WinDivert и winws работают с привилегиями SYSTEM, потому что фильтр должен обрабатывать общесистемный трафик; уязвимость в любом из бинарников — это граница привилегий. Обновляйте набор при выходе нового релиза.

---

## Структура проекта

```
tarn/
├── manifest.json            # MV3 + закреплённый "key" → детерминированный ID
├── background.js            # service worker, логика native messaging
├── popup.html popup.js popup.css
├── options.html options.js options.css
├── lib/                     # parser, proxy, storage, i18n, adblock, antitrack
├── icons/ fonts/ mascot/    # статические ресурсы
├── native-host/
│   ├── tarn_host.py             # Python stdio native host
│   ├── tarn_host_wrapper.bat    # cmd-обёртка (генерируется с ABS-путём python)
│   ├── com.tarn.host.json       # шаблон (install.bat заполняет ABS-путь)
│   ├── diagnose.ps1             # проверка работоспособности
│   └── install.sh               # установщик для Linux/macOS
├── engine/
│   ├── bins/                # wireproxy.exe + winws.exe + WinDivert + bins
│   └── conf/                # списки доменов/IP пакетного фильтра (редактируемые)
├── install.bat              # двойной клик (Windows, без администратора)
├── install_service.bat      # повышенный помощник (WinDivert + служба tarndpi + SDDL)
├── uninstall.bat            # удаляет ключи реестра, службу, папку приложения
├── tools/
│   ├── ext_id.py            # вычисляет ID расширения из manifest.json
│   ├── gen_key.py           # одноразовый генератор ключевой пары (только мейнтейнер)
│   └── build_release.py     # сборщик релизного zip (только мейнтейнер)
├── LICENSES/                # лицензии третьих сторон
└── THIRD_PARTY_NOTICES.md
```

---

### Туннель отваливается при включённом DPI-фильтре

**Симптом**: туннель случайно отключается, когда активен пакетный DPI-фильтр.

**Причина**: DPI-фильтр (WinDivert) может мешать UDP-трафику туннеля, когда игровой фильтр в режиме "all" или "udp", вызывая таймауты keepalive.

**Решение**: порт туннеля по умолчанию (51820) автоматически исключён из UDP-диапазона игрового фильтра. Если вы используете свой порт туннеля, добавьте его в список исключений DPI:
1. Откройте Настройки расширения → Пакетный фильтр
2. Добавьте порт конечной точки туннеля в поле «Исключённые домены» как номер порта (например, `51820`)
3. Перезапустите DPI-фильтр

Альтернатива: переключите игровой фильтр в режим "tcp" (Настройки → Пакетный фильтр → Режим игрового фильтра).

---

## Лицензии

GPL-3.0 (см. `LICENSE`). Встроенные компоненты третьих сторон сохраняют свои лицензии в `LICENSES/` (см. `THIRD_PARTY_NOTICES.md`): wireproxy (ISC — форк windtf от pufferffish/wireproxy), движок пакетного фильтра (MIT — семейство flowseal/zapret), WinDivert (двойная LGPL-3.0/GPL-2.0), cygwin1.dll (LGPL-3.0+ с Cygwin Linking Exception), встроенный Python (PSF License), Press Start 2P / Share Tech Mono (OFL-1.1).

---

Пользователи сами отвечают за приобретение или настройку своих серверов и за соблюдение законов своей юрисдикции при использовании этого ПО.

<p align="center">
  <img src="mascot/joy.png" width="80" alt="Тарн-маскот">
</p>

---

### Git LFS (для контрибьюторов)

Репозиторий содержит большие бинарные файлы (`engine/bins/*.exe`, `engine/bins/*.sys`,
`engine/bins/*.dll`, `python-embed-amd64.zip`). При контрибуции используйте
[Git LFS](https://git-lfs.com/), чтобы не раздувать историю git:

```bash
git lfs install
git lfs track "engine/bins/*.exe" "engine/bins/*.sys" "engine/bins/*.dll" "python-embed-amd64.zip"
git add .gitattributes
```

Бинарные релизы распространяются через GitHub Releases, а не через git clone.

---

### Локализация

Этот README — один файл с тремя версиями: английской, русской и китайской.
Навигация между ними — по ссылкам вверху страницы.

---

<a name="zh"></a>

<p align="center">
  <img src="mascot/wave.png" width="110" alt="Tarn 吉祥物">
</p>

# Tarn — Chromium 网络研究工具

**[English](#en) · [Русский](#ru) · [简体中文](#zh)**

一个在**浏览器内部**运行隧道的 Chromium 扩展：导入一个 `.conf`（*您自己已拥有的*配置），点击 Connect，浏览器流量就会通过本地 `wireproxy` 实例经由真实隧道传输——无需系统 VPN、无需账户、无需服务器。

该仓库还附带 **DPI 研究工具**（知名 zapret 引擎家族的一个移植版）：用于研究您网络上流量行为的 desync 策略和连通性诊断。所有探测目标和域名列表**均可由用户配置**；没有为任何特定服务预配置任何内容——IP 范围表（`engine\conf\ip.lst`）随附引擎的普通上游 ipset 基线（未标记的 CIDR 范围，无服务定向；见 `engine\bins\ATTRIBUTION.md`），可像任何其他列表一样裁剪或替换。

> **注意**：本项目**不**运营 VPN 服务器、不销售订阅、不提供现成的端点。您自带隧道配置。作者不是任何形式的服务提供商。使用本软件时，用户有责任自行获取或搭建服务器，并遵守其所在司法辖区的适用法律。

> **出口通知**：本软件包含加密功能，可能
> 受出口管制法规约束。详见 `EXPORT_CONTROL.md`。
> 处于禁运目的地（古巴、伊朗、朝鲜、叙利亚、克里米亚地区）的用户
> 在下载或使用本软件前必须确保遵守适用的制裁规定。

> **杀毒软件通知**：WinDivert 和 winws 是合法的开源工具，但
> 经常被杀毒引擎（卡巴斯基、Windows Defender、ESET）标记。
> 这些是基于工具能力的启发式检测，并非恶意行为。
> 详见 `SECURITY.md` 及误报报告指南。

> **法律声明**：Tarn 是网络研究工具，不是 VPN 服务。完整免责声明见 `LEGAL.md`。
> 用户有责任遵守适用的法律。

**亮点**

<p align="center">
  <img src="mascot/shield1.png" width="80" alt="盾牌吉祥物">
</p>

- **确定性扩展 ID**：`jiadcegfgdohggekdciecfialalkbnpo` — 通过 `manifest.json` 中的 `"key"` 字段固定，因此 ID 在每台机器上完全相同，无论解压到哪个文件夹都不会破坏 native messaging
- **零接触安装**：双击 `install.bat` — 无需管理员权限（一个可选的 UAC 弹窗创建 `tarndpi` 服务）、无需下载、全部已打包。它会**自动从** `manifest.json` **推导 ID**（通过 `tools/ext_id.py`）— 无需硬编码或编辑任何内容。先加载扩展，再运行 `install.bat`，弹窗就会**自行**从*“隧道不可用”*变为*“可用”* — 无需重新加载、无需重启 Chrome
- MV3 service worker，Python 编写的 native-messaging 主机；隧道本身不需要内核驱动
- 可选的数据包过滤器（`winws.exe` + WinDivert）
- **自动策略选择**：移植自 flowseal/zapret 家族的 10 种 DPI desync 策略（`fake+fakedsplit` (ALT)、`simple fake`、`fake+multisplit` (ALT11)、`hostfakesplit` (ALT9)、`EXP`、`fake TLS auto` ×2、`multisplit`、`syndata+multidisorder` (ALT5)、`fake badseq`）；启动时主机会向**配置的探测目标**探测真实连通性（HTTP，任意状态码 = 可达，加权通过 ≥3/5 主机；目标可在 设置 → 数据包过滤器 →“探测目标”中编辑），选择有效的策略，缓存到 `%USERPROFILE%\.tarn-tunnel\dpi_strategy.txt` 并在下次复用。手动选择策略 + 设置 → 数据包过滤器中的一键**“完整策略测试”**：将每个配置运行 N 次（每次 1–5 轮），显示带 % 和每次运行日志的实时进度条，支持暂停/继续/停止，对结果排序并自动保存最佳配置。所有文件都在 zip 内；内置二进制文件在使用前会通过固定的 SHA-256 哈希验证（见*安全*）。
- **无 UAC 的 DPI 服务**：`install.bat` 创建 `tarndpi` Windows 服务（通过一个 UAC 弹窗），`start= demand` — winws **仅在**隧道激活时运行，重启后绝不残留。服务 SDDL 授予**普通用户**启动和停止权限（启动权限 = SDDL 中的 generic-execute `GX`，Windows 将其重新编码为 `RP`；没有它 `sc start` 会报 "Access is denied (5)"，DPI 永远不会启动），而 `SERVICE_CHANGE_CONFIG`（重写策略 ImagePath）**仅授予运行 `install.bat` 的用户** — 而不是所有 Authenticated Users（见*安全*）。主机为每种策略重写服务 ImagePath 时使用 DPI 服务管理器的精确引号格式（每次更改后用 `sc qc` 验证），并在接受策略前探测真实连通性。游戏过滤器标志（`engine\game_filter.enabled`，默认 `all`）与经过验证的上游设置一致。

---

## 安装（3 分钟）

1. **获取文件**
   - **简单方式**：从 GitHub Releases 下载 `Tarn-vX.Y.Z.zip` → 右键 → *全部解压…* 到任意文件夹
   - **开发者方式**：`git clone https://github.com/AntyCore723/tarn.git` — 仓库本身就是现成的文件夹，无需构建

2. **在 Chrome 中加载扩展**
   - 打开 `chrome://extensions/`
   - 打开右上角的**开发者模式**
   - 点击**加载已解压的扩展程序** → 选择刚解压/克隆的文件夹
   - Tarn 出现在工具栏中（固定它）

3. **安装 native host**
   - 打开 Tarn 弹窗（工具栏图标）— 在 native host 安装前会显示**“隧道不可用”**。**这是正常的。**
   - 双击**解压文件夹中的** `install.bat`（第 2 步加载的同一个文件夹）
   - install.bat 注册主机几秒后，弹窗**自行**变为**“可用”** — 无需重新加载、无需重启 Chrome（Chrome 在每次连接尝试时都会读取 native-host 注册表，因此运行中的扩展会立即检测到安装）
   - 脚本会：检测 Python 3（`py` / `python` / `python3`）**或回退到内置的 embedded Python — 无需安装 Python**；复制 `wireproxy.exe`、`winws.exe`、`WinDivert`、DPI 二进制 → `%USERPROFILE%\.tarn-tunnel\`；写入带有**您的精确扩展 ID** 的 native-messaging 清单并注册到 Chrome、Edge、Brave（HKCU，无需管理员）；**创建 `tarndpi` DPI 服务**（一个 UAC 弹窗 — 点击“是”；服务 SDDL 允许普通用户启动/停止它，因此 DPI 不会再弹窗）。所有内容记录在 `%USERPROFILE%\.tarn-tunnel\install.log`。

4. **连接** — 点击 Tarn 图标。**数据包过滤器**无需配置：打开“数据包过滤器”标签 → **完整策略测试** → 启用过滤器。**隧道**：粘贴 `.conf` → 点击 **Connect**。弹窗显示“External IP: …”

**升级**：在 `chrome://extensions/` 中点击**更新**，然后再次双击 `install.bat`（幂等）。弹窗每次打开时都会重新验证主机 — 状态会自行回到“可用”，**无需重启 Chrome**。

**DPI 配置**：引擎的域名列表（`engine\conf\dom.lst`、`tgt.lst`）**按设计为空** — 通过 设置 → 数据包过滤器 →“附加域名”添加您关心的网站（存储在 `dom.user` 中，更新时绝不会被覆盖），并在 设置 → 数据包过滤器 →“探测目标”中调整用于验证策略的**探测目标**。排除列表同样**按设计为空**（`exc.lst` 是带注释的模板；可选的 `exc.default-template` 配置文件可复制进去以获得完整的入门集），另有 `ipexc.lst` 用于私有/link-local IP 范围，已预填。您自己的“永不触碰”条目通过 设置 → 数据包过滤器 →“排除的域名”添加（存储在 `exc.user` 中）。

---

## 故障排除

| 症状 | 原因 | 解决 |
|---|---|---|
| “Native host not installed. Run install.bat” | 未运行 install.bat / 注册表缺失 | 双击文件夹中的 `install.bat` |
| chrome://extensions 中显示“Error when communicating with the native messaging host” | `allowed_origins` 与加载的扩展 ID 不匹配，或 Chrome 在主机清单修复前已启动 | 重新运行 `install.bat` — 弹窗会自行重新验证主机 |
| host.log 显示 `host started` 然后 `stdin closed, exiting` | 相同的 origin 不匹配（Chrome 断开连接） | 重新运行 `install.bat`；重新打开弹窗 |
| “This extension contains key files” 警告 | `.pem`/私钥位于加载的文件夹内 | 官方 zip 从不包含密钥。如果看到，请从文件夹中删除 `tools/extension_key.*` |
| 日志中弹窗显示 `mAMkZ…` 之类的 ID | 旧版损坏构建硬编码了错误 ID | 使用当前版本；ID 现在自动推导 |
| “Filter service failed to start” / 过滤器开关保持开启 | `tarndpi` 服务缺失或配置错误（例如 1.6.0 之前安装的 SDDL，或损坏的 ImagePath） | 重新运行 `install.bat`（v1.6.1+ 会以加固的 SDDL 和 demand start 重建服务）— 无需重启 Chrome |
| host.log 显示 `hosts update failed: Permission denied …drivers\etc\hosts.bak.wgbt` | 编辑 hosts 文件需要提升权限；非管理员主机无法写入 | 非关键：数据包过滤器在没有 hosts 条目时也能工作。被屏蔽的 CDN 子域可能仍会失败 — 在 设置 → 数据包过滤器 中启用 `dpiForceDoh` 作为 DNS 层面的解决方法 |
| 过滤器在 Windows 11 24H2+ 上无法启动 | Microsoft 更改了交叉签名内核驱动信任（2026 年 3 月）；WinDivert64.sys 可能无法加载 | 启用测试签名模式（`bcdedit /set testsigning on`）或等待上游 WinDivert 更新。见安全部分 |

深度诊断：设置 → 数据包过滤器 →“完整诊断”（引擎文件、`tarndpi` 服务 + SDDL、DNS 解析、真实互联网探测、主机日志尾部 — 一键生成可复制的报告），或 `powershell -File native-host\diagnose.ps1`

---

## 为什么需要确定性 ID？（“隧道不可用”的根源）

Chrome 推导已解压扩展的 ID：**要么**来自 `manifest.json` 中的 `"key"` 字段，**要么**（没有它时）来自文件夹绝对路径的 SHA-256。没有 `"key"` 时：

- 复制/移动/重新解压文件夹 → 新路径 → **新 ID**；
- native host 的 `allowed_origins`（固定到旧 ID）不再匹配；
- Chrome 拒绝启动主机 → *“Error when communicating with the native messaging host”* / *“隧道不可用”*。

有了固定的 `"key"`（公钥，base64 DER SPKI），ID 计算如下：

```
ID = nibble-map-a..p( SHA-256( public_key_DER_SPKI )[:16] )   # 32 个字符
```

…并且对**每个用户、每台机器、每个文件夹路径**都相同。`install.bat` 在安装时从 `manifest.json` 推导它，因此永远不会失步。在您机器上验证：

```
python tools/ext_id.py manifest.json   → jiadcegfgdohggekdciecfialalkbnpo
```

私钥**不随项目分发**（见 `tools/gen_key.py`）；仅当您将来发布到 Chrome Web Store 时才需要。

---

## 安全

**本软件做什么**（安装前须知）：

- 创建以 **SYSTEM** 身份运行 `winws.exe` 的 `tarndpi` Windows 服务（`install.bat`，一个 UAC 弹窗）和 `WinDivert` 内核驱动。隧道本身以您的用户身份运行。
- 服务按需启动（`start= demand`）：winws **仅在过滤器启用时**运行，并在隧道断开时停止。重启后不会残留任何东西。
- native host（`tarn_host.py`）可能会编辑 `C:\Windows\System32\drivers\etc\hosts`（数据包过滤器主机条目），并在“Force DoH”开启时编辑系统 DNS/DoH 注册表设置。禁用时，**只**恢复此代码更改过的接口和值 — 用户 DNS（DHCP 或静态）会原样恢复；hosts 文件备份仅在文件仍与 Tarn 写入的内容匹配时恢复（否则只移除 DPI 标记块，保留您的编辑）。

**已采取的措施：**

- **无本地权限提升**：`tarndpi` 服务 SDDL 仅授予 Authenticated Users 启动/停止权限 — `SERVICE_CHANGE_CONFIG` 仅授予运行 `install.bat` 的用户（通过其 SID）。授予所有用户此权限会让任何本地账户通过 `sc config tarndpi binPath= …` + `sc start tarndpi` 以 SYSTEM 身份运行任意代码。（v1.6.0 及更早版本存在此缺陷；升级到 1.6.1+ 后重新运行 `install.bat` 以加固 SDDL。）
- **受限的进程控制**：仅当 winws 实例的命令行指向 `%USERPROFILE%\.tarn-tunnel\engine` 时才停止它们 — 属于其他软件或其他用户的实例绝不会被终止。遗留的 `zapret` 服务仅在其 ImagePath 指向此隧道应用目录时才被移除。
- **供应链**：`wireproxy.exe` 和数据包过滤器引擎（`winws.exe`、
  `WinDivert64.sys`、`WinDivert.dll`、`cygwin1.dll`）在复制时**以及**每次启动前
  都会通过固定的 SHA-256 哈希验证 — 引擎以 SYSTEM 身份运行，因此用户可写
  目录中被篡改的二进制文件将是权限提升漏洞。只执行固定的内置 `wireproxy`
  （无 PATH 回退）；下载的二进制文件除非与固定值匹配，否则会被拒绝。
  扩展的私钥签名密钥从不分发。
- **主机加固**：来自扩展的系统代理值在插入 PowerShell 前经过字符集验证；主机
  仅将 SOCKS/HTTP 监听器绑定到 loopback；入站 native-messaging 消息
  有大小上限并严格解析；备份导入采用白名单（未知键丢弃、值类型检查、
  `socksHost` 锁定为 loopback）。
- **隐私**：无 Google Fonts CDN — 所有字体均已内置；无遥测，除隧道/IP 检查
  端点（`api.ipify.org`、`ifconfig.me`、`api.myip.com`）和数据包过滤器连通性
  探测外无任何网络调用。

**残余风险**（扩展中无法修复）：WinDivert 和 winws 以 SYSTEM 权限运行，因为过滤器必须处理全系统流量；任一二进制中的漏洞都是权限边界。新版本发布时请更新捆绑包。

---

## 项目结构

```
tarn/
├── manifest.json            # MV3 + 固定 "key" → 确定性 ID
├── background.js            # service worker，native-messaging 逻辑
├── popup.html popup.js popup.css
├── options.html options.js options.css
├── lib/                     # parser, proxy, storage, i18n, adblock, antitrack
├── icons/ fonts/ mascot/    # 静态资源
├── native-host/
│   ├── tarn_host.py             # Python stdio native host
│   ├── tarn_host_wrapper.bat    # cmd 包装器（以 ABS python 路径生成）
│   ├── com.tarn.host.json       # 模板（install.bat 填充 ABS 路径）
│   ├── diagnose.ps1             # 健全性检查器
│   └── install.sh               # Linux/macOS 安装程序
├── engine/
│   ├── bins/                # wireproxy.exe + winws.exe + WinDivert + bins
│   └── conf/                # 数据包过滤器域名/IP 列表（可编辑）
├── install.bat              # 双击即可（Windows，无需管理员）
├── install_service.bat      # 提升权限的辅助程序（WinDivert + tarndpi 服务 + SDDL）
├── uninstall.bat            # 移除注册表项、服务、应用目录
├── tools/
│   ├── ext_id.py            # 从 manifest.json 推导扩展 ID
│   ├── gen_key.py           # 一次性密钥对生成器（仅维护者）
│   └── build_release.py     # 发布 zip 构建器（仅维护者）
├── LICENSES/                # 第三方许可证
└── THIRD_PARTY_NOTICES.md
```

---

### 同时启用 DPI 过滤器时隧道断开

**症状**：数据包 DPI 过滤器激活时隧道随机断开。

**原因**：当游戏过滤器处于 “all” 或 “udp” 模式时，DPI 过滤器（WinDivert）可能会干扰隧道的 UDP 流量，导致 keepalive 超时。

**解决**：隧道默认端口（51820）会自动从游戏过滤器的 UDP 端口范围中排除。如果您使用自定义隧道端口，请将其添加到 DPI 排除列表：
1. 打开扩展设置 → 数据包过滤器
2. 将隧道端点端口作为端口号添加到“排除的域名”字段（例如 `51820`）
3. 重启 DPI 过滤器

或者，将游戏过滤器切换到 “tcp” 模式（设置 → 数据包过滤器 → 游戏过滤器模式）。

---

## 许可证

GPL-3.0（见 `LICENSE`）。捆绑的第三方组件在 `LICENSES/` 中保留其许可证（见 `THIRD_PARTY_NOTICES.md`）：wireproxy（ISC — windtf 对 pufferffish/wireproxy 的分支）、数据包过滤器引擎（MIT — flowseal/zapret 家族）、WinDivert（LGPL-3.0/GPL-2.0 双重）、cygwin1.dll（LGPL-3.0+，含 Cygwin Linking Exception）、内置 Python（PSF License）、Press Start 2P / Share Tech Mono（OFL-1.1）。

---

使用本软件时，用户有责任自行获取或搭建服务器，并遵守其所在司法辖区的适用法律。

<p align="center">
  <img src="mascot/joy.png" width="80" alt="Tarn 吉祥物">
</p>

---

### Git LFS（供贡献者使用）

本仓库包含大型二进制文件（`engine/bins/*.exe`、`engine/bins/*.sys`、
`engine/bins/*.dll`、`python-embed-amd64.zip`）。贡献时请使用
[Git LFS](https://git-lfs.com/) 以避免膨胀 git 历史：

```bash
git lfs install
git lfs track "engine/bins/*.exe" "engine/bins/*.sys" "engine/bins/*.dll" "python-embed-amd64.zip"
git add .gitattributes
```

二进制版本通过 GitHub Releases 分发，而不是通过 git clone。

---

### 本地化

本 README 为单个文件，包含英语、俄语和中文三个版本。
请使用页面顶部的导航链接在版本之间切换。
