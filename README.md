# Неделя 1 (1-2): Основы сетей

## Задачи выполнены:
- Установлены VirtualBox, Kali, Ubuntu
- Выполнена проверка сети (файл week1_networks/network_check.txt).
- Захвачена сессия TCP и найдено трёхстороннее рукопожатие (week1_networks/tcp_handshake.png).
- Сохранён pcap (week1_networks/capture.pcapng).

# Неделя 1 (3-4): OSI модель

1. Physical — кабели, Wi-Fi, электрические сигналы
2. Data Link — Ethernet, MAC-адреса, кадры
3. Network — IP, маршрутизация
4. Transport — TCP/UDP, порты
5. Session — управление сессиями
6. Presentation — кодировки, шифрование
7. Application — HTTP, DNS, SMTP, FTP

## Теория кратко:
- OSI: L3 IP, L4 TCP/UDP, L7 HTTP/DNS/TLS.
- TCP vs UDP: TCP — надёжная доставка (ACK, порядок), UDP — быстрее, без гарантий.
- DNS (L7): домен → IP (обычно UDP/53).
- TLS поверх TCP: шифрует трафик (HTTPS). Признак начала — Client Hello.

## Практика и артефакты:
- Захват трафика: capture.pcapng.
- Найдены: DNS-запрос(ы), TCP 3-way handshake, TLS Client Hello.
- Скрины: dns_query.png, tls_clienthello.png.
- Базовые сетевые команды: ip a, ip route, ss -tunap, ping → net_basics.txt.

-----------------------------------------
- ip a — мой IP и интерфейсы
- ip route — как пакеты уходят в сеть
- ping — работает ли сеть/DNS
- ss -tunap — какие соединения активны
- ip neigh — кто есть в локалке
- tcpdump — снифинг на уровне консоли //-i
-----------------------------------------

# Неделя 1 (5-6): инциденты (SSH brute-force, Sysmon)

## Теория кратко:
- Brute-force SSH: множественные Failed password за короткий интервал с одного IP (или многих IP).
- Защита: запрет root-логина, SSH-ключи, Fail2Ban.
- Sysmon (Win): расширенные логи (EventID 1 — создание процесса). Анализируем путь, имя, командную строку, родителя, хеши.

## Практика и артефакты:
- /incidents/ssh_auth.log — учебный лог.
- Агрегация попыток: ssh_bruteforce_summary.txt.
- Выводы и меры: ssh_bruteforce_findings.txt.
- Разбор процесса: sysmon_sample.xml + отчёт sysmon_report.txt.

------------------------------------------
### Шаблоны команд (grep/regex) для поиска brute-force SSH
- IPv4 (устойчивее, чем через awk)
- grep -h "Failed password" week5-incidents/ssh_auth.log \
| grep -Po 'from \K([0-9]{1,3}\.){3}[0-9]{1,3}' \
| sort | uniq -c | sort -nr

- IPv6 (или «любой адрес после from»)
- grep -h "Failed password" week5-incidents/ssh_auth.log \
| grep -Po 'from \K([0-9a-fA-F:]+)' \
| sort | uniq -c | sort -nr

- Объединённый (попытка покрыть IPv4/IPv6 одним выражением)
- grep -h "Failed password" week5-incidents/ssh_auth.log \
| grep -Po 'from \K((([0-9]{1,3}\.){3}[0-9]{1,3})|([0-9a-fA-F:]+))' \
| sort | uniq -c | sort -nr
--------------------------------------------
### Шаблон отчёта о подозрительном процессе (Sysmon, EventID=1):
- Событие: Sysmon EventID=1 (Process Create)
- Время (UTC): <YYYY-MM-DD HH:MM:SS.mmm>
- Пользователь: <DOMAIN\user или SID, если доступно>

- Image: <полный путь к бинарнику, напр. C:\Users\<user>\AppData\Local\Temp\evil.exe>
- CommandLine: <полная командная строка>
- ParentImage: <родительский процесс, напр. C:\Windows\System32\cmd.exe>
- ParentCommandLine: <если доступно>
- Hashes: <MD5/SHA256, если в событии есть>
- IntegrityLevel: <Low/Medium/High/System, если есть>
- Signed: <подписан/не подписан, издатель>

Признаки подозрительности:
- [ ] Нетипичный путь (Temp/AppData/Profiles/Downloads и т.п.)
- [ ] Подозрительное имя файла/маскировка (например, chroome.exe)
- [ ] Вредоносные/нетипичные аргументы (например, --steal-data, base64/обфускация)
- [ ] Подозрительный родитель (Office → cmd/powershell, script host и т.п.)
- [ ] Отсутствие цифровой подписи/фальшивая подпись
- [ ] Нетипичный уровень привилегий/контекст

Предварительная оценка риска: <низкий/средний/высокий> (почему)

Рекомендации по реагированию:
1) Изоляция хоста от сети (если риск высокий).
2) Сбор артефактов: логи Sysmon (1/3/7/11), Prefetch, Amcache/Shimcache, Scheduled Tasks, Run-ключи.
3) Дамп/выгрузка файла и проверка хешей (VirusTotal, локальные IOC).
4) Поиск по IOC (хеш/имя/командная строка/родитель) на других хостах.
5) Проверка автозапуска и сетевых соединений, удаление/блокировка, восстановление доверенных конфигураций.

# Неделя 1 (7-8): SIEM и таймлайн инцидента
## Цели:
- Познакомиться с концепцией SIEM (Security Information and Event Management).
- Научиться собирать системные события в JSON-формате.
- Составить учебный таймлайн инцидента (цепочку действий атакующего).
- Сформировать базовый отчёт («топ команд sudo»).

## Выполнено:
- Имитация работы Filebeat: сбор логов через journalctl в JSON:
-- journalctl -n 80 -o json > week7-siem/filebeat_sample.json
- получен файл filebeat_sample.json с последними системными событиями.
- Построен отчёт по командам sudo:

grep -F '"SYSLOG_IDENTIFIER":"sudo"' filebeat_sample.json \
| grep -Po '"MESSAGE":"\s*[^"]+"' \
| sort | uniq -c | sort -nr > week7-siem/sudo_commands_top.txt

- получен файл sudo_commands_top.txt.
- составлен учебный таймлайн атаки (пример SSH brute-force → успешный вход → запуск malware → исходящее C2-соединение) → файл timeline.txt.

## Полученные артефакты:
- filebeat_sample.json (образец системных логов в JSON)
- sudo_commands_top.txt (отчёт топ sudo-команд)
- timeline.txt (учебный таймлайн инцидента).

------------------------------------------------------
# Итоги Недели 1:
- Разобрались с сетевым стеком и TLS;
- Научились работать с tcpdump и Wireshark;
- Освоили базовый анализ логов Linux, выявление brute-force;
- Составили первый инцидент-таймлайн;
- В репозитории теперь есть структурированные артефакты по каждой теме.
--------------------------------------------------------
# Неделя 2 – Харднинг (День 9–10)

## Теория
- **Харднинг** — меры по снижению атакуемой поверхности.  
- Основные шаги для Linux:
  - запрет root-входа по SSH;  
  - переход на SSH-ключи вместо паролей;  
  - использование Fail2Ban для защиты от брутфорса;  
  - настройка фаервола (UFW).  

### SSH
- `PermitRootLogin no` — запрещает вход под root.  
- `PasswordAuthentication no` — отключает пароли (оставляем yes временно, чтобы не потерять доступ).  
- `AllowUsers admin` — разрешает вход только конкретному пользователю.  

### Fail2Ban
- Считывает логи (`/var/log/auth.log`).  
- При превышении `maxretry` → добавляет IP в бан через firewall.  
- В `jail.local` включили jail `[sshd]` с `enabled = true`.  

### UFW (Uncomplicated Firewall)
- `sudo ufw enable` — включить firewall.  
- `sudo ufw allow ssh` — разрешить доступ по SSH (порт 22/tcp).  
- `sudo ufw allow http` — разрешить доступ по HTTP (порт 80/tcp).  
- `sudo ufw status verbose` — показать правила.  

## Практика
- Файл [`sshd_config_hardening.txt`](./sshd_config_hardening.txt) — изменённые строки из `/etc/ssh/sshd_config`.  
- Файл [`fail2ban_status.txt`](./fail2ban_status.txt) — вывод `sudo fail2ban-client status sshd`.  
- Файл [`ufw_status.txt`](./ufw_status.txt) — вывод `sudo ufw status verbose`.  

## Итоги
- Root-вход отключён.  
- Fail2Ban отслеживает brute-force на SSH.  
- UFW ограничивает доступ только разрешёнными портами.  
- Базовый харднинг сервера выполнен.

# Неделя 2 – День 11: SSH-ключи (вход без пароля)

## Цели:
- Сгенерировать пару SSH-ключей (ed25519).
- Настроить вход на сервер по ключу.
- Отключить парольную аутентификацию.

## Выполнено: 
- Генерация ключей (Windows):
-----------------------------------
ssh-keygen -t ed25519 -C "comment"
# ключи: %USERPROFILE%\.ssh\id_ed25519 (+ .pub)
-----------------------------------
- Установка ключа на сервер (Ubuntu):
-----------------------------------
mkdir -p ~/.ssh
cat ~/files/id_ed25519.pub >> ~/.ssh/authorized_keys   # или свой .pub
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
-----------------------------------
- Проверка входа с хоста (через Port Forwarding):
-----------------------------------
ssh -p 2222 admin@127.0.0.1
-----------------------------------
- Жёсткое отключение паролей (после проверки ключа):
-----------------------------------
sudo nano /etc/ssh/sshd_config
# добавить/проверить:
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
sudo systemctl restart ssh
-----------------------------------

## Практика (week2-ssh-key/):
- ssh_keygen_screenshot.png — скрин генерации ключа 
- authorized_keys.txt — содержимое ~/.ssh/authorized_keys на сервере
- sshd_config_keys.txt — строки из /etc/ssh/sshd_config с PubkeyAuthentication и PasswordAuthentication.

## Быстрые проверки/диагностика:

- Права:
chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; chown -R admin:admin ~/.ssh ~

- Логи при ошибке:
sudo tail -f /var/log/auth.log

- Явно указать приватный ключ на клиенте:
ssh -p 2222 -i %USERPROFILE%\.ssh\%keyname% admin@127.0.0.1
