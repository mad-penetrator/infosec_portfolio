## Неделя 1 (1-2)

Задачи выполнены:
- Установлены VirtualBox, Kali, Ubuntu
- Выполнена проверка сети (файл week1_networks/network_check.txt).
- Захвачена сессия TCP и найдено трёхстороннее рукопожатие (week1_networks/tcp_handshake.png).
- Сохранён pcap (week1_networks/capture.pcapng).

## Неделя 1 (3-4) — OSI модель

1. Physical — кабели, Wi-Fi, электрические сигналы
2. Data Link — Ethernet, MAC-адреса, кадры
3. Network — IP, маршрутизация
4. Transport — TCP/UDP, порты
5. Session — управление сессиями
6. Presentation — кодировки, шифрование
7. Application — HTTP, DNS, SMTP, FTP

Теория кратко:
- OSI: L3 IP, L4 TCP/UDP, L7 HTTP/DNS/TLS.
- TCP vs UDP: TCP — надёжная доставка (ACK, порядок), UDP — быстрее, без гарантий.
- DNS (L7): домен → IP (обычно UDP/53).
- TLS поверх TCP: шифрует трафик (HTTPS). Признак начала — Client Hello.

Практика и артефакты:
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

## Неделя 1 (5–6): инциденты (SSH brute-force, Sysmon)

Теория кратко:
- Brute-force SSH: множественные Failed password за короткий интервал с одного IP (или многих IP).
- Защита: запрет root-логина, SSH-ключи, Fail2Ban.
- Sysmon (Win): расширенные логи (EventID 1 — создание процесса). Анализируем путь, имя, командную строку, родителя, хеши.

Практика и артефакты:
- /incidents/ssh_auth.log — учебный лог.
- Агрегация попыток: ssh_bruteforce_summary.txt.
- Выводы и меры: ssh_bruteforce_findings.txt.
- Разбор процесса: sysmon_sample.xml + отчёт sysmon_report.txt.

------------------------------------------
//Шаблоны команд (grep/regex) для поиска brute-force SSH
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
//Шаблон отчёта о подозрительном процессе (Sysmon, EventID=1):
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

