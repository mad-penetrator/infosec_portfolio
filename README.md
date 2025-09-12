## Неделя 1 — Сети и подготовка окружения

Задачи выполнены:
- Установлены VirtualBox, Kali, Ubuntu
- Выполнена проверка сети (файл week1_networks/network_check.txt).
- Захвачена сессия TCP и найдено трёхстороннее рукопожатие (week1_networks/tcp_handshake.png).
- Сохранён pcap (week1_networks/capture.pcapng).

## Неделя 1 (продолжение) — OSI модель

1. Physical — кабели, Wi-Fi, электрические сигналы
2. Data Link — Ethernet, MAC-адреса, кадры
3. Network — IP, маршрутизация
4. Transport — TCP/UDP, порты
5. Session — управление сессиями
6. Presentation — кодировки, шифрование
7. Application — HTTP, DNS, SMTP, FTP
-----------------------------------------
ip a — мой IP и интерфейсы
ip route — как пакеты уходят в сеть
ping — работает ли сеть/DNS
ss -tunap — какие соединения активны
ip neigh — кто есть в локалке
tcpdump — снифинг на уровне консоли //-i
