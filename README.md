# Log Analyzer Pro

Инструмент для анализа web access-логов с фокусом на bounce/direct-трафик, подозрительные паттерны и всплески нагрузки.

## Что умеет

- Парсит Apache/Nginx/extended-форматы, включая `.gz`.
- Автоматически подхватывает access-логи с именами вроде `*access*`, `*-acc-*`, `*-acc`.
- Считает direct-трафик, bounce rate, подозрительные IP/User-Agent.
- Выявляет периоды аномальной нагрузки.
- Генерирует отчеты:
  - Excel (`.xlsx`)
  - HTML
  - PDF для прикрепления к задаче
  - краткий текстовый итог (`.txt`)
- Делает AI-анализ (GigaChat) по готовому Excel-отчету.

## Установка

```bash
./setup.sh
```

Скрипт поднимет виртуальное окружение и установит зависимости.

## Базовый запуск

```bash
./venv/bin/python3 main.py logs/
```

> Если используете другое окружение, замените путь к Python.

## Частые сценарии

### Анализ за конкретный период

```bash
./venv/bin/python3 main.py logs/ --start-date 2025-12-01 --end-date 2025-12-31
```

### Ограничить объем данных в памяти

```bash
./venv/bin/python3 main.py logs/ --max-entries 5000000
```

### Выбрать формат отчета

```bash
./venv/bin/python3 main.py logs/ --format excel
./venv/bin/python3 main.py logs/ --format html
./venv/bin/python3 main.py logs/ --format pdf
./venv/bin/python3 main.py logs/ --format all
```

## Кэш и производительность

По умолчанию включен дисковый кэш распарсенных записей:

- путь: `<папка_логов>/.log_analyz_cache/`
- файлы: `entries.db` (SQLite), `progress.json`
- уже обработанные файлы пропускаются при повторном запуске
- для разных `--start-date`/`--end-date` используются отдельные подкаталоги кэша

Флаги:

- `--no-cache` — отключить кэш (все парсится заново)
- `--cache-dir <DIR>` — указать свою папку кэша
- `--max-entries N` — ограничить число записей, загружаемых для анализа

## Отчеты

После запуска результаты появляются в `results/<domain>/`:

- `<domain>_report_<timestamp>.xlsx`
- `<domain>_report_<timestamp>.html` (если выбран `html`/`all`)
- `<domain>_report_<timestamp>.pdf` (если выбран `pdf`/`all`)
- `<domain>_summary_<timestamp>.txt` (краткий итог)

### Что есть в Excel

- `Сводка`
- `Заключение` — человекочитаемый вывод для проверки direct/bounce
- `Вклад в bounce` — оценка доли подозрительных отказов и bounce rate после их исключения
- `Сравнение периодов` — весь период, база до последних 7 дней, последние 7 дней
- `Рекомендации IP` и `Рекомендации UA` — block/monitor/allow с причинами
- `Категории атак` — типы сканирования (`.env`, `wp-config`, webshell, credentials и т.д.)
- `Готовые правила` — примеры nginx/iptables/rate limit
- `Не блокировать` — allowlist-пояснения для поисковых ботов, prefetch и внутренних IP
- `Матрица угроз` — SOC/MITRE-подобное разложение по стадиям атаки
- `Возможные успехи` — чувствительные URL, вернувшие 2xx/3xx
- `Payload findings` — признаки SQLi/XSS/LFI/path traversal/command injection
- `Kill chain IP` — последовательность стадий по IP
- `Кампании` — волны активности по часам
- `Обзор по датам` — дневной срез:
  - всего запросов
  - прямых заходов
  - отказов
  - процент отказов
- сессии считаются с тайм-аутом 30 минут для одного IP + User-Agent
- листы по suspicious IP/UA, ошибкам, нагрузке и аномалиям

Дополнительно создаётся папка `<domain>_iocs_<timestamp>/`:

- `blocklist_ips.txt`
- `monitor_ips.txt`
- `suspicious_user_agents.txt`
- `suspicious_paths.txt`
- `nginx_security_rules.conf`
- `iptables_drop.sh`
- `ioc_summary.md`

## AI анализ

AI-отчет строится по Excel-таблицам, а не по сырым логам.

Полный цикл:

```bash
./venv/bin/python3 main.py logs/ --ai --auth-key <ВАШ_КЛЮЧ>
```

AI по готовому Excel:

```bash
./venv/bin/python3 main.py --ai-report results/site_com/site_com_report_20260209.xlsx --auth-key <ВАШ_КЛЮЧ>
```

## Основные CLI флаги

- `log_path` — файл или директория логов
- `--domain` — домен (или `auto`)
- `--start-date YYYY-MM-DD`
- `--end-date YYYY-MM-DD`
- `--format excel|html|all`
- `--max-entries N`
- `--no-cache`
- `--cache-dir DIR`
- `--no-geoip`
- `--ai`, `--ai-report`, `--auth-key`, `--model`

## Структура проекта

- `main.py` — точка входа
- `core/` — парсинг, анализ, кэш, geoip
- `report/` — Excel/HTML отчеты
- `ai/` — интеграция с GigaChat
- `results/` — результаты анализа
