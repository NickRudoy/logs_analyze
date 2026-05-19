import gzip
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse


class ErrorLogAnalyzer:
    """Анализатор nginx/php error-логов."""

    NGINX_RE = re.compile(
        r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
        r'\[(?P<level>\w+)\] (?P<pid>[^:]+): (?P<message>.*)$'
    )
    PHP_START_RE = re.compile(
        r'^\[(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})(?: [^\]]+)?\] '
        r'PHP (?P<level>[^:]+):\s+(?P<message>.*)$'
    )
    FIELD_RE = re.compile(r'(client|server|request|upstream|host|referrer): (?:"([^"]*)"|([^,]+))')

    def __init__(self, log_path, domain='auto', start_date=None, end_date=None, log_files=None, verbose=False):
        self.log_path = Path(log_path)
        self.domain_input = domain
        self.domain = domain if domain not in (None, 'auto') else None
        self.domain_source = 'аргумент --domain' if self.domain else 'auto'
        self.start_date = start_date
        self.end_date = end_date
        self.verbose = verbose
        self.log_files = [Path(p) for p in log_files] if log_files else self._resolve_log_files(self.log_path)
        self.entries = []
        self.skipped_count = 0

    def _resolve_log_files(self, log_path):
        if log_path.is_file():
            return [log_path]
        if log_path.is_dir():
            all_files = [p for p in log_path.iterdir() if p.is_file()]

            def is_error_log(path):
                name = path.name.lower()
                suffixes = ''.join(path.suffixes).lower()
                has_error_marker = 'error.log' in name or 'php_errors' in name or 'php-error' in name
                supported_suffix = (
                    path.suffix in {'', '.log', '.gz', '.txt'}
                    or suffixes.endswith(('.log.gz', '.txt.gz'))
                    or re.search(r'\.log\.\d+(\.gz)?$', name) is not None
                )
                return has_error_marker and supported_suffix

            error_files = sorted([p for p in all_files if is_error_log(p)])
            if not error_files:
                print(f"Ошибка: в директории {log_path} нет error-логов для анализа")
                sys.exit(1)
            return error_files
        print(f"Ошибка: путь {log_path} не найден")
        sys.exit(1)

    def _open_log(self, log_file):
        if log_file.suffix == '.gz':
            return gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore')
        return open(log_file, 'r', encoding='utf-8', errors='ignore')

    def _infer_domain_from_filenames(self):
        domains = []
        for log_file in self.log_files:
            name = log_file.name.lower()
            candidates = re.findall(r'([a-z0-9-]+(?:\.[a-z0-9-]+){1,})', name)
            for candidate in candidates:
                labels = candidate.split('.')
                while labels and (labels[-1] in {'log', 'error', 'php_errors', 'gz', 'txt'} or labels[-1].isdigit()):
                    labels.pop()
                if len(labels) >= 2:
                    domains.append('.'.join(labels))
        return domains

    def _infer_domain_from_entries(self):
        hosts = []
        for entry in self.entries:
            host = (entry.get('host') or entry.get('server') or '').split(':')[0].lower()
            if host and not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                hosts.append(host)
        return hosts

    def ensure_domain(self):
        if self.domain:
            print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
            return self.domain
        candidates = self._infer_domain_from_filenames() + self._infer_domain_from_entries()
        if candidates:
            self.domain = Counter(candidates).most_common(1)[0][0]
            self.domain_source = 'определён из error-логов'
        elif self.domain_input not in (None, 'auto'):
            self.domain = self.domain_input
            self.domain_source = 'аргумент --domain (fallback)'
        else:
            self.domain = 'site'
            self.domain_source = 'значение по умолчанию'
        print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
        return self.domain

    def parse_logs(self):
        print(f"Парсинг error-логов из {self.log_path}...")
        print(f"Найдено файлов для анализа: {len(self.log_files)}")
        if self.start_date:
            print(f"Фильтр: с {self.start_date.strftime('%Y-%m-%d')}")
        if self.end_date:
            print(f"Фильтр: по {self.end_date.strftime('%Y-%m-%d')}")

        for file_index, log_file in enumerate(self.log_files, 1):
            print(f"\n[{file_index}/{len(self.log_files)}] Файл: {log_file}")
            try:
                with self._open_log(log_file) as f:
                    if 'php' in log_file.name.lower():
                        self._parse_php_log(f, log_file)
                    else:
                        self._parse_nginx_error_log(f, log_file)
            except FileNotFoundError:
                print(f"Ошибка: файл {log_file} не найден")
                sys.exit(1)
            except Exception as exc:
                print(f"Ошибка при чтении файла {log_file}: {exc}")
                sys.exit(1)

        print(f"\nВсего error-событий для анализа: {len(self.entries):,}")
        if self.skipped_count:
            print(f"Пропущено нераспознанных строк: {self.skipped_count:,}")

    def _parse_nginx_error_log(self, lines, log_file):
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            entry = self._parse_nginx_line(line, log_file.name, line_num)
            if entry:
                self._append_if_in_period(entry)
            else:
                self.skipped_count += 1
            if line_num % 10000 == 0:
                print(f"  Обработано строк: {line_num:,} | Событий: {len(self.entries):,}")

    def _parse_php_log(self, lines, log_file):
        current = None
        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.rstrip('\n')
            match = self.PHP_START_RE.match(line)
            if match:
                if current:
                    self._append_if_in_period(current)
                current = self._build_php_entry(match, log_file.name, line_num)
                continue
            if current:
                if len(current['stack_trace']) < 12000:
                    current['stack_trace'] += line + '\n'
            elif line.strip():
                self.skipped_count += 1
            if line_num % 20000 == 0:
                print(f"  Обработано строк: {line_num:,} | Событий: {len(self.entries):,}")
        if current:
            self._append_if_in_period(current)

    def _append_if_in_period(self, entry):
        ts = entry.get('timestamp')
        if not ts:
            self.skipped_count += 1
            return
        if self.start_date and ts < self.start_date:
            return
        if self.end_date and ts > self.end_date:
            return
        entry['categories'] = self._classify_event(entry)
        entry['risk'] = self._risk_for_event(entry)
        self.entries.append(entry)

    def _parse_nginx_line(self, line, source_file, line_num):
        match = self.NGINX_RE.match(line)
        if not match:
            return None
        try:
            ts = datetime.strptime(match.group('ts'), '%Y/%m/%d %H:%M:%S')
        except ValueError:
            return None
        message = match.group('message')
        fields = self._extract_fields(message)
        method, url, protocol = self._split_request(fields.get('request', '-'))
        return {
            'source': 'nginx',
            'source_file': source_file,
            'line_num': line_num,
            'timestamp': ts,
            'level': match.group('level').lower(),
            'message': self._strip_fields(message),
            'client': fields.get('client', ''),
            'server': fields.get('server', ''),
            'request': fields.get('request', ''),
            'method': method,
            'url': url,
            'protocol': protocol,
            'upstream': fields.get('upstream', ''),
            'host': fields.get('host', ''),
            'referrer': fields.get('referrer', ''),
            'stack_trace': '',
        }

    def _build_php_entry(self, match, source_file, line_num):
        try:
            ts = datetime.strptime(match.group('ts'), '%d-%b-%Y %H:%M:%S')
        except ValueError:
            ts = None
        message = match.group('message')
        return {
            'source': 'php',
            'source_file': source_file,
            'line_num': line_num,
            'timestamp': ts,
            'level': f"php {match.group('level').lower()}",
            'message': message,
            'client': '',
            'server': '',
            'request': '',
            'method': '-',
            'url': self._extract_php_path(message),
            'protocol': '',
            'upstream': '',
            'host': '',
            'referrer': '',
            'stack_trace': '',
        }

    def _extract_fields(self, message):
        fields = {}
        for match in self.FIELD_RE.finditer(message):
            fields[match.group(1)] = (match.group(2) if match.group(2) is not None else match.group(3)).strip()
        return fields

    def _strip_fields(self, message):
        return re.split(r', client: |, server: |, request: |, upstream: |, host: |, referrer: ', message, maxsplit=1)[0]

    def _split_request(self, request):
        parts = request.split()
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        if len(parts) == 2:
            return parts[0], parts[1], ''
        if len(parts) == 1 and parts[0] != '-':
            return '-', parts[0], ''
        return '-', '-', ''

    def _extract_php_path(self, message):
        match = re.search(r' in (/[^:]+):\d+', message)
        return match.group(1) if match else ''

    def _classify_event(self, entry):
        haystack = self._event_text(entry)
        categories = []
        checks = [
            ('disk', ['no space left on device', 'incomplete', 'pwritev()', 'write() to']),
            ('upstream/504-risk', ['upstream timed out', 'connect() to unix:', 'resource temporarily unavailable', 'recv() failed', 'no live upstreams']),
            ('attack scan', ['/.env', '.env.', '/.git', 'wp-config', 'wp-content', 'wp-includes', 'backup.', 'dump.', 'archive.', '.tar', '.gz', 'config.js', 'settings.js', 'env.js', 'shell?', 'wget http', 'curl http', 'mozi']),
            ('captcha/php app error', ['yasmartcaptcha', 'ajaxform', 'formit', 'php fatal error', 'php parse error', 'php warning']),
            ('rate limiting / load pressure', ['delaying request', 'limiting requests', 'limit_req']),
            ('missing file/cache', ['openat()', 'no such file or directory', 'directory index']),
        ]
        for category, needles in checks:
            if any(needle in haystack for needle in needles):
                categories.append(category)
        if not categories:
            categories.append('other')
        return categories

    def _risk_for_event(self, entry):
        categories = set(entry.get('categories', []))
        level = entry.get('level', '')
        if 'disk' in categories or 'upstream/504-risk' in categories:
            return 'critical' if level in {'alert', 'crit', 'emerg'} or 'timed out' in self._event_text(entry) else 'high'
        if 'attack scan' in categories and self._has_high_risk_probe(entry):
            return 'high'
        if 'captcha/php app error' in categories and 'fatal' in level:
            return 'high'
        if level in {'alert', 'crit', 'emerg'}:
            return 'high'
        if 'rate limiting / load pressure' in categories or 'attack scan' in categories:
            return 'medium'
        return 'low'

    def _has_high_risk_probe(self, entry):
        text = self._event_text(entry)
        return any(token in text for token in ['/.env', '/.git', 'wp-config', 'shell?', 'mozi', 'backup.', 'dump.', 'archive.', '.tar'])

    def _event_text(self, entry):
        return ' '.join([
            str(entry.get('level', '')),
            str(entry.get('message', '')),
            str(entry.get('request', '')),
            str(entry.get('url', '')),
            str(entry.get('referrer', '')),
            str(entry.get('stack_trace', '')),
        ]).lower()

    def analyze(self):
        print("\nАнализ error-событий...")
        if not self.entries:
            return self._empty_analysis()

        levels = Counter(e['level'] for e in self.entries)
        categories = Counter(cat for e in self.entries for cat in e.get('categories', []))
        risks = Counter(e['risk'] for e in self.entries)
        daily = defaultdict(lambda: {'total': 0, 'levels': Counter(), 'categories': Counter(), 'risks': Counter()})
        hourly = defaultdict(lambda: {'total': 0, 'ips': Counter(), 'categories': Counter(), 'risks': Counter(), 'sample_events': []})
        ip_counter = Counter()
        url_counter = Counter()
        host_counter = Counter()
        ref_counter = Counter()
        message_counter = Counter()
        ip_categories = defaultdict(Counter)

        for entry in self.entries:
            day = entry['timestamp'].date().isoformat()
            hour = entry['timestamp'].replace(minute=0, second=0, microsecond=0)
            daily[day]['total'] += 1
            daily[day]['levels'][entry['level']] += 1
            daily[day]['risks'][entry['risk']] += 1
            hourly[hour]['total'] += 1
            hourly[hour]['risks'][entry['risk']] += 1
            if entry.get('client'):
                ip_counter[entry['client']] += 1
                hourly[hour]['ips'][entry['client']] += 1
            if entry.get('url') and entry.get('url') != '-':
                url_counter[entry['url']] += 1
            if entry.get('host'):
                host_counter[entry['host']] += 1
            if entry.get('referrer'):
                ref_counter[entry['referrer']] += 1
            msg_key = self._normalize_message(entry['message'])
            message_counter[msg_key] += 1
            for category in entry.get('categories', []):
                daily[day]['categories'][category] += 1
                hourly[hour]['categories'][category] += 1
                if entry.get('client'):
                    ip_categories[entry['client']][category] += 1
            if len(hourly[hour]['sample_events']) < 5:
                hourly[hour]['sample_events'].append(self._sample_event(entry))

        daily_rows = self._build_daily_rows(daily)
        peak_rows = self._build_peak_rows(hourly)
        ip_rows = self._build_ip_rows(ip_counter, ip_categories)
        findings = self._build_findings(categories, levels, risks, peak_rows)
        conclusion = self._build_conclusion(categories, levels, risks, daily_rows, peak_rows)

        print(f"Уровни: {dict(levels.most_common())}")
        print(f"Категории: {dict(categories.most_common())}")

        return {
            'summary': {
                'total_events': len(self.entries),
                'first_seen': min(e['timestamp'] for e in self.entries),
                'last_seen': max(e['timestamp'] for e in self.entries),
                'levels': levels.most_common(),
                'categories': categories.most_common(),
                'risks': risks.most_common(),
                'files': [str(p) for p in self.log_files],
                'skipped_lines': self.skipped_count,
            },
            'daily_stats': daily_rows,
            'peak_periods': peak_rows,
            'top_ips': ip_rows,
            'top_urls': url_counter.most_common(100),
            'top_hosts': host_counter.most_common(50),
            'top_referrers': ref_counter.most_common(50),
            'top_messages': message_counter.most_common(100),
            'findings': findings,
            'conclusion': conclusion,
            'samples': [self._sample_event(e) for e in self.entries if e.get('risk') in {'critical', 'high'}][:500],
        }

    def _empty_analysis(self):
        return {
            'summary': {'total_events': 0, 'levels': [], 'categories': [], 'risks': [], 'files': [str(p) for p in self.log_files], 'skipped_lines': self.skipped_count},
            'daily_stats': [],
            'peak_periods': [],
            'top_ips': [],
            'top_urls': [],
            'top_hosts': [],
            'top_referrers': [],
            'top_messages': [],
            'findings': ['В выбранном периоде error-события не найдены.'],
            'conclusion': 'В выбранном периоде error-события не найдены.',
            'samples': [],
        }

    def _normalize_message(self, message):
        msg = re.sub(r'"/var/www/[^"]+"', '"/var/www/.../"', message)
        msg = re.sub(r'\b\d+\b', 'N', msg)
        return msg[:300]

    def _build_daily_rows(self, daily):
        rows = []
        for day in sorted(daily.keys()):
            data = daily[day]
            rows.append({
                'date': day,
                'total': data['total'],
                'levels': dict(data['levels'].most_common()),
                'categories': dict(data['categories'].most_common()),
                'risks': dict(data['risks'].most_common()),
            })
        return rows

    def _build_peak_rows(self, hourly):
        rows = []
        if not hourly:
            return rows
        counts = [data['total'] for data in hourly.values()]
        avg = sum(counts) / len(counts)
        threshold = max(avg * 2, sorted(counts)[int(len(counts) * 0.9)] if len(counts) > 1 else counts[0])
        for hour, data in hourly.items():
            top_ip, top_ip_count = data['ips'].most_common(1)[0] if data['ips'] else ('', 0)
            top_ip_share = (top_ip_count / data['total'] * 100) if data['total'] else 0
            is_peak = data['total'] >= threshold or data['risks'].get('critical', 0) > 0 or data['categories'].get('disk', 0) > 0
            if not is_peak:
                continue
            rows.append({
                'period_start': hour,
                'period_end': hour + timedelta(hours=1),
                'events': data['total'],
                'unique_ips': len(data['ips']),
                'top_ip': top_ip,
                'top_ip_count': top_ip_count,
                'top_ip_share': top_ip_share,
                'categories': dict(data['categories'].most_common(5)),
                'risks': dict(data['risks'].most_common()),
                'samples': data['sample_events'],
            })
        return sorted(rows, key=lambda x: (x['risks'].get('critical', 0), x['events']), reverse=True)[:200]

    def _build_ip_rows(self, ip_counter, ip_categories):
        rows = []
        for ip, count in ip_counter.most_common(100):
            categories = ip_categories[ip]
            action = 'monitor'
            if categories.get('attack scan', 0) >= 20 or categories.get('upstream/504-risk', 0) >= 10:
                action = 'block/limit'
            if categories.get('disk', 0) > 0:
                action = 'investigate'
            rows.append({
                'ip': ip,
                'events': count,
                'categories': dict(categories.most_common()),
                'action': action,
            })
        return rows

    def _build_findings(self, categories, levels, risks, peak_rows):
        findings = []
        if categories.get('attack scan', 0):
            findings.append(f"Обнаружено сканирование/пробы чувствительных путей: {categories['attack scan']:,} событий.")
        if categories.get('disk', 0):
            findings.append(f"Подтверждены проблемы дискового пространства/записи логов: {categories['disk']:,} событий.")
        if categories.get('upstream/504-risk', 0):
            findings.append(f"Есть признаки риска 504/PHP-FPM upstream: {categories['upstream/504-risk']:,} событий.")
        if categories.get('captcha/php app error', 0):
            findings.append(f"Есть PHP/application ошибки, включая возможную связь с капчей/FormIt: {categories['captcha/php app error']:,} событий.")
        if categories.get('rate limiting / load pressure', 0):
            findings.append(f"Nginx применял rate limiting / задержку запросов: {categories['rate limiting / load pressure']:,} событий.")
        if levels.get('alert', 0) or levels.get('crit', 0):
            findings.append(f"Есть критичные уровни nginx: alert={levels.get('alert', 0)}, crit={levels.get('crit', 0)}.")
        if peak_rows:
            findings.append(f"Найдены пиковые часы error-событий: {len(peak_rows)}.")
        if not findings:
            findings.append("Критичных признаков по error-логам не найдено, но требуется сверка с access-логами для полной картины.")
        return findings

    def _build_conclusion(self, categories, levels, risks, daily_rows, peak_rows):
        parts = []
        parts.append(
            "По предоставленным error-логам видны следы автоматического сканирования сайта "
            "и отдельных технических проблем. Это не является прямым доказательством заражения, "
            "но указывает на регулярные попытки найти чувствительные файлы и технические endpoints."
        )
        if categories.get('disk', 0):
            parts.append(
                "Проблема с дисковым пространством подтверждается сообщениями nginx о невозможности записи "
                "логов / временных файлов; этот фактор мог приводить к нестабильности и 504."
            )
        if categories.get('upstream/504-risk', 0):
            parts.append(
                "Также есть upstream timeout / PHP-FPM ошибки, поэтому после очистки диска стоит проверить "
                "нагрузку PHP-FPM, медленные запросы и повторяемость timeout по свежим логам."
            )
        if categories.get('captcha/php app error', 0):
            parts.append(
                "В PHP-логах есть ошибки приложения, включая YaSmartCaptcha/AjaxForm/FormIt; капчу нужно проверить "
                "как отдельный источник fatal/parse ошибок после внедрения."
            )
        latest = daily_rows[-1] if daily_rows else None
        if latest:
            latest_critical = latest['risks'].get('critical', 0) if isinstance(latest.get('risks'), dict) else 0
            latest_disk = latest['categories'].get('disk', 0) if isinstance(latest.get('categories'), dict) else 0
            if latest_critical == 0 and latest_disk == 0:
                parts.append(
                    "По последнему дню в выбранных логах массовых свежих падений из-за диска не видно, "
                    "но сканирование и отдельные технические ошибки продолжаются."
                )
        if risks.get('critical', 0) == 0 and not categories.get('disk', 0):
            parts.append("Критичных свежих признаков повторения 504 по error-логам не выделено.")
        return "\n".join(parts)

    def _sample_event(self, entry):
        return {
            'time': entry['timestamp'],
            'source': entry.get('source', ''),
            'level': entry.get('level', ''),
            'risk': entry.get('risk', ''),
            'categories': '; '.join(entry.get('categories', [])),
            'client': entry.get('client', ''),
            'host': entry.get('host', ''),
            'request': entry.get('request', ''),
            'url': entry.get('url', ''),
            'message': entry.get('message', '')[:500],
            'source_file': entry.get('source_file', ''),
        }

    def _slugify_filename(self, value):
        value = (value or 'site').lower()
        value = re.sub(r'[^a-z0-9а-яё._-]+', '_', value, flags=re.IGNORECASE)
        value = value.strip('._-')
        return value or 'site'
