
import gzip
import hashlib
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, unquote
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from .parser import LogParser
from .geoip import GeoIPAnalyzer
from .user_agent import UserAgentAnalyzer
from . import cache as cache_mod

class DirectTrafficAnalyzer:
    """Анализатор прямого трафика"""
    
    def __init__(self, log_path, domain='auto', start_date=None, end_date=None, use_geoip=True, log_files=None, verbose=False, max_entries=None, use_cache=True, cache_dir=None):
        self.log_path = Path(log_path)
        self.log_files = [Path(p) for p in log_files] if log_files else self._resolve_log_files(self.log_path)
        self.domain_input = domain
        self.domain = domain if domain not in (None, 'auto') else None
        self.domain_source = 'аргумент --domain' if self.domain else 'auto'
        self.start_date = start_date
        self.end_date = end_date
        self.use_geoip = use_geoip
        self.verbose = verbose
        self.max_entries = max_entries  # ограничение по числу записей (для экономии памяти)
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        self.entries = []
        self.direct_traffic_count = 0
        self.bounce_session_keys = set()
        self.geo_analyzer = GeoIPAnalyzer(use_api=use_geoip, verbose=verbose) if use_geoip else None
        self.ua_analyzer = UserAgentAnalyzer()

    def _cache_key(self):
        """Разделяет кэш по параметрам, влияющим на состав распарсенных записей."""
        parts = [
            f"start={self.start_date.isoformat() if self.start_date else ''}",
            f"end={self.end_date.isoformat() if self.end_date else ''}",
        ]
        if not any(part.split("=", 1)[1] for part in parts):
            return None
        digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
        return f"parsed_{digest}"
    
    def _resolve_log_files(self, log_path):
        """Определяет список файлов для анализа"""
        if log_path.is_file():
            return [log_path]
        if log_path.is_dir():
            all_files = [p for p in log_path.iterdir() if p.is_file()]
            def is_access_log(p):
                name_lower = p.name.lower()
                has_access = (
                    'access' in name_lower
                    or '-acc-' in name_lower
                    or name_lower.endswith('-acc')
                )
                suffixes = ''.join(p.suffixes).lower()
                return has_access and (
                    p.suffix in {'', '.log', '.gz', '.txt'}
                    or suffixes.endswith(('.log.gz', '.txt.gz'))
                    or re.search(r'\.log\.\d+(\.gz)?$', name_lower) is not None
                )
            access_files = sorted([p for p in all_files if is_access_log(p)])
            skipped_logs = [p.name for p in all_files if ('log' in p.name.lower() or p.suffix == '.gz') and p not in access_files]
            if skipped_logs:
                print(f"Пропущены (не access-логи, в отчёт не входят): {', '.join(sorted(skipped_logs))}")
            if not access_files:
                print(f"Ошибка: в директории {log_path} нет access-логов для анализа")
                sys.exit(1)
            return access_files
        
        print(f"Ошибка: путь {log_path} не найден")
        sys.exit(1)
    
    def _is_ip(self, host):
        parts = host.split('.')
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        return False
    
    def _infer_domain_from_filenames(self):
        """Пытается определить домен из названий лог-файлов"""
        domains = []
        for log_file in self.log_files:
            name = log_file.name.lower()
            candidates = re.findall(r'([a-z0-9-]+(?:\.[a-z0-9-]+){1,})', name)
            for candidate in candidates:
                labels = candidate.split('.')
                while labels and (labels[-1] in {'log', 'access', 'acc', 'error', 'gz', 'txt'} or labels[-1].isdigit()):
                    labels.pop()
                if len(labels) < 2:
                    continue
                normalized = '.'.join(labels)
                if not self._is_ip(normalized):
                    domains.append(normalized)
        return domains
    
    def _infer_domain_from_referers(self):
        """Пытается определить домен сайта по referer-ам"""
        hosts = []
        for entry in self.entries:
            ref = entry.get('referer', '')
            if not ref or ref == '-':
                continue
            parsed = urlparse(ref)
            host = parsed.hostname
            if host and not self._is_ip(host):
                hosts.append(host.lower())
        return hosts
    
    def _infer_domain(self):
        candidates = []
        candidates.extend(self._infer_domain_from_filenames())
        candidates.extend(self._infer_domain_from_referers())
        
        if not candidates:
            return None
        
        return Counter(candidates).most_common(1)[0][0]
    
    def ensure_domain(self):
        """Устанавливает домен"""
        if self.domain:
            print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
            return self.domain
        
        inferred = self._infer_domain()
        if inferred:
            self.domain = inferred
            self.domain_source = 'определён из логов'
        else:
            if self.domain_input not in (None, 'auto'):
                self.domain = self.domain_input
                self.domain_source = 'аргумент --domain (fallback)'
            else:
                self.domain = 'example.com'
                self.domain_source = 'значение по умолчанию'
            print(f"Предупреждение: не удалось автоматически определить домен, используем {self.domain}")
        
        print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
        return self.domain
    
    def _open_log(self, log_file):
        if log_file.suffix == '.gz':
            return gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore')
        return open(log_file, 'r', encoding='utf-8', errors='ignore')

    def _is_direct_entry(self, entry):
        """Проверяет прямой заход: пустой referer плюс фильтр ботов/статики."""
        referer = entry.get('referer', '')
        if referer not in ('', '-'):
            return False

        user_agent = entry.get('user_agent', '').lower()
        if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'googlebot', 'yandex', 'bing']):
            return False

        url = entry.get('url', '').lower()
        if any(resource in url for resource in ['/wp-content/', '/wp-includes/', '/wp-json/', '/wp-cron', '/wp-admin/', '.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg']):
            return False
        return True
    
    def _flush_batch(self, batch, db_path):
        if not batch:
            return
        cache_mod.insert_batch(db_path, batch)
        batch.clear()

    def _load_entries_from_cache(self):
        """Загружает записи из SQLite-кэша в self.entries (батчами, с учётом max_entries)."""
        cache_dir = cache_mod.get_cache_dir(self.log_path, self.cache_dir, self._cache_key())
        db_path = cache_mod.get_db_path(cache_dir)
        total = cache_mod.count_entries(db_path)
        if total == 0:
            return
        print(f"\nЗагрузка из кэша: {total:,} записей в БД.", end="")
        limit = self.max_entries
        if limit:
            print(f" В память загружаем не более {limit:,} (--max-entries).")
        else:
            print(" Загружаем все в память (при OOM используйте --max-entries).")
        load_count = 0
        start_id = 0
        batch_size = 500_000
        while True:
            batch, start_id = cache_mod.load_entries_batch(db_path, start_id=start_id, batch_size=batch_size)
            if not batch:
                break
            for e in batch:
                self.entries.append(e)
                load_count += 1
                if limit and load_count >= limit:
                    break
            if limit and load_count >= limit:
                break
            if start_id == 0:
                break
        print(f"Загружено записей в память: {len(self.entries):,}")

    def parse_logs(self):
        """Парсит логи; при use_cache пишет в SQLite и при повторном запуске пропускает уже обработанные файлы."""
        print(f"Парсинг логов из {self.log_path}...")
        print(f"Найдено файлов для анализа: {len(self.log_files)}")
        
        if self.start_date:
            print(f"Фильтр: с {self.start_date.strftime('%Y-%m-%d')}")
        if self.end_date:
            print(f"Фильтр: по {self.end_date.strftime('%Y-%m-%d')}")
        if self.max_entries:
            print(f"Лимит записей: {self.max_entries:,} (для экономии памяти)")
        
        use_cache = self.use_cache and (self.log_path.is_dir() or self.log_path.is_file())
        cache_key = self._cache_key()
        cache_dir = cache_mod.get_cache_dir(self.log_path, self.cache_dir, cache_key) if use_cache else None
        db_path = cache_mod.get_db_path(cache_dir) if use_cache else None
        log_dir_abs = cache_mod._norm_path(self.log_path if self.log_path.is_dir() else self.log_path.parent)
        if use_cache:
            cache_mod.init_db(db_path)
        progress = cache_mod.load_progress(cache_dir) if use_cache else None
        completed_files = []
        total_in_db = cache_mod.count_entries(db_path) if use_cache else 0
        if use_cache and progress and progress.get("log_dir") == log_dir_abs:
            completed_files = list(progress.get("completed_files", []))
            incomplete = progress.get("current_file")
            if incomplete:
                n = int(progress.get("current_file_rows") or 0)
                if n > 0:
                    cache_mod.remove_last_n_rows(db_path, n)
                    total_in_db = max(0, total_in_db - n)
                    print(f"Удалено {n:,} записей незавершённого файла «{incomplete}» (повторный разбор).")
                completed_files = [f for f in completed_files if f != incomplete]
            if completed_files:
                print(f"Кэш найден: уже обработано файлов: {len(completed_files)}. Пропуск этих файлов.")
        
        parsed_count = 0
        skipped_count = 0
        batch = []
        
        for file_index, log_file in enumerate(self.log_files, 1):
            if use_cache and log_file.name in completed_files:
                print(f"\n[{file_index}/{len(self.log_files)}] Пропущен (в кэше): {log_file.name}")
                continue
            if self.max_entries and not use_cache and len(self.entries) >= self.max_entries:
                print(f"\nДостигнут лимит --max-entries={self.max_entries:,}, парсинг остановлен.")
                break
            print(f"\n[{file_index}/{len(self.log_files)}] Файл: {log_file}")
            current_file_rows = 0
            flushes_since_save = 0
            if use_cache:
                cache_mod.save_progress(cache_dir, log_dir_abs, completed_files, total_in_db, current_file=log_file.name, current_file_rows=0)
            try:
                with self._open_log(log_file) as f:
                    for line_num, line in enumerate(f, 1):
                        if self.max_entries and not use_cache and len(self.entries) >= self.max_entries:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        
                        entry = LogParser.parse_line(line)
                        if entry:
                            if self.start_date and entry['timestamp'] < self.start_date:
                                skipped_count += 1
                                continue
                            if self.end_date and entry['timestamp'] > self.end_date:
                                skipped_count += 1
                                continue
                            if use_cache:
                                batch.append(entry)
                                if len(batch) >= cache_mod.BATCH_SIZE:
                                    n = len(batch)
                                    self._flush_batch(batch, db_path)
                                    current_file_rows += n
                                    total_in_db += n
                                    flushes_since_save += 1
                                    if flushes_since_save >= 5:
                                        cache_mod.save_progress(cache_dir, log_dir_abs, completed_files, total_in_db, current_file=log_file.name, current_file_rows=current_file_rows)
                                        flushes_since_save = 0
                                parsed_count += 1
                            else:
                                self.entries.append(entry)
                                parsed_count += 1
                        else:
                            skipped_count += 1
                        
                        if line_num % 10000 == 0:
                            print(f"  Обработано строк: {line_num:,} | Всего распознано записей: {parsed_count:,}")
                    if use_cache:
                        if batch:
                            n = len(batch)
                            self._flush_batch(batch, db_path)
                            current_file_rows += n
                            total_in_db += n
                        completed_files.append(log_file.name)
                        cache_mod.save_progress(cache_dir, log_dir_abs, completed_files, total_in_db, current_file=None, current_file_rows=0)
                    if self.max_entries and not use_cache and len(self.entries) >= self.max_entries:
                        break
            except FileNotFoundError:
                print(f"Ошибка: файл {log_file} не найден")
                sys.exit(1)
            except Exception as e:
                print(f"Ошибка при чтении файла {log_file}: {e}")
                sys.exit(1)
        
        if use_cache:
            self._load_entries_from_cache()
        print(f"\nВсего записей для анализа: {len(self.entries):,}")
        if skipped_count > 0:
            print(f"Пропущено нераспознанных строк: {skipped_count:,}")
        
    def identify_direct_traffic(self):
        """Определяет прямые заходы (direct traffic)"""
        print("\nОпределение прямого трафика...")
        self.direct_traffic_count = sum(1 for entry in self.entries if self._is_direct_entry(entry))
        print(f"Прямых заходов: {self.direct_traffic_count}")
        
    def analyze_bounce_rate(self):
        """Анализирует отказы (bounce rate)"""
        print("\nАнализ отказов...")
        sessions = defaultdict(lambda: {'entries': []})
        daily_stats = defaultdict(lambda: {'total_requests': 0, 'direct': 0, 'bounces': 0})
        for entry in self.entries:
            day = entry['timestamp'].date().isoformat()
            daily_stats[day]['total_requests'] += 1
            if not self._is_direct_entry(entry):
                continue
            key = f"{entry['ip']}|{entry['user_agent']}"
            sessions[key]['entries'].append(entry)
            daily_stats[day]['direct'] += 1

        session_timeout = timedelta(minutes=30)
        session_entries = {}
        for base_key, data in sessions.items():
            current_session = []
            session_index = 0
            previous_ts = None
            for entry in sorted(data['entries'], key=lambda e: e['timestamp']):
                if previous_ts is not None and entry['timestamp'] - previous_ts > session_timeout:
                    if current_session:
                        session_entries[f"{base_key}|{session_index}"] = current_session
                    session_index += 1
                    current_session = []
                current_session.append(entry)
                previous_ts = entry['timestamp']
            if current_session:
                session_entries[f"{base_key}|{session_index}"] = current_session

        bounce_session_keys = {
            k for k, entries in session_entries.items()
            if sum(1 for entry in entries if entry['status'] == 200) <= 1
        }
        self.bounce_session_keys = bounce_session_keys

        bounce_count = 0
        bounce_samples = []
        for key in bounce_session_keys:
            entries = session_entries[key]
            bounce_count += len(entries)
            for entry in entries:
                day = entry['timestamp'].date().isoformat()
                daily_stats[day]['bounces'] += 1
                if len(bounce_samples) < 1000:
                    bounce_samples.append(entry)

        bounce_entry_keys = {
            self._entry_identity(entry)
            for key in bounce_session_keys
            for entry in session_entries[key]
        }

        total_direct = self.direct_traffic_count
        non_bounces = max(0, total_direct - bounce_count)
        bounce_rate = (bounce_count / total_direct * 100) if total_direct else 0

        daily_rows = []
        for day in sorted(daily_stats.keys()):
            d = daily_stats[day]
            day_bounce_rate = (d['bounces'] / d['direct'] * 100) if d['direct'] else 0
            daily_rows.append({
                'date': day,
                'total_requests': d['total_requests'],
                'direct': d['direct'],
                'bounces': d['bounces'],
                'bounce_rate': day_bounce_rate
            })

        print(f"Отказов: {bounce_count} ({bounce_rate:.2f}%)")
        print(f"Не отказов: {non_bounces} ({100 - bounce_rate:.2f}%)")

        return {
            'total_direct': total_direct,
            'bounces': bounce_count,
            'non_bounces': non_bounces,
            'bounce_rate': bounce_rate,
            'bounce_entries': bounce_samples,
            'daily_stats': daily_rows,
            'bounce_session_keys': bounce_session_keys,
            'bounce_entry_keys': bounce_entry_keys,
            'direct_sessions': len(session_entries),
            'bounce_sessions': len(bounce_session_keys),
        }

    def _entry_identity(self, entry):
        """Компактный идентификатор записи для внутренних пересечений выборок."""
        return (
            entry.get('ip'),
            entry.get('user_agent'),
            entry.get('timestamp'),
            entry.get('url'),
            entry.get('status'),
        )
    
    def find_suspicious_patterns(self, bounce_analysis):
        """Выявляет подозрительные паттерны"""
        print("\nПоиск подозрительных паттернов...")
        bounce_entry_keys = bounce_analysis.get('bounce_entry_keys', set())
        
        initial_success = 0
        initial_errors = 0
        if self.use_geoip and self.geo_analyzer:
            print("Получение геолокации для IP...")
            initial_success = self.geo_analyzer.success_count
            initial_errors = self.geo_analyzer.error_count
        
        suspicious = {
            'suspicious_ips': [],
            'suspicious_user_agents': [],
            'high_frequency_ips': [],
            'error_patterns': [],
            'country_stats': defaultdict(lambda: {'count': 0, 'ips': set()}),
            'datacenter_ips': []
        }

        if not bounce_entry_keys:
            return suspicious

        ip_counter = Counter()
        ip_unique_urls = defaultdict(set)
        ip_unique_uas = defaultdict(set)
        ip_sample_urls = defaultdict(list)
        ip_attack_categories = defaultdict(Counter)
        ip_first_seen = {}
        ip_last_seen = {}
        ua_counter = Counter()
        ua_unique_ips = defaultdict(set)
        ua_sample_urls = defaultdict(set)
        ua_attack_categories = defaultdict(Counter)
        ip_timestamps = defaultdict(list)
        error_counter = Counter()
        attack_category_counter = Counter()

        for entry in self.entries:
            if not self._is_direct_entry(entry):
                continue
            key = self._entry_identity(entry)
            if key not in bounce_entry_keys:
                continue

            ip = entry['ip']
            ua = entry['user_agent']
            url = entry['url']
            ts = entry['timestamp']
            status = entry['status']

            ip_counter[ip] += 1
            ip_unique_urls[ip].add(url)
            ip_unique_uas[ip].add(ua)
            if len(ip_sample_urls[ip]) < 200:
                ip_sample_urls[ip].append(url)
            attack_category = self._classify_attack_category(url)
            ip_attack_categories[ip][attack_category] += 1
            ua_attack_categories[ua][attack_category] += 1
            attack_category_counter[attack_category] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts

            ua_counter[ua] += 1
            ua_unique_ips[ua].add(ip)
            if len(ua_sample_urls[ua]) < 50:
                ua_sample_urls[ua].add(url)

            if len(ip_timestamps[ip]) < 5000:
                ip_timestamps[ip].append(ts)
            if status >= 400:
                error_counter[(ip, status)] += 1
        
        for ip, count in ip_counter.most_common(50):
            unique_urls = len(ip_unique_urls[ip])
            unique_user_agents = len(ip_unique_uas[ip])
            
            suspicious_score = 0
            reasons = []
            
            if count > 10:
                suspicious_score += 1
                reasons.append(f"Много отказов ({count})")
            
            if unique_urls > 20:
                suspicious_score += 1
                reasons.append(f"Много разных URL ({unique_urls})")
            
            if unique_user_agents == 1 and count > 5:
                suspicious_score += 1
                reasons.append("Одинаковый user-agent")
            
            urls = ip_sample_urls[ip]
            if self._has_scanning_pattern(urls):
                suspicious_score += 2
                reasons.append("Паттерн сканирования")
            
            if suspicious_score >= 2:
                ip_info = {}
                if self.geo_analyzer:
                    ip_info = self.geo_analyzer.get_ip_info(ip)
                    suspicious['country_stats'][ip_info['country']]['count'] += count
                    suspicious['country_stats'][ip_info['country']]['ips'].add(ip)
                    
                    if ip_info.get('is_datacenter'):
                        suspicious['datacenter_ips'].append({
                            'ip': ip,
                            'country': ip_info['country'],
                            'isp': ip_info['isp'],
                            'bounce_count': count
                        })
                
                suspicious['suspicious_ips'].append({
                    'ip': ip,
                    'bounce_count': count,
                    'unique_urls': unique_urls,
                    'unique_user_agents': unique_user_agents,
                    'user_agents': list(ip_unique_uas[ip])[:10],
                    'sample_urls': urls[:10],
                    'attack_categories': dict(ip_attack_categories[ip].most_common(5)),
                    'score': suspicious_score,
                    'reasons': reasons,
                    'first_seen': ip_first_seen.get(ip, datetime.now()),
                    'last_seen': ip_last_seen.get(ip, datetime.now()),
                    'country': ip_info.get('country', 'Unknown'),
                    'country_code': ip_info.get('country_code', 'XX'),
                    'city': ip_info.get('city', 'Unknown'),
                    'isp': ip_info.get('isp', 'Unknown'),
                    'ip_type': ip_info.get('ip_type', 'Unknown'),
                    'is_datacenter': ip_info.get('is_datacenter', False)
                })
        
        for ua, count in ua_counter.most_common(30):
            if count > 5:
                unique_ips = len(ua_unique_ips[ua])
                
                if count > 10 or (unique_ips > 5 and count > 5):
                    ua_info = self.ua_analyzer.parse_user_agent(ua)
                    
                    suspicious['suspicious_user_agents'].append({
                        'user_agent': ua[:200],
                        'bounce_count': count,
                        'unique_ips': unique_ips,
                        'sample_ips': list(ua_unique_ips[ua])[:10],
                        'sample_urls': list(ua_sample_urls[ua])[:10],
                        'attack_categories': dict(ua_attack_categories[ua].most_common(5)),
                        'browser': ua_info['browser'],
                        'browser_version': ua_info['browser_version'],
                        'os': ua_info['os'],
                        'os_version': ua_info['os_version'],
                        'device_type': ua_info['device_type'],
                        'is_bot': ua_info['is_bot'],
                        'is_mobile': ua_info['is_mobile']
                    })
        
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) < 5:
                continue
            
            timestamps.sort()
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
                avg_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
                
                if 1 <= avg_diff <= 3 and len(timestamps) > 10:
                    suspicious['high_frequency_ips'].append({
                        'ip': ip,
                        'request_count': len(timestamps),
                        'avg_interval_seconds': avg_diff,
                        'time_span': (timestamps[-1] - timestamps[0]).total_seconds()
                    })
        
        for (ip, status), count in error_counter.most_common(20):
            if count > 5:
                suspicious['error_patterns'].append({
                    'ip': ip,
                    'status': status,
                    'count': count
                })

        suspicious['attack_categories'] = [
            {'category': category, 'count': count}
            for category, count in attack_category_counter.most_common()
        ]
        
        if self.use_geoip and self.geo_analyzer:
            success_count = self.geo_analyzer.success_count - initial_success
            error_count = self.geo_analyzer.error_count - initial_errors
            total_requests = success_count + error_count
            if total_requests > 0:
                success_rate = (success_count / total_requests) * 100
                print(f"Геолокация: успешно {success_count}/{total_requests} ({success_rate:.1f}%), ошибок: {error_count}")
        
        return suspicious

    def _classify_attack_category(self, url):
        """Классифицирует URL по типовым признакам нежелательной активности."""
        path = urlparse(url).path.lower()
        raw = url.lower()
        checks = [
            ('env/config scan', ['.env', 'config.php', 'configuration.php', 'database.yml', 'settings.php', '.pypirc']),
            ('credential scan', ['.aws/credentials', 'id_rsa', '.ssh', 'credentials', 'password', 'passwd']),
            ('wordpress scan', ['wp-login', 'wp-admin', 'wp-config', 'xmlrpc.php', 'wp-content', 'wp-includes']),
            ('php shell scan', ['shell.php', 'ws80.php', 'wso.php', 'fm.php', 'sf.php', 'alfa.php', 'c99.php', 'r57.php']),
            ('admin/login scan', ['/admin', '/login', '/manager', '/bitrix/admin', '/phpmyadmin']),
            ('tech file scan', ['.git', '.svn', '.hg', '.dockerenv', 'phpinfo', 'phpversion', 'server-status']),
            ('encoded/probing URL', ['%2e', '%61', '%63', '::$data']),
        ]
        for category, needles in checks:
            if any(needle in path or needle in raw for needle in needles):
                return category
        if path.endswith('.php') and path not in {'/index.php'}:
            return 'generic php probe'
        return 'generic probing'

    def build_investigation_report(self, bounce_analysis, suspicious_patterns, load_analysis=None):
        """Готовит человекочитаемое заключение и практические рекомендации."""
        total_direct = bounce_analysis.get('total_direct', 0)
        total_bounces = bounce_analysis.get('bounces', 0)
        suspicious_ips = sorted(
            suspicious_patterns.get('suspicious_ips', []),
            key=lambda x: (x.get('score', 0), x.get('bounce_count', 0)),
            reverse=True
        )
        datacenter_ips = {x.get('ip') for x in suspicious_patterns.get('datacenter_ips', [])}
        datacenter_count = len(datacenter_ips) if self.use_geoip else None

        recommendations = []
        block_ips = []
        monitor_ips = []
        for item in suspicious_ips:
            action = self._recommend_ip_action(item, datacenter_ips)
            row = {
                'ip': item['ip'],
                'action': action,
                'severity': self._severity_for_ip(item, action),
                'bounce_count': item.get('bounce_count', 0),
                'score': item.get('score', 0),
                'country': item.get('country', 'Unknown'),
                'isp': item.get('isp', 'Unknown'),
                'is_datacenter': item.get('is_datacenter', False) or item['ip'] in datacenter_ips,
                'attack_categories': '; '.join(item.get('attack_categories', {}).keys()),
                'reason': '; '.join(item.get('reasons', [])),
                'sample_urls': '; '.join(item.get('sample_urls', [])[:5]),
            }
            recommendations.append(row)
            if action == 'block':
                block_ips.append(item['ip'])
            elif action == 'monitor':
                monitor_ips.append(item['ip'])

        suspicious_bounces = sum(x.get('bounce_count', 0) for x in suspicious_ips)
        suspicious_bounces = min(suspicious_bounces, total_bounces)
        cleaned_bounces = max(0, total_bounces - suspicious_bounces)
        cleaned_bounce_rate = (cleaned_bounces / total_direct * 100) if total_direct else 0
        contribution_pct = (suspicious_bounces / total_bounces * 100) if total_bounces else 0

        ua_recommendations = self._build_ua_recommendations(suspicious_patterns.get('suspicious_user_agents', []))
        attack_categories = suspicious_patterns.get('attack_categories', [])
        period_comparison = self._build_period_comparison(bounce_analysis.get('daily_stats', []))
        rules = self._build_security_rules(block_ips, ua_recommendations)
        allowlist_notes = self._build_allowlist_notes(suspicious_patterns)
        security = self.build_security_report(recommendations, suspicious_patterns)

        conclusion = self._build_conclusion(
            total_direct=total_direct,
            total_bounces=total_bounces,
            suspicious_bounces=suspicious_bounces,
            contribution_pct=contribution_pct,
            block_count=len(block_ips),
            datacenter_count=datacenter_count,
            attack_categories=attack_categories,
            load_analysis=load_analysis,
        )

        return {
            'conclusion': conclusion,
            'period_comparison': period_comparison,
            'bounce_contribution': {
                'total_direct': total_direct,
                'total_bounces': total_bounces,
                'raw_bounce_rate': bounce_analysis.get('bounce_rate', 0),
                'suspicious_bounces': suspicious_bounces,
                'suspicious_bounce_share': contribution_pct,
                'cleaned_bounces': cleaned_bounces,
                'cleaned_bounce_rate': cleaned_bounce_rate,
            },
            'recommendations': recommendations,
            'ua_recommendations': ua_recommendations,
            'attack_categories': attack_categories,
            'rules': rules,
            'allowlist_notes': allowlist_notes,
            'security': security,
            'block_ips': block_ips,
            'monitor_ips': monitor_ips,
            'geoip_enabled': self.use_geoip,
        }

    def build_security_report(self, recommendations, suspicious_patterns):
        """Расширенный SOC/forensics-срез по access-логам."""
        suspicious_ip_actions = {row['ip']: row['action'] for row in recommendations}
        high_risk_ips = {ip for ip, action in suspicious_ip_actions.items() if action in {'block', 'monitor'}}
        successful_sensitive = []
        payload_findings = []
        sensitive_counter = Counter()
        payload_counter = Counter()
        ip_stage_counter = defaultdict(Counter)
        hourly_campaigns = defaultdict(lambda: {
            'request_count': 0,
            'ips': Counter(),
            'categories': Counter(),
            'payloads': Counter(),
            'sample_urls': []
        })

        for entry in self.entries:
            ip = entry.get('ip')
            url = entry.get('url', '')
            status = int(entry.get('status', 0) or 0)
            category = self._classify_attack_category(url)
            stage = self._security_stage_for_category(category)
            payloads = self._detect_payload_patterns(url)
            is_sensitive = category in {
                'env/config scan', 'credential scan', 'wordpress scan',
                'php shell scan', 'admin/login scan', 'tech file scan'
            }

            if is_sensitive:
                sensitive_counter[category] += 1
            if payloads:
                for payload in payloads:
                    payload_counter[payload] += 1

            if ip in high_risk_ips or is_sensitive or payloads:
                ip_stage_counter[ip][stage] += 1
                hour = entry['timestamp'].replace(minute=0, second=0, microsecond=0)
                campaign = hourly_campaigns[hour]
                campaign['request_count'] += 1
                campaign['ips'][ip] += 1
                campaign['categories'][category] += 1
                for payload in payloads:
                    campaign['payloads'][payload] += 1
                if len(campaign['sample_urls']) < 10:
                    campaign['sample_urls'].append(url)

            if is_sensitive and 200 <= status < 400 and len(successful_sensitive) < 500:
                successful_sensitive.append({
                    'time': entry['timestamp'],
                    'ip': ip,
                    'status': status,
                    'url': url,
                    'category': category,
                    'method': entry.get('method', '-'),
                    'user_agent': entry.get('user_agent', '')[:200],
                    'risk': self._risk_for_successful_sensitive(category, status),
                    'interpretation': self._interpret_sensitive_status(status, category),
                    'note': 'Проверить конечный ответ, Location для редиректа, размер ответа и наличие реального файла/эндпоинта.',
                })

            if payloads and len(payload_findings) < 500:
                payload_findings.append({
                    'time': entry['timestamp'],
                    'ip': ip,
                    'status': status,
                    'url': url,
                    'payload_types': '; '.join(payloads),
                    'method': entry.get('method', '-'),
                    'user_agent': entry.get('user_agent', '')[:200],
                    'risk': 'high' if status < 500 else 'medium',
                })

        kill_chain = self._build_kill_chain(ip_stage_counter, recommendations)
        campaigns = self._build_campaign_rows(hourly_campaigns)
        mitre_matrix = self._build_mitre_matrix(suspicious_patterns, payload_counter)
        iocs = self._build_iocs(recommendations, suspicious_patterns, payload_findings, successful_sensitive)
        manual_checklist = self._build_manual_checklist(successful_sensitive, payload_findings, suspicious_patterns)

        return {
            'successful_sensitive': successful_sensitive,
            'payload_findings': payload_findings,
            'kill_chain': kill_chain,
            'campaigns': campaigns,
            'mitre_matrix': mitre_matrix,
            'sensitive_summary': [
                {'category': category, 'count': count}
                for category, count in sensitive_counter.most_common()
            ],
            'payload_summary': [
                {'payload_type': payload, 'count': count}
                for payload, count in payload_counter.most_common()
            ],
            'manual_checklist': manual_checklist,
            'iocs': iocs,
        }

    def _security_stage_for_category(self, category):
        mapping = {
            'env/config scan': 'Credential Access',
            'credential scan': 'Credential Access',
            'wordpress scan': 'Initial Access',
            'php shell scan': 'Execution / Webshell Discovery',
            'admin/login scan': 'Initial Access',
            'tech file scan': 'Discovery',
            'encoded/probing URL': 'Defense Evasion / Discovery',
            'generic php probe': 'Reconnaissance',
            'generic probing': 'Reconnaissance',
        }
        return mapping.get(category, 'Reconnaissance')

    def _mitre_for_stage(self, stage):
        mapping = {
            'Reconnaissance': ('TA0043', 'Active Scanning / Web Service Discovery'),
            'Credential Access': ('TA0006', 'Credentials from Files / Cloud Credentials'),
            'Initial Access': ('TA0001', 'Exploit Public-Facing Application / Valid Accounts'),
            'Execution / Webshell Discovery': ('TA0002', 'Web Shell / Command and Scripting Interpreter'),
            'Discovery': ('TA0007', 'File and Directory Discovery'),
            'Defense Evasion / Discovery': ('TA0005/TA0007', 'Obfuscated Files or Information / Discovery'),
        }
        return mapping.get(stage, ('TA0043', 'Active Scanning'))

    def _detect_payload_patterns(self, url):
        raw = url.lower()
        decoded = unquote(raw)
        haystack = f"{raw} {decoded}"
        checks = [
            ('SQL injection', ['union select', "' or 1=1", '" or "1"="1', 'information_schema', 'sleep(', 'benchmark(']),
            ('XSS', ['<script', '%3cscript', 'javascript:', 'onerror=', 'onload=']),
            ('Path traversal', ['../', '..%2f', '%2e%2e', '/etc/passwd', 'boot.ini']),
            ('Command injection', [';cat ', '|cat ', 'wget http', 'curl http', 'bash -c', 'cmd.exe', '/bin/sh']),
            ('LFI/RFI', ['?file=', '&file=', '?page=http', '&page=http', 'php://', 'expect://', 'data://']),
            ('Scanner signature', ['sqlmap', 'acunetix', 'nikto', 'nuclei', 'wpscan', 'nessus']),
        ]
        found = []
        for name, needles in checks:
            if any(needle in haystack for needle in needles):
                found.append(name)
        return found

    def _risk_for_successful_sensitive(self, category, status):
        if category in {'credential scan', 'env/config scan'} and status == 200:
            return 'critical'
        if category in {'php shell scan', 'tech file scan'} and status == 200:
            return 'high'
        if status in {301, 302, 307, 308}:
            return 'medium'
        return 'medium'

    def _interpret_sensitive_status(self, status, category):
        if status == 200:
            if category in {'credential scan', 'env/config scan'}:
                return 'Критично: чувствительный путь отдал 200. Срочно проверить, не раскрыт ли файл/секрет.'
            return 'Высокий риск: эндпоинт существует или отдал контент. Проверить содержимое ответа.'
        if status in {301, 302, 307, 308}:
            return 'Редирект: проверить Location и конечный статус. Часто это HTTPS/slash redirect, но endpoint может существовать.'
        if status == 403:
            return 'Защита сработала: доступ запрещён. Оставить правило и мониторить повторения.'
        if status == 404:
            return 'Путь не найден: признак сканирования, но успешного доступа не видно.'
        if 500 <= status < 600:
            return 'Ошибка сервера: проверить error.log, возможна попытка эксплуатации или нагрузочный эффект.'
        return 'Требует ручной проверки по access/error логам.'

    def _build_kill_chain(self, ip_stage_counter, recommendations):
        rec_by_ip = {row['ip']: row for row in recommendations}
        rows = []
        for ip, stages in ip_stage_counter.items():
            if ip not in rec_by_ip and sum(stages.values()) < 5:
                continue
            ordered = [f"{stage} ({count})" for stage, count in stages.most_common()]
            rec = rec_by_ip.get(ip, {})
            rows.append({
                'ip': ip,
                'action': rec.get('action', 'monitor'),
                'severity': rec.get('severity', 'medium'),
                'stages': ' -> '.join(ordered),
                'stage_count': len(stages),
                'total_events': sum(stages.values()),
            })
        return sorted(rows, key=lambda x: (x['severity'] == 'critical', x['total_events']), reverse=True)[:200]

    def _build_campaign_rows(self, hourly_campaigns):
        rows = []
        for hour, data in hourly_campaigns.items():
            if data['request_count'] < 20 and len(data['ips']) < 3:
                continue
            rows.append({
                'period_start': hour,
                'request_count': data['request_count'],
                'unique_ips': len(data['ips']),
                'top_ips': ', '.join(f"{ip}({count})" for ip, count in data['ips'].most_common(5)),
                'top_categories': ', '.join(f"{cat}({count})" for cat, count in data['categories'].most_common(5)),
                'payloads': ', '.join(f"{name}({count})" for name, count in data['payloads'].most_common(5)),
                'sample_urls': '; '.join(data['sample_urls'][:5])[:500],
            })
        return sorted(rows, key=lambda x: x['request_count'], reverse=True)[:200]

    def _build_mitre_matrix(self, suspicious_patterns, payload_counter):
        stage_counter = Counter()
        evidence = defaultdict(list)
        for item in suspicious_patterns.get('attack_categories', []):
            category = item['category']
            stage = self._security_stage_for_category(category)
            stage_counter[stage] += item['count']
            if len(evidence[stage]) < 5:
                evidence[stage].append(category)
        for payload, count in payload_counter.items():
            stage = 'Exploitation Attempt'
            stage_counter[stage] += count
            if len(evidence[stage]) < 5:
                evidence[stage].append(payload)
        rows = []
        for stage, count in stage_counter.most_common():
            tactic_id, technique = self._mitre_for_stage(stage)
            rows.append({
                'stage': stage,
                'mitre_tactic': tactic_id,
                'technique': technique,
                'events': count,
                'evidence': '; '.join(evidence[stage]),
                'risk': 'critical' if stage in {'Credential Access', 'Exploitation Attempt'} else 'high',
            })
        return rows

    def _build_iocs(self, recommendations, suspicious_patterns, payload_findings, successful_sensitive):
        block_ips = [row['ip'] for row in recommendations if row.get('action') == 'block']
        monitor_ips = [row['ip'] for row in recommendations if row.get('action') == 'monitor']
        user_agents = [
            row.get('user_agent', '')
            for row in self._build_ua_recommendations(suspicious_patterns.get('suspicious_user_agents', []))
            if row.get('action') == 'block' and row.get('user_agent') not in ('', '-')
        ]
        paths = set()
        for item in suspicious_patterns.get('suspicious_ips', []):
            for url in item.get('sample_urls', [])[:10]:
                path = urlparse(url).path
                if path:
                    paths.add(path)
        for row in payload_findings[:100]:
            paths.add(urlparse(row['url']).path)
        for row in successful_sensitive[:100]:
            paths.add(urlparse(row['url']).path)
        return {
            'block_ips': block_ips,
            'monitor_ips': monitor_ips,
            'user_agents': sorted(set(user_agents)),
            'paths': sorted(paths)[:500],
        }

    def _build_manual_checklist(self, successful_sensitive, payload_findings, suspicious_patterns):
        checklist = [
            {
                'priority': 'critical',
                'check': 'Проверить чувствительные URL с HTTP 200',
                'why': '200 по .env/config/credentials/webshell-путям может означать доступный файл или endpoint.',
                'how': 'Открыть только из доверенной сети или проверить curl -I, access.log, error.log, размер ответа и Location.',
            },
            {
                'priority': 'high',
                'check': 'Проверить все 301/302 по admin/wp/php путям',
                'why': 'Редирект может быть обычным HTTPS/slash redirect, но также подтверждает существование маршрута.',
                'how': 'Проверить цепочку редиректов и конечный статус; убедиться, что нет 200 на чувствительном endpoint.',
            },
            {
                'priority': 'high',
                'check': 'Сверить top IP с CDN/proxy и реальным client IP',
                'why': 'Если сайт за прокси, 127.0.0.1 или IP балансировщика могут скрывать реального атакующего.',
                'how': 'Проверить X-Forwarded-For/real_ip_header и настройки nginx/apache.',
            },
            {
                'priority': 'medium',
                'check': 'Проверить payload findings в error.log',
                'why': 'Path traversal/LFI/SQLi могут не дать 200, но вызвать 400/500 или следы в приложении.',
                'how': 'По времени и IP сопоставить access.log с error.log и application logs.',
            },
            {
                'priority': 'medium',
                'check': 'Перед блокировкой применить allowlist',
                'why': 'Поисковые боты, prefetch proxy, мониторинг и офисные IP нельзя блокировать только по одному признаку.',
                'how': 'Проверить reverse DNS/ASN, список клиентов, мониторинги и интеграции.',
            },
        ]
        if not any(row.get('status') == 200 for row in successful_sensitive):
            checklist[0]['priority'] = 'medium'
            checklist[0]['why'] = 'В текущем срезе явных HTTP 200 по чувствительным путям не найдено, но правило полезно для проверки будущих отчётов.'
        if not payload_findings:
            checklist[3]['priority'] = 'low'
            checklist[3]['why'] = 'Payload-паттерны в текущем срезе не найдены, но проверка полезна при расследовании.'
        if suspicious_patterns.get('datacenter_ips'):
            checklist.append({
                'priority': 'medium',
                'check': 'Проверить датацентры и облачные сети',
                'why': 'Сканирование с облачных IP часто лучше отправлять на challenge/rate-limit, а не всегда блокировать ASN целиком.',
                'how': 'Сгруппировать по ASN/провайдеру и оценить ложноположительные риски.',
            })
        return checklist

    def _recommend_ip_action(self, item, datacenter_ips):
        categories = set(item.get('attack_categories', {}).keys())
        high_risk_category = bool(categories & {
            'env/config scan', 'credential scan', 'php shell scan',
            'wordpress scan', 'tech file scan', 'encoded/probing URL'
        })
        if item.get('score', 0) >= 4 and (item.get('bounce_count', 0) >= 50 or high_risk_category):
            return 'block'
        if item.get('is_datacenter') or item.get('ip') in datacenter_ips:
            return 'block' if item.get('bounce_count', 0) >= 25 else 'monitor'
        if item.get('score', 0) >= 2:
            return 'monitor'
        return 'allow'

    def _severity_for_ip(self, item, action):
        if action == 'block' and item.get('score', 0) >= 5:
            return 'critical'
        if action == 'block':
            return 'high'
        if action == 'monitor':
            return 'medium'
        return 'low'

    def _build_ua_recommendations(self, suspicious_user_agents):
        rows = []
        explicit_bad = ['securityscanner', 'python-requests', 'curl', 'wget', 'scrapy', 'masscan']
        monitor_names = ['chrome privacy preserving prefetch proxy']
        for item in suspicious_user_agents:
            ua = item.get('user_agent', '')
            ua_lower = ua.lower()
            if ua == '-' or any(token in ua_lower for token in explicit_bad):
                action = 'block'
            elif any(token in ua_lower for token in monitor_names):
                action = 'allow/monitor'
            elif item.get('bounce_count', 0) >= 100 and item.get('unique_ips', 0) >= 3:
                action = 'monitor'
            else:
                action = 'monitor'
            rows.append({
                'user_agent': ua,
                'action': action,
                'bounce_count': item.get('bounce_count', 0),
                'unique_ips': item.get('unique_ips', 0),
                'attack_categories': '; '.join(item.get('attack_categories', {}).keys()),
                'sample_ips': '; '.join(item.get('sample_ips', [])[:5]),
                'sample_urls': '; '.join(item.get('sample_urls', [])[:5]),
            })
        return rows

    def _build_period_comparison(self, daily_stats):
        if not daily_stats:
            return []
        rows = []
        sorted_rows = sorted(daily_stats, key=lambda x: x['date'])
        periods = [('Весь период', sorted_rows)]
        if len(sorted_rows) >= 14:
            periods.extend([
                ('База: до последних 7 дней', sorted_rows[:-7]),
                ('Последние 7 дней', sorted_rows[-7:]),
            ])
        if len(sorted_rows) >= 2:
            periods.extend([
                ('Первый день', [sorted_rows[0]]),
                ('Последний день', [sorted_rows[-1]]),
            ])
        for name, items in periods:
            direct = sum(x.get('direct', 0) for x in items)
            bounces = sum(x.get('bounces', 0) for x in items)
            total = sum(x.get('total_requests', 0) for x in items)
            rows.append({
                'period': name,
                'start': items[0]['date'],
                'end': items[-1]['date'],
                'total_requests': total,
                'direct': direct,
                'bounces': bounces,
                'bounce_rate': (bounces / direct * 100) if direct else 0,
            })
        return rows

    def _build_security_rules(self, block_ips, ua_recommendations):
        block_ips = block_ips[:50]
        block_uas = [
            row['user_agent'] for row in ua_recommendations
            if row.get('action') == 'block' and row.get('user_agent') not in ('', '-')
        ][:15]
        rules = []
        if block_ips:
            rules.append({
                'type': 'nginx deny',
                'description': 'Точечная блокировка IP с критичными признаками сканирования.',
                'rule': '\n'.join(f"deny {ip};" for ip in block_ips[:20]),
            })
            rules.append({
                'type': 'iptables',
                'description': 'Альтернатива для сетевого уровня.',
                'rule': '\n'.join(f"iptables -A INPUT -s {ip} -j DROP" for ip in block_ips[:20]),
            })
        if block_uas:
            escaped = '|'.join(re.escape(ua[:80]) for ua in block_uas)
            rules.append({
                'type': 'nginx user-agent filter',
                'description': 'Блокировка явно технических user-agent. Массовые браузерные UA лучше мониторить, а не блокировать.',
                'rule': f'if ($http_user_agent ~* "({escaped})") {{\n    return 403;\n}}',
            })
        rules.append({
            'type': 'nginx sensitive paths',
            'description': 'Закрыть типовые пути, по которым ходят сканеры конфигов и секретов.',
            'rule': 'location ~* "(\\.env|\\.git|\\.svn|\\.aws|wp-config|database\\.yml|phpinfo|phpversion)" {\n    deny all;\n}',
        })
        rules.append({
            'type': 'nginx rate limit',
            'description': 'Ограничить частые direct-запросы с одного IP.',
            'rule': 'limit_req_zone $binary_remote_addr zone=direct_limit:10m rate=5r/s;\nlimit_req zone=direct_limit burst=20 nodelay;',
        })
        return rules

    def _build_allowlist_notes(self, suspicious_patterns):
        notes = [
            {
                'item': 'Поисковые боты',
                'action': 'allow after verification',
                'note': 'Googlebot/Bing/Yandex не блокировать только по UA; проверять reverse DNS и ASN.',
            },
            {
                'item': 'Chrome Privacy Preserving Prefetch Proxy',
                'action': 'allow/monitor',
                'note': 'Может давать direct-like запросы и .well-known/traffic-advice; лучше не блокировать автоматически.',
            },
            {
                'item': '127.0.0.1 и приватные IP',
                'action': 'investigate locally',
                'note': 'Разбирать отдельно: это может быть прокси, health-check, cron или особенность логирования.',
            },
            {
                'item': 'IP клиента и подрядчиков',
                'action': 'allowlist',
                'note': 'Перед применением deny-правил исключить офисные, мониторинговые и интеграционные адреса.',
            },
        ]
        if suspicious_patterns.get('datacenter_ips'):
            notes.append({
                'item': 'Датацентры',
                'action': 'block or challenge',
                'note': 'Не весь датацентр вреден, но при сканировании технических URL лучше блокировать или отправлять на антибот.',
            })
        return notes

    def _build_conclusion(self, total_direct, total_bounces, suspicious_bounces, contribution_pct, block_count, datacenter_count, attack_categories, load_analysis):
        top_categories = ', '.join(
            f"{x['category']} ({x['count']})" for x in attack_categories[:3]
        ) or 'нет выраженных категорий'
        anomaly_count = len(load_analysis.get('anomalies', [])) if load_analysis else 0
        dc_text = (
            f"IP из датацентров: {datacenter_count}"
            if datacenter_count is not None
            else "GeoIP отключён, принадлежность к датацентрам не оценивалась"
        )
        return (
            "Рост отказов по direct-трафику следует проверять как смесь реальных прямых визитов и нежелательной активности. "
            f"В текущем срезе найдено {suspicious_bounces:,} подозрительных отказов из {total_bounces:,} "
            f"({contribution_pct:.1f}% отказов direct). "
            f"К блокировке рекомендовано {block_count} IP, {dc_text}, "
            f"аномальных периодов нагрузки: {anomaly_count}. "
            f"Основные признаки: {top_categories}. "
            "Рекомендуется применять точечные блокировки IP, закрыть технические пути, включить rate limiting и проверять спорные UA/IP через allowlist."
        )
    
    def _has_scanning_pattern(self, urls):
        """Определяет паттерны сканирования"""
        if len(urls) < 5:
            return False
        
        wp_patterns = ['wp-admin', 'wp-login', 'wp-content', 'wp-includes', 'xmlrpc', 'phpmyadmin', 'admin', 'login']
        if any(pattern in ' '.join(urls).lower() for pattern in wp_patterns):
            return True
        
        paths = [urlparse(url).path for url in urls]
        unique_paths = len(set(paths))
        if unique_paths > len(urls) * 0.8:
            return True
        
        return False
    
    def analyze_by_periods(self, bounce_entries):
        """Анализирует отказы по временным периодам"""
        if not bounce_entries:
            return []
        
        hourly_stats = defaultdict(lambda: {'count': 0, 'unique_ips': set(), 'status_codes': Counter()})
        
        for entry in bounce_entries:
            hour_key = entry['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_stats[hour_key]['count'] += 1
            hourly_stats[hour_key]['unique_ips'].add(entry['ip'])
            hourly_stats[hour_key]['status_codes'][entry['status']] += 1
        
        period_data = []
        for hour, stats in sorted(hourly_stats.items()):
            period_data.append({
                'Период': hour.strftime('%Y-%m-%d %H:00'),
                'Количество отказов': stats['count'],
                'Уникальных IP': len(stats['unique_ips']),
                'Средний отказов на IP': f"{stats['count'] / len(stats['unique_ips']):.2f}" if stats['unique_ips'] else '0',
                'Код 200': stats['status_codes'].get(200, 0),
                'Код 404': stats['status_codes'].get(404, 0),
                'Другие коды': sum(count for code, count in stats['status_codes'].items() if code not in [200, 404])
            })
        
        return period_data
    
    def analyze_load_periods(self, window_minutes=15, threshold_percentile=75):
        """Анализирует периоды высокой нагрузки"""
        print(f"\nАнализ периодов нагрузки (окно: {window_minutes} минут)...")
        
        if not self.entries:
            return {
                'high_load_periods': [],
                'normal_load_periods': [],
                'anomalies': [],
                'comparison': {}
            }
        
        window_stats = defaultdict(lambda: {
            'count': 0,
            'unique_ips': set(),
            'unique_urls': set(),
            'status_codes': Counter(),
            'ips': Counter(),
            'urls': Counter(),
            'user_agents': Counter(),
            'methods': Counter(),
            'total_size': 0
        })
        
        for entry in self.entries:
            timestamp = entry['timestamp']
            minutes = timestamp.minute
            window_start_minute = (minutes // window_minutes) * window_minutes
            window_key = timestamp.replace(minute=window_start_minute, second=0, microsecond=0)
            
            stats = window_stats[window_key]
            stats['count'] += 1
            stats['unique_ips'].add(entry['ip'])
            stats['unique_urls'].add(entry['url'])
            stats['status_codes'][entry['status']] += 1
            stats['ips'][entry['ip']] += 1
            stats['urls'][entry['url']] += 1
            stats['user_agents'][entry['user_agent']] += 1
            stats['methods'][entry['method']] += 1
            try:
                size = int(entry['size']) if entry['size'] != '-' else 0
                stats['total_size'] += size
            except:
                pass
        
        request_counts = [stats['count'] for stats in window_stats.values()]
        if not request_counts:
            return {
                'high_load_periods': [],
                'normal_load_periods': [],
                'anomalies': [],
                'comparison': {}
            }
        
        if HAS_NUMPY:
            threshold = np.percentile(request_counts, threshold_percentile)
            mean_count = np.mean(request_counts)
            median_count = np.median(request_counts)
        else:
            sorted_counts = sorted(request_counts)
            threshold_idx = int(len(sorted_counts) * threshold_percentile / 100)
            threshold = sorted_counts[threshold_idx] if threshold_idx < len(sorted_counts) else sorted_counts[-1]
            mean_count = sum(request_counts) / len(request_counts)
            median_idx = len(sorted_counts) // 2
            median_count = sorted_counts[median_idx] if sorted_counts else 0
        
        print(f"Порог высокой нагрузки: {threshold:.0f} запросов")
        
        high_load_periods = []
        normal_load_periods = []
        
        for window_key, stats in sorted(window_stats.items()):
            period_info = {
                'period_start': window_key,
                'period_end': window_key + timedelta(minutes=window_minutes),
                'request_count': stats['count'],
                'unique_ips': len(stats['unique_ips']),
                'unique_urls': len(stats['unique_urls']),
                'requests_per_ip': stats['count'] / len(stats['unique_ips']) if stats['unique_ips'] else 0,
                'top_ips': dict(stats['ips'].most_common(10)),
                'top_urls': dict(stats['urls'].most_common(10)),
                'top_user_agents': dict(stats['user_agents'].most_common(5)),
                'status_codes': dict(stats['status_codes']),
                'methods': dict(stats['methods']),
                'total_size_mb': stats['total_size'] / (1024 * 1024),
                'avg_size_kb': (stats['total_size'] / stats['count'] / 1024) if stats['count'] > 0 else 0
            }
            
            if stats['count'] >= threshold:
                high_load_periods.append(period_info)
            else:
                normal_load_periods.append(period_info)
        
        anomalies = self._detect_load_anomalies(high_load_periods, normal_load_periods)
        comparison = self._compare_load_periods(high_load_periods, normal_load_periods)
        
        return {
            'high_load_periods': high_load_periods,
            'normal_load_periods': normal_load_periods,
            'anomalies': anomalies,
            'comparison': comparison,
            'threshold': threshold,
            'mean_count': mean_count,
            'median_count': median_count,
            'window_minutes': window_minutes
        }
    
    def _detect_load_anomalies(self, high_load_periods, normal_load_periods):
        """Выявляет аномалии в периоды высокой нагрузки"""
        if not high_load_periods or not normal_load_periods:
            return []
        
        if HAS_NUMPY:
            normal_avg_ips = np.mean([p['unique_ips'] for p in normal_load_periods]) if normal_load_periods else 0
            normal_avg_requests_per_ip = np.mean([p['requests_per_ip'] for p in normal_load_periods]) if normal_load_periods else 0
        else:
            normal_ips_list = [p['unique_ips'] for p in normal_load_periods] if normal_load_periods else []
            normal_avg_ips = sum(normal_ips_list) / len(normal_ips_list) if normal_ips_list else 0
            normal_requests_per_ip_list = [p['requests_per_ip'] for p in normal_load_periods] if normal_load_periods else []
            normal_avg_requests_per_ip = sum(normal_requests_per_ip_list) / len(normal_requests_per_ip_list) if normal_requests_per_ip_list else 0
        
        anomalies = []
        
        for period in high_load_periods:
            anomaly_reasons = []
            
            if period['requests_per_ip'] > normal_avg_requests_per_ip * 2:
                anomaly_reasons.append(f"Высокое количество запросов на IP ({period['requests_per_ip']:.1f} vs норма {normal_avg_requests_per_ip:.1f})")
            
            if period['unique_ips'] < normal_avg_ips * 0.5 and period['request_count'] > 100:
                anomaly_reasons.append(f"Мало уникальных IP ({period['unique_ips']} vs норма {normal_avg_ips:.0f}) при высокой нагрузке")
            
            error_count = sum(count for code, count in period['status_codes'].items() if code >= 400)
            error_rate = error_count / period['request_count'] * 100 if period['request_count'] > 0 else 0
            if error_rate > 20:
                anomaly_reasons.append(f"Высокий процент ошибок ({error_rate:.1f}%)")
            
            if period['top_ips']:
                top_ip, top_count = max(period['top_ips'].items(), key=lambda x: x[1])
                top_ip_share = top_count / period['request_count'] * 100
                if top_ip_share > 30:
                    anomaly_reasons.append(f"Один IP доминирует: {top_ip} ({top_ip_share:.1f}% запросов)")
            
            if period['top_urls']:
                top_url, top_count = max(period['top_urls'].items(), key=lambda x: x[1])
                top_url_share = top_count / period['request_count'] * 100
                if top_url_share > 40:
                    anomaly_reasons.append(f"Один URL доминирует: {top_url[:100]} ({top_url_share:.1f}% запросов)")
            
            if anomaly_reasons:
                anomalies.append({
                    'period_start': period['period_start'],
                    'period_end': period['period_end'],
                    'request_count': period['request_count'],
                    'unique_ips': period['unique_ips'],
                    'reasons': anomaly_reasons,
                    'top_ips': period['top_ips'],
                    'top_urls': period['top_urls'],
                    'error_rate': error_rate
                })
        
        return anomalies
    
    def _compare_load_periods(self, high_load_periods, normal_load_periods):
        """Сравнивает периоды высокой и нормальной нагрузки"""
        if not high_load_periods or not normal_load_periods:
            return {}
        
        def calc_avg(periods, key):
            if not periods:
                return 0
            if HAS_NUMPY:
                return np.mean([p[key] for p in periods])
            else:
                values = [p[key] for p in periods]
                return sum(values) / len(values) if values else 0
        
        comparison = {
            'high_load': {
                'avg_requests': calc_avg(high_load_periods, 'request_count'),
                'avg_unique_ips': calc_avg(high_load_periods, 'unique_ips'),
                'avg_requests_per_ip': calc_avg(high_load_periods, 'requests_per_ip'),
                'avg_unique_urls': calc_avg(high_load_periods, 'unique_urls'),
                'total_periods': len(high_load_periods)
            },
            'normal_load': {
                'avg_requests': calc_avg(normal_load_periods, 'request_count'),
                'avg_unique_ips': calc_avg(normal_load_periods, 'unique_ips'),
                'avg_requests_per_ip': calc_avg(normal_load_periods, 'requests_per_ip'),
                'avg_unique_urls': calc_avg(normal_load_periods, 'unique_urls'),
                'total_periods': len(normal_load_periods)
            }
        }
        
        comparison['difference'] = {}
        for key in ['avg_requests', 'avg_unique_ips', 'avg_requests_per_ip', 'avg_unique_urls']:
            high_val = comparison['high_load'][key]
            normal_val = comparison['normal_load'][key]
            if normal_val > 0:
                diff_percent = ((high_val - normal_val) / normal_val) * 100
                comparison['difference'][key] = diff_percent
            else:
                comparison['difference'][key] = 0
        
        return comparison

    def _slugify_filename(self, filename):
        """Создает безопасное имя файла"""
        return re.sub(r'[^a-z0-9]+', '_', filename.lower()).strip('_')

    def print_summary(self, bounce_analysis, suspicious_patterns, load_analysis):
        """Выводит сводку в консоль"""
        print("\n" + "="*50)
        print("СВОДКА")
        print("="*50)
        
        print(f"\nАнализ для домена: {self.domain} (источник: {self.domain_source})")
        print(f"Всего записей обработано: {len(self.entries)}")
        
        print("\nОТКАЗЫ (BOUNCE RATE)")
        print(f"Всего прямых заходов: {bounce_analysis['total_direct']}")
        print(f"Отказов: {bounce_analysis['bounces']}")
        print(f"Bounce Rate: {bounce_analysis['bounce_rate']:.2f}%")
        print(f"Прямых сессий: {bounce_analysis.get('direct_sessions', 0)}")
        print(f"Сессий с отказом: {bounce_analysis.get('bounce_sessions', 0)}")
        
        print("\nПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ")
        suspicious_ips = suspicious_patterns['suspicious_ips']
        print(f"Подозрительных IP: {len(suspicious_ips)}")
        
        if suspicious_ips:
            print("\nТоп подозрительных IP:")
            sorted_ips = sorted(suspicious_ips, key=lambda x: x['score'], reverse=True)[:5]
            for ip in sorted_ips:
                country = ip.get('country', 'Unknown')
                print(f"  - {ip['ip']} ({country}): Score {ip['score']}, Отказов {ip['bounce_count']}")
                if ip['reasons']:
                    print(f"    Причины: {', '.join(ip['reasons'])}")
        
        if suspicious_patterns['datacenter_ips']:
            print(f"\nОбнаружено заходов из датацентров: {len(suspicious_patterns['datacenter_ips'])}")
            
        print("\nНАГРУЗКА")
        if load_analysis and load_analysis.get('high_load_periods'):
            print(f"Периодов высокой нагрузки: {len(load_analysis['high_load_periods'])}")
            print(f"Порог нагрузки: {load_analysis.get('threshold', 0):.0f} запросов/{load_analysis.get('window_minutes', 15)}мин")
        else:
            print("Периодов высокой нагрузки не выявлено")
