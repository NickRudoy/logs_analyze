
import gzip
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from .parser import LogParser
from .geoip import GeoIPAnalyzer
from .user_agent import UserAgentAnalyzer

class DirectTrafficAnalyzer:
    """Анализатор прямого трафика"""
    
    def __init__(self, log_path, domain='auto', start_date=None, end_date=None, use_geoip=True, log_files=None, verbose=False):
        self.log_path = Path(log_path)
        self.log_files = [Path(p) for p in log_files] if log_files else self._resolve_log_files(self.log_path)
        self.domain_input = domain
        self.domain = domain if domain not in (None, 'auto') else None
        self.domain_source = 'аргумент --domain' if self.domain else 'auto'
        self.start_date = start_date
        self.end_date = end_date
        self.use_geoip = use_geoip
        self.verbose = verbose
        self.entries = []
        self.direct_traffic = []
        self.geo_analyzer = GeoIPAnalyzer(use_api=use_geoip, verbose=verbose) if use_geoip else None
        self.ua_analyzer = UserAgentAnalyzer()
    
    def _resolve_log_files(self, log_path):
        """Определяет список файлов для анализа"""
        if log_path.is_file():
            return [log_path]
        if log_path.is_dir():
            all_files = [p for p in log_path.iterdir() if p.is_file()]
            access_files = sorted([
                p for p in all_files
                if 'access' in p.name.lower() and (p.suffix in {'', '.log', '.gz', '.txt'} or True)
            ])
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
                while labels and (labels[-1] in {'log', 'access', 'error', 'gz', 'txt'} or labels[-1].isdigit()):
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
    
    def parse_logs(self):
        """Парсит логи из файла"""
        print(f"Парсинг логов из {self.log_path}...")
        print(f"Найдено файлов для анализа: {len(self.log_files)}")
        
        if self.start_date:
            print(f"Фильтр: с {self.start_date.strftime('%Y-%m-%d')}")
        if self.end_date:
            print(f"Фильтр: по {self.end_date.strftime('%Y-%m-%d')}")
        
        parsed_count = 0
        skipped_count = 0
        
        for file_index, log_file in enumerate(self.log_files, 1):
            print(f"\n[{file_index}/{len(self.log_files)}] Файл: {log_file}")
            try:
                with self._open_log(log_file) as f:
                    for line_num, line in enumerate(f, 1):
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
                            self.entries.append(entry)
                            parsed_count += 1
                        else:
                            skipped_count += 1
                        
                        if line_num % 10000 == 0:
                            print(f"  Обработано строк: {line_num:,} | Всего распознано записей: {parsed_count:,}")
            except FileNotFoundError:
                print(f"Ошибка: файл {log_file} не найден")
                sys.exit(1)
            except Exception as e:
                print(f"Ошибка при чтении файла {log_file}: {e}")
                sys.exit(1)
        
        print(f"\nВсего записей: {len(self.entries):,}")
        if skipped_count > 0:
            print(f"Пропущено нераспознанных строк: {skipped_count:,}")
        
    def identify_direct_traffic(self):
        """Определяет прямые заходы (direct traffic)"""
        print("\nОпределение прямого трафика...")
        
        for entry in self.entries:
            referer = entry['referer']
            is_direct = (
                referer == '-' or 
                referer == '' or
                self.domain not in referer.lower()
            )
            
            if is_direct:
                user_agent = entry['user_agent'].lower()
                if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'googlebot', 'yandex', 'bing']):
                    continue
                
                url = entry['url'].lower()
                if any(resource in url for resource in ['/wp-content/', '/wp-includes/', '/wp-json/', '/wp-cron', '/wp-admin/', '.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg']):
                    continue
                
                self.direct_traffic.append(entry)
        
        print(f"Прямых заходов: {len(self.direct_traffic)}")
        
    def analyze_bounce_rate(self):
        """Анализирует отказы (bounce rate)"""
        print("\nАнализ отказов...")
        
        sessions = defaultdict(list)
        
        for entry in self.direct_traffic:
            key = f"{entry['ip']}|{entry['user_agent']}"
            sessions[key].append(entry)
        
        bounces = []
        non_bounces = []
        
        for key, session_entries in sessions.items():
            session_entries.sort(key=lambda x: x['timestamp'])
            successful_requests = [e for e in session_entries if e['status'] == 200]
            
            if len(successful_requests) <= 1:
                bounces.extend(session_entries)
            else:
                non_bounces.extend(session_entries)
        
        bounce_rate = len(bounces) / len(self.direct_traffic) * 100 if self.direct_traffic else 0
        
        print(f"Отказов: {len(bounces)} ({bounce_rate:.2f}%)")
        print(f"Не отказов: {len(non_bounces)} ({100 - bounce_rate:.2f}%)")
        
        return {
            'total_direct': len(self.direct_traffic),
            'bounces': len(bounces),
            'non_bounces': len(non_bounces),
            'bounce_rate': bounce_rate,
            'bounce_entries': bounces,
            'non_bounce_entries': non_bounces
        }
    
    def find_suspicious_patterns(self, bounce_entries):
        """Выявляет подозрительные паттерны"""
        print("\nПоиск подозрительных паттернов...")
        
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
        
        ip_counter = Counter(e['ip'] for e in bounce_entries)
        ip_sessions = defaultdict(list)
        for entry in bounce_entries:
            ip_sessions[entry['ip']].append(entry)
        
        for ip, count in ip_counter.most_common(50):
            sessions = ip_sessions[ip]
            unique_urls = len(set(e['url'] for e in sessions))
            unique_user_agents = len(set(e['user_agent'] for e in sessions))
            
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
            
            urls = [e['url'] for e in sessions]
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
                    'user_agents': list(set(e['user_agent'] for e in sessions)),
                    'sample_urls': urls[:10],
                    'score': suspicious_score,
                    'reasons': reasons,
                    'first_seen': min(e['timestamp'] for e in sessions),
                    'last_seen': max(e['timestamp'] for e in sessions),
                    'country': ip_info.get('country', 'Unknown'),
                    'country_code': ip_info.get('country_code', 'XX'),
                    'city': ip_info.get('city', 'Unknown'),
                    'isp': ip_info.get('isp', 'Unknown'),
                    'ip_type': ip_info.get('ip_type', 'Unknown'),
                    'is_datacenter': ip_info.get('is_datacenter', False)
                })
        
        ua_counter = Counter(e['user_agent'] for e in bounce_entries)
        ua_sessions = defaultdict(list)
        for entry in bounce_entries:
            ua_sessions[entry['user_agent']].append(entry)
        
        for ua, count in ua_counter.most_common(30):
            if count > 5:
                sessions = ua_sessions[ua]
                unique_ips = len(set(e['ip'] for e in sessions))
                
                if count > 10 or (unique_ips > 5 and count > 5):
                    ua_info = self.ua_analyzer.parse_user_agent(ua)
                    
                    suspicious['suspicious_user_agents'].append({
                        'user_agent': ua[:200],
                        'bounce_count': count,
                        'unique_ips': unique_ips,
                        'sample_ips': list(set(e['ip'] for e in sessions))[:10],
                        'sample_urls': list(set(e['url'] for e in sessions))[:10],
                        'browser': ua_info['browser'],
                        'browser_version': ua_info['browser_version'],
                        'os': ua_info['os'],
                        'os_version': ua_info['os_version'],
                        'device_type': ua_info['device_type'],
                        'is_bot': ua_info['is_bot'],
                        'is_mobile': ua_info['is_mobile']
                    })
        
        ip_timestamps = defaultdict(list)
        for entry in bounce_entries:
            ip_timestamps[entry['ip']].append(entry['timestamp'])
        
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
        
        error_entries = [e for e in bounce_entries if e['status'] >= 400]
        error_counter = Counter((e['ip'], e['status']) for e in error_entries)
        
        for (ip, status), count in error_counter.most_common(20):
            if count > 5:
                suspicious['error_patterns'].append({
                    'ip': ip,
                    'status': status,
                    'count': count
                })
        
        if self.use_geoip and self.geo_analyzer:
            success_count = self.geo_analyzer.success_count - initial_success
            error_count = self.geo_analyzer.error_count - initial_errors
            total_requests = success_count + error_count
            if total_requests > 0:
                success_rate = (success_count / total_requests) * 100
                print(f"Геолокация: успешно {success_count}/{total_requests} ({success_rate:.1f}%), ошибок: {error_count}")
        
        return suspicious
    
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
            'total_size': 0,
            'entries': []
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
            stats['entries'].append(entry)
        
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

