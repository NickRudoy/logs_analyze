"""
Анализатор логов для выявления подозрительных источников прямого трафика.
Анализирует Apache/Nginx access logs и выявляет паттерны, связанные с ростом отказов.

Версия: 1.0
Автор: NickRudoy
"""

import re
import gzip
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse
import argparse
import sys
from pathlib import Path
import time
import json
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Предупреждение: библиотека requests не установлена. Геолокация будет отключена.")
    print("Установите: pip install requests")


class GeoIPAnalyzer:
    """Анализатор геолокации и информации об IP"""
    
    def __init__(self, use_api=True):
        self.use_api = use_api and HAS_REQUESTS
        self.cache = {}  # Кэш для уже проверенных IP
        self.api_delay = 0.2  # Задержка между запросами к API (секунды)
        self.last_request_time = 0
        
    def get_ip_info(self, ip):
        """Получает информацию об IP: страна, город, провайдер, тип"""
        if ip in self.cache:
            return self.cache[ip]
        
        if not self.use_api:
            return {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'isp': 'Unknown',
                'ip_type': 'Unknown',
                'is_datacenter': False
            }
        
        # Проверка на локальные/приватные IP
        if self._is_private_ip(ip):
            return {
                'country': 'Local',
                'country_code': 'LOC',
                'city': 'Local Network',
                'isp': 'Local',
                'ip_type': 'Private',
                'is_datacenter': False
            }
        
        # Задержка для соблюдения rate limit
        current_time = time.time()
        if current_time - self.last_request_time < self.api_delay:
            time.sleep(self.api_delay - (current_time - self.last_request_time))
        
        try:
            # Используем ip-api.com (бесплатный, до 45 запросов/мин)
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=5,
                params={'fields': 'status,message,country,countryCode,city,isp,org,as,query'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    ip_info = {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'ip_type': self._determine_ip_type(data.get('isp', ''), data.get('org', '')),
                        'is_datacenter': self._is_datacenter(data.get('isp', ''), data.get('org', ''))
                    }
                    self.cache[ip] = ip_info
                    self.last_request_time = time.time()
                    return ip_info
        except Exception as e:
            # В случае ошибки API возвращаем Unknown
            pass
        
        # Fallback
        ip_info = {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'isp': 'Unknown',
            'ip_type': 'Unknown',
            'is_datacenter': False
        }
        self.cache[ip] = ip_info
        return ip_info
    
    def _is_private_ip(self, ip):
        """Проверяет, является ли IP приватным"""
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])
                # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                if first == 127:  # localhost
                    return True
            except:
                pass
        return False
    
    def _is_datacenter(self, isp, org):
        """Определяет, является ли IP датацентром"""
        datacenter_keywords = [
            'datacenter', 'data center', 'hosting', 'server', 'cloud',
            'amazon', 'aws', 'google cloud', 'azure', 'digitalocean',
            'linode', 'vultr', 'ovh', 'hetzner', 'online.net',
            'leaseweb', 'server', 'vps', 'dedicated', 'colo'
        ]
        
        combined = (isp + ' ' + org).lower()
        return any(keyword in combined for keyword in datacenter_keywords)
    
    def _determine_ip_type(self, isp, org):
        """Определяет тип IP"""
        combined = (isp + ' ' + org).lower()
        
        if self._is_datacenter(isp, org):
            return 'Datacenter'
        if any(keyword in combined for keyword in ['mobile', 'cellular', '3g', '4g', '5g', 'lte']):
            return 'Mobile'
        if any(keyword in combined for keyword in ['residential', 'home', 'broadband']):
            return 'Residential'
        
        return 'Unknown'


class UserAgentAnalyzer:
    """Анализатор User-Agent строк"""
    
    @staticmethod
    def parse_user_agent(ua_string):
        """Парсит User-Agent и извлекает информацию о браузере, ОС, устройстве"""
        if not ua_string or ua_string == '-':
            return {
                'browser': 'Unknown',
                'browser_version': 'Unknown',
                'os': 'Unknown',
                'os_version': 'Unknown',
                'device_type': 'Unknown',
                'is_bot': False,
                'is_mobile': False
            }
        
        ua_lower = ua_string.lower()
        
        # Определение ботов
        bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests']
        is_bot = any(keyword in ua_lower for keyword in bot_keywords)
        
        # Определение мобильных устройств
        mobile_keywords = ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'windows phone']
        is_mobile = any(keyword in ua_lower for keyword in mobile_keywords)
        
        # Определение браузера
        browser = 'Unknown'
        browser_version = 'Unknown'
        
        if 'chrome' in ua_lower and 'edg' not in ua_lower:
            browser = 'Chrome'
            match = re.search(r'chrome/([\d.]+)', ua_lower)
            if match:
                browser_version = match.group(1)
        elif 'firefox' in ua_lower:
            browser = 'Firefox'
            match = re.search(r'firefox/([\d.]+)', ua_lower)
            if match:
                browser_version = match.group(1)
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            browser = 'Safari'
            match = re.search(r'version/([\d.]+)', ua_lower)
            if match:
                browser_version = match.group(1)
        elif 'edg' in ua_lower or 'edge' in ua_lower:
            browser = 'Edge'
            match = re.search(r'edg[ea]?/([\d.]+)', ua_lower)
            if match:
                browser_version = match.group(1)
        elif 'opera' in ua_lower or 'opr' in ua_lower:
            browser = 'Opera'
            match = re.search(r'(?:opera|opr)/([\d.]+)', ua_lower)
            if match:
                browser_version = match.group(1)
        
        # Определение ОС
        os_name = 'Unknown'
        os_version = 'Unknown'
        
        if 'windows' in ua_lower:
            os_name = 'Windows'
            match = re.search(r'windows nt ([\d.]+)', ua_lower)
            if match:
                version = match.group(1)
                version_map = {'10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7'}
                os_version = version_map.get(version, version)
        elif 'android' in ua_lower:
            os_name = 'Android'
            match = re.search(r'android ([\d.]+)', ua_lower)
            if match:
                os_version = match.group(1)
        elif 'iphone' in ua_lower or 'ipad' in ua_lower:
            os_name = 'iOS'
            match = re.search(r'os ([\d_]+)', ua_lower)
            if match:
                os_version = match.group(1).replace('_', '.')
        elif 'mac os' in ua_lower or 'macintosh' in ua_lower:
            os_name = 'macOS'
            match = re.search(r'mac os x ([\d_]+)', ua_lower)
            if match:
                os_version = match.group(1).replace('_', '.')
        elif 'linux' in ua_lower:
            os_name = 'Linux'
        
        # Тип устройства
        device_type = 'Desktop'
        if is_mobile:
            if 'tablet' in ua_lower or 'ipad' in ua_lower:
                device_type = 'Tablet'
            else:
                device_type = 'Mobile'
        elif 'bot' in ua_lower or 'crawler' in ua_lower:
            device_type = 'Bot'
        
        return {
            'browser': browser,
            'browser_version': browser_version,
            'os': os_name,
            'os_version': os_version,
            'device_type': device_type,
            'is_bot': is_bot,
            'is_mobile': is_mobile
        }


class LogParser:
    """Парсер access-логов (Apache/Nginx Combined)"""
    
    # Apache Combined Log Format
    APACHE_PATTERN = (
        'apache',
        re.compile(
            r'(\S+) '  # hostname
            r'(\S+) '  # IP
            r'(\S+) '  # remote user
            r'(\S+) '  # auth user
            r'\[([^\]]+)\] '  # timestamp
            r'"(\S+) '  # method
            r'([^"]+) '  # URL
            r'([^"]+)" '  # protocol
            r'(\d+) '  # status
            r'(\S+) '  # size
            r'"([^"]*)" '  # referer
            r'"([^"]*)"'  # user-agent
        )
    )
    
    # Nginx combined (пример: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent")
    NGINX_PATTERN = (
        'nginx',
        re.compile(
            r'(\S+) '        # IP (remote_addr)
            r'(\S+) '        # ident / "-"
            r'(\S+) '        # remote user
            r'\[([^\]]+)\] ' # timestamp
            r'"([^"]+)" '    # request line (method path protocol)
            r'(\d{3}) '      # status
            r'(\S+) '        # size
            r'"([^"]*)" '    # referer
            r'"([^"]*)"'     # user-agent
        )
    )
    
    PATTERNS = [APACHE_PATTERN, NGINX_PATTERN]
    
    @staticmethod
    def _parse_timestamp(timestamp_str):
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except Exception:
            try:
                return datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
            except Exception:
                return None
    
    @staticmethod
    def _split_request(request_str):
        method = url = protocol = '-'
        parts = request_str.split()
        if len(parts) >= 1:
            method = parts[0]
        if len(parts) >= 2:
            url = parts[1]
        if len(parts) >= 3:
            protocol = parts[2]
        return method, url, protocol
    
    @staticmethod
    def parse_line(line):
        """Парсит одну строку лога (Apache или Nginx combined)"""
        for fmt, pattern in LogParser.PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            try:
                if fmt == 'apache':
                    hostname, ip, remote_user, auth_user, timestamp_str, method, url, protocol, status, size, referer, user_agent = match.groups()
                else:  # nginx
                    ip, ident, remote_user, timestamp_str, request_str, status, size, referer, user_agent = match.groups()
                    hostname = ident
                    auth_user = '-'
                    method, url, protocol = LogParser._split_request(request_str)
                
                timestamp = LogParser._parse_timestamp(timestamp_str)
                if not timestamp:
                    continue
                
                return {
                    'hostname': hostname,
                    'ip': ip,
                    'remote_user': remote_user,
                    'auth_user': auth_user,
                    'timestamp': timestamp,
                    'method': method,
                    'url': url,
                    'protocol': protocol,
                    'status': int(status),
                    'size': size if size != '-' else '0',
                    'referer': referer,
                    'user_agent': user_agent,
                    'raw_line': line,
                    'log_format': fmt
                }
            except Exception:
                continue
        return None


class DirectTrafficAnalyzer:
    """Анализатор прямого трафика"""
    
    def __init__(self, log_path, domain='auto', start_date=None, end_date=None, use_geoip=True, log_files=None):
        self.log_path = Path(log_path)
        self.log_files = [Path(p) for p in log_files] if log_files else self._resolve_log_files(self.log_path)
        self.domain_input = domain
        self.domain = domain if domain not in (None, 'auto') else None
        self.domain_source = 'аргумент --domain' if self.domain else 'auto'
        self.start_date = start_date
        self.end_date = end_date
        self.use_geoip = use_geoip
        self.entries = []
        self.direct_traffic = []
        self.geo_analyzer = GeoIPAnalyzer(use_api=use_geoip) if use_geoip else None
        self.ua_analyzer = UserAgentAnalyzer()
    
    def _resolve_log_files(self, log_path):
        """Определяет список файлов для анализа (один файл или все файлы директории).
        
        Для директории берем только access-логи, чтобы не пытаться парсить error-логи.
        """
        if log_path.is_file():
            return [log_path]
        if log_path.is_dir():
            access_files = sorted([
                p for p in log_path.iterdir()
                if p.is_file() and 'access' in p.name.lower() and (p.suffix in {'', '.log', '.gz', '.txt'} or True)
            ])
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
            # Ищем куски вида example.com или example.com.ua перед расширениями
            candidates = re.findall(r'([a-z0-9-]+(?:\.[a-z0-9-]+){1,})', name)
            for candidate in candidates:
                labels = candidate.split('.')
                # Убираем служебные суффиксы и числовые части (даты)
                while labels and (labels[-1] in {'log', 'access', 'error', 'gz', 'txt'} or labels[-1].isdigit()):
                    labels.pop()
                if len(labels) < 2:
                    continue
                normalized = '.'.join(labels)
                if not self._is_ip(normalized):
                    domains.append(normalized)
        return domains
    
    def _infer_domain_from_referers(self):
        """Пытается определить домен сайта по referer-ам (берём самые частые)"""
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
        
        # Берём самый частый
        return Counter(candidates).most_common(1)[0][0]
    
    def ensure_domain(self):
        """Устанавливает домен: приоритет аргументу, иначе пытаемся определить по логам"""
        if self.domain:
            print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
            return self.domain
        
        inferred = self._infer_domain()
        if inferred:
            self.domain = inferred
            self.domain_source = 'определён из логов'
        else:
            # Фолбек — если пользователь явно указал, иначе дефолт
            if self.domain_input not in (None, 'auto'):
                self.domain = self.domain_input
                self.domain_source = 'аргумент --domain (fallback)'
            else:
                self.domain = 'example.com'
                self.domain_source = 'значение по умолчанию'
            print(f"Предупреждение: не удалось автоматически определить домен, используем {self.domain}")
        
        print(f"Используем домен: {self.domain} (источник: {self.domain_source})")
        return self.domain
    
    def _slugify_filename(self, name):
        """Подготавливает строку для имени файла отчёта"""
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
        safe = safe.strip('._-')
        return safe or 'site'
        
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
                            # Фильтрация по датам, если указаны
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
        
        # Прямой трафик: referer = "-" или пустой, или не содержит домен сайта
        for entry in self.entries:
            referer = entry['referer']
            is_direct = (
                referer == '-' or 
                referer == '' or
                self.domain not in referer.lower()
            )
            
            if is_direct:
                # Исключаем ботов и служебные запросы
                user_agent = entry['user_agent'].lower()
                if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'googlebot', 'yandex', 'bing']):
                    continue
                
                # Исключаем статические ресурсы и API
                url = entry['url'].lower()
                if any(resource in url for resource in ['/wp-content/', '/wp-includes/', '/wp-json/', '/wp-cron', '/wp-admin/', '.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg']):
                    continue
                
                self.direct_traffic.append(entry)
        
        print(f"Прямых заходов: {len(self.direct_traffic)}")
        
    def analyze_bounce_rate(self):
        """Анализирует отказы (bounce rate)"""
        print("\nАнализ отказов...")
        
        # Группируем по IP и user-agent для определения сессий
        sessions = defaultdict(list)
        
        for entry in self.direct_traffic:
            key = f"{entry['ip']}|{entry['user_agent']}"
            sessions[key].append(entry)
        
        # Определяем отказы: сессия с одним запросом или только ошибками
        bounces = []
        non_bounces = []
        
        for key, session_entries in sessions.items():
            # Сортируем по времени
            session_entries.sort(key=lambda x: x['timestamp'])
            
            # Фильтруем только успешные запросы (200)
            successful_requests = [e for e in session_entries if e['status'] == 200]
            
            if len(successful_requests) <= 1:
                # Отказ: только один запрос или все запросы неуспешные
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
        
        if self.use_geoip:
            print("Получение геолокации для IP...")
        
        suspicious = {
            'suspicious_ips': [],
            'suspicious_user_agents': [],
            'suspicious_urls': [],
            'high_frequency_ips': [],
            'error_patterns': [],
            'country_stats': defaultdict(lambda: {'count': 0, 'ips': set()}),
            'datacenter_ips': []
        }
        
        # Анализ по IP
        ip_counter = Counter(e['ip'] for e in bounce_entries)
        ip_sessions = defaultdict(list)
        for entry in bounce_entries:
            ip_sessions[entry['ip']].append(entry)
        
        # IP с большим количеством отказов
        for ip, count in ip_counter.most_common(50):
            sessions = ip_sessions[ip]
            unique_urls = len(set(e['url'] for e in sessions))
            unique_user_agents = len(set(e['user_agent'] for e in sessions))
            
            # Подозрительные признаки:
            # - Много отказов с одного IP
            # - Много разных URL (сканирование)
            # - Одинаковый user-agent для всех запросов
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
            
            # Проверка на паттерны сканирования
            urls = [e['url'] for e in sessions]
            if self._has_scanning_pattern(urls):
                suspicious_score += 2
                reasons.append("Паттерн сканирования")
            
            if suspicious_score >= 2:
                # Получаем информацию об IP
                ip_info = {}
                if self.geo_analyzer:
                    ip_info = self.geo_analyzer.get_ip_info(ip)
                    # Обновляем статистику по странам
                    suspicious['country_stats'][ip_info['country']]['count'] += count
                    suspicious['country_stats'][ip_info['country']]['ips'].add(ip)
                    
                    # Отмечаем датацентры
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
        
        # Анализ по user-agent
        ua_counter = Counter(e['user_agent'] for e in bounce_entries)
        ua_sessions = defaultdict(list)
        for entry in bounce_entries:
            ua_sessions[entry['user_agent']].append(entry)
        
        for ua, count in ua_counter.most_common(30):
            if count > 5:
                sessions = ua_sessions[ua]
                unique_ips = len(set(e['ip'] for e in sessions))
                
                # Подозрительный user-agent если:
                # - Много отказов с одного UA
                # - Много разных IP используют один UA
                if count > 10 or (unique_ips > 5 and count > 5):
                    # Парсим User-Agent
                    ua_info = self.ua_analyzer.parse_user_agent(ua)
                    
                    suspicious['suspicious_user_agents'].append({
                        'user_agent': ua[:200],  # Ограничиваем длину
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
        
        # Анализ частоты запросов
        ip_timestamps = defaultdict(list)
        for entry in bounce_entries:
            ip_timestamps[entry['ip']].append(entry['timestamp'])
        
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) < 5:
                continue
            
            timestamps.sort()
            # Проверяем частоту запросов
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
                avg_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
                
                # Подозрительно: запросы каждые 1-3 секунды (автоматизация)
                if 1 <= avg_diff <= 3 and len(timestamps) > 10:
                    suspicious['high_frequency_ips'].append({
                        'ip': ip,
                        'request_count': len(timestamps),
                        'avg_interval_seconds': avg_diff,
                        'time_span': (timestamps[-1] - timestamps[0]).total_seconds()
                    })
        
        # Анализ ошибок
        error_entries = [e for e in bounce_entries if e['status'] >= 400]
        error_counter = Counter((e['ip'], e['status']) for e in error_entries)
        
        for (ip, status), count in error_counter.most_common(20):
            if count > 5:
                suspicious['error_patterns'].append({
                    'ip': ip,
                    'status': status,
                    'count': count
                })
        
        return suspicious
    
    def _has_scanning_pattern(self, urls):
        """Определяет паттерны сканирования"""
        if len(urls) < 5:
            return False
        
        # Паттерны сканирования:
        # 1. Последовательные номера в URL
        # 2. Много разных категорий/каталогов
        # 3. Поиск уязвимостей (wp-admin, wp-login, etc.)
        
        wp_patterns = ['wp-admin', 'wp-login', 'wp-content', 'wp-includes', 'xmlrpc', 'phpmyadmin', 'admin', 'login']
        if any(pattern in ' '.join(urls).lower() for pattern in wp_patterns):
            return True
        
        # Много разных путей
        paths = [urlparse(url).path for url in urls]
        unique_paths = len(set(paths))
        if unique_paths > len(urls) * 0.8:  # Большинство URL уникальны
            return True
        
        return False
    
    def _analyze_by_periods(self, bounce_entries):
        """Анализирует отказы по временным периодам"""
        if not bounce_entries:
            return []
        
        # Группируем по часам
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
    
    def generate_report(self, bounce_analysis, suspicious_patterns):
        """Генерирует отчет"""
        print("\nГенерация отчета...")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_slug = self._slugify_filename(self.domain or 'site')
        report_file = f"{domain_slug}_report_{timestamp}.xlsx"
        
        # Анализ по периодам
        period_analysis = self._analyze_by_periods(bounce_analysis['bounce_entries'])
        
        with pd.ExcelWriter(report_file, engine='openpyxl') as writer:
            # Сводка
            summary_data = {
                'Метрика': [
                    'Всего записей в логе',
                    'Прямых заходов',
                    'Отказов',
                    'Не отказов',
                    'Процент отказов (%)',
                    'Дата начала анализа',
                    'Дата окончания анализа'
                ],
                'Значение': [
                    len(self.entries),
                    bounce_analysis['total_direct'],
                    bounce_analysis['bounces'],
                    bounce_analysis['non_bounces'],
                    f"{bounce_analysis['bounce_rate']:.2f}%",
                    min(e['timestamp'] for e in self.entries).strftime('%Y-%m-%d %H:%M:%S') if self.entries else 'N/A',
                    max(e['timestamp'] for e in self.entries).strftime('%Y-%m-%d %H:%M:%S') if self.entries else 'N/A'
                ]
            }
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Сводка', index=False)
            
            # Анализ по периодам
            if period_analysis:
                period_df = pd.DataFrame(period_analysis)
                period_df.to_excel(writer, sheet_name='Анализ по периодам', index=False)
            
            # Подозрительные IP
            if suspicious_patterns['suspicious_ips']:
                suspicious_ips_data = []
                for item in suspicious_patterns['suspicious_ips']:
                    suspicious_ips_data.append({
                        'IP': item['ip'],
                        'Страна': item.get('country', 'Unknown'),
                        'Код страны': item.get('country_code', 'XX'),
                        'Город': item.get('city', 'Unknown'),
                        'Провайдер': item.get('isp', 'Unknown'),
                        'Тип IP': item.get('ip_type', 'Unknown'),
                        'Датацентр': 'Да' if item.get('is_datacenter') else 'Нет',
                        'Количество отказов': item['bounce_count'],
                        'Уникальных URL': item['unique_urls'],
                        'Уникальных User-Agent': item['unique_user_agents'],
                        'User-Agent': '; '.join(item['user_agents'][:3])[:200],
                        'Оценка подозрительности': item['score'],
                        'Причины': '; '.join(item['reasons']),
                        'Первый визит': item['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Последний визит': item['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Примеры URL': '; '.join(item['sample_urls'][:5])[:500]
                    })
                pd.DataFrame(suspicious_ips_data).to_excel(writer, sheet_name='Подозрительные IP', index=False)
            
            # Подозрительные User-Agent
            if suspicious_patterns['suspicious_user_agents']:
                ua_data = []
                for item in suspicious_patterns['suspicious_user_agents']:
                    ua_data.append({
                        'User-Agent': item['user_agent'][:200],
                        'Браузер': item.get('browser', 'Unknown'),
                        'Версия браузера': item.get('browser_version', 'Unknown'),
                        'ОС': item.get('os', 'Unknown'),
                        'Версия ОС': item.get('os_version', 'Unknown'),
                        'Тип устройства': item.get('device_type', 'Unknown'),
                        'Бот': 'Да' if item.get('is_bot') else 'Нет',
                        'Мобильное': 'Да' if item.get('is_mobile') else 'Нет',
                        'Количество отказов': item['bounce_count'],
                        'Уникальных IP': item['unique_ips'],
                        'Примеры IP': '; '.join(item['sample_ips'][:5]),
                        'Примеры URL': '; '.join(item['sample_urls'][:5])[:500]
                    })
                pd.DataFrame(ua_data).to_excel(writer, sheet_name='Подозрительные User-Agent', index=False)
            
            # Статистика по странам
            if suspicious_patterns['country_stats']:
                country_data = []
                for country, stats in sorted(suspicious_patterns['country_stats'].items(), 
                                           key=lambda x: x[1]['count'], reverse=True):
                    country_data.append({
                        'Страна': country,
                        'Количество отказов': stats['count'],
                        'Уникальных IP': len(stats['ips'])
                    })
                pd.DataFrame(country_data).to_excel(writer, sheet_name='Статистика по странам', index=False)
            
            # IP из датацентров
            if suspicious_patterns['datacenter_ips']:
                dc_data = []
                for item in suspicious_patterns['datacenter_ips']:
                    dc_data.append({
                        'IP': item['ip'],
                        'Страна': item['country'],
                        'Провайдер': item['isp'],
                        'Количество отказов': item['bounce_count']
                    })
                pd.DataFrame(dc_data).to_excel(writer, sheet_name='IP из датацентров', index=False)
            
            # Высокочастотные IP
            if suspicious_patterns['high_frequency_ips']:
                freq_data = []
                for item in suspicious_patterns['high_frequency_ips']:
                    freq_data.append({
                        'IP': item['ip'],
                        'Количество запросов': item['request_count'],
                        'Средний интервал (сек)': f"{item['avg_interval_seconds']:.2f}",
                        'Временной промежуток (сек)': f"{item['time_span']:.2f}"
                    })
                pd.DataFrame(freq_data).to_excel(writer, sheet_name='Высокочастотные IP', index=False)
            
            # Паттерны ошибок
            if suspicious_patterns['error_patterns']:
                error_data = []
                for item in suspicious_patterns['error_patterns']:
                    error_data.append({
                        'IP': item['ip'],
                        'HTTP статус': item['status'],
                        'Количество': item['count']
                    })
                pd.DataFrame(error_data).to_excel(writer, sheet_name='Паттерны ошибок', index=False)
            
            # Детали отказов (первые 1000)
            if bounce_analysis['bounce_entries']:
                bounce_data = []
                for entry in bounce_analysis['bounce_entries'][:1000]:
                    bounce_data.append({
                        'IP': entry['ip'],
                        'User-Agent': entry['user_agent'],
                        'URL': entry['url'],
                        'Статус': entry['status'],
                        'Referer': entry['referer'],
                        'Время': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    })
                pd.DataFrame(bounce_data).to_excel(writer, sheet_name='Детали отказов', index=False)
        
        print(f"\nОтчет сохранен: {report_file}")
        return report_file
    
    def print_summary(self, bounce_analysis, suspicious_patterns):
        """Выводит краткую сводку в консоль"""
        print("\n" + "="*80)
        print("СВОДКА АНАЛИЗА ПРЯМОГО ТРАФИКА")
        print("="*80)
        print(f"\nВсего записей в логе: {len(self.entries):,}")
        print(f"Прямых заходов: {bounce_analysis['total_direct']:,}")
        print(f"Отказов: {bounce_analysis['bounces']:,} ({bounce_analysis['bounce_rate']:.2f}%)")
        print(f"Не отказов: {bounce_analysis['non_bounces']:,} ({100 - bounce_analysis['bounce_rate']:.2f}%)")
        
        print(f"\nПодозрительных IP: {len(suspicious_patterns['suspicious_ips'])}")
        if suspicious_patterns['suspicious_ips']:
            print("\nТоп-10 подозрительных IP:")
            for i, item in enumerate(suspicious_patterns['suspicious_ips'][:10], 1):
                country_info = f" ({item.get('country', 'Unknown')})" if item.get('country') != 'Unknown' else ""
                dc_info = " [Датацентр]" if item.get('is_datacenter') else ""
                print(f"  {i}. {item['ip']}{country_info}{dc_info} - {item['bounce_count']} отказов (оценка: {item['score']})")
                print(f"     Причины: {', '.join(item['reasons'])}")
        
        # Статистика по странам
        if suspicious_patterns['country_stats']:
            print(f"\nТоп-5 стран по отказам:")
            sorted_countries = sorted(suspicious_patterns['country_stats'].items(), 
                                     key=lambda x: x[1]['count'], reverse=True)
            for i, (country, stats) in enumerate(sorted_countries[:5], 1):
                print(f"  {i}. {country}: {stats['count']} отказов, {len(stats['ips'])} уникальных IP")
        
        # Датацентры
        if suspicious_patterns['datacenter_ips']:
            print(f"\nIP из датацентров: {len(suspicious_patterns['datacenter_ips'])}")
            print("Топ-5 IP из датацентров:")
            for i, item in enumerate(suspicious_patterns['datacenter_ips'][:5], 1):
                print(f"  {i}. {item['ip']} ({item['country']}, {item['isp']}) - {item['bounce_count']} отказов")
        
        print(f"\nПодозрительных User-Agent: {len(suspicious_patterns['suspicious_user_agents'])}")
        if suspicious_patterns['suspicious_user_agents']:
            print("\nТоп-5 подозрительных User-Agent:")
            for i, item in enumerate(suspicious_patterns['suspicious_user_agents'][:5], 1):
                print(f"  {i}. {item['bounce_count']} отказов - {item['user_agent'][:80]}...")
        
        print(f"\nВысокочастотных IP: {len(suspicious_patterns['high_frequency_ips'])}")
        if suspicious_patterns['high_frequency_ips']:
            print("\nТоп-5 высокочастотных IP:")
            for i, item in enumerate(suspicious_patterns['high_frequency_ips'][:5], 1):
                print(f"  {i}. {item['ip']} - {item['request_count']} запросов, интервал {item['avg_interval_seconds']:.2f} сек")
        
        print("\n" + "="*80)


def main():
    def resolve_log_path(path_str):
        """Пытается определить путь к логам.
        
        1) Как передано (с учётом ~)
        2) Относительно текущей директории
        3) Относительно директории скрипта
        """
        candidates = []
        direct = Path(path_str).expanduser()
        candidates.append(direct)
        # Если передан абсолютный путь вида "/logs", пробуем без ведущего слеша
        if not direct.exists() and path_str.startswith('/'):
            candidates.append(Path(path_str.lstrip('/')).expanduser())
        # Относительно текущего каталога запуска
        candidates.append(Path.cwd() / path_str.lstrip('/'))
        # Относительно каталога скрипта
        script_dir = Path(__file__).resolve().parent
        candidates.append(script_dir / path_str.lstrip('/'))
        
        for candidate in candidates:
            if candidate.exists():
                return candidate
        print(f"Ошибка: путь {path_str} не найден. Проверенные варианты: {[str(c) for c in candidates]}")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='Анализатор прямого трафика из Apache логов',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  # Базовый анализ
  python analyze_direct_traffic.py logs/access.log
  
  # Анализ всех логов в директории
  python analyze_direct_traffic.py logs/
  
  # Анализ с явным указанием домена
  python analyze_direct_traffic.py logs/access.log --domain example.com
  
  # Анализ за конкретный период
  python analyze_direct_traffic.py logs/access.log --start-date 2025-12-01 --end-date 2025-12-11
        """
    )
    parser.add_argument('log_path', help='Путь к файлу access.log или директории с логами')
    parser.add_argument('--domain', default='auto', help='Домен сайта (по умолчанию auto: определяется из логов)')
    parser.add_argument('--start-date', help='Начальная дата фильтрации (формат: YYYY-MM-DD)')
    parser.add_argument('--end-date', help='Конечная дата фильтрации (формат: YYYY-MM-DD)')
    parser.add_argument('--no-geoip', action='store_true', help='Отключить геолокацию IP (быстрее, но без информации о странах)')
    
    args = parser.parse_args()
    
    # Парсинг дат
    start_date = None
    end_date = None
    if args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
        except ValueError:
            print(f"Ошибка: неверный формат даты --start-date. Используйте YYYY-MM-DD")
            sys.exit(1)
    if args.end_date:
        try:
            end_date = datetime.strptime(args.end_date, '%Y-%m-%d')
            # Устанавливаем конец дня
            end_date = end_date.replace(hour=23, minute=59, second=59)
        except ValueError:
            print(f"Ошибка: неверный формат даты --end-date. Используйте YYYY-MM-DD")
            sys.exit(1)
    
    resolved_path = resolve_log_path(args.log_path)
    # Получаем список файлов (без учёта домена) для группировки
    temp_analyzer = DirectTrafficAnalyzer(resolved_path, args.domain, start_date, end_date, use_geoip=not args.no_geoip)
    all_files = temp_analyzer.log_files
    
    def extract_domain_from_name(path_obj):
        name = path_obj.name.lower()
        candidates = re.findall(r'([a-z0-9-]+(?:\.[a-z0-9-]+){1,})', name)
        for candidate in candidates:
            labels = candidate.split('.')
            while labels and (labels[-1] in {'log', 'access', 'error', 'gz', 'txt'} or labels[-1].isdigit()):
                labels.pop()
            if len(labels) >= 2:
                return '.'.join(labels)
        return None
    
    # Если домен задан явно — анализируем все файлы одним запуском
    if args.domain not in (None, 'auto'):
        analyzer = DirectTrafficAnalyzer(resolved_path, args.domain, start_date, end_date, use_geoip=not args.no_geoip, log_files=all_files)
        analyzer.parse_logs()
        analyzer.ensure_domain()
        analyzer.identify_direct_traffic()
        bounce_analysis = analyzer.analyze_bounce_rate()
        suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
        analyzer.print_summary(bounce_analysis, suspicious_patterns)
        report_file = analyzer.generate_report(bounce_analysis, suspicious_patterns)
        print(f"\nАнализ завершен! Отчет сохранен в {report_file}")
        return
    
    # Авто-разбиение по доменам из имён файлов
    domain_groups = {}
    for f in all_files:
        domain_candidate = extract_domain_from_name(f)
        domain_key = domain_candidate or 'unknown'
        domain_groups.setdefault(domain_key, []).append(f)
    
    # Если найдено несколько доменов — отдельный отчёт на каждый
    for domain_key, files in domain_groups.items():
        print(f"\n=== Анализ домена: {domain_key} ===")
        analyzer = DirectTrafficAnalyzer(resolved_path, domain_key if domain_key != 'unknown' else 'auto', start_date, end_date, use_geoip=not args.no_geoip, log_files=files)
        analyzer.parse_logs()
        analyzer.ensure_domain()
        analyzer.identify_direct_traffic()
        bounce_analysis = analyzer.analyze_bounce_rate()
        suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
        analyzer.print_summary(bounce_analysis, suspicious_patterns)
        report_file = analyzer.generate_report(bounce_analysis, suspicious_patterns)
        print(f"\nАнализ завершен! Отчет сохранен в {report_file}")


if __name__ == '__main__':
    main()
