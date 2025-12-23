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
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("Предупреждение: библиотека numpy не установлена. Анализ нагрузки будет упрощен.")
    print("Установите: pip install numpy")
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Предупреждение: библиотека requests не установлена. Геолокация будет отключена.")
    print("Установите: pip install requests")


class GeoIPAnalyzer:
    """Анализатор геолокации и информации об IP"""
    
    def __init__(self, use_api=True, verbose=False):
        self.use_api = use_api and HAS_REQUESTS
        self.cache = {}  # Кэш для уже проверенных IP
        self.api_delay = 0.2  # Задержка между запросами к API (секунды)
        self.last_request_time = 0
        self.verbose = verbose
        self.error_count = 0
        self.success_count = 0
        
    def get_ip_info(self, ip):
        """Получает информацию об IP: страна, город, провайдер, тип"""
        if ip in self.cache:
            return self.cache[ip]
        
        if not self.use_api:
            if self.verbose:
                print(f"Геолокация отключена для IP {ip}")
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
            ip_info = {
                'country': 'Local',
                'country_code': 'LOC',
                'city': 'Local Network',
                'isp': 'Local',
                'ip_type': 'Private',
                'is_datacenter': False
            }
            self.cache[ip] = ip_info
            return ip_info
        
        # Задержка для соблюдения rate limit
        current_time = time.time()
        if current_time - self.last_request_time < self.api_delay:
            time.sleep(self.api_delay - (current_time - self.last_request_time))
        
        # Пробуем несколько API
        ip_info = self._try_ip_api_com(ip)
        if ip_info and ip_info.get('country') != 'Unknown':
            self.cache[ip] = ip_info
            self.success_count += 1
            return ip_info
        
        # Если первый API не сработал, пробуем альтернативный
        ip_info = self._try_alternative_api(ip)
        if ip_info and ip_info.get('country') != 'Unknown':
            self.cache[ip] = ip_info
            self.success_count += 1
            return ip_info
        
        # Fallback
        self.error_count += 1
        if self.verbose and self.error_count <= 5:
            print(f"Не удалось получить геолокацию для IP {ip}")
        
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
    
    def _try_ip_api_com(self, ip):
        """Пробует получить информацию через ip-api.com"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    f'http://ip-api.com/json/{ip}',
                    timeout=10,
                    params={'fields': 'status,message,country,countryCode,city,isp,org,as,query'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        self.last_request_time = time.time()
                        return {
                            'country': data.get('country', 'Unknown'),
                            'country_code': data.get('countryCode', 'XX'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'ip_type': self._determine_ip_type(data.get('isp', ''), data.get('org', '')),
                            'is_datacenter': self._is_datacenter(data.get('isp', ''), data.get('org', ''))
                        }
                    else:
                        message = data.get('message', 'Unknown error')
                        # Если rate limit - увеличиваем задержку и пробуем еще раз
                        if 'rate limit' in message.lower() or '429' in str(response.status_code):
                            if attempt < max_retries - 1:
                                wait_time = (attempt + 1) * 2  # Увеличиваем задержку
                                if self.verbose:
                                    print(f"Rate limit для {ip}, ждем {wait_time} сек...")
                                time.sleep(wait_time)
                                continue
                            elif self.verbose:
                                print(f"ip-api.com rate limit для {ip} после {max_retries} попыток")
                        elif self.verbose:
                            print(f"ip-api.com ошибка для {ip}: {message}")
                elif response.status_code == 429:
                    # Rate limit - пробуем еще раз с задержкой
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 2
                        if self.verbose:
                            print(f"HTTP 429 для {ip}, ждем {wait_time} сек...")
                        time.sleep(wait_time)
                        continue
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                elif self.verbose:
                    print(f"Timeout при запросе к ip-api.com для {ip}")
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                elif self.verbose:
                    print(f"Ошибка сети при запросе к ip-api.com для {ip}: {e}")
            except Exception as e:
                if self.verbose:
                    print(f"Неожиданная ошибка ip-api.com для {ip}: {e}")
                break
        
        return None
    
    def _try_alternative_api(self, ip):
        """Пробует альтернативный API (ipapi.co)"""
        try:
            response = requests.get(
                f'https://ipapi.co/{ip}/json/',
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {
                        'country': data.get('country_name', 'Unknown'),
                        'country_code': data.get('country_code', 'XX'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('org', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'ip_type': self._determine_ip_type(data.get('org', ''), ''),
                        'is_datacenter': self._is_datacenter(data.get('org', ''), '')
                    }
        except Exception:
            # Молча игнорируем ошибки альтернативного API
            pass
        
        return None
    
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
    
    # Расширенный формат с временем обработки: IP - - [timestamp timezone - processing_time] status "request" size "referer" "user-agent" "-"
    # Пример: 69.63.189.13 - - [23/Dec/2025:00:00:03 -0500 - 0.005] 206 "GET /robots.txt HTTP/2.0" 1517 "-" "user-agent" "-"
    EXTENDED_PATTERN = (
        'extended',
        re.compile(
            r'(\S+) '        # IP
            r'(\S+) '        # ident / "-"
            r'(\S+) '        # remote user
            r'\[([^\]]+)\] ' # timestamp with timezone and processing time (например: 23/Dec/2025:00:00:03 -0500 - 0.005)
            r'(\d{3}) '      # status
            r'"([^"]+)" '    # request line (method path protocol)
            r'(\S+) '        # size
            r'"([^"]*)" '    # referer
            r'"([^"]*)" '    # user-agent
            r'"([^"]*)"'     # дополнительное поле (обычно "-")
        )
    )
    
    PATTERNS = [APACHE_PATTERN, NGINX_PATTERN, EXTENDED_PATTERN]
    
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
    def _parse_extended_timestamp(timestamp_str):
        """Парсит расширенный формат timestamp с временем обработки.
        
        Поддерживает форматы:
        - '23/Dec/2025:00:00:03 -0500 - 0.005'
        - '23/Dec/2025:00:00:06 -0500 - 0.000 : 0.004'
        - '23/Dec/2025:00:00:15 -0500 - 0.000, 0.000 : 1.491'
        """
        try:
            # Извлекаем основную часть: дата/время и timezone
            # Ищем паттерн: "DD/MMM/YYYY:HH:MM:SS +/-HHMM"
            # Используем regex для более надежного извлечения
            match = re.search(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+([+-]\d{4})', timestamp_str)
            if match:
                date_time_str = match.group(1)  # "23/Dec/2025:00:00:03"
                timezone_str = match.group(2)   # "-0500"
                full_str = f"{date_time_str} {timezone_str}"
                return datetime.strptime(full_str, '%d/%b/%Y:%H:%M:%S %z')
        except Exception:
            pass
        
        try:
            # Пробуем без timezone
            match = re.search(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', timestamp_str)
            if match:
                date_time_str = match.group(1)
                return datetime.strptime(date_time_str, '%d/%b/%Y:%H:%M:%S')
        except Exception:
            pass
        
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
        """Парсит одну строку лога (Apache, Nginx combined или расширенный формат)"""
        for fmt, pattern in LogParser.PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            try:
                if fmt == 'apache':
                    hostname, ip, remote_user, auth_user, timestamp_str, method, url, protocol, status, size, referer, user_agent = match.groups()
                    timestamp = LogParser._parse_timestamp(timestamp_str)
                elif fmt == 'extended':
                    # Формат: IP - - [timestamp timezone - processing_time] status "request" size "referer" "user-agent" "-"
                    ip, ident, remote_user, timestamp_str, status, request_str, size, referer, user_agent, extra = match.groups()
                    hostname = ident
                    auth_user = '-'
                    method, url, protocol = LogParser._split_request(request_str)
                    timestamp = LogParser._parse_extended_timestamp(timestamp_str)
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
            except Exception as e:
                continue
        return None


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
        
        initial_success = 0
        initial_errors = 0
        if self.use_geoip:
            print("Получение геолокации для IP...")
            if self.geo_analyzer:
                initial_success = self.geo_analyzer.success_count
                initial_errors = self.geo_analyzer.error_count
        
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
        
        # Выводим статистику геолокации
        if self.use_geoip and self.geo_analyzer:
            success_count = self.geo_analyzer.success_count - initial_success
            error_count = self.geo_analyzer.error_count - initial_errors
            total_requests = success_count + error_count
            if total_requests > 0:
                success_rate = (success_count / total_requests) * 100
                print(f"Геолокация: успешно {success_count}/{total_requests} ({success_rate:.1f}%), ошибок: {error_count}")
                if error_count > 0 and success_rate < 50:
                    print("Предупреждение: много ошибок геолокации. Проверьте интернет-соединение.")
                    print("  Возможные причины: rate limit API, проблемы с сетью, или используйте --no-geoip для отключения")
            elif total_requests == 0:
                print("Геолокация: запросы не выполнялись (возможно, все IP уже в кэше)")
        
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
    
    def analyze_load_periods(self, window_minutes=15, threshold_percentile=75):
        """Анализирует периоды высокой нагрузки на основе количества запросов
        
        Args:
            window_minutes: размер окна анализа в минутах (по умолчанию 15)
            threshold_percentile: процентиль для определения высокой нагрузки (по умолчанию 75)
        
        Returns:
            dict с информацией о периодах высокой нагрузки и аномалиях
        """
        print(f"\nАнализ периодов нагрузки (окно: {window_minutes} минут)...")
        
        if not self.entries:
            return {
                'high_load_periods': [],
                'normal_load_periods': [],
                'anomalies': [],
                'comparison': {}
            }
        
        # Группируем все записи по временным окнам
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
            # Округляем до ближайшего окна
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
        
        # Вычисляем статистику для определения порога
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
            # Упрощенный расчет без numpy
            sorted_counts = sorted(request_counts)
            threshold_idx = int(len(sorted_counts) * threshold_percentile / 100)
            threshold = sorted_counts[threshold_idx] if threshold_idx < len(sorted_counts) else sorted_counts[-1]
            mean_count = sum(request_counts) / len(request_counts)
            median_idx = len(sorted_counts) // 2
            median_count = sorted_counts[median_idx] if sorted_counts else 0
        
        print(f"Среднее количество запросов за {window_minutes} мин: {mean_count:.0f}")
        print(f"Медиана: {median_count:.0f}")
        print(f"Порог высокой нагрузки ({threshold_percentile} перцентиль): {threshold:.0f} запросов")
        
        # Разделяем на периоды высокой и нормальной нагрузки
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
        
        print(f"Периодов высокой нагрузки: {len(high_load_periods)}")
        print(f"Периодов нормальной нагрузки: {len(normal_load_periods)}")
        
        # Анализ аномалий в периоды высокой нагрузки
        anomalies = self._detect_load_anomalies(high_load_periods, normal_load_periods)
        
        # Сравнение периодов высокой и нормальной нагрузки
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
        
        # Вычисляем средние значения для нормальных периодов
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
            
            # Аномалия: слишком много запросов с одного IP
            if period['requests_per_ip'] > normal_avg_requests_per_ip * 2:
                anomaly_reasons.append(f"Высокое количество запросов на IP ({period['requests_per_ip']:.1f} vs норма {normal_avg_requests_per_ip:.1f})")
            
            # Аномалия: небольшое количество уникальных IP при высокой нагрузке
            if period['unique_ips'] < normal_avg_ips * 0.5 and period['request_count'] > 100:
                anomaly_reasons.append(f"Мало уникальных IP ({period['unique_ips']} vs норма {normal_avg_ips:.0f}) при высокой нагрузке")
            
            # Аномалия: много ошибок
            error_count = sum(count for code, count in period['status_codes'].items() if code >= 400)
            error_rate = error_count / period['request_count'] * 100 if period['request_count'] > 0 else 0
            if error_rate > 20:
                anomaly_reasons.append(f"Высокий процент ошибок ({error_rate:.1f}%)")
            
            # Аномалия: доминирование одного IP
            if period['top_ips']:
                top_ip, top_count = max(period['top_ips'].items(), key=lambda x: x[1])
                top_ip_share = top_count / period['request_count'] * 100
                if top_ip_share > 30:
                    anomaly_reasons.append(f"Один IP доминирует: {top_ip} ({top_ip_share:.1f}% запросов)")
            
            # Аномалия: доминирование одного URL
            if period['top_urls']:
                top_url, top_count = max(period['top_urls'].items(), key=lambda x: x[1])
                top_url_share = top_count / period['request_count'] * 100
                if top_url_share > 40:
                    anomaly_reasons.append(f"Один URL доминирует: {top_url[:100]} ({top_url_share:.1f}% запросов)")
            
            # Аномалия: много запросов к статическим ресурсам
            static_patterns = ['.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2']
            static_count = sum(count for url, count in period['top_urls'].items() 
                             if any(pattern in url.lower() for pattern in static_patterns))
            static_share = static_count / period['request_count'] * 100 if period['request_count'] > 0 else 0
            if static_share > 50:
                anomaly_reasons.append(f"Много запросов к статическим ресурсам ({static_share:.1f}%)")
            
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
        
        def calc_median(periods, key):
            if not periods:
                return 0
            values = sorted([p[key] for p in periods])
            if HAS_NUMPY:
                return np.median(values)
            else:
                median_idx = len(values) // 2
                return values[median_idx] if values else 0
        
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
        
        # Вычисляем разницу в процентах
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
    
    def generate_report(self, bounce_analysis, suspicious_patterns, load_analysis=None):
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
            
            # Анализ нагрузки
            if load_analysis:
                # Периоды высокой нагрузки
                if load_analysis['high_load_periods']:
                    high_load_data = []
                    for period in load_analysis['high_load_periods']:
                        top_ips_str = ', '.join([f"{ip}({count})" for ip, count in list(period['top_ips'].items())[:5]])
                        top_urls_str = ', '.join([f"{url[:50]}({count})" for url, count in list(period['top_urls'].items())[:5]])
                        status_codes_str = ', '.join([f"{code}({count})" for code, count in list(period['status_codes'].items())[:5]])
                        
                        high_load_data.append({
                            'Начало периода': period['period_start'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Конец периода': period['period_end'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Количество запросов': period['request_count'],
                            'Уникальных IP': period['unique_ips'],
                            'Уникальных URL': period['unique_urls'],
                            'Запросов на IP': f"{period['requests_per_ip']:.2f}",
                            'Топ IP': top_ips_str[:200],
                            'Топ URL': top_urls_str[:300],
                            'Коды ответов': status_codes_str[:200],
                            'Методы': ', '.join([f"{m}({c})" for m, c in list(period['methods'].items())[:5]]),
                            'Общий размер (МБ)': f"{period['total_size_mb']:.2f}",
                            'Средний размер (КБ)': f"{period['avg_size_kb']:.2f}"
                        })
                    pd.DataFrame(high_load_data).to_excel(writer, sheet_name='Периоды высокой нагрузки', index=False)
                
                # Аномалии в периоды нагрузки
                if load_analysis['anomalies']:
                    anomalies_data = []
                    for anomaly in load_analysis['anomalies']:
                        top_ips_str = ', '.join([f"{ip}({count})" for ip, count in list(anomaly['top_ips'].items())[:5]])
                        top_urls_str = ', '.join([f"{url[:50]}({count})" for url, count in list(anomaly['top_urls'].items())[:5]])
                        
                        anomalies_data.append({
                            'Начало периода': anomaly['period_start'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Конец периода': anomaly['period_end'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Количество запросов': anomaly['request_count'],
                            'Уникальных IP': anomaly['unique_ips'],
                            'Процент ошибок': f"{anomaly['error_rate']:.2f}%",
                            'Причины аномалии': '; '.join(anomaly['reasons']),
                            'Топ IP': top_ips_str[:200],
                            'Топ URL': top_urls_str[:300]
                        })
                    pd.DataFrame(anomalies_data).to_excel(writer, sheet_name='Аномалии нагрузки', index=False)
                
                # Сравнение периодов
                if load_analysis['comparison']:
                    comp = load_analysis['comparison']
                    comparison_data = {
                        'Метрика': [
                            'Среднее количество запросов',
                            'Среднее уникальных IP',
                            'Среднее запросов на IP',
                            'Среднее уникальных URL',
                            'Количество периодов'
                        ],
                        'Высокая нагрузка': [
                            f"{comp['high_load']['avg_requests']:.0f}",
                            f"{comp['high_load']['avg_unique_ips']:.0f}",
                            f"{comp['high_load']['avg_requests_per_ip']:.2f}",
                            f"{comp['high_load']['avg_unique_urls']:.0f}",
                            comp['high_load']['total_periods']
                        ],
                        'Нормальная нагрузка': [
                            f"{comp['normal_load']['avg_requests']:.0f}",
                            f"{comp['normal_load']['avg_unique_ips']:.0f}",
                            f"{comp['normal_load']['avg_requests_per_ip']:.2f}",
                            f"{comp['normal_load']['avg_unique_urls']:.0f}",
                            comp['normal_load']['total_periods']
                        ],
                        'Разница (%)': [
                            f"{comp['difference'].get('avg_requests', 0):.1f}%",
                            f"{comp['difference'].get('avg_unique_ips', 0):.1f}%",
                            f"{comp['difference'].get('avg_requests_per_ip', 0):.1f}%",
                            f"{comp['difference'].get('avg_unique_urls', 0):.1f}%",
                            '-'
                        ]
                    }
                    pd.DataFrame(comparison_data).to_excel(writer, sheet_name='Сравнение нагрузки', index=False)
                
                # Статистика по IP в периоды высокой нагрузки
                if load_analysis['high_load_periods']:
                    # Собираем все IP из периодов высокой нагрузки
                    ip_stats_high = defaultdict(lambda: {'count': 0, 'periods': set()})
                    for period in load_analysis['high_load_periods']:
                        for ip, count in period['top_ips'].items():
                            ip_stats_high[ip]['count'] += count
                            ip_stats_high[ip]['periods'].add(period['period_start'])
                    
                    if ip_stats_high:
                        ip_data = []
                        for ip, stats in sorted(ip_stats_high.items(), key=lambda x: x[1]['count'], reverse=True)[:100]:
                            ip_info = {}
                            if self.geo_analyzer:
                                ip_info = self.geo_analyzer.get_ip_info(ip)
                            
                            ip_data.append({
                                'IP': ip,
                                'Всего запросов': stats['count'],
                                'Периодов высокой нагрузки': len(stats['periods']),
                                'Страна': ip_info.get('country', 'Unknown'),
                                'Провайдер': ip_info.get('isp', 'Unknown'),
                                'Тип IP': ip_info.get('ip_type', 'Unknown'),
                                'Датацентр': 'Да' if ip_info.get('is_datacenter') else 'Нет'
                            })
                        pd.DataFrame(ip_data).to_excel(writer, sheet_name='IP в периоды нагрузки', index=False)
        
        print(f"\nОтчет сохранен: {report_file}")
        return report_file
    
    def print_summary(self, bounce_analysis, suspicious_patterns, load_analysis=None):
        """Выводит краткую сводку в консоль"""
        print("\n" + "="*80)
        print("СВОДКА АНАЛИЗА ПРЯМОГО ТРАФИКА")
        print("="*80)
        print(f"\nВсего записей в логе: {len(self.entries):,}")
        print(f"Прямых заходов: {bounce_analysis['total_direct']:,}")
        print(f"Отказов: {bounce_analysis['bounces']:,} ({bounce_analysis['bounce_rate']:.2f}%)")
        print(f"Не отказов: {bounce_analysis['non_bounces']:,} ({100 - bounce_analysis['bounce_rate']:.2f}%)")
        
        # Анализ нагрузки
        if load_analysis:
            print("\n" + "-"*80)
            print("АНАЛИЗ НАГРУЗКИ НА СЕРВЕР")
            print("-"*80)
            print(f"Периодов высокой нагрузки: {len(load_analysis['high_load_periods'])}")
            print(f"Периодов нормальной нагрузки: {len(load_analysis['normal_load_periods'])}")
            
            if load_analysis.get('threshold'):
                print(f"Порог высокой нагрузки: {load_analysis['threshold']:.0f} запросов за {load_analysis['window_minutes']} минут")
            
            if load_analysis['comparison']:
                comp = load_analysis['comparison']
                print(f"\nСравнение периодов:")
                print(f"  Высокая нагрузка: {comp['high_load']['avg_requests']:.0f} запросов/период")
                print(f"  Нормальная нагрузка: {comp['normal_load']['avg_requests']:.0f} запросов/период")
                if comp['difference'].get('avg_requests'):
                    print(f"  Разница: +{comp['difference']['avg_requests']:.1f}%")
            
            if load_analysis['anomalies']:
                print(f"\nОбнаружено аномалий: {len(load_analysis['anomalies'])}")
                print("\nТоп-5 аномальных периодов:")
                for i, anomaly in enumerate(load_analysis['anomalies'][:5], 1):
                    print(f"  {i}. {anomaly['period_start'].strftime('%Y-%m-%d %H:%M')} - {anomaly['request_count']} запросов")
                    print(f"     Причины: {', '.join(anomaly['reasons'][:2])}")
            
            # Топ IP в периоды высокой нагрузки
            if load_analysis['high_load_periods']:
                ip_stats_high = defaultdict(int)
                for period in load_analysis['high_load_periods']:
                    for ip, count in period['top_ips'].items():
                        ip_stats_high[ip] += count
                
                if ip_stats_high:
                    print(f"\nТоп-5 IP в периоды высокой нагрузки:")
                    for i, (ip, count) in enumerate(sorted(ip_stats_high.items(), key=lambda x: x[1], reverse=True)[:5], 1):
                        print(f"  {i}. {ip} - {count} запросов")
        
        print("\n" + "-"*80)
        print("ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ")
        print("-"*80)
        print(f"Подозрительных IP: {len(suspicious_patterns['suspicious_ips'])}")
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
    parser.add_argument('--load-window', type=int, default=15, help='Размер окна анализа нагрузки в минутах (по умолчанию: 15)')
    parser.add_argument('--load-threshold', type=int, default=75, help='Процентиль для определения высокой нагрузки (по умолчанию: 75)')
    parser.add_argument('--verbose', action='store_true', help='Подробный вывод (включая ошибки геолокации)')
    
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
    temp_analyzer = DirectTrafficAnalyzer(resolved_path, args.domain, start_date, end_date, use_geoip=not args.no_geoip, verbose=args.verbose)
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
    
    def extract_base_name(path_obj):
        """Извлекает базовое имя файла без дат и расширений для группировки"""
        name = path_obj.stem  # Имя без расширения
        # Убираем даты в конце (формат: -YYYYMMDD или .YYYYMMDD)
        name = re.sub(r'[-.]\d{8}(\.gz)?$', '', name)
        # Убираем номера ротации (формат: .1, .2, .10 и т.д.)
        name = re.sub(r'\.\d+$', '', name)
        return name.lower()
    
    # Если домен задан явно — анализируем все файлы одним запуском
    if args.domain not in (None, 'auto'):
        analyzer = DirectTrafficAnalyzer(resolved_path, args.domain, start_date, end_date, use_geoip=not args.no_geoip, log_files=all_files, verbose=args.verbose)
        analyzer.parse_logs()
        analyzer.ensure_domain()
        analyzer.identify_direct_traffic()
        bounce_analysis = analyzer.analyze_bounce_rate()
        suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
        # Анализ нагрузки
        load_analysis = analyzer.analyze_load_periods(window_minutes=args.load_window, threshold_percentile=args.load_threshold)
        analyzer.print_summary(bounce_analysis, suspicious_patterns, load_analysis)
        report_file = analyzer.generate_report(bounce_analysis, suspicious_patterns, load_analysis)
        print(f"\nАнализ завершен! Отчет сохранен в {report_file}")
        return
    
    # Авто-разбиение по доменам из имён файлов
    # Сначала группируем по базовым именам (для файлов типа default_access.log, default_access.log-20251219.gz)
    base_name_groups = {}
    for f in all_files:
        base_name = extract_base_name(f)
        base_name_groups.setdefault(base_name, []).append(f)
    
    # Затем проверяем домены в каждой группе базовых имен
    all_groups = []
    
    for base_name, files in base_name_groups.items():
        # Пытаемся найти домены в этой группе файлов
        domains_in_group = set()
        for f in files:
            domain_candidate = extract_domain_from_name(f)
            if domain_candidate:
                domains_in_group.add(domain_candidate)
        
        # Если в группе найден один домен - используем его
        if len(domains_in_group) == 1:
            domain_key = list(domains_in_group)[0]
            all_groups.append(('domain', domain_key, files))
        # Если несколько доменов или доменов нет - используем базовое имя
        else:
            all_groups.append(('basename', base_name, files))
    
    # Если все файлы относятся к одной группе - один анализ
    if len(all_groups) == 1:
        group_type, group_key, files = all_groups[0]
        if group_type == 'domain':
            domain_name = group_key
            print(f"\n=== Объединенный анализ домена: {domain_name} ===")
            print(f"Обрабатывается {len(files)} файлов за весь период")
        else:
            domain_name = 'auto'
            print(f"\n=== Объединенный анализ (базовое имя: {group_key}) ===")
            print(f"Обрабатывается {len(files)} файлов за весь период")
        
        analyzer = DirectTrafficAnalyzer(resolved_path, domain_name, start_date, end_date, use_geoip=not args.no_geoip, log_files=files, verbose=args.verbose)
        analyzer.parse_logs()
        analyzer.ensure_domain()
        analyzer.identify_direct_traffic()
        bounce_analysis = analyzer.analyze_bounce_rate()
        suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
        # Анализ нагрузки
        load_analysis = analyzer.analyze_load_periods(window_minutes=args.load_window, threshold_percentile=args.load_threshold)
        analyzer.print_summary(bounce_analysis, suspicious_patterns, load_analysis)
        report_file = analyzer.generate_report(bounce_analysis, suspicious_patterns, load_analysis)
        print(f"\nАнализ завершен! Отчет сохранен в {report_file}")
    else:
        # Если найдено несколько групп — отдельный отчёт на каждую
        for group_type, group_key, files in all_groups:
            if group_type == 'domain':
                domain_name = group_key
                print(f"\n=== Анализ домена: {domain_name} ===")
            else:
                domain_name = 'auto'
                print(f"\n=== Анализ (базовое имя: {group_key}) ===")
            
            analyzer = DirectTrafficAnalyzer(resolved_path, domain_name, start_date, end_date, use_geoip=not args.no_geoip, log_files=files, verbose=args.verbose)
            analyzer.parse_logs()
            analyzer.ensure_domain()
            analyzer.identify_direct_traffic()
            bounce_analysis = analyzer.analyze_bounce_rate()
            suspicious_patterns = analyzer.find_suspicious_patterns(bounce_analysis['bounce_entries'])
            # Анализ нагрузки
            load_analysis = analyzer.analyze_load_periods(window_minutes=args.load_window, threshold_percentile=args.load_threshold)
            analyzer.print_summary(bounce_analysis, suspicious_patterns, load_analysis)
            report_file = analyzer.generate_report(bounce_analysis, suspicious_patterns, load_analysis)
            print(f"\nАнализ завершен! Отчет сохранен в {report_file}")


if __name__ == '__main__':
    main()
