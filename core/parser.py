import re
from datetime import datetime

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
    def _normalize_timestamp(dt_obj):
        """Приводит datetime к единому виду без tzinfo для сравнения."""
        if not dt_obj:
            return None
        if dt_obj.tzinfo is not None:
            # Убираем tzinfo, чтобы сравнивать с локальными/naive датами
            return dt_obj.replace(tzinfo=None)
        return dt_obj
    
    @staticmethod
    def _parse_timestamp(timestamp_str):
        try:
            return LogParser._normalize_timestamp(
                datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            )
        except Exception:
            try:
                return LogParser._normalize_timestamp(
                    datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                )
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
                return LogParser._normalize_timestamp(
                    datetime.strptime(full_str, '%d/%b/%Y:%H:%M:%S %z')
                )
        except Exception:
            pass
        
        try:
            # Пробуем без timezone
            match = re.search(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', timestamp_str)
            if match:
                date_time_str = match.group(1)
                return LogParser._normalize_timestamp(
                    datetime.strptime(date_time_str, '%d/%b/%Y:%H:%M:%S')
                )
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
