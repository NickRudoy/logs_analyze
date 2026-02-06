import time
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

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
