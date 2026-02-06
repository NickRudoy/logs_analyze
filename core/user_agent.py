
import re

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
