
import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    "analyzer": {
        "load_window_minutes": 15,
        "load_threshold_percentile": 75,
        "anomalies": {
            "error_rate_threshold": 20,
            "top_ip_share_threshold": 30,
            "top_url_share_threshold": 40
        }
    },
    "geoip": {
        "enabled": True,
        "api_delay": 0.2
    },
    "ai": {
        "enabled": False,
        "auth_key": "",
        "model": "GigaChat",
        "verify_ssl": False
    },
    "report": {
        "format": "excel"
    }
}

class Config:
    def __init__(self, config_path=None):
        self.config = DEFAULT_CONFIG.copy()
        if config_path:
            self.load(config_path)
    
    def load(self, config_path):
        path = Path(config_path)
        if not path.exists():
            print(f"Конфигурация {path} не найдена, используются значения по умолчанию")
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
                self._update_recursive(self.config, user_config)
            print(f"Конфигурация загружена из {path}")
        except Exception as e:
            print(f"Ошибка при загрузке конфигурации: {e}")
            
    def _update_recursive(self, d, u):
        for k, v in u.items():
            if isinstance(v, dict):
                d[k] = self._update_recursive(d.get(k, {}), v)
            else:
                d[k] = v
        return d
    
    def get(self, path, default=None):
        keys = path.split('.')
        val = self.config
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                return default
        return val if val is not None else default
