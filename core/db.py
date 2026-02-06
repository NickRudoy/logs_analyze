import sqlite3
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class DBManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = None
        
    def connect(self):
        """Ustanavlivaet soedinenie s BD"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        # WAL mode — меньше disk I/O, лучше для больших объёмов
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.init_schema()
        
    def close(self):
        if self.conn:
            self.conn.close()
            
    def init_schema(self):
        """Sozdaet structuru tablic"""
        query = """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp DATETIME,
            method TEXT,
            url TEXT,
            protocol TEXT,
            status INTEGER,
            size INTEGER,
            referer TEXT,
            user_agent TEXT,
            is_bot BOOLEAN,
            country TEXT,
            provider TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_ip ON logs(ip);
        CREATE INDEX IF NOT EXISTS idx_ts ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_status ON logs(status);
        CREATE INDEX IF NOT EXISTS idx_ua ON logs(user_agent);
        """
        with self.conn:
            self.conn.executescript(query)
            
    def insert_batch(self, entries):
        """Bystraya vstavka packa zapisey"""
        if not entries:
            return
            
        # Podgotovka dannyh dlya vstavki
        data = []
        for entry in entries:
            # Preobrazuem datetime v string dlya sqlite
            ts = entry.get('timestamp')
            if isinstance(ts, datetime):
                ts = ts.isoformat()
                
            row = (
                entry.get('ip'),
                ts,
                entry.get('method'),
                entry.get('url'),
                entry.get('protocol'),
                entry.get('status'),
                entry.get('size'),
                entry.get('referer'),
                entry.get('user_agent'),
                entry.get('is_bot', False),
                entry.get('country'),
                entry.get('provider')
            )
            data.append(row)
            
        for attempt in range(3):
            try:
                with self.conn:
                    self.conn.executemany("""
                        INSERT INTO logs (
                            ip, timestamp, method, url, protocol, status, size, 
                            referer, user_agent, is_bot, country, provider
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, data)
                return
            except sqlite3.OperationalError as e:
                if "disk I/O" in str(e) or "database is locked" in str(e):
                    import time
                    time.sleep(1 * (attempt + 1))
                    continue
                logger.error(f"DB Insert error: {e}")
                print(f"Ошибка БД: {e}. Проверьте место на диске и права доступа.")
                raise
            except sqlite3.Error as e:
                logger.error(f"DB Insert error: {e}")
                print(f"Ошибка БД при вставке {len(data)} записей: {e}")
                raise

    def execute_query(self, query, params=()):
        """Vypolnyaet SQL zapros i vozvrashchaet rezultat"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor

    def get_distinct_ips(self):
        """Vozvrashchaet spisok unikalnyh IP iz tablicy logs"""
        cursor = self.execute_query("SELECT DISTINCT ip FROM logs WHERE ip IS NOT NULL")
        return [row[0] for row in cursor.fetchall()]

    def get_distinct_ips_without_geo(self):
        """Vozvrashchaet IP, kotorym nuzhna geolokaciya (country IS NULL)"""
        cursor = self.execute_query(
            "SELECT DISTINCT ip FROM logs WHERE ip IS NOT NULL AND (country IS NULL OR country = '')"
        )
        return [row[0] for row in cursor.fetchall()]

    def get_geo_for_ip(self, ip):
        """Vozvrashchaet (country, provider) dlya IP iz logs, esli est. Inache None."""
        cursor = self.execute_query(
            "SELECT country, provider FROM logs WHERE ip = ? AND country IS NOT NULL AND country != '' LIMIT 1",
            (ip,)
        )
        row = cursor.fetchone()
        return (row[0], row[1]) if row else None

    def get_ips_with_geo(self):
        """Vozvrashchaet [(ip, country, provider), ...] dlya predzapolneniya kesha GeoIP."""
        cursor = self.execute_query(
            "SELECT DISTINCT ip, country, provider FROM logs WHERE ip IS NOT NULL AND country IS NOT NULL AND country != ''"
        )
        return [(row[0], row[1], row[2]) for row in cursor.fetchall()]

    def update_geo_for_ip(self, ip, country, provider):
        """Obnovlyaet country i provider dlya vseh zapisey s dannym IP"""
        with self.conn:
            self.conn.execute(
                "UPDATE logs SET country = ?, provider = ? WHERE ip = ?",
                (country or 'Unknown', provider or 'Unknown', ip)
            )
