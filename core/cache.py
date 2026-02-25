# -*- coding: utf-8 -*-
"""Кэш распознанных записей на диск: SQLite + progress-файл для возобновления парсинга."""

import json
import sqlite3
from pathlib import Path
from datetime import datetime

PROGRESS_FILENAME = "progress.json"
DB_FILENAME = "entries.db"
BATCH_SIZE = 200_000


def _connect(db_path):
    """Создаёт SQLite-соединение с быстрыми безопасными PRAGMA."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _norm_path(p):
    return str(Path(p).resolve())


def get_cache_dir(log_path, cache_dir=None):
    """Директория кэша: cache_dir или .log_analyz_cache рядом с логами."""
    base = Path(log_path).resolve()
    if base.is_file():
        base = base.parent
    if cache_dir:
        return Path(cache_dir).resolve()
    return base / ".log_analyz_cache"


def get_progress_path(cache_dir):
    return Path(cache_dir) / PROGRESS_FILENAME


def get_db_path(cache_dir):
    return Path(cache_dir) / DB_FILENAME


def load_progress(cache_dir):
    """Читает progress.json. Возвращает None если нет или не совпадает log_dir."""
    path = get_progress_path(cache_dir)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_progress(cache_dir, log_dir_abs, completed_files, total_entries, current_file=None, current_file_rows=0):
    path = get_progress_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "version": 1,
            "log_dir": log_dir_abs,
            "completed_files": completed_files,
            "db_path": str(get_db_path(cache_dir)),
            "total_entries": total_entries,
            "current_file": current_file,
            "current_file_rows": current_file_rows,
        }, f, ensure_ascii=False, indent=2)


def remove_last_n_rows(db_path, n):
    """Удаляет последние n строк (чтобы убрать незавершённый файл при resume)."""
    if n <= 0:
        return
    conn = _connect(db_path)
    conn.execute("DELETE FROM entries WHERE id IN (SELECT id FROM entries ORDER BY id DESC LIMIT ?)", (n,))
    conn.commit()
    conn.close()


def init_db(db_path):
    """Создаёт таблицу entries если её нет."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ts_iso TEXT,
            method TEXT,
            url TEXT,
            status INTEGER,
            size TEXT,
            referer TEXT,
            user_agent TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(ts_iso)")
    conn.commit()
    conn.close()


def insert_batch(db_path, rows):
    """Вставляет пачку записей. rows: list of dicts с ключами ip, timestamp, method, url, status, size, referer, user_agent."""
    if not rows:
        return
    conn = _connect(db_path)
    conn.executemany(
        """INSERT INTO entries (ip, ts_iso, method, url, status, size, referer, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                r["ip"],
                r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else r["timestamp"],
                r.get("method", "-"),
                r["url"],
                r["status"],
                r.get("size", "-"),
                r.get("referer", "-"),
                r.get("user_agent", ""),
            )
            for r in rows
        ],
    )
    conn.commit()
    conn.close()


def count_entries(db_path):
    """Общее число записей в кэше."""
    conn = _connect(db_path)
    n = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    conn.close()
    return n


def iter_entries(db_path, start=0, limit=None):
    """Итератор по записям из БД. Yields (entry_dict, row_id). entry_dict как у LogParser, timestamp — datetime."""
    conn = _connect(db_path)
    conn.row_factory = sqlite3.Row
    q = "SELECT id, ip, ts_iso, method, url, status, size, referer, user_agent FROM entries WHERE id > ? ORDER BY id"
    args = [start]
    if limit is not None:
        q += " LIMIT ?"
        args.append(limit)
    cursor = conn.execute(q, args)
    for row in cursor:
        ts = row["ts_iso"]
        try:
            if "T" in str(ts):
                timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if timestamp.tzinfo:
                    timestamp = timestamp.replace(tzinfo=None)
            else:
                timestamp = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = datetime.now()
        yield (
            {
                "ip": row["ip"],
                "timestamp": timestamp,
                "method": row["method"],
                "url": row["url"],
                "status": row["status"],
                "size": row["size"],
                "referer": row["referer"],
                "user_agent": row["user_agent"],
            },
            row["id"],
        )
    conn.close()


def load_entries_batch(db_path, start_id=0, batch_size=500_000):
    """Загружает один батч записей. Возвращает (list of entry dicts, last_id или 0)."""
    batch = []
    last_id = start_id
    for entry, row_id in iter_entries(db_path, start=start_id, limit=batch_size):
        batch.append(entry)
        last_id = row_id
    return batch, last_id
