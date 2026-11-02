"""Tiny SQLite layer for scan history."""
import json
import sqlite3
import time

DB = "scans.db"


def _conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, mode TEXT, status TEXT,
            created REAL, finished REAL, pages INTEGER DEFAULT 0, finding_count INTEGER DEFAULT 0,
            findings TEXT DEFAULT '[]', log TEXT DEFAULT '')""")


def create(target, mode):
    with _conn() as c:
        return c.execute("INSERT INTO scans (target, mode, status, created) VALUES (?,?,?,?)",
                         (target, mode, "queued", time.time())).lastrowid


def update(scan_id, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    with _conn() as c:
        c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def append_log(scan_id, line):
    with _conn() as c:
        c.execute("UPDATE scans SET log = log || ? WHERE id=?", (line + "\n", scan_id))


def get(scan_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    scan = dict(row)
    scan["findings"] = json.loads(scan["findings"])
    return scan


def recent(limit=10):
    with _conn() as c:
        rows = c.execute("SELECT id, target, mode, status, finding_count, created FROM scans "
                         "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]