import sqlite3
import json
import csv
from typing import List, Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str = "knocksphere.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_discovered INTEGER,
                    wildcard_detected INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    subdomain TEXT NOT NULL,
                    ips TEXT,
                    source TEXT,
                    is_wildcard INTEGER,
                    http_status INTEGER,
                    http_title TEXT,
                    http_url TEXT,
                    tls_version TEXT,
                    tls_issuer TEXT,
                    tls_expiry TEXT,
                    tls_weak INTEGER,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            conn.commit()

    def create_scan(self, domain: str, wildcard_detected: bool) -> int:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scans (domain, total_discovered, wildcard_detected) VALUES (?, 0, ?)",
                (domain, int(wildcard_detected))
            )
            conn.commit()
            return cur.lastrowid

    def save_results(self, scan_id: int, results: List[Dict[str, Any]]):
        with self._get_conn() as conn:
            cur = conn.cursor()
            for r in results:
                cur.execute("""
                    INSERT INTO results (
                        scan_id, subdomain, ips, source, is_wildcard,
                        http_status, http_title, http_url,
                        tls_version, tls_issuer, tls_expiry, tls_weak
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    r.get("subdomain"),
                    json.dumps(r.get("ips", [])),
                    r.get("source", "unknown"),
                    int(r.get("is_wildcard", False)),
                    r.get("http_status"),
                    r.get("http_title"),
                    r.get("http_url"),
                    r.get("tls_version"),
                    r.get("tls_issuer"),
                    r.get("tls_expiry"),
                    int(r.get("tls_weak", False))
                ))
            cur.execute("UPDATE scans SET total_discovered = ? WHERE id = ?", (len(results), scan_id))
            conn.commit()

    def list_scans(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM scans ORDER BY created_at DESC")
            return [dict(row) for row in cur.fetchall()]

    def get_scan_results(self, scan_id: int) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM results WHERE scan_id = ?", (scan_id,))
            rows = [dict(row) for row in cur.fetchall()]
            for r in rows:
                r["ips"] = json.loads(r["ips"]) if r["ips"] else []
            return rows

    def search_subdomains(self, query: str) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT r.*, s.domain as root_domain, s.created_at
                FROM results r JOIN scans s ON r.scan_id = s.id
                WHERE r.subdomain LIKE ?
            """, (f"%{query}%",))
            rows = [dict(row) for row in cur.fetchall()]
            for r in rows:
                r["ips"] = json.loads(r["ips"]) if r["ips"] else []
            return rows

    def delete_scan(self, scan_id: int) -> bool:
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    def export_csv(self, scan_id: int, filepath: str) -> bool:
        results = self.get_scan_results(scan_id)
        if not results:
            return False
        keys = results[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            for row in results:
                row["ips"] = ",".join(row["ips"])
                dict_writer.writerow(row)
        return True
