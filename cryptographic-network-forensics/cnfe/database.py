import json
import sqlite3
from pathlib import Path
from typing import Any


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: str) -> None:
    with connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                requested_target TEXT NOT NULL,
                resolved_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)"
        )
        connection.commit()


def save_scan(db_path: str, result: dict[str, Any]) -> None:
    with connect(db_path) as connection:
        connection.execute(
            """INSERT INTO scans
               (id, created_at, requested_target, resolved_ip, port, status, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result["id"], result["created_at"], result["target"],
                result["resolved_ip"], result["port"], result["status"],
                json.dumps(result),
            ),
        )
        connection.commit()


def list_scans(db_path: str, limit: int = 50) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT result_json FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [json.loads(row["result_json"]) for row in rows]
