"""Durable, actor-bound workflow definitions and immutable action plans."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class OpsStore:
    def __init__(self, path: str | None = None):
        configured = path or os.getenv("FLATBEE_OPS_DB", "data/flatbee_ops.sqlite")
        self.path = Path(configured).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _migrate(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflows (
                    name TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    definition_hash TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS action_plans (
                    id TEXT PRIMARY KEY,
                    actor_email TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    executed_at TEXT,
                    result_json TEXT
                );
                CREATE INDEX IF NOT EXISTS action_plans_actor_status
                    ON action_plans(actor_email, status, created_at DESC);
                """
            )

    @staticmethod
    def _public_plan(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "actor_email": row["actor_email"],
            "operation": row["operation"],
            "summary": row["summary"],
            "payload": json.loads(row["payload_json"]),
            "payload_hash": row["payload_hash"],
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "executed_at": row["executed_at"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
        }

    def prepare(
        self,
        actor_email: str,
        operation: str,
        summary: str,
        payload: dict[str, Any],
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        now = _now()
        plan_id = str(uuid.uuid4())
        payload_hash = stable_hash(payload)
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO action_plans
                    (id, actor_email, operation, summary, payload_json, payload_hash,
                     status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    plan_id,
                    actor_email,
                    operation,
                    summary,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    payload_hash,
                    _iso(now),
                    _iso(now + timedelta(seconds=max(60, min(ttl_seconds, 3600)))),
                ),
            )
        return self.get_plan(plan_id, actor_email)

    def get_plan(self, plan_id: str, actor_email: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM action_plans WHERE id = ? AND actor_email = ?",
                (plan_id, actor_email),
            ).fetchone()
        if row is None:
            raise ValueError("Action plan was not found for this actor")
        return self._public_plan(row)

    def execute_workflow_upsert(
        self, plan_id: str, actor_email: str, confirmation: str
    ) -> dict[str, Any]:
        if confirmation != plan_id:
            raise ValueError("confirmation must exactly match plan_id")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM action_plans WHERE id = ? AND actor_email = ?",
                (plan_id, actor_email),
            ).fetchone()
            if row is None:
                raise ValueError("Action plan was not found for this actor")
            if row["status"] != "pending":
                raise ValueError(f"Action plan is {row['status']}, not pending")
            if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= _now():
                connection.execute(
                    "UPDATE action_plans SET status='expired' WHERE id=?", (plan_id,)
                )
                raise ValueError("Action plan has expired")
            if row["operation"] != "workflow.upsert":
                raise ValueError(f"Unsupported action operation: {row['operation']}")

            payload = json.loads(row["payload_json"])
            current = connection.execute(
                "SELECT version FROM workflows WHERE name = ?", (payload["name"],)
            ).fetchone()
            version = (int(current["version"]) + 1) if current else 1
            now = _iso(_now())
            connection.execute(
                """
                INSERT INTO workflows
                    (name, description, definition_json, definition_hash, version,
                     active, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    description=excluded.description,
                    definition_json=excluded.definition_json,
                    definition_hash=excluded.definition_hash,
                    version=excluded.version,
                    active=1,
                    updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at
                """,
                (
                    payload["name"],
                    payload["description"],
                    json.dumps(payload["definition"], ensure_ascii=False, sort_keys=True),
                    stable_hash(payload["definition"]),
                    version,
                    actor_email,
                    now,
                ),
            )
            result = {"workflow": payload["name"], "version": version, "active": True}
            connection.execute(
                """
                UPDATE action_plans
                SET status='completed', executed_at=?, result_json=?
                WHERE id=?
                """,
                (now, json.dumps(result, sort_keys=True), plan_id),
            )
            connection.commit()
        return {"ok": True, "plan_id": plan_id, **result}

    def list_workflows(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM workflows WHERE active=1 ORDER BY name"
            ).fetchall()
        return [self._workflow(row) for row in rows]

    def get_workflow(self, name: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM workflows WHERE name=? AND active=1", (name,)
            ).fetchone()
        if row is None:
            raise ValueError(f"Workflow {name!r} was not found")
        return self._workflow(row)

    @staticmethod
    def _workflow(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "name": row["name"],
            "description": row["description"],
            "definition": json.loads(row["definition_json"]),
            "definition_hash": row["definition_hash"],
            "version": row["version"],
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"],
        }

