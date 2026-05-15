"""Audit logging in JSON Lines format."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class AuditLog:
    """Append-only JSONL writer. Thread-safe for in-process writers."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, separators=(',', ':'))
        with self._lock:
            with self.path.open('a') as f:
                f.write(line + '\n')

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
