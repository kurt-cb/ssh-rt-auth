"""SQLite-backed cert cache.

The in-memory `CertCache` is fine for long-lived processes (the AsyncSSH
server keeps one Shim alive for the lifetime of the daemon), but the
OpenSSH `AuthorizedKeysCommand` shim runs as a fresh short-lived
subprocess for every authentication attempt — an in-memory cache there is
useless. Worse, sshd typically invokes `AuthorizedKeysCommand` *twice* per
accepted connection (check + verify), so without persistence we double the
CA load and duplicate the audit log.

This module implements the same get/put interface as ``CertCache`` but
persists each entry in a SQLite database. Atomic; safe for concurrent
readers + a writer (SQLite's built-in WAL handles it).
"""
from __future__ import annotations

import datetime as _dt
import sqlite3
import threading
from pathlib import Path

from .cache import CacheEntry


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cert_cache (
    fingerprint  TEXT    NOT NULL,
    source_ip    TEXT    NOT NULL,
    cert_der     BLOB    NOT NULL,
    serial       TEXT    NOT NULL,
    not_after    INTEGER NOT NULL,    -- unix seconds
    created_at   INTEGER NOT NULL,    -- unix seconds
    PRIMARY KEY (fingerprint, source_ip)
);
CREATE INDEX IF NOT EXISTS cert_cache_not_after ON cert_cache(not_after);
"""


class SqliteCertCache:
    """Persistent cert cache. Same get/put surface as ``CertCache``."""

    def __init__(self, db_path: str | Path, max_entries: int = 1000):
        self.db_path = Path(db_path)
        self.max_entries = max_entries
        # Parent dir must exist before we open the database.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        # `isolation_level=None` so each statement commits immediately, plus
        # WAL so a single writer never blocks readers (the shim's two
        # invocations per ssh attempt aren't strictly concurrent, but better
        # safe than sorry).
        c = sqlite3.connect(self.db_path, isolation_level=None, timeout=5.0)
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA busy_timeout=5000')
        return c

    # ---- public API (mirrors CertCache) -----------------------------------

    def get(self, fingerprint: str, source_ip: str,
            now: _dt.datetime | None = None) -> CacheEntry | None:
        now = now or _dt.datetime.now(tz=_dt.timezone.utc)
        now_ts = int(now.timestamp())
        with self._lock, self._conn() as c:
            row = c.execute(
                'SELECT cert_der, serial, not_after, created_at '
                'FROM cert_cache WHERE fingerprint=? AND source_ip=?',
                (fingerprint, source_ip),
            ).fetchone()
            if row is None:
                return None
            cert_der, serial, not_after, created_at = row
            if not_after <= now_ts:
                # Expired — evict so the next call goes back to the CA.
                c.execute('DELETE FROM cert_cache WHERE fingerprint=? '
                          'AND source_ip=?', (fingerprint, source_ip))
                return None
            return CacheEntry(
                cert_der=bytes(cert_der), serial=serial,
                not_after=_dt.datetime.fromtimestamp(
                    not_after, tz=_dt.timezone.utc),
                created_at=_dt.datetime.fromtimestamp(
                    created_at, tz=_dt.timezone.utc),
            )

    def put(self, fingerprint: str, source_ip: str,
            entry: CacheEntry) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                'INSERT OR REPLACE INTO cert_cache '
                '(fingerprint, source_ip, cert_der, serial, not_after, '
                ' created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (fingerprint, source_ip, entry.cert_der, entry.serial,
                 int(entry.not_after.timestamp()),
                 int(entry.created_at.timestamp())),
            )
            # LRU-ish eviction: drop oldest by created_at when over max.
            n = c.execute('SELECT COUNT(*) FROM cert_cache').fetchone()[0]
            if n > self.max_entries:
                c.execute(
                    'DELETE FROM cert_cache WHERE rowid IN '
                    '(SELECT rowid FROM cert_cache ORDER BY created_at '
                    ' ASC LIMIT ?)',
                    (n - self.max_entries,))

    def __len__(self) -> int:
        with self._conn() as c:
            return c.execute(
                'SELECT COUNT(*) FROM cert_cache').fetchone()[0]

    def clear(self) -> None:
        with self._lock, self._conn() as c:
            c.execute('DELETE FROM cert_cache')

    def vacuum_expired(self, now: _dt.datetime | None = None) -> int:
        """Drop all expired rows; return count removed.

        Worth calling on shim startup to keep the DB tight; the per-get
        eviction handles the steady state already."""
        now = now or _dt.datetime.now(tz=_dt.timezone.utc)
        with self._lock, self._conn() as c:
            cur = c.execute(
                'DELETE FROM cert_cache WHERE not_after <= ?',
                (int(now.timestamp()),))
            return cur.rowcount
