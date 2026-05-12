"""In-memory cert cache keyed on (fingerprint, source_ip)."""
from __future__ import annotations

import datetime as _dt
import threading
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    cert_der: bytes
    serial: str
    not_after: _dt.datetime
    created_at: _dt.datetime


class CertCache:
    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self._items: 'OrderedDict[tuple[str, str], CacheEntry]' = OrderedDict()
        self._lock = threading.Lock()

    def get(self, fingerprint: str, source_ip: str,
            now: _dt.datetime | None = None) -> CacheEntry | None:
        now = now or _dt.datetime.now(tz=_dt.timezone.utc)
        with self._lock:
            entry = self._items.get((fingerprint, source_ip))
            if entry is None:
                return None
            if entry.not_after <= now:
                # Expired — evict.
                del self._items[(fingerprint, source_ip)]
                return None
            # Touch for LRU.
            self._items.move_to_end((fingerprint, source_ip))
            return entry

    def put(self, fingerprint: str, source_ip: str, entry: CacheEntry) -> None:
        with self._lock:
            self._items[(fingerprint, source_ip)] = entry
            self._items.move_to_end((fingerprint, source_ip))
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
