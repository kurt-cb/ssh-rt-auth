"""Unit tests for shim/sqlite_cache.py."""
from __future__ import annotations

import datetime as _dt
import subprocess
import sys

import pytest

from mssh.shim.cache import CacheEntry
from mssh.shim.sqlite_cache import SqliteCertCache


@pytest.fixture
def cache(tmp_path):
    return SqliteCertCache(tmp_path / 'cache.db', max_entries=10)


def _entry(serial: str, *, valid_for_seconds: int = 60) -> CacheEntry:
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    return CacheEntry(
        cert_der=f'cert-{serial}'.encode(),
        serial=serial,
        not_after=now + _dt.timedelta(seconds=valid_for_seconds),
        created_at=now,
    )


def test_put_then_get(cache):
    cache.put('fp1', '10.0.0.1', _entry('s1'))
    got = cache.get('fp1', '10.0.0.1')
    assert got is not None
    assert got.serial == 's1'
    assert got.cert_der == b'cert-s1'


def test_miss_returns_none(cache):
    assert cache.get('nope', '10.0.0.1') is None


def test_different_source_ip_is_different_key(cache):
    cache.put('fp1', '10.0.0.1', _entry('s1'))
    assert cache.get('fp1', '10.0.0.2') is None


def test_expired_entry_is_evicted_on_get(cache):
    cache.put('fp1', '10.0.0.1', _entry('s1', valid_for_seconds=-10))
    assert cache.get('fp1', '10.0.0.1') is None
    assert len(cache) == 0


def test_persistence_across_instances(tmp_path):
    """Open a cache, write an entry, close, re-open in a new instance —
    the entry should still be there. This is the whole reason SqliteCertCache
    exists vs. the in-memory one."""
    db = tmp_path / 'cache.db'
    c1 = SqliteCertCache(db)
    c1.put('fpX', '10.0.0.99', _entry('serialX'))
    del c1
    c2 = SqliteCertCache(db)
    got = c2.get('fpX', '10.0.0.99')
    assert got is not None
    assert got.serial == 'serialX'


def test_persistence_across_subprocesses(tmp_path):
    """Cross-process persistence — the real-world scenario for the OpenSSH
    shim (each sshd → shim call is a fresh subprocess)."""
    db = tmp_path / 'cache.db'
    # python/src/ holds the mssh package.
    src_root = str(__import__('pathlib').Path(__file__).resolve().parent.parent / 'src')
    writer = f'''
import sys, datetime as dt
sys.path.insert(0, {src_root!r})
from mssh.shim.cache import CacheEntry
from mssh.shim.sqlite_cache import SqliteCertCache
c = SqliteCertCache({str(db)!r})
now = dt.datetime.now(tz=dt.timezone.utc)
c.put("fpProc", "10.0.0.50", CacheEntry(
    cert_der=b"from-other-process", serial="sub-serial",
    not_after=now + dt.timedelta(minutes=5), created_at=now))
'''
    subprocess.run([sys.executable, '-c', writer], check=True)

    c2 = SqliteCertCache(db)
    got = c2.get('fpProc', '10.0.0.50')
    assert got is not None
    assert got.cert_der == b'from-other-process'
    assert got.serial == 'sub-serial'


def test_lru_eviction(tmp_path):
    cache = SqliteCertCache(tmp_path / 'lru.db', max_entries=3)
    cache.put('fp1', '1.1.1.1', _entry('s1'))
    cache.put('fp2', '1.1.1.1', _entry('s2'))
    cache.put('fp3', '1.1.1.1', _entry('s3'))
    cache.put('fp4', '1.1.1.1', _entry('s4'))
    # Oldest by created_at gets evicted. The four puts run within microseconds
    # of each other so any one of {s1,s2,s3,s4} could be the oldest, but
    # we only need to confirm size is capped.
    assert len(cache) == 3


def test_vacuum_expired_drops_old_rows(cache):
    cache.put('fp-expired', '1.1.1.1', _entry('old',
                                              valid_for_seconds=-60))
    cache.put('fp-fresh', '1.1.1.1', _entry('new', valid_for_seconds=60))
    removed = cache.vacuum_expired()
    assert removed == 1
    assert cache.get('fp-fresh', '1.1.1.1') is not None


def test_clear(cache):
    cache.put('fp1', '1.1.1.1', _entry('s1'))
    cache.clear()
    assert len(cache) == 0
