"""Unit tests for ca/audit.py."""
from __future__ import annotations

from mssh.ca.audit import AuditLog


def test_write_and_read(tmp_path):
    a = AuditLog(tmp_path / 'audit.jsonl')
    a.write({'type': 'admin', 'action': 'server.add', 'result': 'ok'})
    a.write({'type': 'authorization', 'decision': 'granted'})
    entries = a.read_all()
    assert len(entries) == 2
    assert entries[0]['action'] == 'server.add'
    assert entries[1]['decision'] == 'granted'


def test_read_empty(tmp_path):
    a = AuditLog(tmp_path / 'nope.jsonl')
    assert a.read_all() == []


def test_thread_safe_writes(tmp_path):
    import threading
    a = AuditLog(tmp_path / 'a.jsonl')
    def _run():
        for i in range(50):
            a.write({'i': i})
    threads = [threading.Thread(target=_run) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    entries = a.read_all()
    assert len(entries) == 200
