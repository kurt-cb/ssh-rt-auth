"""Structured per-operation logging for LXC integration tests.

When an assertion fails, the goal is to see — without sshing into anything —
exactly what was attempted, what the CA decided, and what the shim observed.

Use ``OpsLog`` as a context manager around a logical operation (e.g. one SSH
connection attempt, one admin API call). On exit, the operation row is
formatted; on failure the bound diagnostic snapshots are printed.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import sys
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable


# ANSI escape (always emitted; if the test output isn't a TTY, the codes are
# harmless noise).
_OK    = '\033[32m'      # green
_FAIL  = '\033[31m'      # red
_DIM   = '\033[2m'
_BOLD  = '\033[1m'
_END   = '\033[0m'


def _now() -> str:
    return _dt.datetime.now().strftime('%H:%M:%S.%f')[:-3]


@dataclass
class OpsLog:
    """Captures one logical operation.

    Example::

        with OpsLog('ssh', source='u1', target='srv-a', user='alice',
                    expect='granted') as op:
            rc, stdout, stderr = run_ssh(...)
            op.record(actual='granted' if rc == 0 else 'denied',
                      stdout=stdout, stderr=stderr,
                      ok=(rc == 0))
            op.attach('audit_tail',
                      pull_audit_tail(ca_host))
    """
    kind: str
    expect: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    actual: str | None = None
    ok: bool | None = None
    duration_ms: float = 0.0
    diagnostics: dict[str, str] = field(default_factory=dict)
    _t0: float = 0.0

    def __init__(self, kind: str, **attrs):
        self.kind = kind
        self.expect = attrs.pop('expect', None)
        self.attrs = attrs
        self.actual = None
        self.ok = None
        self.diagnostics = {}
        self._t0 = 0.0
        self.duration_ms = 0.0

    def __enter__(self) -> 'OpsLog':
        import time
        self._t0 = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        import time
        self.duration_ms = (time.monotonic() - self._t0) * 1000
        if exc is not None and self.ok is None:
            self.ok = False
            self.actual = f'exception: {exc!r}'
            self.diagnostics['traceback'] = ''.join(
                traceback.format_exception(exc_type, exc, tb))
        self._emit()
        return False     # don't swallow exceptions

    def record(self, *, actual: str, ok: bool, **diagnostics) -> None:
        self.actual = actual
        self.ok = ok
        for k, v in diagnostics.items():
            if v is None:
                continue
            self.diagnostics[k] = str(v)

    def attach(self, name: str, value: Any) -> None:
        if value is None:
            return
        if not isinstance(value, str):
            try:
                value = json.dumps(value, indent=2, default=str)
            except Exception:
                value = repr(value)
        self.diagnostics[name] = value

    def _emit(self) -> None:
        status = 'OK' if self.ok else 'FAIL' if self.ok is not None else '??'
        colour = _OK if self.ok else _FAIL if self.ok is not None else _DIM
        attr_str = ' '.join(f'{k}={v}' for k, v in self.attrs.items())
        expect = f'expect={self.expect}' if self.expect else ''
        actual = f'actual={self.actual}' if self.actual else ''
        line = (f'{_DIM}[{_now()}]{_END} {colour}{_BOLD}{self.kind:>10s}{_END} '
                f'{colour}{status:4s}{_END} '
                f'{attr_str}  {expect}  {actual} '
                f'{_DIM}({self.duration_ms:.0f}ms){_END}')
        print(line, file=sys.stderr, flush=True)
        if self.ok is False:
            for name, body in self.diagnostics.items():
                print(f'  {_DIM}── {name}{_END}', file=sys.stderr)
                for ln in str(body).rstrip('\n').splitlines():
                    print(f'    {ln}', file=sys.stderr)


def banner(title: str, *, char: str = '=') -> None:
    bar = char * 78
    print(f'\n{_BOLD}{bar}\n {title}\n{bar}{_END}', file=sys.stderr, flush=True)


def section(title: str) -> None:
    print(f'\n{_DIM}── {title} ──{_END}', file=sys.stderr, flush=True)


def render_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    """Render rows as a fixed-width table to a string."""
    widths = {c: max(len(c), *(len(str(r.get(c, ''))) for r in rows))
              for c in columns}
    out = ['  '.join(c.ljust(widths[c]) for c in columns),
           '  '.join('-' * widths[c] for c in columns)]
    for r in rows:
        out.append('  '.join(str(r.get(c, '')).ljust(widths[c]) for c in columns))
    return '\n'.join(out)


def pull_audit_tail(lxc_exec_fn: Callable, container: str,
                    audit_path: str = '/var/log/ssh-rt-auth/audit.jsonl',
                    n: int = 5) -> list[dict[str, Any]]:
    """Read the last ``n`` JSON-lines entries from the CA's audit log."""
    r = lxc_exec_fn(container, 'tail', '-n', str(n), audit_path, check=False)
    out = []
    for line in (r.stdout or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out
