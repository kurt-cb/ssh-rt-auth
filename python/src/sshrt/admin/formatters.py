"""Output formatters for ssh-rt-admin (table / json / yaml)."""
from __future__ import annotations

import json
from typing import Any

import yaml


def render(data: Any, fmt: str = 'table') -> str:
    if fmt == 'json':
        return json.dumps(data, indent=2, sort_keys=True)
    if fmt == 'yaml':
        return yaml.safe_dump(data, sort_keys=True)
    return _table(data)


def _table(data: Any) -> str:
    if isinstance(data, list):
        if not data:
            return '(none)'
        if isinstance(data[0], dict):
            return _list_of_dicts(data)
        return '\n'.join(str(x) for x in data)
    if isinstance(data, dict):
        return _kv(data)
    return str(data)


def _list_of_dicts(items: list[dict[str, Any]]) -> str:
    keys: list[str] = []
    for item in items:
        for k in item.keys():
            if k not in keys:
                keys.append(k)
    rows = [[str(item.get(k, '')) for k in keys] for item in items]
    widths = [max(len(k), *(len(r[i]) for r in rows)) for i, k in enumerate(keys)]
    out = ['  '.join(k.ljust(w) for k, w in zip(keys, widths))]
    for r in rows:
        out.append('  '.join(c.ljust(w) for c, w in zip(r, widths)))
    return '\n'.join(out)


def _kv(d: dict[str, Any]) -> str:
    if not d:
        return '(empty)'
    width = max(len(k) for k in d.keys())
    lines = []
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        lines.append(f'{k.ljust(width)}  {v}')
    return '\n'.join(lines)
