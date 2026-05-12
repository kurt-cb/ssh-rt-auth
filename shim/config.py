"""Shim configuration loader."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ShimConfig:
    ca_endpoints: list[str] = field(default_factory=list)
    mtls_cert: str = ''
    mtls_key: str = ''
    ca_trust_root: str = ''
    auth_trust_root: str = ''
    server_name: str = ''           # this server's canonical name (for sshd validation)
    cache_max_entries: int = 1000
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    emergency_cert: str = ''
    emergency_trust_root: str = ''
    log_level: str = 'info'

    @classmethod
    def load(cls, path: str | Path) -> 'ShimConfig':
        with Path(path).open() as f:
            data = yaml.safe_load(f) or {}
        cache = data.get('cache') or {}
        timeouts = data.get('timeouts') or {}
        log_ = data.get('log') or {}
        return cls(
            ca_endpoints=list(data.get('ca_endpoints') or []),
            mtls_cert=str(data.get('mtls_cert') or ''),
            mtls_key=str(data.get('mtls_key') or ''),
            ca_trust_root=str(data.get('ca_trust_root') or ''),
            auth_trust_root=str(data.get('auth_trust_root') or ''),
            server_name=str(data.get('server_name') or ''),
            cache_max_entries=int(cache.get('max_entries') or 1000),
            connect_timeout=float(timeouts.get('connect') or 5.0),
            read_timeout=float(timeouts.get('read') or 10.0),
            emergency_cert=str(data.get('emergency_cert') or ''),
            emergency_trust_root=str(data.get('emergency_trust_root') or ''),
            log_level=str(log_.get('level') or 'info'),
        )

    def validate(self) -> None:
        if not self.ca_endpoints:
            raise ValueError('shim config requires at least one ca_endpoints entry')
        for f in ['mtls_cert', 'mtls_key', 'ca_trust_root', 'auth_trust_root']:
            v = getattr(self, f)
            if not v:
                raise ValueError(f'shim config requires {f}')
            if not Path(v).exists():
                raise ValueError(f'shim config: {f}={v} does not exist')
