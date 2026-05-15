"""wrapper.yaml loader and validator.

Mirrors the schema in ``wrapper/config/wrapper.yaml.example``. The loader
is dataclass-based with explicit field types; ``validate()`` performs
cross-field checks and on-disk-permission checks for cert/key paths.

The wrapper YAML is intentionally small — see
[detailed-wrapper.md § 11](../../design/ssh-rt-auth-detailed-wrapper.md).
Operators do not edit the inner sshd config; that is rendered hermetically
by the wrapper from a template that ships in the wrapper package.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


MODE_FALLBACK = 'fallback'
MODE_ENFORCE = 'enforce'
VALID_MODES = (MODE_FALLBACK, MODE_ENFORCE)


@dataclass
class FallbackConfig:
    host: str = '127.0.0.1'
    port: int = 22


@dataclass
class ListenConfig:
    external_address: str = '0.0.0.0'
    external_port: int = 2200
    interfaces: list[str] = field(default_factory=list)


@dataclass
class TLSConfig:
    server_cert: str = ''
    server_key: str = ''
    user_ca_pubkey: str = ''


@dataclass
class CAConfig:
    endpoints: list[str] = field(default_factory=list)
    client_cert: str = ''
    client_key: str = ''
    ca_pubkey: str = ''
    timeout_seconds: float = 5.0
    emergency_cert: str = ''


@dataclass
class InnerConfig:
    sshd_binary: str = '/usr/sbin/sshd'
    port_range: tuple[int, int] = (49152, 65535)


@dataclass
class UsersConfig:
    allowed: list[str] = field(default_factory=list)


@dataclass
class LoggingConfig:
    level: str = 'info'
    destination: str = 'stderr'
    audit_destination: str = 'file:/var/log/ssh-rt-auth/wrapper-audit.jsonl'


@dataclass
class PerformanceConfig:
    inner_cipher_none: bool = False
    max_concurrent_sessions: int = 200


@dataclass
class WrapperConfig:
    mode: str = MODE_FALLBACK
    fallback: FallbackConfig = field(default_factory=FallbackConfig)
    listen: ListenConfig = field(default_factory=ListenConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    ca: CAConfig = field(default_factory=CAConfig)
    inner: InnerConfig = field(default_factory=InnerConfig)
    users: UsersConfig = field(default_factory=UsersConfig)
    logging_: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)

    @classmethod
    def load(cls, path: str | Path) -> 'WrapperConfig':
        with Path(path).open() as f:
            data = yaml.safe_load(f) or {}
        fb = data.get('fallback') or {}
        ls = data.get('listen') or {}
        tls = data.get('tls') or {}
        ca = data.get('ca') or {}
        inner = data.get('inner') or {}
        users = data.get('users') or {}
        log_ = data.get('logging') or {}
        perf = data.get('performance') or {}

        # port_range can come in as [lo, hi] list — coerce to tuple.
        port_range = inner.get('port_range') or [49152, 65535]
        if len(port_range) != 2:
            raise ValueError('inner.port_range must be [low, high]')

        return cls(
            mode=str(data.get('mode') or MODE_FALLBACK),
            fallback=FallbackConfig(
                host=str(fb.get('host') or '127.0.0.1'),
                port=int(fb.get('port') or 22),
            ),
            listen=ListenConfig(
                external_address=str(ls.get('external_address') or '0.0.0.0'),
                external_port=int(ls.get('external_port') or 2200),
                interfaces=list(ls.get('interfaces') or []),
            ),
            tls=TLSConfig(
                server_cert=str(tls.get('server_cert') or ''),
                server_key=str(tls.get('server_key') or ''),
                user_ca_pubkey=str(tls.get('user_ca_pubkey') or ''),
            ),
            ca=CAConfig(
                endpoints=list(ca.get('endpoints') or []),
                client_cert=str(ca.get('client_cert') or ''),
                client_key=str(ca.get('client_key') or ''),
                ca_pubkey=str(ca.get('ca_pubkey') or ''),
                timeout_seconds=float(ca.get('timeout_seconds') or 5.0),
                emergency_cert=str(ca.get('emergency_cert') or ''),
            ),
            inner=InnerConfig(
                sshd_binary=str(inner.get('sshd_binary') or '/usr/sbin/sshd'),
                port_range=(int(port_range[0]), int(port_range[1])),
            ),
            users=UsersConfig(
                allowed=list(users.get('allowed') or []),
            ),
            logging_=LoggingConfig(
                level=str(log_.get('level') or 'info'),
                destination=str(log_.get('destination') or 'stderr'),
                audit_destination=str(
                    log_.get('audit_destination')
                    or 'file:/var/log/ssh-rt-auth/wrapper-audit.jsonl'),
            ),
            performance=PerformanceConfig(
                inner_cipher_none=bool(perf.get('inner_cipher_none')),
                max_concurrent_sessions=int(
                    perf.get('max_concurrent_sessions') or 200),
            ),
        )

    def validate(self) -> None:
        """Cross-field validation. Raises ValueError on any problem."""
        if self.mode not in VALID_MODES:
            raise ValueError(
                f'mode must be one of {VALID_MODES}, got {self.mode!r}')

        if not (1 <= self.listen.external_port <= 65535):
            raise ValueError(
                f'listen.external_port out of range: '
                f'{self.listen.external_port}')

        if self.mode == MODE_FALLBACK:
            if not (1 <= self.fallback.port <= 65535):
                raise ValueError(
                    f'fallback.port out of range: {self.fallback.port}')
            # In fallback mode we don't strictly need TLS / CA / inner
            # config — they're all unused. So no further checks.
            return

        # Enforce-mode validation
        for field_name in ('server_cert', 'server_key', 'user_ca_pubkey'):
            v = getattr(self.tls, field_name)
            if not v:
                raise ValueError(f'tls.{field_name} required in enforce mode')
            if not Path(v).exists():
                raise ValueError(
                    f'tls.{field_name}={v} does not exist')

        if not self.ca.endpoints:
            raise ValueError(
                'ca.endpoints requires at least one URL in enforce mode')
        for field_name in ('client_cert', 'client_key', 'ca_pubkey'):
            v = getattr(self.ca, field_name)
            if not v:
                raise ValueError(f'ca.{field_name} required in enforce mode')
            if not Path(v).exists():
                raise ValueError(f'ca.{field_name}={v} does not exist')

        lo, hi = self.inner.port_range
        if not (1024 <= lo < hi <= 65535):
            raise ValueError(
                f'inner.port_range out of range: ({lo}, {hi})')

        if not self.users.allowed:
            raise ValueError(
                "users.allowed is empty in enforce mode — set ['*'] "
                'to allow any user, or list specific usernames')

    def check_permissions(self) -> None:
        """Check on-disk permissions of cert/key files. Raises ValueError
        if a private key file is group- or world-readable."""
        if self.mode != MODE_ENFORCE:
            return
        for path_ in (self.tls.server_key, self.ca.client_key):
            if not path_:
                continue
            try:
                mode = os.stat(path_).st_mode
            except OSError:
                continue
            if mode & 0o077:
                raise ValueError(
                    f'private key {path_} has insecure permissions '
                    f'(mode={mode & 0o777:o}). Run: chmod 0600 {path_}')
