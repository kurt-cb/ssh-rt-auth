"""YAML-backed enrollment database.

Schema follows ssh-rt-auth-detailed-ca-admin.md. Atomic writes (write-temp +
rename) so concurrent reads never see a partial file.
"""
from __future__ import annotations

import datetime as _dt
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Dataclasses (in-memory shape; YAML mirrors this directly)
# ---------------------------------------------------------------------------

@dataclass
class Server:
    name: str
    mtls_subject: str
    groups: list[str] = field(default_factory=list)
    enrolled_at: str = ''
    enrolled_by: str = ''


@dataclass
class KeyBinding:
    fingerprint: str
    type: str               # "pubkey" | "openssh-cert"
    key_type: str           # "ssh-ed25519" etc.
    key_id: str = ''        # cert only
    principals: list[str] = field(default_factory=list)
    added_at: str = ''
    added_by: str = ''


@dataclass
class Policy:
    id: str
    servers: list[str] = field(default_factory=list)
    server_groups: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    source_cidrs: list[str] = field(default_factory=list)
    time_window: dict[str, Any] | None = None
    max_cert_validity_seconds: int = 3600
    environment: dict[str, str] = field(default_factory=dict)
    force_command: str | None = None
    created_at: str = ''
    created_by: str = ''


@dataclass
class User:
    username: str
    keys: list[KeyBinding] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    enrolled_at: str = ''
    enrolled_by: str = ''


@dataclass
class Admin:
    name: str
    role: str               # "superuser" | "server-admin" | "user-admin" | "auditor"
    mtls_subject: str
    enrolled_at: str = ''
    enrolled_by: str = ''


VALID_ROLES = {'superuser', 'server-admin', 'user-admin', 'auditor'}


# ---------------------------------------------------------------------------
# Enrollment store
# ---------------------------------------------------------------------------

class EnrollmentError(Exception):
    """Domain error in the enrollment store (duplicate name, unknown ref, etc.)."""


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class Enrollment:
    """YAML-file enrollment store with in-process locking.

    Not safe for multi-process writers; the PoC is single-process.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.servers: dict[str, Server] = {}
        self.users: dict[str, User] = {}
        self.admins: dict[str, Admin] = {}
        self._policy_seq = 0
        if self.path.exists():
            self.load()
        else:
            # Ensure parent exists for later saves.
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---- persistence ----

    def load(self) -> None:
        with self._lock:
            with self.path.open() as f:
                data = yaml.safe_load(f) or {}
            self.servers = {
                name: Server(name=name, **fields)
                for name, fields in (data.get('servers') or {}).items()
            }
            self.admins = {
                name: Admin(name=name, **fields)
                for name, fields in (data.get('admins') or {}).items()
            }
            self.users = {}
            max_pol = 0
            for uname, ufields in (data.get('users') or {}).items():
                keys = [KeyBinding(**k) for k in (ufields.get('keys') or [])]
                policies = [Policy(**p) for p in (ufields.get('policies') or [])]
                for p in policies:
                    n = _policy_num(p.id)
                    if n > max_pol:
                        max_pol = n
                self.users[uname] = User(
                    username=uname,
                    keys=keys,
                    policies=policies,
                    enrolled_at=ufields.get('enrolled_at', ''),
                    enrolled_by=ufields.get('enrolled_by', ''),
                )
            self._policy_seq = max_pol

    def save(self) -> None:
        with self._lock:
            out: dict[str, Any] = {}
            if self.servers:
                out['servers'] = {
                    s.name: {
                        'mtls_subject': s.mtls_subject,
                        'groups': list(s.groups),
                        'enrolled_at': s.enrolled_at,
                        'enrolled_by': s.enrolled_by,
                    }
                    for s in self.servers.values()
                }
            if self.admins:
                out['admins'] = {
                    a.name: {
                        'role': a.role,
                        'mtls_subject': a.mtls_subject,
                        'enrolled_at': a.enrolled_at,
                        'enrolled_by': a.enrolled_by,
                    }
                    for a in self.admins.values()
                }
            if self.users:
                out['users'] = {
                    u.username: {
                        'keys': [asdict(k) for k in u.keys],
                        'policies': [asdict(p) for p in u.policies],
                        'enrolled_at': u.enrolled_at,
                        'enrolled_by': u.enrolled_by,
                    }
                    for u in self.users.values()
                }
            tmp = self.path.with_suffix(self.path.suffix + '.tmp')
            with tmp.open('w') as f:
                yaml.safe_dump(out, f, sort_keys=True)
            os.replace(tmp, self.path)

    # ---- server ops ----

    def add_server(self, name: str, mtls_subject: str,
                   groups: list[str] | None = None,
                   enrolled_by: str = '') -> Server:
        with self._lock:
            if name in self.servers:
                raise EnrollmentError(f'server already exists: {name}')
            if any(s.mtls_subject == mtls_subject for s in self.servers.values()):
                raise EnrollmentError(f'mtls_subject already in use: {mtls_subject}')
            srv = Server(name=name, mtls_subject=mtls_subject,
                         groups=list(groups or []),
                         enrolled_at=_now_iso(), enrolled_by=enrolled_by)
            self.servers[name] = srv
            self.save()
            return srv

    def remove_server(self, name: str) -> None:
        with self._lock:
            if name not in self.servers:
                raise EnrollmentError(f'server not found: {name}')
            del self.servers[name]
            self.save()

    def find_server_by_mtls_subject(self, subject: str) -> Server | None:
        with self._lock:
            for s in self.servers.values():
                if s.mtls_subject == subject:
                    return s
            return None

    def set_server_groups(self, name: str, groups: list[str]) -> Server:
        with self._lock:
            if name not in self.servers:
                raise EnrollmentError(f'server not found: {name}')
            self.servers[name].groups = list(groups)
            self.save()
            return self.servers[name]

    # ---- admin ops ----

    def add_admin(self, name: str, role: str, mtls_subject: str,
                  enrolled_by: str = '') -> Admin:
        with self._lock:
            if role not in VALID_ROLES:
                raise EnrollmentError(f'invalid role: {role}')
            if name in self.admins:
                raise EnrollmentError(f'admin already exists: {name}')
            if any(a.mtls_subject == mtls_subject for a in self.admins.values()):
                raise EnrollmentError(f'mtls_subject already in use: {mtls_subject}')
            adm = Admin(name=name, role=role, mtls_subject=mtls_subject,
                        enrolled_at=_now_iso(), enrolled_by=enrolled_by)
            self.admins[name] = adm
            self.save()
            return adm

    def remove_admin(self, name: str) -> None:
        with self._lock:
            if name not in self.admins:
                raise EnrollmentError(f'admin not found: {name}')
            if self.admins[name].role == 'superuser':
                remaining = [a for a in self.admins.values()
                             if a.role == 'superuser' and a.name != name]
                if not remaining:
                    raise EnrollmentError('cannot remove the last superuser')
            del self.admins[name]
            self.save()

    def find_admin_by_mtls_subject(self, subject: str) -> Admin | None:
        with self._lock:
            for a in self.admins.values():
                if a.mtls_subject == subject:
                    return a
            return None

    # ---- user ops ----

    def add_user(self, username: str, enrolled_by: str = '') -> User:
        with self._lock:
            if username in self.users:
                raise EnrollmentError(f'user already exists: {username}')
            u = User(username=username,
                     enrolled_at=_now_iso(), enrolled_by=enrolled_by)
            self.users[username] = u
            self.save()
            return u

    def remove_user(self, username: str) -> None:
        with self._lock:
            if username not in self.users:
                raise EnrollmentError(f'user not found: {username}')
            del self.users[username]
            self.save()

    def add_user_key(self, username: str, key: KeyBinding,
                     added_by: str = '') -> KeyBinding:
        with self._lock:
            if username not in self.users:
                raise EnrollmentError(f'user not found: {username}')
            for k in self.users[username].keys:
                if k.fingerprint == key.fingerprint:
                    raise EnrollmentError(
                        f'fingerprint already bound to {username}: {key.fingerprint}')
            if not key.added_at:
                key.added_at = _now_iso()
            if not key.added_by:
                key.added_by = added_by
            self.users[username].keys.append(key)
            self.save()
            return key

    def remove_user_key(self, username: str, fingerprint: str) -> None:
        with self._lock:
            if username not in self.users:
                raise EnrollmentError(f'user not found: {username}')
            before = len(self.users[username].keys)
            self.users[username].keys = [
                k for k in self.users[username].keys if k.fingerprint != fingerprint
            ]
            if len(self.users[username].keys) == before:
                raise EnrollmentError(f'key not found: {fingerprint}')
            self.save()

    def find_user_by_fingerprint(self, fingerprint: str) -> User | None:
        with self._lock:
            for u in self.users.values():
                if any(k.fingerprint == fingerprint for k in u.keys):
                    return u
            return None

    def find_user_by_key_id(self, key_id: str) -> User | None:
        with self._lock:
            for u in self.users.values():
                if any(k.key_id and k.key_id == key_id for k in u.keys):
                    return u
            return None

    # ---- policy ops ----

    def add_policy(self, username: str, policy_fields: dict[str, Any],
                   created_by: str = '') -> Policy:
        with self._lock:
            if username not in self.users:
                raise EnrollmentError(f'user not found: {username}')
            servers = policy_fields.get('servers') or []
            server_groups = policy_fields.get('server_groups') or []
            # Wildcard entries (containing *, ?, [) are not validated — we
            # don't know yet which enrolled names they'll match at authz time.
            # Plain names must already exist in the servers table.
            for s in servers:
                if any(ch in s for ch in '*?['):
                    continue
                if s not in self.servers:
                    raise EnrollmentError(f'unknown server in policy: {s}')
            if not servers and not server_groups:
                raise EnrollmentError(
                    'policy must reference at least one server or server_group')
            self._policy_seq += 1
            pid = f'pol-{self._policy_seq:03d}'
            policy = Policy(
                id=pid,
                servers=list(servers),
                server_groups=list(server_groups),
                channels=list(policy_fields.get('channels') or []),
                source_cidrs=list(policy_fields.get('source_cidrs') or []),
                time_window=policy_fields.get('time_window'),
                max_cert_validity_seconds=int(
                    policy_fields.get('max_cert_validity_seconds') or 3600),
                environment=dict(policy_fields.get('environment') or {}),
                force_command=policy_fields.get('force_command'),
                created_at=_now_iso(),
                created_by=created_by,
            )
            self.users[username].policies.append(policy)
            self.save()
            return policy

    def remove_policy(self, policy_id: str) -> None:
        with self._lock:
            for u in self.users.values():
                before = len(u.policies)
                u.policies = [p for p in u.policies if p.id != policy_id]
                if len(u.policies) != before:
                    self.save()
                    return
            raise EnrollmentError(f'policy not found: {policy_id}')

    # ---- queries (read-only snapshots) ----

    def all_servers(self) -> list[Server]:
        with self._lock:
            return list(self.servers.values())

    def all_users(self) -> list[User]:
        with self._lock:
            return list(self.users.values())

    def all_admins(self) -> list[Admin]:
        with self._lock:
            return list(self.admins.values())


def _policy_num(pid: str) -> int:
    if pid.startswith('pol-'):
        try:
            return int(pid[4:])
        except ValueError:
            return 0
    return 0
