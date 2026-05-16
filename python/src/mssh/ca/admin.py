"""Admin API handlers.

Role-permission table mirrors ssh-rt-auth-detailed-rest-api.md. Each handler
takes a parsed request body, the admin's enrollment record, and the
``AdminContext``; returns ``(http_status, json_body)``.
"""
from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass
from typing import Any, Callable

from . import cert_minter
from .audit import AuditLog
from .enrollment import Admin, Enrollment, EnrollmentError, KeyBinding
from .identity_parser import (CertIdentity, IdentityParseError, PubkeyIdentity,
                              parse_identity)


# Role permissions: maps action key -> set of allowed roles.
_PERMISSIONS = {
    'server.add':       {'superuser', 'server-admin'},
    'server.remove':    {'superuser', 'server-admin'},
    'server.groups':    {'superuser', 'server-admin'},
    'server.list':      {'superuser', 'server-admin', 'user-admin', 'auditor'},
    'user.add':         {'superuser', 'user-admin'},
    'user.remove':      {'superuser', 'user-admin'},
    'user.key.add':     {'superuser', 'user-admin'},
    'user.key.remove':  {'superuser', 'user-admin'},
    'policy.add':       {'superuser', 'user-admin'},
    'policy.remove':    {'superuser', 'user-admin'},
    'user.list':        {'superuser', 'server-admin', 'user-admin', 'auditor'},
    'admin.add':        {'superuser'},
    'admin.remove':     {'superuser'},
    'admin.list':       {'superuser', 'auditor'},
    'audit.read':       {'superuser', 'server-admin', 'user-admin', 'auditor'},
}


def role_permits(role: str, action: str) -> bool:
    return role in _PERMISSIONS.get(action, set())


@dataclass
class AdminContext:
    enrollment: Enrollment
    audit: AuditLog
    tls_ca_key: Any
    tls_ca_cert: Any
    server_cert_validity_days: int
    admin_cert_validity_days: int
    mtls_key_type: str


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _audit_admin(ctx: AdminContext, admin: Admin, action: str,
                 target: dict, result: str) -> None:
    ctx.audit.write({
        'timestamp': _now_iso(),
        'type': 'admin',
        'action': action,
        'admin': {'name': admin.name, 'role': admin.role,
                  'mtls_subject': admin.mtls_subject},
        'target': target,
        'result': result,
    })


def _forbidden(action: str, admin: Admin) -> tuple[int, dict]:
    return 403, {
        'status': 'error', 'reason': 'forbidden',
        'detail': f"admin role {admin.role!r} cannot perform {action!r}",
    }


def _check(action: str, admin: Admin) -> tuple[int, dict] | None:
    if not role_permits(admin.role, action):
        return _forbidden(action, admin)
    return None


def _err(status: int, reason: str, detail: str) -> tuple[int, dict]:
    return status, {'status': 'error', 'reason': reason, 'detail': detail}


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

def server_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('server.add', admin)):
        return err
    name = body.get('name')
    if not isinstance(name, str) or not name:
        return _err(400, 'bad_request', 'missing/invalid name')
    groups = body.get('groups') or []
    mtls_subject = f'CN={name}'
    try:
        cert_bundle = cert_minter.issue_client_cert(
            common_name=name, tls_ca_key=ctx.tls_ca_key,
            tls_ca_cert=ctx.tls_ca_cert,
            validity_days=ctx.server_cert_validity_days,
            key_type=ctx.mtls_key_type,
        )
        srv = ctx.enrollment.add_server(name, mtls_subject, groups,
                                        enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'server.add',
                 {'server_name': srv.name, 'groups': list(srv.groups)}, 'ok')
    return 201, {
        'status': 'ok',
        'server': {
            'name': srv.name, 'groups': list(srv.groups),
            'mtls_subject': srv.mtls_subject,
        },
        'credentials': {
            'cert_pem': cert_bundle.cert_pem.decode('ascii'),
            'key_pem': cert_bundle.key_pem.decode('ascii'),
            'ca_cert_pem': cert_bundle.ca_cert_pem.decode('ascii'),
        },
    }


def server_remove(ctx: AdminContext, admin: Admin, name: str) -> tuple[int, dict]:
    if (err := _check('server.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_server(name)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'server.remove', {'server_name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def server_set_groups(ctx: AdminContext, admin: Admin, name: str,
                      body: dict) -> tuple[int, dict]:
    if (err := _check('server.groups', admin)):
        return err
    groups = body.get('groups')
    if not isinstance(groups, list):
        return _err(400, 'bad_request', 'groups must be a list')
    try:
        srv = ctx.enrollment.set_server_groups(name, groups)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'server.groups',
                 {'server_name': name, 'groups': list(srv.groups)}, 'ok')
    return 200, {
        'status': 'ok',
        'server': {'name': srv.name, 'groups': list(srv.groups)},
    }


def server_list(ctx: AdminContext, admin: Admin,
                group: str | None = None, name_prefix: str | None = None
                ) -> tuple[int, dict]:
    if (err := _check('server.list', admin)):
        return err
    items = []
    for s in ctx.enrollment.all_servers():
        if group and group not in s.groups:
            continue
        if name_prefix and not s.name.startswith(name_prefix):
            continue
        items.append({
            'name': s.name, 'groups': list(s.groups),
            'mtls_subject': s.mtls_subject, 'enrolled_at': s.enrolled_at,
        })
    return 200, {'status': 'ok', 'servers': items}


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def user_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('user.add', admin)):
        return err
    username = body.get('username')
    if not isinstance(username, str) or not username:
        return _err(400, 'bad_request', 'missing/invalid username')
    try:
        u = ctx.enrollment.add_user(username, enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'user.add', {'username': username}, 'ok')
    return 201, {
        'status': 'ok',
        'user': {'username': u.username, 'keys': [], 'policies': []},
    }


def user_remove(ctx: AdminContext, admin: Admin, username: str) -> tuple[int, dict]:
    if (err := _check('user.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_user(username)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.remove', {'username': username}, 'ok')
    return 200, {'status': 'ok', 'removed': username}


def user_key_add(ctx: AdminContext, admin: Admin, username: str,
                 body: dict) -> tuple[int, dict]:
    if (err := _check('user.key.add', admin)):
        return err
    type_ = body.get('type')
    data_b64 = body.get('data')
    if type_ not in ('pubkey', 'openssh-cert'):
        return _err(400, 'bad_request', 'type must be pubkey or openssh-cert')
    if not isinstance(data_b64, str):
        return _err(400, 'bad_request', 'data must be base64 string')
    try:
        blob = base64.b64decode(data_b64, validate=True)
    except Exception as e:
        return _err(400, 'bad_request', f'invalid base64: {e}')
    try:
        parsed = parse_identity(type_, blob)
    except IdentityParseError as e:
        return _err(400, 'bad_request', f'cannot parse key: {e}')

    if isinstance(parsed, CertIdentity):
        kb = KeyBinding(
            fingerprint=parsed.fingerprint, type='openssh-cert',
            key_type=parsed.key_type, key_id=parsed.key_id,
            principals=list(parsed.principals),
        )
        extra = {
            'key_id': parsed.key_id,
            'principals': list(parsed.principals),
            'signing_ca_fingerprint': parsed.signature_key_fingerprint,
        }
    elif isinstance(parsed, PubkeyIdentity):
        kb = KeyBinding(
            fingerprint=parsed.fingerprint, type='pubkey',
            key_type=parsed.key_type,
        )
        extra = {}
    else:
        return _err(500, 'internal', 'unexpected parsed type')

    try:
        ctx.enrollment.add_user_key(username, kb, added_by=admin.name)
    except EnrollmentError as e:
        if 'already bound' in str(e):
            return _err(409, 'conflict', str(e))
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.key.add',
                 {'username': username, 'fingerprint': kb.fingerprint}, 'ok')
    return 201, {
        'status': 'ok',
        'key': {
            'type': kb.type, 'fingerprint': kb.fingerprint,
            'key_type': kb.key_type, **extra,
        },
    }


def user_key_remove(ctx: AdminContext, admin: Admin, username: str,
                    fingerprint: str) -> tuple[int, dict]:
    if (err := _check('user.key.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_user_key(username, fingerprint)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'user.key.remove',
                 {'username': username, 'fingerprint': fingerprint}, 'ok')
    return 200, {'status': 'ok', 'removed_fingerprint': fingerprint}


def user_list(ctx: AdminContext, admin: Admin,
              username: str | None = None,
              fingerprint: str | None = None) -> tuple[int, dict]:
    if (err := _check('user.list', admin)):
        return err
    out = []
    for u in ctx.enrollment.all_users():
        if username and u.username != username:
            continue
        if fingerprint and not any(k.fingerprint == fingerprint for k in u.keys):
            continue
        out.append({
            'username': u.username,
            'keys': [
                {'type': k.type, 'fingerprint': k.fingerprint, 'key_type': k.key_type,
                 'key_id': k.key_id, 'principals': list(k.principals)}
                for k in u.keys
            ],
            'policies': [
                {
                    'id': p.id, 'servers': list(p.servers),
                    'server_groups': list(p.server_groups),
                    'channels': list(p.channels),
                    'source_cidrs': list(p.source_cidrs),
                    'time_window': p.time_window,
                    'max_cert_validity_seconds': p.max_cert_validity_seconds,
                    'environment': dict(p.environment),
                    'force_command': p.force_command,
                }
                for p in u.policies
            ],
            'enrolled_at': u.enrolled_at,
        })
    return 200, {'status': 'ok', 'users': out}


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def policy_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('policy.add', admin)):
        return err
    username = body.get('username')
    policy = body.get('policy')
    if not isinstance(username, str) or not isinstance(policy, dict):
        return _err(400, 'bad_request', 'username and policy required')
    if not policy.get('channels'):
        return _err(400, 'bad_request', 'policy.channels required')
    try:
        p = ctx.enrollment.add_policy(username, policy, created_by=admin.name)
    except EnrollmentError as e:
        if 'user not found' in str(e):
            return _err(404, 'not_found', str(e))
        return _err(400, 'bad_request', str(e))
    _audit_admin(ctx, admin, 'policy.add',
                 {'username': username, 'policy_id': p.id}, 'ok')
    return 201, {'status': 'ok', 'policy_id': p.id, 'username': username}


def policy_remove(ctx: AdminContext, admin: Admin, policy_id: str) -> tuple[int, dict]:
    if (err := _check('policy.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_policy(policy_id)
    except EnrollmentError as e:
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'policy.remove', {'policy_id': policy_id}, 'ok')
    return 200, {'status': 'ok', 'removed_policy': policy_id}


# ---------------------------------------------------------------------------
# Admins
# ---------------------------------------------------------------------------

def admin_add(ctx: AdminContext, admin: Admin, body: dict) -> tuple[int, dict]:
    if (err := _check('admin.add', admin)):
        return err
    name = body.get('name')
    role = body.get('role')
    if not isinstance(name, str) or not name:
        return _err(400, 'bad_request', 'missing/invalid name')
    if role not in {'superuser', 'server-admin', 'user-admin', 'auditor'}:
        return _err(400, 'bad_request', f'invalid role: {role!r}')
    mtls_subject = f'CN={name}'
    try:
        cert_bundle = cert_minter.issue_client_cert(
            common_name=name, tls_ca_key=ctx.tls_ca_key,
            tls_ca_cert=ctx.tls_ca_cert,
            validity_days=ctx.admin_cert_validity_days,
            key_type=ctx.mtls_key_type,
        )
        new_admin = ctx.enrollment.add_admin(
            name, role, mtls_subject, enrolled_by=admin.name)
    except EnrollmentError as e:
        return _err(409, 'conflict', str(e))
    _audit_admin(ctx, admin, 'admin.add', {'name': name, 'role': role}, 'ok')
    return 201, {
        'status': 'ok',
        'admin': {'name': new_admin.name, 'role': new_admin.role,
                  'mtls_subject': new_admin.mtls_subject},
        'credentials': {
            'cert_pem': cert_bundle.cert_pem.decode('ascii'),
            'key_pem': cert_bundle.key_pem.decode('ascii'),
            'ca_cert_pem': cert_bundle.ca_cert_pem.decode('ascii'),
        },
    }


def admin_remove(ctx: AdminContext, admin: Admin, name: str) -> tuple[int, dict]:
    if (err := _check('admin.remove', admin)):
        return err
    try:
        ctx.enrollment.remove_admin(name)
    except EnrollmentError as e:
        if 'last superuser' in str(e):
            return _err(409, 'conflict', str(e))
        return _err(404, 'not_found', str(e))
    _audit_admin(ctx, admin, 'admin.remove', {'name': name}, 'ok')
    return 200, {'status': 'ok', 'removed': name}


def admin_list(ctx: AdminContext, admin: Admin) -> tuple[int, dict]:
    if (err := _check('admin.list', admin)):
        return err
    out = [
        {'name': a.name, 'role': a.role, 'mtls_subject': a.mtls_subject,
         'enrolled_at': a.enrolled_at}
        for a in ctx.enrollment.all_admins()
    ]
    return 200, {'status': 'ok', 'admins': out}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit_read(ctx: AdminContext, admin: Admin,
               filters: dict) -> tuple[int, dict]:
    if (err := _check('audit.read', admin)):
        return err
    entries = ctx.audit.read_all()

    def keep(e: dict) -> bool:
        t = filters.get('type', 'all')
        if t != 'all' and e.get('type') != t:
            return False
        since = filters.get('since')
        until = filters.get('until')
        if since and e.get('timestamp', '') < since:
            return False
        if until and e.get('timestamp', '') > until:
            return False
        if filters.get('username'):
            ident = e.get('identity') or {}
            if ident.get('username') != filters['username']:
                return False
        if filters.get('server'):
            srv = e.get('server') or {}
            if srv.get('canonical_name') != filters['server']:
                return False
        if filters.get('decision'):
            if e.get('decision') != filters['decision']:
                return False
        if filters.get('admin'):
            a = e.get('admin') or {}
            if a.get('name') != filters['admin']:
                return False
        return True

    filtered = [e for e in entries if keep(e)]
    limit = int(filters.get('limit') or 100)
    offset = int(filters.get('offset') or 0)
    return 200, {
        'status': 'ok',
        'total': len(filtered),
        'entries': filtered[offset:offset + limit],
    }
