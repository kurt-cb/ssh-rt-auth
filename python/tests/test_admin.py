"""Unit tests for the admin handlers (RBAC, server/user/policy CRUD)."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


def _b64(b): return base64.b64encode(b).decode('ascii')


@pytest.fixture
def adminctx(ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )
    return ctx


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def auditor():
    return Admin(name='audit-alice', role='auditor',
                 mtls_subject='CN=audit-alice')


def test_server_add_returns_credentials(adminctx, superuser):
    status, body = admin_handlers.server_add(
        adminctx, superuser, {'name': 'srv1', 'groups': ['prod']})
    assert status == 201
    assert body['server']['name'] == 'srv1'
    assert '-----BEGIN' in body['credentials']['cert_pem']


def test_server_add_forbidden_for_auditor(adminctx, auditor):
    status, body = admin_handlers.server_add(
        adminctx, auditor, {'name': 'srv1', 'groups': []})
    assert status == 403
    assert body['reason'] == 'forbidden'


def test_user_add_then_key(adminctx, superuser, test_key):
    admin_handlers.user_add(adminctx, superuser, {'username': 'alice'})
    status, body = admin_handlers.user_key_add(
        adminctx, superuser, 'alice',
        {'type': 'pubkey', 'data': _b64(test_key.public_blob)})
    assert status == 201
    assert body['key']['fingerprint'] == test_key.fingerprint


def test_user_key_bad_base64(adminctx, superuser):
    admin_handlers.user_add(adminctx, superuser, {'username': 'alice'})
    status, body = admin_handlers.user_key_add(
        adminctx, superuser, 'alice',
        {'type': 'pubkey', 'data': 'not%base64'})
    assert status == 400


def test_policy_add_forbidden_for_server_admin(adminctx):
    srvadmin = Admin(name='ops', role='server-admin', mtls_subject='CN=ops')
    admin_handlers.user_add(adminctx, _superuser(), {'username': 'alice'})
    admin_handlers.server_add(adminctx, _superuser(), {'name': 'srv1', 'groups': []})
    status, body = admin_handlers.policy_add(adminctx, srvadmin, {
        'username': 'alice', 'policy': {
            'servers': ['srv1'], 'channels': ['session']}})
    assert status == 403


def test_admin_add_only_superuser(adminctx):
    user_admin = Admin(name='ua', role='user-admin', mtls_subject='CN=ua')
    status, _ = admin_handlers.admin_add(
        adminctx, user_admin, {'name': 'x', 'role': 'auditor'})
    assert status == 403
    status, body = admin_handlers.admin_add(
        adminctx, _superuser(), {'name': 'newadm', 'role': 'auditor'})
    assert status == 201
    assert body['admin']['role'] == 'auditor'


def test_cannot_remove_last_superuser(adminctx):
    # The ca_dir fixture seeded one superuser; the admin can be retrieved by name.
    adminctx.enrollment.add_admin('extra', 'auditor', 'CN=extra')
    superusers = [a for a in adminctx.enrollment.all_admins() if a.role == 'superuser']
    assert len(superusers) == 1
    status, _ = admin_handlers.admin_remove(
        adminctx, _superuser(), superusers[0].name)
    assert status == 409


def _superuser() -> Admin:
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')
