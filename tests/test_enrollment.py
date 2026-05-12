"""Unit tests for the YAML-backed enrollment store."""
from __future__ import annotations

import pytest

from ca.enrollment import Enrollment, EnrollmentError, KeyBinding


@pytest.fixture
def enroll(tmp_path):
    return Enrollment(tmp_path / 'enrollment.yaml')


def test_add_server(enroll):
    s = enroll.add_server('srv1', 'CN=srv1', ['production'])
    assert s.name == 'srv1'
    assert 'production' in s.groups
    assert enroll.find_server_by_mtls_subject('CN=srv1').name == 'srv1'


def test_duplicate_server_rejected(enroll):
    enroll.add_server('srv1', 'CN=srv1', [])
    with pytest.raises(EnrollmentError):
        enroll.add_server('srv1', 'CN=srv1-other', [])
    with pytest.raises(EnrollmentError):
        enroll.add_server('srv2', 'CN=srv1', [])


def test_remove_server(enroll):
    enroll.add_server('srv1', 'CN=srv1', [])
    enroll.remove_server('srv1')
    with pytest.raises(EnrollmentError):
        enroll.remove_server('srv1')


def test_admin_roles(enroll):
    a = enroll.add_admin('boot', 'superuser', 'CN=boot')
    assert a.role == 'superuser'
    with pytest.raises(EnrollmentError):
        enroll.add_admin('bad', 'wizard', 'CN=bad')


def test_last_superuser_cannot_be_removed(enroll):
    enroll.add_admin('boot', 'superuser', 'CN=boot')
    enroll.add_admin('extra', 'auditor', 'CN=extra')
    with pytest.raises(EnrollmentError):
        enroll.remove_admin('boot')
    # If we add another superuser, the original can be removed.
    enroll.add_admin('boot2', 'superuser', 'CN=boot2')
    enroll.remove_admin('boot')


def test_user_key_lookup_by_fingerprint(enroll):
    enroll.add_user('alice')
    kb = KeyBinding(fingerprint='SHA256:AAA', type='pubkey', key_type='ssh-ed25519')
    enroll.add_user_key('alice', kb)
    u = enroll.find_user_by_fingerprint('SHA256:AAA')
    assert u and u.username == 'alice'
    assert enroll.find_user_by_fingerprint('SHA256:NOPE') is None


def test_duplicate_user_key_rejected(enroll):
    enroll.add_user('alice')
    enroll.add_user_key('alice',
                        KeyBinding('SHA256:K', 'pubkey', 'ssh-ed25519'))
    with pytest.raises(EnrollmentError):
        enroll.add_user_key('alice',
                            KeyBinding('SHA256:K', 'pubkey', 'ssh-ed25519'))


def test_remove_user_key(enroll):
    enroll.add_user('alice')
    enroll.add_user_key('alice',
                        KeyBinding('SHA256:K', 'pubkey', 'ssh-ed25519'))
    enroll.remove_user_key('alice', 'SHA256:K')
    assert enroll.find_user_by_fingerprint('SHA256:K') is None
    with pytest.raises(EnrollmentError):
        enroll.remove_user_key('alice', 'SHA256:NOPE')


def test_policy_requires_server_or_group(enroll):
    enroll.add_user('alice')
    with pytest.raises(EnrollmentError):
        enroll.add_policy('alice', {'channels': ['session']})


def test_policy_unknown_server_rejected(enroll):
    enroll.add_user('alice')
    with pytest.raises(EnrollmentError):
        enroll.add_policy('alice', {'servers': ['ghost'],
                                    'channels': ['session']})


def test_policy_wildcard_server_allowed(enroll):
    """Wildcard entries skip the exists-check (we don't know what names
    they'll match at authz time)."""
    enroll.add_user('alice')
    p = enroll.add_policy('alice', {'servers': ['srv-*', 'edge-?-prod'],
                                    'channels': ['session']})
    assert p.servers == ['srv-*', 'edge-?-prod']


def test_policy_id_sequencing(enroll):
    enroll.add_server('s1', 'CN=s1', [])
    enroll.add_user('alice')
    p1 = enroll.add_policy('alice', {'servers': ['s1'], 'channels': ['session']})
    p2 = enroll.add_policy('alice', {'servers': ['s1'], 'channels': ['session']})
    assert p1.id == 'pol-001'
    assert p2.id == 'pol-002'


def test_persistence_round_trip(tmp_path):
    e1 = Enrollment(tmp_path / 'enroll.yaml')
    e1.add_admin('boot', 'superuser', 'CN=boot')
    e1.add_server('s1', 'CN=s1', ['prod'])
    e1.add_user('alice')
    e1.add_user_key('alice',
                    KeyBinding('SHA256:K', 'pubkey', 'ssh-ed25519'))
    e1.add_policy('alice', {'servers': ['s1'], 'channels': ['session']})

    e2 = Enrollment(tmp_path / 'enroll.yaml')
    assert e2.find_admin_by_mtls_subject('CN=boot') is not None
    assert e2.find_server_by_mtls_subject('CN=s1').groups == ['prod']
    u = e2.find_user_by_fingerprint('SHA256:K')
    assert u is not None and u.username == 'alice'
    assert u.policies[0].id == 'pol-001'

    # Next policy continues sequence from 002, not 001.
    e2.add_policy('alice', {'servers': ['s1'], 'channels': ['session']})
    u = e2.find_user_by_fingerprint('SHA256:K')
    assert [p.id for p in u.policies] == ['pol-001', 'pol-002']
