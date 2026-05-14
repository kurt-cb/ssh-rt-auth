"""Tests for wrapper.python.userca."""
from __future__ import annotations

import datetime as _dt
import os
import stat
import tempfile

import asyncssh
import pytest

from wrapper.python.userca import (DEFAULT_USER_CERT_TTL_SECONDS, UserCA)


def test_generate_returns_usable_ca():
    ca = UserCA.generate()
    assert ca.fingerprint.startswith('SHA256:')
    assert b'ssh-ed25519' in ca.public_key_openssh


def test_load_round_trip(tmp_path):
    ca = UserCA.generate()
    priv = tmp_path / 'user-ca'
    pub = tmp_path / 'user-ca.pub'
    ca.write_private_to(priv)
    ca.write_public_to(pub)

    # Permissions check.
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert stat.S_IMODE(pub.stat().st_mode) == 0o644

    loaded = UserCA.load(priv)
    assert loaded.fingerprint == ca.fingerprint


def test_load_rejects_insecure_perms(tmp_path):
    ca = UserCA.generate()
    priv = tmp_path / 'user-ca'
    ca.write_private_to(priv)
    os.chmod(priv, 0o644)
    with pytest.raises(ValueError, match='insecure permissions'):
        UserCA.load(priv)


def test_mint_basic():
    ca = UserCA.generate()
    minted = ca.mint_user_cert('alice')
    assert isinstance(minted.user_private_key, asyncssh.SSHKey)
    assert isinstance(minted.cert, asyncssh.SSHCertificate)
    # Principal honored — exposed by asyncssh as a list of strings.
    assert 'alice' in minted.cert.principals
    # Default TTL respected (within ~6s of now+default).
    now = _dt.datetime.now(_dt.timezone.utc)
    delta = (minted.valid_before - now).total_seconds()
    assert 0 < delta <= DEFAULT_USER_CERT_TTL_SECONDS + 1


def test_mint_with_force_command():
    ca = UserCA.generate()
    minted = ca.mint_user_cert('alice', force_command='/usr/bin/backup')
    # asyncssh stores critical options under .options as bytes-keyed
    # dict.
    opts = minted.cert.options
    fc = opts.get('force-command') or opts.get(b'force-command')
    if isinstance(fc, bytes):
        fc = fc.decode()
    assert fc == '/usr/bin/backup'


def test_mint_caps_at_default_ttl_when_valid_before_too_far():
    ca = UserCA.generate()
    far_future = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)
    minted = ca.mint_user_cert('alice', valid_before=far_future)
    # Should be capped to ~DEFAULT_USER_CERT_TTL_SECONDS.
    now = _dt.datetime.now(_dt.timezone.utc)
    delta = (minted.valid_before - now).total_seconds()
    assert delta <= DEFAULT_USER_CERT_TTL_SECONDS + 1


def test_mint_respects_short_valid_before():
    ca = UserCA.generate()
    soon = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=10)
    minted = ca.mint_user_cert('alice', valid_before=soon)
    # Honored (less than the cap).
    assert minted.valid_before == soon
