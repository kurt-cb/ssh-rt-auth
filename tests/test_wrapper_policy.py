"""Tests for wrapper.python.policy — parsing CA-minted X.509 authz certs
and translating extensions to OpenSSH critical-options.

The CA-minting machinery is in ca.cert_minter; we reuse it here so the
tests stay tied to whatever the CA actually emits (no hand-rolled
fixtures that can drift)."""
from __future__ import annotations

import datetime as _dt

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from ca.cert_minter import (generate_signing_key, _self_signed,
                             mint_authorization_cert)
from wrapper.python.policy import (parse_cert_policy,
                                    translate_to_inner_cert_kwargs)


def _mint(**overrides):
    """Mint a real authz cert via the CA code path and return its DER."""
    signing_key = generate_signing_key('ec')
    signing_cert = _self_signed('test-auth-root', signing_key)
    # User's "SSH pubkey" — bytes that match the wire-format ssh-ed25519
    # blob the CA expects.
    ed_key = ed25519.Ed25519PrivateKey.generate().public_key()
    raw = ed_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # SSH wire format: u32 "ssh-ed25519" + u32 raw key.
    import struct
    name = b'ssh-ed25519'
    blob = (struct.pack('>I', len(name)) + name
            + struct.pack('>I', len(raw)) + raw)

    defaults = dict(
        subject_username='alice',
        subject_pubkey_blob=blob,
        signing_key=signing_key,
        signing_cert=signing_cert,
        not_before=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=1),
        not_after=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1),
        source_bind='10.0.0.0/8',
        server_bind='web-prod-01',
        channels=['session', 'direct-tcpip'],
    )
    defaults.update(overrides)
    cert, _serial = mint_authorization_cert(**defaults)
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_minimum():
    der = _mint()
    p = parse_cert_policy(der)
    assert p.source_bind == '10.0.0.0/8'
    assert p.server_bind == 'web-prod-01'
    assert p.channels == ['direct-tcpip', 'session']  # CA sorts them
    assert p.force_command == ''
    assert p.environment == {}
    assert p.max_session_seconds is None


def test_parse_with_force_command_and_env():
    der = _mint(force_command='/usr/bin/backup',
                environment={'TMPDIR': '/var/tmp', 'TZ': 'UTC'},
                max_session_seconds=900)
    p = parse_cert_policy(der)
    assert p.force_command == '/usr/bin/backup'
    assert p.environment == {'TMPDIR': '/var/tmp', 'TZ': 'UTC'}
    assert p.max_session_seconds == 900


def test_translate_to_inner_cert_kwargs():
    der = _mint(source_bind='192.168.0.0/24',
                force_command='/bin/restricted')
    p = parse_cert_policy(der)
    kw = translate_to_inner_cert_kwargs(p)
    assert kw.force_command == '/bin/restricted'
    # source_bind is NOT propagated onto the inner cert — see the
    # comment in policy.translate_to_inner_cert_kwargs for why.
    assert kw.source_address is None


def test_translate_skips_unenforceable_fields():
    """server_bind, channels, environment, max_session, source_bind
    don't become OpenSSH critical-options at this layer — they're
    enforced elsewhere by the wrapper (or, for source-bind,
    already enforced by the CA at the outer-mTLS layer)."""
    der = _mint()
    p = parse_cert_policy(der)
    kw = translate_to_inner_cert_kwargs(p)
    assert kw.force_command is None
    assert kw.source_address is None
