"""Tests for wrapper.python.mssh — pure-data helpers + outer-protocol-v1
header / ack encoding."""
from __future__ import annotations

import json
import os

import pytest

from wrapper.python.mssh import (DEFAULT_WRAPPER_PORT, Identity,
                                  PROTOCOL_VERSION, Target,
                                  build_header, load_config, parse_ack,
                                  parse_target, resolve_identity,
                                  validate_identity)


# ---- parse_target ----------------------------------------------------------

def test_parse_target_basic():
    t = parse_target('alice@host-01', default_port=2200)
    assert t == Target('alice', 'host-01', 2200)


def test_parse_target_with_port():
    t = parse_target('alice@host-01:2222', default_port=2200)
    assert t == Target('alice', 'host-01', 2222)


def test_parse_target_default_user():
    t = parse_target('host-01', default_port=2200, default_user='bob')
    assert t == Target('bob', 'host-01', 2200)


def test_parse_target_invalid_port():
    with pytest.raises(ValueError, match='invalid port'):
        parse_target('alice@host:abc', default_port=2200)


def test_parse_target_empty_host():
    with pytest.raises(ValueError, match='host required'):
        parse_target('alice@', default_port=2200)


def test_parse_target_ipv6_brackets_unsupported():
    with pytest.raises(ValueError, match='IPv6 bracket'):
        parse_target('alice@[::1]:2200', default_port=2200)


# ---- config loader ---------------------------------------------------------

def test_load_config_missing_returns_empty(tmp_path):
    assert load_config(tmp_path / 'nope') == {}


def test_load_config_parses_key_value(tmp_path):
    p = tmp_path / 'mssh.conf'
    p.write_text(
        '# this is a comment\n'
        '\n'
        'default_port = 2222\n'
        'cert= /etc/mssh/cert.pem  # inline comment\n'
        'key =/etc/mssh/key.pem\n'
    )
    cfg = load_config(p)
    assert cfg == {
        'default_port': '2222',
        'cert': '/etc/mssh/cert.pem',
        'key': '/etc/mssh/key.pem',
    }


def test_load_config_rejects_malformed(tmp_path):
    p = tmp_path / 'mssh.conf'
    p.write_text('this line has no equals\n')
    with pytest.raises(ValueError, match='expected key=value'):
        load_config(p)


# ---- identity resolution ---------------------------------------------------

def test_resolve_identity_priority_cli_beats_env_beats_config(
        tmp_path, monkeypatch):
    monkeypatch.setenv('MSSH_CERT', '/env/cert')
    cfg = {'cert': '/cfg/cert', 'key': '/cfg/key', 'ca': '/cfg/ca'}
    ident = resolve_identity(cfg, cert_override='/cli/cert')
    assert str(ident.cert) == '/cli/cert'
    assert str(ident.key) == '/cfg/key'
    assert str(ident.ca) == '/cfg/ca'


def test_resolve_identity_env_beats_config(monkeypatch):
    monkeypatch.setenv('MSSH_CA', '/env/ca')
    cfg = {'ca': '/cfg/ca'}
    ident = resolve_identity(cfg)
    assert str(ident.ca) == '/env/ca'


def test_validate_identity_missing_file(tmp_path):
    ident = Identity(cert=tmp_path / 'no-cert',
                     key=tmp_path / 'no-key',
                     ca=tmp_path / 'no-ca')
    with pytest.raises(ValueError, match='not found'):
        validate_identity(ident)


def test_validate_identity_insecure_key_perms(tmp_path):
    cert = tmp_path / 'c'; cert.write_text('x'); os.chmod(cert, 0o644)
    key  = tmp_path / 'k'; key.write_text('x'); os.chmod(key, 0o644)
    ca   = tmp_path / 'a'; ca.write_text('x'); os.chmod(ca, 0o644)
    ident = Identity(cert=cert, key=key, ca=ca)
    with pytest.raises(ValueError, match='insecure permissions'):
        validate_identity(ident)


def test_validate_identity_secure_perms_passes(tmp_path):
    cert = tmp_path / 'c'; cert.write_text('x')
    key  = tmp_path / 'k'; key.write_text('x'); os.chmod(key, 0o600)
    ca   = tmp_path / 'a'; ca.write_text('x')
    ident = Identity(cert=cert, key=key, ca=ca)
    validate_identity(ident)


# ---- outer protocol header / ack -------------------------------------------

def test_build_header_shape():
    line = build_header(Target('alice', 'host', 2200),
                        command='uname -a', interactive=False)
    assert line.endswith(b'\n')
    body = json.loads(line.rstrip(b'\n').decode())
    assert body == {
        'v': PROTOCOL_VERSION,
        'command': 'uname -a',
        'interactive': False,
        'term': None,
        'rows': None,
        'cols': None,
        'env': None,
        'principal_hint': 'alice',
    }


def test_build_header_interactive_with_pty():
    line = build_header(Target('alice', 'h', 2200),
                        command=None, interactive=True,
                        term='xterm-256color', rows=24, cols=80,
                        env={'EDITOR': 'vim'})
    body = json.loads(line)
    assert body['command'] is None
    assert body['interactive'] is True
    assert body['term'] == 'xterm-256color'
    assert body['rows'] == 24
    assert body['cols'] == 80
    assert body['env'] == {'EDITOR': 'vim'}


def test_build_header_compact_encoding():
    """No spaces in the JSON — keeps the header small and predictable."""
    line = build_header(Target('alice', 'h', 2200), command='ls')
    assert b': ' not in line
    assert b', ' not in line


def test_build_header_too_large():
    # Force the env field to exceed the limit.
    huge = {'A' * 10: 'B' * 5000}
    with pytest.raises(ValueError, match='header too large'):
        build_header(Target('alice', 'h', 2200),
                     command='ls', env=huge)


def test_parse_ack_ok():
    ok, reason = parse_ack(b'{"v":1,"ok":true}\n')
    assert ok is True
    assert reason == ''


def test_parse_ack_denied_with_reason():
    ok, reason = parse_ack(b'{"v":1,"ok":false,"reason":"unknown_identity"}\n')
    assert ok is False
    assert reason == 'unknown_identity'


def test_parse_ack_unsupported_version():
    with pytest.raises(ValueError, match='unsupported ack version'):
        parse_ack(b'{"v":42,"ok":true}\n')


def test_parse_ack_garbage():
    with pytest.raises(ValueError, match='malformed ack'):
        parse_ack(b'this is not json\n')


def test_parse_ack_non_object():
    with pytest.raises(ValueError, match='malformed ack'):
        parse_ack(b'[1,2,3]\n')
