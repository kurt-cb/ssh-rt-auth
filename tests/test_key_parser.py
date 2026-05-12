"""Unit tests for cli/key_parser.py."""
from __future__ import annotations

import pytest

from cli.key_parser import parse_key_file, parse_key_text


def test_parse_pubkey_line(test_key):
    parsed = parse_key_text(test_key.openssh_line)
    assert parsed.type == 'pubkey'
    assert parsed.key_type == 'ssh-ed25519'
    assert parsed.fingerprint == test_key.fingerprint


def test_parse_pubkey_with_options(test_key):
    line = f'no-port-forwarding,no-agent-forwarding {test_key.openssh_line}'
    parsed = parse_key_text(line)
    assert parsed.type == 'pubkey'
    assert parsed.fingerprint == test_key.fingerprint


def test_parse_pubkey_file(tmp_path, test_key):
    p = tmp_path / 'k.pub'
    p.write_text(test_key.openssh_line + '\n')
    parsed = parse_key_file(p)
    assert parsed.fingerprint == test_key.fingerprint


def test_parse_empty_rejected():
    with pytest.raises(Exception):
        parse_key_text('')
