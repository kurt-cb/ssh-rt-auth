"""Tests for mssh.msshd.config."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from mssh.msshd.config import (MODE_ENFORCE, MODE_FALLBACK, WrapperConfig)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def test_load_defaults_fallback(tmp_path):
    cfg_path = _write(tmp_path, 'w.yaml', 'mode: fallback\n')
    cfg = WrapperConfig.load(cfg_path)
    cfg.validate()
    assert cfg.mode == MODE_FALLBACK
    assert cfg.listen.external_port == 2200
    assert cfg.fallback.host == '127.0.0.1'
    assert cfg.fallback.port == 22


def test_load_full_fallback(tmp_path):
    cfg_path = _write(tmp_path, 'w.yaml',
        'mode: fallback\n'
        'fallback: {host: 10.0.0.1, port: 2022}\n'
        'listen: {external_address: 0.0.0.0, external_port: 2200}\n')
    cfg = WrapperConfig.load(cfg_path)
    cfg.validate()
    assert cfg.fallback.host == '10.0.0.1'
    assert cfg.fallback.port == 2022


def test_invalid_mode(tmp_path):
    cfg_path = _write(tmp_path, 'w.yaml', 'mode: bogus\n')
    cfg = WrapperConfig.load(cfg_path)
    with pytest.raises(ValueError, match='mode must be'):
        cfg.validate()


def test_listen_port_out_of_range(tmp_path):
    cfg_path = _write(tmp_path, 'w.yaml',
        'mode: fallback\n'
        'listen: {external_port: 99999}\n')
    cfg = WrapperConfig.load(cfg_path)
    with pytest.raises(ValueError, match='external_port'):
        cfg.validate()


def test_enforce_missing_tls(tmp_path):
    cfg_path = _write(tmp_path, 'w.yaml',
        'mode: enforce\n'
        'users: {allowed: [alice]}\n')
    cfg = WrapperConfig.load(cfg_path)
    with pytest.raises(ValueError, match='tls.server_cert'):
        cfg.validate()


def test_enforce_full_valid(tmp_path):
    # Create dummy cert files so the existence check passes.
    for f in ('server.crt', 'server.key', 'user-ca.pub',
              'mtls.crt', 'mtls.key', 'mtls-ca.pub'):
        (tmp_path / f).write_text('dummy')
    cfg_path = _write(tmp_path, 'w.yaml',
        f'mode: enforce\n'
        f'tls:\n'
        f'  server_cert: {tmp_path}/server.crt\n'
        f'  server_key:  {tmp_path}/server.key\n'
        f'  user_ca_pubkey: {tmp_path}/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://ca.test:8443]\n'
        f'  client_cert: {tmp_path}/mtls.crt\n'
        f'  client_key:  {tmp_path}/mtls.key\n'
        f'  ca_pubkey:   {tmp_path}/mtls-ca.pub\n'
        f'users: {{allowed: [alice]}}\n')
    cfg = WrapperConfig.load(cfg_path)
    cfg.validate()
    assert cfg.mode == MODE_ENFORCE


def test_enforce_empty_users(tmp_path):
    for f in ('server.crt', 'server.key', 'user-ca.pub',
              'mtls.crt', 'mtls.key', 'mtls-ca.pub'):
        (tmp_path / f).write_text('dummy')
    cfg_path = _write(tmp_path, 'w.yaml',
        f'mode: enforce\n'
        f'tls:\n'
        f'  server_cert: {tmp_path}/server.crt\n'
        f'  server_key:  {tmp_path}/server.key\n'
        f'  user_ca_pubkey: {tmp_path}/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://ca.test:8443]\n'
        f'  client_cert: {tmp_path}/mtls.crt\n'
        f'  client_key:  {tmp_path}/mtls.key\n'
        f'  ca_pubkey:   {tmp_path}/mtls-ca.pub\n')
    cfg = WrapperConfig.load(cfg_path)
    with pytest.raises(ValueError, match='users.allowed is empty'):
        cfg.validate()


def test_check_permissions_world_readable_key(tmp_path):
    for f in ('server.crt', 'server.key', 'user-ca.pub',
              'mtls.crt', 'mtls.key', 'mtls-ca.pub'):
        (tmp_path / f).write_text('dummy')
    # Make the server.key world-readable.
    os.chmod(tmp_path / 'server.key', 0o644)
    cfg_path = _write(tmp_path, 'w.yaml',
        f'mode: enforce\n'
        f'tls:\n'
        f'  server_cert: {tmp_path}/server.crt\n'
        f'  server_key:  {tmp_path}/server.key\n'
        f'  user_ca_pubkey: {tmp_path}/user-ca.pub\n'
        f'ca:\n'
        f'  endpoints: [https://ca.test:8443]\n'
        f'  client_cert: {tmp_path}/mtls.crt\n'
        f'  client_key:  {tmp_path}/mtls.key\n'
        f'  ca_pubkey:   {tmp_path}/mtls-ca.pub\n'
        f'users: {{allowed: [alice]}}\n')
    cfg = WrapperConfig.load(cfg_path)
    cfg.validate()
    with pytest.raises(ValueError, match='insecure permissions'):
        cfg.check_permissions()


def test_example_yaml_loads(tmp_path):
    """The shipped config/wrapper.yaml.example must load cleanly.
    Catches drift between the example and the schema."""
    # Example is at the repo root, two parents up from python/tests/.
    example = (Path(__file__).resolve().parent.parent.parent
               / 'config' / 'wrapper.yaml.example')
    assert example.exists(), f'missing example at {example}'
    cfg = WrapperConfig.load(example)
    # Example is in fallback mode by design; validate without
    # check_permissions (the example's paths are placeholders).
    cfg.validate()
