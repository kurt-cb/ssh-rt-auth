"""Unit tests for shim/config.py."""
from __future__ import annotations

import pytest
import yaml

from shim.config import ShimConfig


def test_load_minimal(tmp_path):
    p = tmp_path / 'cfg.yaml'
    p.write_text(yaml.safe_dump({
        'ca_endpoints': ['https://ca1:8443'],
        'mtls_cert': '/etc/cert.pem',
        'mtls_key': '/etc/key.pem',
        'ca_trust_root': '/etc/ca.pem',
        'auth_trust_root': '/etc/auth.pem',
    }))
    cfg = ShimConfig.load(p)
    assert cfg.ca_endpoints == ['https://ca1:8443']
    assert cfg.cache_max_entries == 1000
    assert cfg.connect_timeout == 5.0


def test_validate_requires_endpoints(tmp_path):
    cfg = ShimConfig()
    with pytest.raises(ValueError):
        cfg.validate()


def test_validate_checks_files_exist(tmp_path):
    cfg = ShimConfig(
        ca_endpoints=['https://x'],
        mtls_cert='/nonexistent',
        mtls_key='/nonexistent',
        ca_trust_root='/nonexistent',
        auth_trust_root='/nonexistent',
    )
    with pytest.raises(ValueError):
        cfg.validate()
