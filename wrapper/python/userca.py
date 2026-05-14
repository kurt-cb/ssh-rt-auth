"""Local user-CA: key custody + per-connection OpenSSH cert minting.

The wrapper holds an Ed25519 user-CA private key in memory after
startup. The matching public key is installed at the inner sshd's
``TrustedUserCAKeys`` path so that any cert signed by this CA is
accepted by the inner sshd as proof of the user's identity.

Per-connection flow:
  1. CA returns an X.509 authorization cert with policy extensions.
  2. Wrapper generates an ephemeral Ed25519 user keypair.
  3. Wrapper calls ``mint_user_cert()`` to produce a short-lived
     OpenSSH user cert signed by the user-CA, carrying:
       - the validated unix principal
       - critical options translated from X.509 extensions (see
         policy.py)
       - validity = min(authz_cert.notAfter, now + DEFAULT_TTL)
  4. Wrapper hands ``(user_priv_key, cert_blob)`` to its asyncssh
     client and connects to the inner sshd. Inner sshd validates the
     cert against TrustedUserCAKeys, accepts, spawns the shell.

Design refs:
- [detailed-wrapper.md §6 + §7](../../design/ssh-rt-auth-detailed-wrapper.md)
- OpenSSH cert format: PROTOCOL.certkeys
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import asyncssh


log = logging.getLogger('ssh-rt-wrapperd.userca')


# Per-connection cert default TTL. The CA-issued authz cert's notAfter
# is the upper bound; the user cert lives no longer than that.
DEFAULT_USER_CERT_TTL_SECONDS = 30


@dataclass
class MintedUserCert:
    """Output of ``mint_user_cert``."""
    user_private_key: asyncssh.SSHKey
    """Ephemeral private key. Used by the wrapper's asyncssh client."""

    cert: asyncssh.SSHCertificate
    """The OpenSSH user cert signed by the user-CA."""

    valid_before: _dt.datetime
    """UTC timestamp at which the cert expires."""


class UserCA:
    """Manages the local user-CA private key.

    Phase 1B holds the key in memory only. Reading from disk happens
    at startup; SIGHUP triggers a re-read for rotation.
    """

    def __init__(self, ca_key: asyncssh.SSHKey):
        self._ca_key = ca_key
        self._fingerprint = ca_key.get_fingerprint()

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def public_key_openssh(self) -> bytes:
        """Wrapper-side accessor for the user-CA pubkey in OpenSSH
        authorized_keys format (one line, e.g.
        ``ssh-ed25519 AAAA... ssh-rt-auth-wrapper-user-ca``)."""
        return self._ca_key.export_public_key('openssh')

    @classmethod
    def generate(cls) -> 'UserCA':
        """Generate a fresh Ed25519 user-CA keypair. Used by
        ``ssh-rt-wrapper-admin init``."""
        ca_key = asyncssh.generate_private_key('ssh-ed25519',
                                                comment='ssh-rt-auth-wrapper-user-ca')
        return cls(ca_key)

    @classmethod
    def load(cls, priv_key_path: str | Path) -> 'UserCA':
        """Load the user-CA private key from disk. Verifies that the
        on-disk perms are restrictive (mode & 077 == 0)."""
        p = Path(priv_key_path)
        st = p.stat()
        if st.st_mode & 0o077:
            raise ValueError(
                f'user-CA private key {p} has insecure permissions '
                f'(mode={stat.S_IMODE(st.st_mode):o}). '
                f'Run: chmod 0600 {p}')
        data = p.read_bytes()
        ca_key = asyncssh.import_private_key(data)
        log.info('loaded user-CA key %s (fingerprint %s)',
                 p, ca_key.get_fingerprint())
        return cls(ca_key)

    def write_private_to(self, path: str | Path) -> None:
        """Atomically write the private key to ``path`` with mode 0600.
        Used by ``ssh-rt-wrapper-admin init``."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + '.tmp')
        tmp.write_bytes(self._ca_key.export_private_key('openssh'))
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
        log.info('wrote user-CA private key to %s (mode 0600)', p)

    def write_public_to(self, path: str | Path) -> None:
        """Write the public key in OpenSSH authorized_keys format to
        ``path`` (mode 0644). This is the file the inner sshd uses for
        ``TrustedUserCAKeys``."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + '.tmp')
        tmp.write_bytes(self.public_key_openssh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
        log.info('wrote user-CA public key to %s (mode 0644)', p)

    def mint_user_cert(
        self,
        principal: str,
        *,
        cert_serial: int = 0,
        key_id: str | None = None,
        valid_before: _dt.datetime | None = None,
        force_command: str | None = None,
        source_address: Sequence[str] | None = None,
        ttl_seconds: int = DEFAULT_USER_CERT_TTL_SECONDS,
    ) -> MintedUserCert:
        """Mint a short-lived OpenSSH user cert for ``principal``.

        Returns ``(user_private_key, cert)``. The cert is signed by
        the wrapper's user-CA key and is accepted by the inner sshd
        (which pins our user-CA pubkey via TrustedUserCAKeys).

        Caller normally derives ``valid_before`` from the CA-issued
        authz cert's notAfter; falls back to now+``ttl_seconds`` if
        unspecified.

        ``force_command`` and ``source_address`` come from the
        translation table in policy.py.
        """
        now = _dt.datetime.now(_dt.timezone.utc)
        if valid_before is None:
            valid_before = now + _dt.timedelta(seconds=ttl_seconds)
        else:
            # Don't issue a cert that outlives our default TTL even if
            # the authz cert is longer-lived. Belt-and-suspenders.
            cap = now + _dt.timedelta(seconds=ttl_seconds)
            if valid_before > cap:
                valid_before = cap

        # Fresh ephemeral user keypair per connection. Not retained.
        user_key = asyncssh.generate_private_key('ssh-ed25519')

        if key_id is None:
            key_id = f'ssh-rt-auth/{principal}/{cert_serial:x}'

        # Slight backdate on valid_after to defend against modest
        # clock drift between wrapper and inner sshd.
        valid_after = now - _dt.timedelta(seconds=5)

        cert = self._ca_key.generate_user_certificate(
            user_key,
            key_id=key_id,
            serial=cert_serial,
            principals=[principal],
            valid_after=valid_after,
            valid_before=valid_before,
            force_command=force_command,
            source_address=list(source_address) if source_address else None,
            # Disable all the OpenSSH "permit-*" extensions by default.
            # The hermetic inner sshd disables these globally anyway,
            # but minting them False keeps the cert itself minimal.
            permit_x11_forwarding=False,
            permit_agent_forwarding=False,
            permit_port_forwarding=False,
            permit_pty=True,                # interactive shell needs PTY
            permit_user_rc=False,
            touch_required=False,
        )

        return MintedUserCert(
            user_private_key=user_key,
            cert=cert,
            valid_before=valid_before,
        )
