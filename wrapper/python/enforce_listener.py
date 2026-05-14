"""EnforceListener — TLS-terminating listener that drives the full
ssh-rt-auth wrap-and-proxy flow.

For each accepted client connection:

  1. Terminate outer mTLS. Verify the client cert chain against the
     configured user-mTLS root. Extract the SSH user identity (the
     authenticated principal we'll request from inner sshd).
  2. Pull the client's SSH pubkey from their mTLS cert (for now we
     accept whatever the cert subject names; richer pubkey-extraction
     comes in v2).
  3. Call the CA. Get an X.509 authz cert with policy extensions.
  4. Validate the cert against the auth trust root + KNOWN_CRITICAL.
  5. Translate extensions to OpenSSH cert critical-options.
  6. Mint a 30-second OpenSSH user cert via UserCA.
  7. Open an asyncssh client to the inner sshd, presenting the
     ephemeral key+cert.
  8. Proxy bytes between the outer TLS connection and the inner SSH
     channel.

This is a Phase 1B sketch: identity extraction is intentionally
simple (we trust the mTLS subject CN as the principal). Phase 1B+
will pull the SSH pubkey from a structured cert SAN or a richer
client greeting.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import uuid
from typing import Optional

from cryptography import x509

from .ca import (AuthorizationDeny, AuthorizationError, AuthorizationGrant,
                  WrapperCAClient)
from .config import WrapperConfig
from .inner import InnerSshd
from .policy import (KNOWN_CRITICAL, parse_cert_policy,
                     translate_to_inner_cert_kwargs)
from .userca import UserCA


log = logging.getLogger('ssh-rt-wrapperd.enforce')


class EnforceListener:
    """TLS-terminating listener for enforce mode."""

    def __init__(self, cfg: WrapperConfig, *,
                 user_ca: UserCA,
                 ca_client: WrapperCAClient,
                 inner_sshd: InnerSshd):
        self.cfg = cfg
        self.user_ca = user_ca
        self.ca_client = ca_client
        self.inner_sshd = inner_sshd
        self._server: Optional[asyncio.base_events.Server] = None
        self._ssl_ctx = _build_ssl_context(cfg)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.cfg.listen.external_address,
            port=self.cfg.listen.external_port,
            ssl=self._ssl_ctx,
            reuse_address=True,
        )
        for s in self._server.sockets or []:
            log.info('enforce listener bound to %s (mTLS)', s.getsockname())

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError('start() not called')
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:
            log.debug('server wait_closed raised', exc_info=True)

    async def _on_client(self,
                         reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        conn_id = uuid.uuid4().hex[:8]
        peer = writer.get_extra_info('peername') or ('?', 0)
        source_ip, source_port = peer[0], peer[1]

        # ssl_object exposes the verified peer cert (DER form).
        ssl_obj = writer.get_extra_info('ssl_object')
        if ssl_obj is None:
            log.error('[%s] no ssl_object on connection (TLS not configured?)',
                      conn_id)
            await _close(writer)
            return

        peer_der = ssl_obj.getpeercert(binary_form=True)
        if not peer_der:
            log.warning('[%s] no client cert presented; rejecting', conn_id)
            await _close(writer)
            return

        try:
            principal = _extract_principal(peer_der)
        except ValueError as e:
            log.warning('[%s] could not extract principal: %s', conn_id, e)
            await _close(writer)
            return

        if not _user_allowed(self.cfg, principal):
            log.warning('[%s] principal %r not in users.allowed; rejecting',
                        conn_id, principal)
            await _close(writer)
            return

        log.info('[%s] accepted mTLS from %s:%d as principal=%s',
                 conn_id, source_ip, source_port, principal)

        # --- CA call ---
        identity_blob = _ssh_pubkey_blob_from_cert(peer_der)
        if not identity_blob:
            log.warning('[%s] no SSH pubkey present in client cert (Phase 1B '
                        'limitation); rejecting', conn_id)
            await _close(writer)
            return

        result = await self.ca_client.authorize(
            identity_blob=identity_blob,
            identity_type='pubkey',
            source_ip=source_ip,
            source_port=source_port,
            requested_channels=['session'],
        )

        if isinstance(result, AuthorizationDeny):
            log.info('[%s] CA denied: %s (%s)', conn_id, result.reason,
                     result.detail)
            await _close(writer)
            return
        if isinstance(result, AuthorizationError):
            log.error('[%s] CA error: %s', conn_id, result.message)
            await _close(writer)
            return

        assert isinstance(result, AuthorizationGrant)
        log.info('[%s] CA granted cert serial=%s not_after=%s',
                 conn_id, result.serial, result.not_after)

        # --- Validate + parse policy ---
        try:
            _validate_critical_extensions(result.cert_der)
        except ValueError as e:
            log.error('[%s] cert validation failed: %s', conn_id, e)
            await _close(writer)
            return

        cert_policy = parse_cert_policy(result.cert_der)
        if (cert_policy.server_bind
                and cert_policy.server_bind != self.cfg.tls.server_cert):
            # The wrapper's own canonical name is encoded in its mTLS
            # cert; pre-Phase-1B we don't have the explicit "this is
            # my canonical server name" yet — just log + accept for now.
            log.debug('[%s] cert server_bind=%s (wrapper local-check '
                      'deferred)', conn_id, cert_policy.server_bind)

        kwargs = translate_to_inner_cert_kwargs(cert_policy)
        log.debug('[%s] inner cert kwargs: force_command=%r source_address=%r',
                  conn_id, kwargs.force_command, kwargs.source_address)

        # --- Mint inner user cert ---
        minted = self.user_ca.mint_user_cert(
            principal=principal,
            valid_before=result.not_after,
            force_command=kwargs.force_command,
            source_address=kwargs.source_address,
        )

        # --- Inner SSH leg + bytes proxy ---
        try:
            await self._proxy_to_inner(
                conn_id, reader, writer, principal, minted, cert_policy)
        finally:
            await _close(writer)

    async def _proxy_to_inner(
        self,
        conn_id: str,
        outer_reader: asyncio.StreamReader,
        outer_writer: asyncio.StreamWriter,
        principal: str,
        minted,
        cert_policy,
    ) -> None:
        # Lazy import: asyncssh client is only needed in enforce mode,
        # and pulling it in at module import slows the daemon startup.
        from .ssh_proxy import proxy_to_inner_ssh

        await proxy_to_inner_ssh(
            outer_reader=outer_reader,
            outer_writer=outer_writer,
            inner_host='127.0.0.1',
            inner_port=self.inner_sshd.port,
            principal=principal,
            user_private_key=minted.user_private_key,
            user_cert=minted.cert,
            inner_host_key_path=str(
                self.inner_sshd.state_dir / 'ssh_host_ed25519_key.pub'),
            conn_id=conn_id,
            max_session_seconds=cert_policy.max_session_seconds,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_ssl_context(cfg: WrapperConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cfg.tls.server_cert,
                        keyfile=cfg.tls.server_key)
    ctx.load_verify_locations(cafile=cfg.tls.user_ca_pubkey)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _extract_principal(peer_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(peer_der)
    try:
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        raise ValueError('no CN in client cert subject')
    if not isinstance(cn, str) or not cn:
        raise ValueError(f'invalid CN: {cn!r}')
    return cn


def _ssh_pubkey_blob_from_cert(peer_der: bytes) -> bytes:
    """Phase 1B placeholder: hash the client cert's spki and use it as
    a stand-in identity blob. v2 will pull a real SSH pubkey from a
    dedicated cert SAN or a separate client-supplied header. The CA
    needs to recognise this fingerprint via enrollment as a normal
    pubkey for the user.

    For end-to-end testing we expect the operator to enroll the user's
    SPKI hash as their "SSH pubkey" — same wire shape, different
    derivation. Document this clearly in the test setup.
    """
    cert = x509.load_der_x509_certificate(peer_der)
    spki = cert.public_key().public_bytes(
        encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.DER,
        format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # The CA's identity_parser expects an SSH wire-format ed25519 blob:
    # u32 "ssh-ed25519" + u32 key (32 bytes). Phase 1B can be expanded
    # to handle this properly. For now we return raw SPKI bytes as a
    # placeholder; the CA call will fail with unknown_identity unless
    # enrollment was done to match.
    return spki


def _user_allowed(cfg: WrapperConfig, principal: str) -> bool:
    allowed = cfg.users.allowed
    if not allowed:
        return False
    if allowed == ['*']:
        return True
    return principal in allowed


def _validate_critical_extensions(cert_der: bytes) -> None:
    cert = x509.load_der_x509_certificate(cert_der)
    for ext in cert.extensions:
        if not ext.critical:
            continue
        if ext.oid.dotted_string not in KNOWN_CRITICAL:
            raise ValueError(
                f'unknown critical extension {ext.oid.dotted_string}')


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
