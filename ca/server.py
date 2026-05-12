"""Flask app + mTLS listener.

For PoC: a single Flask app, mTLS enforced via Werkzeug's ``ssl_context``.
Client cert is extracted from the request environ (``SSL_CLIENT_CERT`` in PEM
or the raw cert from the WSGI handler) — we use the underlying ``ssl`` socket.
"""
from __future__ import annotations

import argparse
import base64
import logging
import ssl
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import oid
from flask import Flask, g, jsonify, request

from . import admin as admin_handlers
from . import authorize
from . import cert_minter
from .audit import AuditLog
from .config import CAConfig
from .enrollment import Enrollment
from .identity_parser import sha256_fingerprint


log = logging.getLogger('ssh-rt-auth-ca')


def _load_identity_trust_root_fingerprints(paths: list[str]) -> set[str]:
    """Load OpenSSH user CA pubkey files and return their SHA256 fingerprints."""
    out: set[str] = set()
    for path in paths:
        p = Path(path)
        if not p.exists():
            log.warning('identity trust root %s does not exist; skipping', path)
            continue
        text = p.read_text().strip()
        # OpenSSH "ssh-ed25519 AAAA... comment" — the middle field is the blob.
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                blob = base64.b64decode(parts[1])
            except Exception:
                continue
            out.add(sha256_fingerprint(blob))
    return out


def _extract_client_cert_subject(req) -> str | None:
    """Pull CN from the client cert presented in this request.

    Werkzeug's dev server forwards the cert via the ``ssl_socket`` on the
    request. We translate that into a CN string ("CN=...") matching the format
    used in the enrollment store. Returns ``None`` if no cert.
    """
    # The peer cert PEM is exposed via environ['werkzeug.peer_cert_chain'] in
    # some setups; the most reliable path on stdlib's wsgiref is the raw socket.
    env = req.environ
    # Try direct WSGI env first (used by tests that inject a cert).
    pem = env.get('SSL_CLIENT_CERT') or env.get('werkzeug.peer_cert_pem')
    if pem:
        try:
            cert = x509.load_pem_x509_certificate(pem.encode('ascii'))
            return _cn_from_cert(cert)
        except Exception:
            return None
    # Fall back to the live socket if available.
    sock = env.get('werkzeug.socket') or env.get('wsgi.input')
    # Newer werkzeug exposes peer cert binary on the connection — but the
    # cleanest cross-version path is to read from the request.environ key set
    # by our custom WSGI wrapper below.
    peer_cert = env.get('peercert_der')
    if peer_cert:
        try:
            cert = x509.load_der_x509_certificate(peer_cert)
            return _cn_from_cert(cert)
        except Exception:
            return None
    return None


def _cn_from_cert(cert: x509.Certificate) -> str | None:
    try:
        cn = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)
        if cn:
            return f'CN={cn[0].value}'
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(config: CAConfig) -> Flask:
    app = Flask(__name__)
    app.config['CA_CONFIG'] = config

    enrollment = Enrollment(config.enrollment_path)
    audit = AuditLog(config.audit_path or '/tmp/ssh-rt-auth-audit.jsonl')

    signing_key = cert_minter.load_private_key(config.signing_key)
    signing_cert = cert_minter.load_certificate(config.signing_cert)
    tls_ca_cert = cert_minter.load_certificate(
        Path(config.signing_cert).parent / 'tls-ca-cert.pem')
    tls_ca_key = cert_minter.load_private_key(
        Path(config.signing_cert).parent / 'tls-ca-key.pem')

    identity_fps = _load_identity_trust_root_fingerprints(config.identity_trust_roots)

    auth_ctx = authorize.AuthorizeContext(
        enrollment=enrollment, audit=audit,
        signing_key=signing_key, signing_cert=signing_cert,
        identity_trust_root_fingerprints=identity_fps,
        default_max_cert_validity_seconds=config.default_max_cert_validity_seconds,
        timestamp_drift_seconds=config.timestamp_drift_seconds,
    )
    admin_ctx = admin_handlers.AdminContext(
        enrollment=enrollment, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=config.server_cert_validity_days,
        admin_cert_validity_days=config.admin_cert_validity_days,
        mtls_key_type=config.mtls_key_type,
    )

    app.config['AUTH_CTX'] = auth_ctx
    app.config['ADMIN_CTX'] = admin_ctx
    app.config['ENROLLMENT'] = enrollment
    app.config['AUDIT'] = audit

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    @app.before_request
    def _attach_caller():
        g.client_subject = _extract_client_cert_subject(request)

    @app.errorhandler(Exception)
    def _on_error(e: Exception):
        log.exception('unhandled error')
        return jsonify(status='error', reason='internal', detail=str(e)), 500

    # ---- Authorization ----
    @app.post('/v1/authorize')
    def _authorize():
        subj = g.client_subject
        if not subj:
            return jsonify(status='error', reason='unauthorized',
                           detail='no mTLS client cert'), 401
        body = request.get_json(silent=True) or {}
        status, payload = authorize.handle_authorize(
            app.config['AUTH_CTX'], subj, body)
        return jsonify(payload), status

    # ---- Admin: helpers ----
    def _admin_or_401():
        subj = g.client_subject
        if not subj:
            return None, (jsonify(status='error', reason='unauthorized',
                                  detail='no mTLS client cert'), 401)
        enrollment: Enrollment = app.config['ENROLLMENT']
        adm = enrollment.find_admin_by_mtls_subject(subj)
        if adm is None:
            return None, (jsonify(status='error', reason='unauthorized',
                                  detail=f'admin cert {subj!r} not enrolled'),
                          401)
        return adm, None

    # ---- Servers ----
    @app.post('/v1/admin/server/add')
    def _server_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/server/<name>')
    def _server_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.put('/v1/admin/server/<name>/groups')
    def _server_groups(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_set_groups(
            app.config['ADMIN_CTX'], adm, name,
            request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.get('/v1/admin/server/list')
    def _server_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.server_list(
            app.config['ADMIN_CTX'], adm,
            group=request.args.get('group'),
            name_prefix=request.args.get('name'))
        return jsonify(payload), status

    # ---- Users ----
    @app.post('/v1/admin/user/add')
    def _user_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/user/<username>')
    def _user_remove(username):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_remove(
            app.config['ADMIN_CTX'], adm, username)
        return jsonify(payload), status

    @app.post('/v1/admin/user/<username>/key')
    def _user_key_add(username):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_key_add(
            app.config['ADMIN_CTX'], adm, username,
            request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/user/<username>/key/<path:fingerprint>')
    def _user_key_remove(username, fingerprint):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_key_remove(
            app.config['ADMIN_CTX'], adm, username, fingerprint)
        return jsonify(payload), status

    @app.get('/v1/admin/user/list')
    def _user_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.user_list(
            app.config['ADMIN_CTX'], adm,
            username=request.args.get('username'),
            fingerprint=request.args.get('fingerprint'))
        return jsonify(payload), status

    # ---- Policy ----
    @app.post('/v1/admin/policy/add')
    def _policy_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.policy_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/policy/<policy_id>')
    def _policy_remove(policy_id):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.policy_remove(
            app.config['ADMIN_CTX'], adm, policy_id)
        return jsonify(payload), status

    # ---- Admins ----
    @app.post('/v1/admin/admin/add')
    def _admin_add():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_add(
            app.config['ADMIN_CTX'], adm, request.get_json(silent=True) or {})
        return jsonify(payload), status

    @app.delete('/v1/admin/admin/<name>')
    def _admin_remove(name):
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_remove(
            app.config['ADMIN_CTX'], adm, name)
        return jsonify(payload), status

    @app.get('/v1/admin/admin/list')
    def _admin_list():
        adm, err = _admin_or_401()
        if err:
            return err
        status, payload = admin_handlers.admin_list(
            app.config['ADMIN_CTX'], adm)
        return jsonify(payload), status

    # ---- Audit ----
    @app.get('/v1/admin/audit')
    def _audit():
        adm, err = _admin_or_401()
        if err:
            return err
        filters = {
            'type': request.args.get('type') or 'all',
            'since': request.args.get('since'),
            'until': request.args.get('until'),
            'username': request.args.get('username'),
            'server': request.args.get('server'),
            'decision': request.args.get('decision'),
            'admin': request.args.get('admin'),
            'limit': request.args.get('limit'),
            'offset': request.args.get('offset'),
        }
        status, payload = admin_handlers.audit_read(
            app.config['ADMIN_CTX'], adm, filters)
        return jsonify(payload), status


# ---------------------------------------------------------------------------
# Werkzeug request handler that surfaces the mTLS peer cert via environ.
# ---------------------------------------------------------------------------

def _make_request_handler():
    """Return a WSGIRequestHandler subclass that exposes the peer cert.

    Werkzeug's default handler hides the SSL peer cert. We override
    ``make_environ`` to add ``peercert_der`` when present.
    """
    from werkzeug.serving import WSGIRequestHandler

    class _SSLRequestHandler(WSGIRequestHandler):
        def make_environ(self):
            env = super().make_environ()
            try:
                der = self.connection.getpeercert(binary_form=True)
                if der:
                    env['peercert_der'] = der
            except Exception:
                pass
            return env

    return _SSLRequestHandler


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='ssh-rt-auth-ca')
    p.add_argument('--config', required=True, help='Path to CA config file')
    p.add_argument('--debug', action='store_true')
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    cfg = CAConfig.load(args.config)
    app = create_app(cfg)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cfg.tls_cert, keyfile=cfg.tls_key)
    ctx.load_verify_locations(cafile=cfg.client_ca_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED

    log.info('CA listening on https://%s:%d', cfg.listen_host, cfg.listen_port)

    # Use Werkzeug's run_simple with our custom request handler so the peer
    # cert reaches the WSGI environ.
    from werkzeug.serving import run_simple
    run_simple(
        hostname=cfg.listen_host, port=cfg.listen_port, application=app,
        ssl_context=ctx, threaded=True, use_reloader=False,
        request_handler=_make_request_handler(),
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
