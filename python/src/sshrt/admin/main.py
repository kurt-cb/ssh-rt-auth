"""ssh-rt-admin CLI entry point (click-based)."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from sshrt.ca.cert_minter import bootstrap_ca

from . import formatters
from .client import CAClient, CAClientError
from .key_parser import b64_blob, parse_key_file


CONFIG_PATH_DEFAULT = Path.home() / '.ssh-rt-admin' / 'config'


def _load_cli_config(path: str | Path | None) -> dict[str, Any]:
    p = Path(path) if path else CONFIG_PATH_DEFAULT
    if not p.exists():
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def _make_client(ctx: click.Context) -> CAClient:
    conf = ctx.obj.get('_config', {})
    ca_url = ctx.obj.get('ca_url') or conf.get('ca_url')
    cert = ctx.obj.get('admin_cert') or conf.get('admin_cert')
    key = ctx.obj.get('admin_key') or conf.get('admin_key')
    ca_cert = ctx.obj.get('ca_cert') or conf.get('ca_cert')
    if not all([ca_url, cert, key, ca_cert]):
        raise click.UsageError(
            'must provide --ca-url, --admin-cert, --admin-key, --ca-cert '
            '(or set them in ~/.ssh-rt-admin/config)')
    return CAClient(base_url=ca_url, admin_cert=cert, admin_key=key,
                    ca_cert=ca_cert)


def _output(ctx: click.Context, data: Any) -> None:
    click.echo(formatters.render(data, fmt=ctx.obj.get('format', 'table')))


def _handle_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except CAClientError as e:
        click.echo(f'error: HTTP {e.status}: {e.body}', err=True)
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Group + global options
# ---------------------------------------------------------------------------

@click.group()
@click.option('--config', 'config_path', type=click.Path(),
              help='Path to ssh-rt-admin config (default: ~/.ssh-rt-admin/config).')
@click.option('--ca-url')
@click.option('--admin-cert', type=click.Path())
@click.option('--admin-key', type=click.Path())
@click.option('--ca-cert', type=click.Path())
@click.option('--format', 'output_format',
              type=click.Choice(['table', 'json', 'yaml']), default='table')
@click.pass_context
def cli(ctx, config_path, ca_url, admin_cert, admin_key, ca_cert, output_format):
    """ssh-rt-admin — management CLI for ssh-rt-auth."""
    ctx.ensure_object(dict)
    ctx.obj['_config'] = _load_cli_config(config_path)
    ctx.obj['ca_url'] = ca_url
    ctx.obj['admin_cert'] = admin_cert
    ctx.obj['admin_key'] = admin_key
    ctx.obj['ca_cert'] = ca_cert
    ctx.obj['format'] = output_format


# ---------------------------------------------------------------------------
# init (no CA call — writes config + bootstrap admin cert)
# ---------------------------------------------------------------------------

@cli.command()
@click.option('--ca-dir', required=True, type=click.Path(),
              help='Directory to write CA keys and certs into.')
@click.option('--bootstrap-admin', default='bootstrap-admin',
              help='CN for the initial superuser admin cert.')
@click.option('--tls-server-cn', default='ssh-rt-auth-ca',
              help='CN for the CA\'s TLS server cert.')
@click.option('--tls-server-san', multiple=True,
              help='SubjectAltName for the CA\'s TLS server cert (repeatable). '
                   'Default: DNS:localhost, IP:127.0.0.1.')
def init(ca_dir, bootstrap_admin, tls_server_cn, tls_server_san):
    """Initialize a fresh CA: signing key + bootstrap admin cert."""
    ca_dir = Path(ca_dir)
    if any(ca_dir.glob('*.pem')) and ca_dir.exists():
        raise click.UsageError(f'{ca_dir} already contains certs; refusing to overwrite')
    sans = list(tls_server_san) or ['DNS:localhost', 'IP:127.0.0.1']
    artifacts = bootstrap_ca(
        ca_dir, bootstrap_admin_cn=bootstrap_admin,
        tls_server_cn=tls_server_cn, tls_server_sans=sans,
    )

    # Drop a default ca-config.yaml so the user can run the server immediately.
    ca_config = {
        'listen': '127.0.0.1:8443',
        'signing_key': str(ca_dir / 'signing-key.pem'),
        'signing_cert': str(ca_dir / 'signing-cert.pem'),
        'tls_cert': str(ca_dir / 'tls-server-cert.pem'),
        'tls_key': str(ca_dir / 'tls-server-key.pem'),
        'client_ca_cert': str(ca_dir / 'tls-ca-cert.pem'),
        'identity_trust_roots': [],
        'enrollment': {'type': 'file', 'path': str(ca_dir / 'enrollment.yaml')},
        'audit': {'type': 'file', 'path': str(ca_dir / 'audit.jsonl')},
        'defaults': {'max_cert_validity_seconds': 3600,
                     'timestamp_drift_seconds': 60},
        'cert_generation': {'key_type': 'ec',
                            'server_cert_validity_days': 365,
                            'admin_cert_validity_days': 365},
    }
    (ca_dir / 'ca-config.yaml').write_text(yaml.safe_dump(ca_config, sort_keys=True))

    # Empty enrollment file so the CA can boot. Seed it with the bootstrap admin.
    enroll = {
        'admins': {
            bootstrap_admin: {
                'role': 'superuser',
                'mtls_subject': f'CN={bootstrap_admin}',
                'enrolled_at': '', 'enrolled_by': 'init',
            }
        }
    }
    (ca_dir / 'enrollment.yaml').write_text(yaml.safe_dump(enroll, sort_keys=True))

    click.echo(f'CA initialized in {ca_dir}')
    click.echo(f'Bootstrap admin cert: {ca_dir}/bootstrap-admin-cert.pem')
    click.echo(f'Bootstrap admin key:  {ca_dir}/bootstrap-admin-key.pem')
    click.echo(f'CA config:            {ca_dir}/ca-config.yaml')


# ---------------------------------------------------------------------------
# server commands
# ---------------------------------------------------------------------------

@cli.group()
def server():
    """Server enrollment commands."""


@server.command('add')
@click.option('--name', required=True)
@click.option('--groups', default='', help='Comma-separated group list.')
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def server_add(ctx, name, groups, out_dir):
    groups_list = [g.strip() for g in groups.split(',') if g.strip()]
    c = _make_client(ctx)
    resp = _handle_call(c.server_add, name, groups_list)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        (od / 'ca-cert.pem').write_text(resp['credentials']['ca_cert_pem'])
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['server'])


@server.command('remove')
@click.option('--name', required=True)
@click.pass_context
def server_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_remove, name))


@server.command('list')
@click.option('--group')
@click.pass_context
def server_list(ctx, group):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_list, group=group))


# ---------------------------------------------------------------------------
# user commands
# ---------------------------------------------------------------------------

@cli.group()
def user():
    """User enrollment commands."""


@user.command('add')
@click.option('--user', 'username', required=True)
@click.option('--key', 'key_path', type=click.Path(exists=True),
              help='SSH pubkey or OpenSSH cert file. Creates user if missing.')
@click.option('--cert', 'cert_path', type=click.Path(exists=True),
              help='OpenSSH cert file (alias of --key for clarity).')
@click.pass_context
def user_add(ctx, username, key_path, cert_path):
    c = _make_client(ctx)
    try:
        _handle_call(c.user_add, username)
    except SystemExit:
        # user may already exist — continue and let the key add report
        pass
    path = key_path or cert_path
    if path:
        parsed = parse_key_file(path)
        resp = _handle_call(c.user_key_add, username, parsed.type, b64_blob(parsed))
        _output(ctx, resp['key'])
    else:
        _output(ctx, {'user_added': username})


@user.command('remove')
@click.option('--user', 'username', required=True)
@click.pass_context
def user_remove(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_remove, username))


@user.command('remove-key')
@click.option('--user', 'username', required=True)
@click.option('--fingerprint', required=True)
@click.pass_context
def user_remove_key(ctx, username, fingerprint):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_key_remove, username, fingerprint))


@user.command('list')
@click.option('--user', 'username')
@click.pass_context
def user_list(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_list, username=username))


# ---------------------------------------------------------------------------
# policy commands
# ---------------------------------------------------------------------------

@cli.group()
def policy():
    """Policy commands."""


@policy.command('add')
@click.option('--user', 'username', required=True)
@click.option('--servers', default='', help='Comma-separated server canonical names.')
@click.option('--server-groups', default='', help='Comma-separated group names.')
@click.option('--channels', required=True,
              help='Comma-separated channel types (e.g. session,direct-tcpip).')
@click.option('--source-cidrs', default='')
@click.option('--max-validity', 'max_validity', default=3600, type=int)
@click.option('--force-command', default=None)
@click.pass_context
def policy_add(ctx, username, servers, server_groups, channels, source_cidrs,
               max_validity, force_command):
    def _split(s): return [x.strip() for x in s.split(',') if x.strip()]
    policy = {
        'servers': _split(servers),
        'server_groups': _split(server_groups),
        'channels': _split(channels),
        'source_cidrs': _split(source_cidrs),
        'max_cert_validity_seconds': max_validity,
        'force_command': force_command,
    }
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_add, username, policy))


@policy.command('remove')
@click.option('--id', 'policy_id', required=True)
@click.pass_context
def policy_remove(ctx, policy_id):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_remove, policy_id))


# ---------------------------------------------------------------------------
# admin commands
# ---------------------------------------------------------------------------

@cli.group()
def admin():
    """Admin user commands (superuser-only operations)."""


@admin.command('add')
@click.option('--name', required=True)
@click.option('--role', required=True,
              type=click.Choice(['superuser', 'server-admin', 'user-admin', 'auditor']))
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def admin_add(ctx, name, role, out_dir):
    c = _make_client(ctx)
    resp = _handle_call(c.admin_add, name, role)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['admin'])


@admin.command('remove')
@click.option('--name', required=True)
@click.pass_context
def admin_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.admin_remove, name))


@admin.command('list')
@click.pass_context
def admin_list(ctx):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.admin_list))


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command('audit')
@click.option('--type', 'type_', default='all')
@click.option('--decision')
@click.option('--user', 'username')
@click.option('--server', 'srv')
@click.option('--limit', default=100, type=int)
@click.pass_context
def audit(ctx, type_, decision, username, srv, limit):
    c = _make_client(ctx)
    out = _handle_call(c.audit, type=type_, decision=decision,
                       username=username, server=srv, limit=limit)
    _output(ctx, out.get('entries', []))


if __name__ == '__main__':
    sys.exit(cli())  # pragma: no cover
