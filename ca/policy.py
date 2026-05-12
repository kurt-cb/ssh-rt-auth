"""Policy evaluation: source CIDR, time window, server match, channel grant."""
from __future__ import annotations

import datetime as _dt
import fnmatch
import ipaddress
from dataclasses import dataclass

from .enrollment import Policy, Server, User


@dataclass
class EvaluationResult:
    ok: bool
    deny_reason: str = ''
    detail: str = ''
    matching_policies: list[Policy] = None    # type: ignore[assignment]
    merged_channels: list[str] = None         # type: ignore[assignment]
    merged_environment: dict[str, str] = None  # type: ignore[assignment]
    merged_force_command: str | None = None
    merged_max_validity: int = 3600


_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']


def _ip_in_any_cidr(ip: str, cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if addr in net:
            return True
    return False


def _time_in_window(now: _dt.datetime, window: dict) -> bool:
    """``window`` schema: ``{days: [...], hours: {start, end}, timezone}``."""
    tz_name = window.get('timezone') or 'UTC'
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tz_name)
    except Exception:
        tz = _dt.timezone.utc
    local = now.astimezone(tz)
    day_name = _DAYS[local.weekday()]
    days = [d.lower() for d in (window.get('days') or [])]
    if days and day_name not in days:
        return False
    hours = window.get('hours') or {}
    start = hours.get('start')
    end = hours.get('end')
    if start and end:
        sh, sm = (int(x) for x in start.split(':'))
        eh, em = (int(x) for x in end.split(':'))
        s_min = sh * 60 + sm
        e_min = eh * 60 + em
        cur = local.hour * 60 + local.minute
        if s_min <= e_min:
            if not (s_min <= cur <= e_min):
                return False
        else:
            # window wraps midnight (e.g., 22:00–06:00)
            if not (cur >= s_min or cur <= e_min):
                return False
    return True


def _server_matches(server: Server, policy: Policy) -> bool:
    # Direct or wildcard match against the policy's `servers` list. Wildcards
    # use shell-glob syntax (fnmatch) so `srv-*` matches `srv-acct`, `srv-sales`
    # etc., and `*-db-*` matches `prod-db-01`.
    for pattern in policy.servers:
        if pattern == server.name:
            return True
        if any(ch in pattern for ch in '*?[') and fnmatch.fnmatchcase(
                server.name, pattern):
            return True
    return any(g in server.groups for g in policy.server_groups)


def evaluate(
    user: User,
    server: Server,
    source_ip: str,
    timestamp: _dt.datetime,
    requested_channels: list[str] | None,
    default_max_validity_seconds: int,
) -> EvaluationResult:
    """Run the full evaluation pipeline. Returns a result with deny_reason set on failure."""
    matching: list[Policy] = []
    last_reason = 'no_matching_policy'
    last_detail = (
        f'user {user.username!r} has no policy granting access to server '
        f'{server.name!r}'
    )

    server_matched_any = False
    for policy in user.policies:
        if not _server_matches(server, policy):
            continue
        server_matched_any = True
        if policy.source_cidrs:
            try:
                if not _ip_in_any_cidr(source_ip, policy.source_cidrs):
                    last_reason = 'source_denied'
                    last_detail = (
                        f'source {source_ip} not in allowed CIDRs '
                        f'{policy.source_cidrs}'
                    )
                    continue
            except (ValueError, ipaddress.AddressValueError) as e:
                return EvaluationResult(
                    ok=False, deny_reason='source_denied',
                    detail=f'invalid source IP {source_ip}: {e}')
        if policy.time_window:
            if not _time_in_window(timestamp, policy.time_window):
                last_reason = 'time_denied'
                last_detail = f'outside time window {policy.time_window}'
                continue
        matching.append(policy)

    if not server_matched_any:
        return EvaluationResult(
            ok=False, deny_reason='no_matching_policy', detail=last_detail)
    if not matching:
        return EvaluationResult(
            ok=False, deny_reason=last_reason, detail=last_detail)

    # Merge.
    merged_channels: set[str] = set()
    merged_env: dict[str, str] = {}
    merged_force: str | None = None
    merged_validity = default_max_validity_seconds
    for p in matching:
        merged_channels.update(p.channels)
        merged_env.update(p.environment or {})
        if p.force_command:
            merged_force = p.force_command
        if p.max_cert_validity_seconds:
            merged_validity = min(merged_validity, p.max_cert_validity_seconds)

    # If the client requested channels, intersect with the merged set.
    granted = sorted(merged_channels)
    if requested_channels is not None:
        requested = set(requested_channels)
        intersection = requested & merged_channels
        if not intersection:
            return EvaluationResult(
                ok=False, deny_reason='channels_denied',
                detail=(f'requested {sorted(requested)} not in allowed '
                        f'{sorted(merged_channels)}'))
        granted = sorted(intersection)

    return EvaluationResult(
        ok=True,
        matching_policies=matching,
        merged_channels=granted,
        merged_environment=merged_env,
        merged_force_command=merged_force,
        merged_max_validity=merged_validity,
    )
