"""Randomized but seed-reproducible test scenario builder.

Given a seed, produces:
- A set of 8 regular users + 2 superuser admins
- For each user: which subset of the 4 SSH hosts they should be allowed to reach
- For each SSH host: which Unix users (subset of all 10) should exist locally

This gives a multi-dimensional matrix while keeping every run reproducible
when the same seed is replayed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


# A pool of names to draw from. The shuffler picks the first N each run, but
# the *order* depends on the seed → different names per run.
_NAME_POOL = [
    'alice', 'bob', 'carol', 'dave', 'eve', 'frank', 'grace', 'heidi',
    'ivan', 'judy', 'mallory', 'nina', 'oscar', 'peggy', 'quinn', 'ruth',
    'sybil', 'trent', 'ursula', 'victor', 'wendy', 'xander', 'yara', 'zoe',
]

# Optional groups a server might join.
_GROUP_POOL = ['production', 'staging', 'databases', 'web', 'infrastructure',
               'development', 'edge']


@dataclass
class UserSpec:
    username: str
    role: str            # 'superuser', 'auditor', or 'regular'
    allowed_hosts: list[str]  # canonical server names the user should reach


@dataclass
class HostSpec:
    canonical_name: str
    container_name: str
    groups: list[str]
    unix_accounts: list[str]   # which usernames have a Unix account here


@dataclass
class Scenario:
    seed: int
    users: list[UserSpec]
    hosts: list[HostSpec]
    superusers: list[str]      # subset of users[].username with role superuser


def build_scenario(seed: int, container_names: list[str]) -> Scenario:
    """Generate a reproducible test scenario for the given LXC containers.

    ``container_names`` is the list of SSH-host containers (4 names from
    lxc_helpers.ALL_SSH_HOSTS, in canonical order).
    """
    if len(container_names) != 4:
        raise ValueError('container_names must have exactly 4 entries')
    rng = random.Random(seed)
    names = list(_NAME_POOL)
    rng.shuffle(names)
    chosen = names[:10]
    superusers = chosen[:2]
    regulars = chosen[2:]

    # Assign canonical server names — shuffle the slot order too.
    canon_slots = ['srv-a', 'srv-b', 'srv-c', 'srv-d']
    rng.shuffle(canon_slots)
    hosts: list[HostSpec] = []
    for canon, container in zip(canon_slots, container_names):
        groups = rng.sample(_GROUP_POOL, k=rng.randint(1, 3))
        # Each host gets a random subset of users with Unix accounts. The user's
        # username is the Unix account name (so policies translate cleanly).
        # Superusers always exist on every host.
        regular_pool = rng.sample(regulars, k=rng.randint(3, len(regulars)))
        accounts = sorted(set(superusers) | set(regular_pool))
        hosts.append(HostSpec(canonical_name=canon, container_name=container,
                              groups=groups, unix_accounts=accounts))

    # For each user, decide which hosts they should be authorized for.
    user_specs: list[UserSpec] = []
    for name in superusers:
        user_specs.append(UserSpec(name, 'superuser',
                                   allowed_hosts=[h.canonical_name for h in hosts]))
    for name in regulars:
        # 1..len(hosts) random hosts.
        k = rng.randint(1, len(hosts))
        allowed = rng.sample([h.canonical_name for h in hosts], k=k)
        user_specs.append(UserSpec(name, 'regular',
                                   allowed_hosts=allowed))

    return Scenario(seed=seed, users=user_specs, hosts=hosts,
                    superusers=superusers)


def render_scenario(scenario: Scenario) -> str:
    """Human-readable rendering for test logs."""
    lines = [f'Scenario seed={scenario.seed}']
    lines.append('Hosts:')
    for h in scenario.hosts:
        lines.append(f'  {h.canonical_name:8s} container={h.container_name:25s} '
                     f'groups={h.groups} accounts={h.unix_accounts}')
    lines.append('Users:')
    for u in scenario.users:
        lines.append(f'  {u.username:10s} role={u.role:9s} '
                     f'allowed={u.allowed_hosts}')
    return '\n'.join(lines)
