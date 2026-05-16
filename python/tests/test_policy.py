"""Unit tests for the policy evaluator."""
from __future__ import annotations

import datetime as _dt

import pytest

from mssh.ca.enrollment import Policy, Server, User
from mssh.ca.policy import evaluate


def _now():
    return _dt.datetime(2026, 5, 11, 14, 23, 7, tzinfo=_dt.timezone.utc)


def _user(*policies: Policy) -> User:
    return User(username='alice', keys=[], policies=list(policies))


def _server(name='srv1', groups=None) -> Server:
    return Server(name=name, mtls_subject=f'CN={name}', groups=groups or [])


def test_no_policies_deny():
    r = evaluate(_user(), _server(), '10.0.0.1', _now(), None, 3600)
    assert not r.ok
    assert r.deny_reason == 'no_matching_policy'


def test_server_mismatch_deny():
    pol = Policy(id='p1', servers=['other'], channels=['session'])
    r = evaluate(_user(pol), _server('srv1'), '10.0.0.1', _now(), None, 3600)
    assert not r.ok
    assert r.deny_reason == 'no_matching_policy'


def test_server_match_by_name():
    pol = Policy(id='p1', servers=['srv1'], channels=['session'])
    r = evaluate(_user(pol), _server('srv1'), '10.0.0.1', _now(), None, 3600)
    assert r.ok
    assert r.merged_channels == ['session']


def test_server_match_by_group():
    pol = Policy(id='p1', server_groups=['production'], channels=['session'])
    r = evaluate(_user(pol), _server('srv1', ['production']),
                 '10.0.0.1', _now(), None, 3600)
    assert r.ok


def test_source_cidr_deny():
    pol = Policy(id='p1', servers=['srv1'],
                 channels=['session'], source_cidrs=['10.0.0.0/8'])
    r = evaluate(_user(pol), _server(), '192.168.1.1', _now(), None, 3600)
    assert not r.ok
    assert r.deny_reason == 'source_denied'


def test_source_cidr_allow():
    pol = Policy(id='p1', servers=['srv1'],
                 channels=['session'], source_cidrs=['10.0.0.0/8'])
    r = evaluate(_user(pol), _server(), '10.5.6.7', _now(), None, 3600)
    assert r.ok


def test_time_window_outside():
    # 14:23 UTC; window is 08:00-12:00 UTC
    pol = Policy(id='p1', servers=['srv1'], channels=['session'],
                 time_window={'days': ['mon'], 'hours': {'start': '08:00',
                                                          'end': '12:00'},
                              'timezone': 'UTC'})
    r = evaluate(_user(pol), _server(), '10.0.0.1', _now(), None, 3600)
    assert not r.ok
    assert r.deny_reason == 'time_denied'


def test_time_window_inside():
    pol = Policy(id='p1', servers=['srv1'], channels=['session'],
                 time_window={'days': ['mon'], 'hours': {'start': '08:00',
                                                          'end': '20:00'},
                              'timezone': 'UTC'})
    r = evaluate(_user(pol), _server(), '10.0.0.1', _now(), None, 3600)
    assert r.ok


def test_requested_channels_intersection():
    pol = Policy(id='p1', servers=['srv1'],
                 channels=['session', 'direct-tcpip'])
    r = evaluate(_user(pol), _server(), '10.0.0.1', _now(),
                 ['session'], 3600)
    assert r.ok
    assert r.merged_channels == ['session']


def test_requested_channels_denied():
    pol = Policy(id='p1', servers=['srv1'], channels=['session'])
    r = evaluate(_user(pol), _server(), '10.0.0.1', _now(),
                 ['x11'], 3600)
    assert not r.ok
    assert r.deny_reason == 'channels_denied'


def test_server_match_by_wildcard():
    pol = Policy(id='p1', servers=['srv-*'], channels=['session'])
    assert evaluate(_user(pol), _server('srv-acct'),
                    '10.0.0.1', _now(), None, 3600).ok
    assert evaluate(_user(pol), _server('srv-sales'),
                    '10.0.0.1', _now(), None, 3600).ok


def test_server_wildcard_does_not_match_outside_pattern():
    pol = Policy(id='p1', servers=['srv-acct-*'], channels=['session'])
    assert not evaluate(_user(pol), _server('srv-sales'),
                        '10.0.0.1', _now(), None, 3600).ok
    assert evaluate(_user(pol), _server('srv-acct-prod'),
                    '10.0.0.1', _now(), None, 3600).ok


def test_server_wildcard_question_mark():
    pol = Policy(id='p1', servers=['srv-?'], channels=['session'])
    assert evaluate(_user(pol), _server('srv-a'),
                    '10.0.0.1', _now(), None, 3600).ok
    assert not evaluate(_user(pol), _server('srv-acct'),
                        '10.0.0.1', _now(), None, 3600).ok


def test_policy_merging():
    p1 = Policy(id='p1', servers=['srv1'], channels=['session'],
                max_cert_validity_seconds=7200)
    p2 = Policy(id='p2', servers=['srv1'], channels=['direct-tcpip'],
                max_cert_validity_seconds=1800,
                force_command='/bin/echo')
    r = evaluate(_user(p1, p2), _server(), '10.0.0.1', _now(), None, 3600)
    assert r.ok
    assert set(r.merged_channels) == {'session', 'direct-tcpip'}
    assert r.merged_max_validity == 1800
    assert r.merged_force_command == '/bin/echo'
