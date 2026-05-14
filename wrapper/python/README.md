# wrapper/python — PoC implementation of the Tier 1 wrapper

**Status:** Not yet implemented. Skeleton only.

The Python PoC implementation of the wrap-and-proxy Tier 1 endpoint.

## Design

Follow [../../design/ssh-rt-auth-detailed-wrapper.md](../../design/ssh-rt-auth-detailed-wrapper.md)
for the implementation blueprint. The Python variant maps onto that
doc as:

| Design doc § | Python module                           |
|--------------|-----------------------------------------|
| §3 outer mTLS listener           | `listener.py`             |
| §5 inner sshd lifecycle          | `inner.py`                |
| §6 local user-CA key custody     | `userca.py`               |
| §7 per-connection flow           | `wrapperd.py` (orchestrator) + `proxy.py` |
| §8 critical-option translation   | `policy.py`               |
| §9 channel-policy enforcement    | `proxy.py` (Variant A first; Variant B later) |
| §11 operator YAML                | `config.py`               |
| §12 systemd                      | `../systemd/`             |
| `ssh-rt-wrapper-admin` CLI       | `admin.py`                |

## Why Python first

- Reuses the PoC's existing `shim/` (mTLS to CA) and `ca/` (cert
  minting helpers) code directly — no porting cost.
- Easy to iterate against the existing LXC integration test suite.
- `asyncssh` provides a clean SSH client for the inner leg.
- `cryptography` provides everything needed to mint OpenSSH user certs.

## Performance caveat

Python isn't the right production target for a long-lived
session-handling daemon. After the Python PoC is functionally
vetted, the work ports to `wrapper/go/`.

## Dependencies (planned)

```
asyncssh>=2.14        # SSH client for the inner leg
cryptography>=41.0    # OpenSSH user cert minting + X.509 parsing
pyyaml>=6.0           # operator config
# (mTLS to CA reuses shim/ from the parent project)
```
