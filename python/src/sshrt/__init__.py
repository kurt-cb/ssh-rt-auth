"""ssh-rt-auth — Python implementation.

Subpackages:
  ca/            CA server (Flask + mTLS).
  admin/         ssh-rt-admin CLI (operator-facing).
  shim/          AuthorizedKeysCommand-style authorization shim.
  debug_sshd/    Debug-only AsyncSSH server that calls the shim
                 (formerly Tier 2 reference; kept as a minimal CA-call
                 surface for debugging the CA / shim path in isolation).
  akc_shim/      Tier 3 entry point — OpenSSH AuthorizedKeysCommand.
  msshd/         Tier 1 wrapper daemon (msshd).
  mssh           Tier 1 client CLI (single module).

Future siblings: ../go/, ../c/ (placeholder skeletons today).

Operator-facing docs / configs live at the repo root
(INSTALLATION.md, config/, scripts/, systemd/).
"""

__version__ = '0.1.0'
