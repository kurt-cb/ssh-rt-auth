"""ssh-rt-auth wrapper — Python PoC implementation.

See:
- wrapper/README.md — overview + variant chooser
- design/ssh-rt-auth-detailed-wrapper.md — implementation blueprint

Phase 1A (current): fallback mode only.
Phase 1B (next):    enforce mode (mTLS, CA call, cert mint, inner sshd).
"""
