"""ssh-rt-auth integration with unmodified OpenSSH (sshd).

This package contains the AuthorizedKeysCommand-based shim that lets stock
OpenSSH (no source patch) consult the ssh-rt-auth CA for every SSH
authentication attempt. See ``openssh_shim.py`` for the executable.
"""
