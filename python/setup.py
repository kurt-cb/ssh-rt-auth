"""Package metadata for sshrt.

Real-world Python packages prefer pyproject.toml, but the venv we
test against here ships setuptools 53 (no PEP 660 / editable
support from pyproject alone). We declare metadata here so the
`pip install -e .` path works on older distros; pyproject.toml
carries only the pytest configuration.
"""
from setuptools import find_packages, setup


setup(
    name='ssh-rt-auth',
    version='0.1.0',
    description='Runtime, CA-mediated SSH authorization (PoC)',
    author='Kurt Godwin',
    license='Apache-2.0',
    python_requires='>=3.9',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'asyncssh>=2.14',
        'cryptography>=41.0',
        'flask>=3.0',
        'pyyaml>=6.0',
        'click>=8.0',
        'requests>=2.31',
    ],
    entry_points={
        'console_scripts': [
            # CA + admin
            'ssh-rt-auth-ca       = sshrt.ca.server:main',
            'ssh-rt-admin         = sshrt.admin.main:cli',
            # Debug-only AsyncSSH server (minimal CA-call surface; not
            # a production tier — used for diagnosing CA/shim issues
            # in isolation from the wrap-and-proxy machinery).
            'ssh-rt-debug-sshd    = sshrt.debug_sshd.ssh_server:main',
            # Tier 1 wrapper
            'msshd                = sshrt.msshd.msshd:main',
            'ssh-rt-wrapper-admin = sshrt.msshd.admin:main',
            # Tier 1 client
            'mssh                 = sshrt.mssh:main',
        ],
    },
)
