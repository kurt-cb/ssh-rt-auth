"""Package metadata for mssh.

Real-world Python packages prefer pyproject.toml, but the venv we
test against here ships setuptools 53 (no PEP 660 / editable
support from pyproject alone). We declare metadata here so the
`pip install -e .` path works on older distros; pyproject.toml
carries only the pytest configuration.
"""
from setuptools import find_packages, setup


setup(
    name='mssh',
    version='0.1.0',
    description='Runtime, CA-mediated SSH authorization',
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
            'mssh-ca              = mssh.ca.server:main',
            'mssh-admin           = mssh.admin.main:cli',
            # Server-side gateway daemon
            'msshd                = mssh.msshd.msshd:main',
            'msshd-admin          = mssh.msshd.admin:main',
            # Client
            'mssh                 = mssh.client:main',
            # Debug-only AsyncSSH server — not a production tier.
            # Minimal CA-call surface for diagnosing CA/policy issues
            # in isolation from the gateway machinery.
            'mssh-debug-sshd      = mssh.debug_sshd.ssh_server:main',
        ],
    },
)
