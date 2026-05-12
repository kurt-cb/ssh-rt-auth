from setuptools import setup, find_packages

setup(
    name='ssh-rt-auth',
    version='0.1.0',
    description='Runtime, CA-mediated SSH authorization (PoC)',
    author='Kurt Godwin',
    packages=['ca', 'cli', 'shim', 'server'],
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
            'ssh-rt-admin=cli.main:cli',
            'ssh-rt-auth-ca=ca.server:main',
            'ssh-rt-auth-server=server.ssh_server:main',
        ],
    },
)
