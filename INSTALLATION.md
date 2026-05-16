# mssh — installation

Quick pointer file. For the full operator workflow (install, enrol,
adopt, troubleshoot) see [docs/operations.md](docs/operations.md).

## Quick install

```bash
git clone https://github.com/kurt-cb/ssh-rt-auth.git
cd ssh-rt-auth/python
pip install -e .
```

Provides: `mssh`, `mssh-admin`, `mssh-ca`, `msshd`.

## Bootstrap a CA

```bash
mssh-admin init --ca-dir /etc/mssh-ca
mssh-ca --config /etc/mssh-ca/ca-config.yaml
```

See [docs/operations.md § bootstrap a CA](docs/operations.md#bootstrap-a-ca)
for the full sequence including admin cert custody, where each key
file lives, and the trust hierarchies you should keep separate.

## Try the adhoc lab first

```bash
cd python && ./setup_adhoc.sh
# Source ./adhoc-env.sh in the resulting shell, then:
#   mssh_as alice acct whoami
#   flip_to_fallback / flip_to_enforce
```

Five LXC containers, full Phase-0→Phase-2 adoption journey in 2
minutes. Read [docs/operations.md § adoption journey](docs/operations.md#the-adoption-journey)
for what the three modes mean and why we structure migrations
around them.

## Distro packages

Not yet. `apt install mssh msshd` is on the roadmap; see
[design/future-ideas.md § distro packaging](design/future-ideas.md).
