"""Entry point: ``python -m sshrt.msshd``."""
from __future__ import annotations

import sys

from .msshd import main


if __name__ == '__main__':
    sys.exit(main())
