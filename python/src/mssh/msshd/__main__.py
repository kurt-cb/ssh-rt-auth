"""Entry point: ``python -m mssh.msshd``."""
from __future__ import annotations

import sys

from .msshd import main


if __name__ == '__main__':
    sys.exit(main())
