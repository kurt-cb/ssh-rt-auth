"""Entry point: ``python -m wrapper.python``."""
from __future__ import annotations

import sys

from .wrapperd import main


if __name__ == '__main__':
    sys.exit(main())
