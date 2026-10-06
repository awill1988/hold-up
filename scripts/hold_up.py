#!/usr/bin/env python3
"""Source-checkout compatibility launcher; the implementation lives in holdup."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import engine

if __name__ == "__main__":
    raise SystemExit(engine.main())
else:
    sys.modules[__name__] = engine
