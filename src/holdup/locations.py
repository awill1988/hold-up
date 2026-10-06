"""XDG locations with native Windows defaults and explicit test isolation."""

import os
from pathlib import Path


def directory(kind):
    if kind in ("state", "runtime") and os.environ.get("HOLD_UP_STATE_DIR"):
        root = Path(os.environ["HOLD_UP_STATE_DIR"])
        return root / "runtime" if kind == "runtime" else root
    variable = "XDG_RUNTIME_DIR" if kind == "runtime" else f"XDG_{kind.upper()}_HOME"
    override = os.environ.get(variable)
    if override and Path(override).is_absolute():
        return Path(override) / "hold-up"
    if os.name == "nt":
        return (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "hold-up" / kind
        )
    if kind == "runtime":
        return directory("state") / "runtime"
    return (
        Path.home()
        / {"state": ".local/state", "config": ".config", "cache": ".cache"}[kind]
        / "hold-up"
    )


def runtime_directory(root):
    # Explicit roots passed by tests must never share endpoint discovery with a profile.
    return directory("runtime") if root == directory("state") else root / "runtime"
