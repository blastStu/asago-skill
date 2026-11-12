"""Filesystem locations shared across the runner."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def component_cli(name: str) -> str:
    """Resolve a component CLI executable.

    Prefers the bin directory of the interpreter running the runner (the
    locked environment), falling back to PATH. Raises when not found so a
    missing component is an actionable error, not a silent PATH miss.
    """
    own_bin = Path(sys.executable).parent / name
    if own_bin.is_file():
        return str(own_bin)
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(
        f"component CLI {name!r} not found next to the runner interpreter "
        f"({own_bin}) or on PATH; run `uv sync --locked` from the skill root"
    )


def default_garak_env() -> Path:
    """The pinned Garak environment directory shipped beside the skill."""
    return Path(__file__).resolve().parents[2] / "garak-env"
