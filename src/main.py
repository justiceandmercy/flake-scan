"""Entry point for the flake-scan command line interface."""

from __future__ import annotations

import sys
from typing import Sequence

import typer

from flakescan.cli import app


def main(argv: Sequence[str] | None = None) -> int:
    """Run the flake-scan Typer application and return a process exit code.

    ``argv`` defaults to ``sys.argv[1:]``.  Keeping argument parsing in Typer
    while returning an integer makes the entry point easy to test without
    spawning a subprocess.
    """
    command = typer.main.get_command(app)
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        command(args, standalone_mode=False)
        return 0
    except (SystemExit, typer.Exit) as exc:
        code = getattr(exc, "code", 0)
        if code is None:
            return 0
        try:
            return int(code)
        except (TypeError, ValueError):
            return 1
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        typer.echo(f"flake-scan: unexpected error: {exc}", err=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
