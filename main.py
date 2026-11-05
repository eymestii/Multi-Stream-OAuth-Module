"""Punto de entrada del módulo OAuth."""

from __future__ import annotations

import sys

from oauth_module.ui.main_window import run_gui


def main() -> int:
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
