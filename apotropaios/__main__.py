# ==============================================================================
# File:         apotropaios/__main__.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Package entry point for `python -m apotropaios`
# Description:  Minimal entry point that delegates to cli.main(). This file
#               enables running the framework as a Python module:
#                   python -m apotropaios [OPTIONS] [COMMAND] [ARGS...]
#
#               The actual argument parsing, initialization, and command dispatch
#               lives in cli.py. This file exists solely to satisfy the Python
#               `-m` package execution convention.
#
# Notes:        - No logic here beyond importing and calling cli.main()
#               - Source guard at bottom enables test importability
#               - Parity target: bash v1.1.10 apotropaios.sh (main function)
# Execution:    python -m apotropaios [OPTIONS] [COMMAND] [ARGS...]
# Examples:     python -m apotropaios --interactive
#               python -m apotropaios detect
#               python -m apotropaios add-rule --dst-port 443 --action accept
#               python -m apotropaios --backend iptables status
#               python -m apotropaios add-rule --help
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import sys


def main() -> None:
    """Top-level entry point for the Apotropaios framework.

    Imports and delegates to cli.main() for argument parsing, framework
    initialization, and command dispatch. Handles top-level exceptions
    to ensure clean exit codes.
    """
    from apotropaios.cli import main as cli_main

    try:
        cli_main()
    except SystemExit:
        # Re-raise SystemExit to preserve exit code (from argparse --help,
        # die(), or sys.exit() in signal handlers)
        raise
    except KeyboardInterrupt:
        # Clean Ctrl+C handling — print newline and exit 130 (128 + SIGINT)
        sys.stderr.write("\n")
        sys.exit(130)
    except Exception as exc:
        # Catch-all for unhandled exceptions — log and exit 1
        sys.stderr.write(f"Fatal error: {exc}\n")
        sys.exit(1)


# Source guard: allows `python -m apotropaios` and test importability
if __name__ == "__main__":
    main()
