#!/usr/bin/env python3
# ==============================================================================
# File:         apotropaios.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Standalone execution without installation
# Description:  Run Apotropaios directly from the project root without pip
#               install. Adds the project root to sys.path and delegates to
#               the package entry point. Mirrors apotropaios.sh from the
#               bash variant.
#
# Usage:
#   sudo python3 apotropaios.py detect
#   sudo python3 apotropaios.py --interactive
#   sudo python3 apotropaios.py add-rule --dst-port 443 --action accept
#   sudo python3 apotropaios.py help
#   sudo python3 apotropaios.py --help
#
# Notes:        - Requires Python 3.12+
#               - No pip install or venv needed
#               - All arguments passed through to CLI
# Version:      1.6.2
# ==============================================================================

import os
import sys

# Ensure the project root is on the import path so apotropaios package resolves
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from apotropaios.cli import main

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        # Re-raise SystemExit to preserve exit code
        raise
    except KeyboardInterrupt:
        # Clean Ctrl+C -- no traceback exposed
        sys.stderr.write("\n")
        sys.exit(130)
    except Exception as exc:
        # Catch-all -- no full traceback exposed to user
        sys.stderr.write(f"Fatal error: {exc}\n")
        sys.exit(1)
