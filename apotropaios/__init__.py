# ==============================================================================
# File:         apotropaios/__init__.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Root package initializer
# Description:  Exposes package-level metadata (version, name) and serves as
#               the top-level namespace for all Apotropaios subpackages.
# Notes:        - Imports are deferred to subpackages to avoid circular deps
#               - Version is the single source of truth (also in constants.py)
# Version:      1.6.2
# ==============================================================================

from apotropaios.core.constants import VERSION

# Re-export as the conventional package attribute. The redundant assignment
# (rather than `import ... as __version__`) makes the export explicit for
# both static analysers and type checkers.
__version__ = VERSION
__project__ = "Apotropaios"
__full_name__ = "Apotropaios - Firewall Manager"

__all__ = ["VERSION", "__version__", "__project__", "__full_name__"]
