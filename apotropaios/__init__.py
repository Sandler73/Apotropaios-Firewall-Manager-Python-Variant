# ==============================================================================
# File:         apotropaios/__init__.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Root package initializer
# Description:  Exposes package-level metadata (version, name) and serves as
#               the top-level namespace for all Apotropaios subpackages.
# Notes:        - Imports are deferred to subpackages to avoid circular deps
#               - Version is the single source of truth (also in constants.py)
# Version:      1.2.1
# ==============================================================================

from apotropaios.core.constants import VERSION as __version__  # noqa: F401
__project__ = "Apotropaios"
__full_name__ = "Apotropaios - Firewall Manager"
