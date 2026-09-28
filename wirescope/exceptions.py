"""WireScope's own exception hierarchy.

The CLI catches these at the top level and prints a clean, single-line
error instead of a raw Python traceback (unless -v/-vv verbose mode is on).
"""

from __future__ import annotations


class WireScopeError(Exception):
    """Base class for all expected WireScope failures."""


class CaptureNotFoundError(WireScopeError):
    pass


class UnsupportedCaptureError(WireScopeError):
    pass


class EmptyCaptureError(WireScopeError):
    pass


class CorruptCaptureError(WireScopeError):
    pass


class CapturePermissionError(WireScopeError):
    pass
