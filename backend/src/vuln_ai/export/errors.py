"""Export error hierarchy for Local Vulnerability AI."""

from __future__ import annotations


class ExportError(Exception):
    """Base exception for all export-related failures."""


class ExportFormatUnsupportedError(ExportError):
    """Raised when an requested export format is not supported."""


class ExportSerializationError(ExportError):
    """Raised when scan data cannot be serialized to the target format."""


class ExportValidationError(ExportError):
    """Raised when the generated export document fails schema or integrity validation."""


class ExportWriteError(ExportError):
    """Raised when writing the export document to disk fails."""
