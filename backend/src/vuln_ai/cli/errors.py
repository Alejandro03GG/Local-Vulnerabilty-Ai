"""Exit codes and error types for the Local Vulnerability AI CLI."""

from __future__ import annotations

from enum import IntEnum


class CLIExitCode(IntEnum):
    """Standardized deterministic exit codes for CLI operations.

    0 = Scan completed without threshold violations / Command succeeded
    1 = Security threshold violated (--fail-on or --fail-on-review triggered)
    2 = CLI usage, invalid arguments, configuration error, or path not found
    3 = Internal execution error or unexpected database failure
    """

    SUCCESS = 0
    THRESHOLD_VIOLATED = 1
    USAGE_ERROR = 2
    INTERNAL_ERROR = 3


class CLIError(Exception):
    """Base exception for CLI execution issues."""

    def __init__(self, message: str, exit_code: CLIExitCode = CLIExitCode.INTERNAL_ERROR) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
