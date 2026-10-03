"""Export service for orchestrating scan data transformations and exports."""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from vuln_ai.core.models import ScanResultSummary
from vuln_ai.export.cyclonedx import export_cyclonedx_dict, export_cyclonedx_json
from vuln_ai.export.errors import (
    ExportError,
    ExportFormatUnsupportedError,
    ExportSerializationError,
    ExportWriteError,
)
from vuln_ai.export.models import ExportFormat, ExportScan
from vuln_ai.export.sarif import export_sarif_dict, export_sarif_json
from vuln_ai.export.spdx import export_spdx_dict, export_spdx_json

logger = logging.getLogger(__name__)

EXPORT_MEDIA_TYPES: dict[str, str] = {
    ExportFormat.SARIF.value: "application/sarif+json",
    ExportFormat.CYCLONEDX.value: "application/vnd.cyclonedx+json",
    ExportFormat.SPDX.value: "application/spdx+json",
}


def atomic_write_text(filepath: Path | str, content: str) -> Path:
    """Atomically write content to a file, preventing partial file writes on failure.

    Uses a temporary file in the destination directory and performs atomic replacement.
    """
    target = Path(filepath).resolve()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise ExportWriteError(f"Cannot create parent directory for '{target}': {exc}") from exc

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=target.parent,
            encoding="utf-8",
            delete=False,
            prefix=f".tmp_{target.name}_",
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, target)
        return target
    except Exception as exc:
        if temp_path and temp_path.exists():
            with contextlib.suppress(OSError):
                temp_path.unlink()
        raise ExportWriteError(f"Failed to atomically write export to '{target}': {exc}") from exc


class ExportService:
    """Service orchestrating exports across SARIF, CycloneDX, and SPDX formats."""

    @staticmethod
    def get_media_type(format_name: str | ExportFormat) -> str:
        """Return canonical MIME type for format."""
        fmt_str = (
            format_name.value
            if isinstance(format_name, ExportFormat)
            else str(format_name).lower().strip()
        )
        return EXPORT_MEDIA_TYPES.get(fmt_str, "application/json")

    @classmethod
    def serialize_dict(cls, scan: ExportScan, export_format: str | ExportFormat) -> dict[str, Any]:
        """Transform canonical ExportScan into target format dictionary."""
        fmt_str = (
            export_format.value
            if isinstance(export_format, ExportFormat)
            else str(export_format).lower().strip()
        )

        try:
            if fmt_str == ExportFormat.SARIF.value:
                return export_sarif_dict(scan)
            if fmt_str == ExportFormat.CYCLONEDX.value:
                return export_cyclonedx_dict(scan)
            if fmt_str == ExportFormat.SPDX.value:
                return export_spdx_dict(scan)
            raise ExportFormatUnsupportedError(
                f"Unsupported export format '{export_format}'. Supported: sarif, cyclonedx, spdx"
            )
        except ExportError:
            raise
        except Exception as exc:
            raise ExportSerializationError(
                f"Failed to serialize scan to '{fmt_str}': {exc}"
            ) from exc

    @classmethod
    def serialize_text(
        cls, scan: ExportScan, export_format: str | ExportFormat, indent: int = 2
    ) -> str:
        """Transform canonical ExportScan into target format JSON string."""
        fmt_str = (
            export_format.value
            if isinstance(export_format, ExportFormat)
            else str(export_format).lower().strip()
        )

        try:
            if fmt_str == ExportFormat.SARIF.value:
                return export_sarif_json(scan, indent=indent)
            if fmt_str == ExportFormat.CYCLONEDX.value:
                return export_cyclonedx_json(scan, indent=indent)
            if fmt_str == ExportFormat.SPDX.value:
                return export_spdx_json(scan, indent=indent)
            raise ExportFormatUnsupportedError(
                f"Unsupported export format '{export_format}'. Supported: sarif, cyclonedx, spdx"
            )
        except ExportError:
            raise
        except Exception as exc:
            raise ExportSerializationError(
                f"Failed to serialize scan to '{fmt_str}': {exc}"
            ) from exc

    @classmethod
    def export_summary(
        cls,
        summary: ScanResultSummary,
        export_format: str | ExportFormat,
        output_path: Path | str | None = None,
        scan_id: str | None = None,
        generated_at: str | None = None,
        indent: int = 2,
        policy_evaluation: Any = None,
    ) -> str:
        """Export ScanResultSummary directly to the chosen format with optional atomic disk write."""
        export_scan = ExportScan.from_scan_summary(
            summary=summary,
            scan_id=scan_id,
            generated_at=generated_at,
            policy_evaluation=policy_evaluation,
        )
        content = cls.serialize_text(export_scan, export_format, indent=indent)

        if output_path is not None:
            atomic_write_text(output_path, content)

        return content
