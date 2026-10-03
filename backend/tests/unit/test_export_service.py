"""Unit tests for ExportService and atomic writing (Etapa 15 §42, §43)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_ai.core.models import (
    ScanResultSummary,
    ScanStatus,
)
from vuln_ai.export.errors import (
    ExportFormatUnsupportedError,
    ExportWriteError,
)
from vuln_ai.export.models import ExportFormat, ExportScan
from vuln_ai.export.service import ExportService, atomic_write_text


def test_export_service_media_types():
    """Verify standard MIME media types for export formats."""
    assert ExportService.get_media_type("sarif") == "application/sarif+json"
    assert ExportService.get_media_type("cyclonedx") == "application/vnd.cyclonedx+json"
    assert ExportService.get_media_type("spdx") == "application/spdx+json"
    assert ExportService.get_media_type("unknown") == "application/json"


def test_export_service_serialization_formats():
    """Verify ExportService serializes canonical model to all 3 standards."""
    summary = ScanResultSummary(
        project_name="svc-test",
        project_path="/svc-test",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif_str = ExportService.serialize_text(scan, ExportFormat.SARIF)
    assert json.loads(sarif_str)["version"] == "2.1.0"

    cdx_str = ExportService.serialize_text(scan, "cyclonedx")
    assert json.loads(cdx_str)["bomFormat"] == "CycloneDX"

    spdx_str = ExportService.serialize_text(scan, ExportFormat.SPDX)
    assert json.loads(spdx_str)["spdxVersion"] == "SPDX-2.3"

    with pytest.raises(ExportFormatUnsupportedError):
        ExportService.serialize_text(scan, "xml")


def test_atomic_write_text(tmp_path: Path):
    """Verify atomic file writing leaves no partial artifacts and overwrites safely."""
    dest_file = tmp_path / "subdir" / "report.json"
    content = '{"valid": true}'

    written_path = atomic_write_text(dest_file, content)
    assert written_path.exists()
    assert written_path.read_text(encoding="utf-8") == content

    # Overwrite safely
    new_content = '{"valid": false}'
    atomic_write_text(dest_file, new_content)
    assert written_path.read_text(encoding="utf-8") == new_content


def test_atomic_write_failure_handling():
    """Verify atomic write raises ExportWriteError on OS failure."""
    with pytest.raises(ExportWriteError):
        # Attempting to write into an impossible path (null byte or invalid filesystem location)
        atomic_write_text("/proc/nonexistent/sub/path/err.txt", "content")


def test_export_summary_orchestration(tmp_path: Path):
    """Verify end-to-end export_summary helper."""
    summary = ScanResultSummary(
        project_name="orch-test",
        project_path="/orch-test",
        scan_status=ScanStatus.COMPLETED,
    )
    out_file = tmp_path / "sarif_results.sarif"
    result_text = ExportService.export_summary(
        summary=summary,
        export_format="sarif",
        output_path=out_file,
    )
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == result_text

    # Without output_path
    no_file_res = ExportService.export_summary(
        summary=summary,
        export_format="cyclonedx",
    )
    assert "bomFormat" in no_file_res


def test_serialize_dict_all_formats():
    """Verify serialize_dict handles sarif, cyclonedx, and spdx correctly."""
    summary = ScanResultSummary(
        project_name="dict-test",
        project_path="/dict-test",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)

    sarif_dict = ExportService.serialize_dict(scan, "sarif")
    assert sarif_dict["version"] == "2.1.0"

    cdx_dict = ExportService.serialize_dict(scan, "cyclonedx")
    assert cdx_dict["bomFormat"] == "CycloneDX"

    spdx_dict = ExportService.serialize_dict(scan, "spdx")
    assert spdx_dict["spdxVersion"] == "SPDX-2.3"

    with pytest.raises(ExportFormatUnsupportedError):
        ExportService.serialize_dict(scan, "unknown-fmt")


def test_serialization_error_wrapping(monkeypatch):
    """Verify unexpected internal errors get wrapped in ExportSerializationError."""
    from vuln_ai.export.errors import ExportSerializationError

    summary = ScanResultSummary(
        project_name="err-test",
        project_path="/err-test",
        scan_status=ScanStatus.COMPLETED,
    )
    scan = ExportScan.from_scan_summary(summary)

    def _broken_export(scan, **kwargs):
        raise TypeError("Broken export logic")

    monkeypatch.setattr("vuln_ai.export.service.export_sarif_dict", _broken_export)
    monkeypatch.setattr("vuln_ai.export.service.export_sarif_json", _broken_export)

    with pytest.raises(ExportSerializationError) as exc_dict:
        ExportService.serialize_dict(scan, "sarif")
    assert "Broken export logic" in str(exc_dict.value)

    with pytest.raises(ExportSerializationError) as exc_text:
        ExportService.serialize_text(scan, "sarif")
    assert "Broken export logic" in str(exc_text.value)
