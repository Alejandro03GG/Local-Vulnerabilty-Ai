"""Tests for SourceRegistry and ScannerRegistry."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.core.models import VulnerabilityRecord
from vuln_ai.scanners.registry import ScannerRegistry
from vuln_ai.sources.registry import SourceRegistry


class DummySource:
    """Dummy vulnerability source implementing VulnerabilitySource protocol."""

    @property
    def name(self) -> str:
        return "DummySource"

    @property
    def source_type(self) -> str:
        return "TEST"

    @property
    def url(self) -> str:
        return "https://example.com/test.json"

    @property
    def records(self) -> list[VulnerabilityRecord]:
        return []

    async def sync(self):
        raise NotImplementedError

    async def search(self, query):
        return []


class DummyScanner:
    """Dummy scanner implementing ProjectScanner protocol."""

    @property
    def name(self) -> str:
        return "DummyScanner"

    @property
    def ecosystem(self) -> str:
        return "pypi"

    def can_scan(self, project_path: Path) -> bool:
        return (project_path / "dummy_marker.txt").exists()

    def scan(self, project_path: Path):
        return []


def test_source_registry_crud():
    """Test register, get, list, __len__, and __contains__ on SourceRegistry."""
    registry = SourceRegistry()
    source = DummySource()

    # Initially empty
    assert len(registry) == 0
    assert "DummySource" not in registry
    assert registry.get("DummySource") is None

    # Register
    registry.register(source)
    assert len(registry) == 1
    assert "DummySource" in registry
    assert registry.get("DummySource") is source
    assert registry.list_sources() == [source]


def test_scanner_registry_crud(tmp_path: Path):
    """Test register, list, get_scanners_for, and scan_all on ScannerRegistry."""
    registry = ScannerRegistry()
    scanner = DummyScanner()

    # Initially empty
    assert len(registry) == 0
    assert len(registry.list_scanners()) == 0

    # Register
    registry.register(scanner)
    assert len(registry) == 1
    assert len(registry.list_scanners()) == 1

    # Project matching: without marker file
    matched = registry.get_scanners_for(tmp_path)
    assert len(matched) == 0

    # With marker file
    (tmp_path / "dummy_marker.txt").touch()
    matched = registry.get_scanners_for(tmp_path)
    assert len(matched) == 1
    assert matched[0] is scanner
