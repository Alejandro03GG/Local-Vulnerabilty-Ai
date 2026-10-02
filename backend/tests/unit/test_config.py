"""Tests for configuration and settings management."""

from __future__ import annotations

from pathlib import Path

from vuln_ai.config import DatabaseSettings, Settings, get_settings


def test_default_settings():
    """Default settings have sensible fallback values."""
    settings = Settings()
    assert settings.log_level == "INFO"
    assert settings.database.url.startswith("sqlite")
    assert settings.kev.timeout_seconds == 30
    assert "cisa.gov" in settings.kev.url
    assert "github.io" in settings.kev.mirror_url
    assert settings.scanner.max_components == 10000


def test_get_db_url_relative_sqlite(tmp_path: Path):
    """Relative sqlite URLs resolve against data_dir."""
    custom_data_dir = tmp_path / "custom_data"
    settings = Settings(
        data_dir=custom_data_dir,
        database=DatabaseSettings(url="sqlite+aiosqlite:///relative.db"),
    )

    resolved_url = settings.get_db_url()
    expected_path = custom_data_dir / "relative.db"
    assert str(expected_path) in resolved_url
    assert custom_data_dir.exists()


def test_get_db_url_absolute_sqlite(tmp_path: Path):
    """Absolute sqlite URLs are preserved as-is."""
    abs_db_path = tmp_path / "absolute.db"
    settings = Settings(
        database=DatabaseSettings(url=f"sqlite+aiosqlite:///{abs_db_path}"),
    )

    assert settings.get_db_url() == f"sqlite+aiosqlite:///{abs_db_path}"


def test_get_db_url_non_sqlite():
    """Non-sqlite URLs (e.g., PostgreSQL) are preserved untouched."""
    pg_url = "postgresql+asyncpg://user:pass@localhost:5432/vulndb"
    settings = Settings(database=DatabaseSettings(url=pg_url))

    assert settings.get_db_url() == pg_url


def test_get_settings_helper():
    """get_settings returns an initialized Settings instance."""
    settings = get_settings()
    assert isinstance(settings, Settings)
