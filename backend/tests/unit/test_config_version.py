"""Regression: API/user-agent versions derive from vuln_ai.__version__."""

from __future__ import annotations

from vuln_ai import __version__
from vuln_ai.config import Settings


def test_settings_version_matches_package_version() -> None:
    settings = Settings()
    assert settings.api.version == __version__
    assert settings.kev.user_agent.endswith(__version__)
    assert settings.osv.user_agent.endswith(__version__)
    assert settings.nvd.user_agent.endswith(__version__)
