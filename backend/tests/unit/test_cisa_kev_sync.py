"""Unit tests for CISAKEVSource sync, network handling, fallback, and error recovery."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from vuln_ai.config import KEVSourceSettings
from vuln_ai.core.exceptions import SourceSyncError
from vuln_ai.sources.cisa_kev import CISAKEVSource


@pytest.mark.asyncio
async def test_kev_sync_success_primary(sample_kev_data: dict):
    """CISAKEVSource sync succeeds on primary URL."""
    settings = KEVSourceSettings(
        url="https://primary.example.com/kev.json",
        mirror_url="https://mirror.example.com/kev.json",
    )
    source = CISAKEVSource(settings)

    with patch.object(source, "_download", new_callable=AsyncMock) as mock_download:
        mock_download.return_value = sample_kev_data
        result = await source.sync()

        assert result.success is True
        assert result.records_synced == 5
        assert len(source.records) == 5
        assert mock_download.call_count == 1
        assert mock_download.call_args[0][0] == settings.url


@pytest.mark.asyncio
async def test_kev_sync_fallback_to_mirror(sample_kev_data: dict):
    """CISAKEVSource sync falls back to mirror URL when primary URL fails."""
    settings = KEVSourceSettings(
        url="https://primary.example.com/kev.json",
        mirror_url="https://mirror.example.com/kev.json",
    )
    source = CISAKEVSource(settings)

    with patch.object(source, "_download", new_callable=AsyncMock) as mock_download:
        # First call fails, second call succeeds with sample data
        mock_download.side_effect = [
            SourceSyncError("Primary connection refused"),
            sample_kev_data,
        ]

        result = await source.sync()

        assert result.success is True
        assert result.records_synced == 5

        assert mock_download.call_count == 2
        assert mock_download.call_args_list[0][0][0] == settings.url
        assert mock_download.call_args_list[1][0][0] == settings.mirror_url


@pytest.mark.asyncio
async def test_kev_sync_all_attempts_fail():
    """CISAKEVSource sync returns failure when both primary and mirror fail."""
    settings = KEVSourceSettings(
        url="https://primary.example.com/kev.json",
        mirror_url="https://mirror.example.com/kev.json",
    )
    source = CISAKEVSource(settings)

    with patch.object(source, "_download", new_callable=AsyncMock) as mock_download:
        mock_download.side_effect = [
            SourceSyncError("Primary 503 Service Unavailable"),
            SourceSyncError("Mirror 404 Not Found"),
        ]

        result = await source.sync()

        assert result.success is False
        assert "Mirror 404 Not Found" in result.error
        assert result.records_synced == 0


@pytest.mark.asyncio
async def test_download_timeout():
    """_download raises SourceSyncError on httpx.TimeoutException."""
    source = CISAKEVSource()

    with (
        patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timeout")),
        pytest.raises(SourceSyncError, match="Timeout downloading"),
    ):
        await source._download("https://example.com/timeout")


@pytest.mark.asyncio
async def test_download_http_status_error():
    """_download raises SourceSyncError on HTTP 500 error."""
    source = CISAKEVSource()

    request = httpx.Request("GET", "https://example.com/error")
    response = httpx.Response(500, request=request)
    with (
        patch(
            "httpx.AsyncClient.get",
            side_effect=httpx.HTTPStatusError("Server Error", request=request, response=response),
        ),
        pytest.raises(SourceSyncError, match="HTTP 500"),
    ):
        await source._download("https://example.com/error")


@pytest.mark.asyncio
async def test_download_network_request_error():
    """_download raises SourceSyncError on network RequestError."""
    source = CISAKEVSource()

    request = httpx.Request("GET", "https://example.com/neterr")
    with (
        patch(
            "httpx.AsyncClient.get",
            side_effect=httpx.ConnectError("Connection refused", request=request),
        ),
        pytest.raises(SourceSyncError, match="Network error"),
    ):
        await source._download("https://example.com/neterr")


@pytest.mark.asyncio
async def test_download_generic_exception():
    """_download raises SourceSyncError on unexpected Exception."""
    source = CISAKEVSource()

    with (
        patch("httpx.AsyncClient.get", side_effect=ValueError("Unexpected issue")),
        pytest.raises(SourceSyncError, match="Unexpected error"),
    ):
        await source._download("https://example.com/crash")
