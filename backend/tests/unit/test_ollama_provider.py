"""Unit tests for OllamaProvider with mocked HTTP transport."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from vuln_ai.ai.models import AnalysisContext
from vuln_ai.ai.ollama_provider import OllamaProvider
from vuln_ai.config import OllamaSettings
from vuln_ai.core.exceptions import (
    AIError,
    AIProviderUnavailableError,
    AIResponseParseError,
)
from vuln_ai.core.models import Ecosystem, MatchType, VersionType


@pytest.fixture
def sample_context() -> AnalysisContext:
    return AnalysisContext(
        component_name="django",
        component_version="4.2.11",
        version_type=VersionType.EXACT,
        ecosystem=Ecosystem.PYPI,
        source_file="requirements.txt",
        cve_id="CVE-2024-1000",
        source_name="CISA KEV",
        vendor_project="Django",
        product="Django",
        short_description="SQL injection in admin filter",
        required_action="Upgrade to Django 4.2.12",
        match_type=MatchType.EXACT_NAME,
        match_confidence=1.0,
        match_evidence=["Component name matches Django"],
    )


@pytest.mark.asyncio
async def test_ollama_analyze_success(
    sample_context: AnalysisContext,
    ollama_analysis_success_data: dict,
):
    """Successful LLM response parses into validated AIAnalysis."""
    provider = OllamaProvider(OllamaSettings(model="llama3.2"))

    mock_resp = httpx.Response(
        200,
        json={
            "message": {"content": json.dumps(ollama_analysis_success_data)},
            "eval_count": 120,
            "prompt_eval_count": 80,
        },
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        analysis = await provider.analyze(sample_context)

        assert analysis.provider == "OllamaProvider"
        assert analysis.model == "llama3.2"
        assert "potentially exposed" in analysis.explanation
        assert len(analysis.evidence) == 2
        assert analysis.requires_human_review is True
        assert analysis.tokens_used == 200
        assert analysis.analysis_duration_seconds >= 0.0

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_connection_refused(sample_context: AnalysisContext):
    """Connection error raises AIProviderUnavailableError."""
    provider = OllamaProvider()

    with (
        patch.object(
            httpx.AsyncClient, "post", side_effect=httpx.ConnectError("Connection refused")
        ),
        pytest.raises(AIProviderUnavailableError, match="connection refused"),
    ):
        await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_timeout(sample_context: AnalysisContext):
    """Timeout raises AIProviderUnavailableError."""
    provider = OllamaProvider(OllamaSettings(timeout_seconds=5))

    with (
        patch.object(
            httpx.AsyncClient, "post", side_effect=httpx.TimeoutException("Read timed out")
        ),
        pytest.raises(AIProviderUnavailableError, match="timed out"),
    ):
        await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_model_not_found_404(sample_context: AnalysisContext):
    """HTTP 404 raises AIProviderUnavailableError indicating model not found."""
    provider = OllamaProvider(OllamaSettings(model="nonexistent-model"))
    req = httpx.Request("POST", "http://localhost:11434/api/chat")
    resp = httpx.Response(404, request=req, text="model not found")

    with (
        patch.object(
            httpx.AsyncClient,
            "post",
            side_effect=httpx.HTTPStatusError("Not Found", request=req, response=resp),
        ),
        pytest.raises(AIProviderUnavailableError, match="not found"),
    ):
        await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_server_error_500(sample_context: AnalysisContext):
    """HTTP 500 error raises AIError."""
    provider = OllamaProvider()
    req = httpx.Request("POST", "http://localhost:11434/api/chat")
    resp = httpx.Response(500, request=req, text="Internal Server Error")

    with (
        patch.object(
            httpx.AsyncClient,
            "post",
            side_effect=httpx.HTTPStatusError("Server Error", request=req, response=resp),
        ),
        pytest.raises(AIError, match="HTTP 500"),
    ):
        await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_invalid_json(sample_context: AnalysisContext):
    """Malformed non-JSON output from LLM raises AIResponseParseError."""
    provider = OllamaProvider()

    mock_resp = httpx.Response(
        200,
        json={"message": {"content": "This is plain text not JSON at all."}},
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(AIResponseParseError, match="failed schema validation"):
            await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_analyze_missing_required_fields(
    sample_context: AnalysisContext,
    ollama_analysis_invalid_data: dict,
):
    """JSON missing required fields raises AIResponseParseError."""
    provider = OllamaProvider()

    mock_resp = httpx.Response(
        200,
        json={"message": {"content": json.dumps(ollama_analysis_invalid_data)}},
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(AIResponseParseError, match="failed schema validation"):
            await provider.analyze(sample_context)

    await provider.close()


@pytest.mark.asyncio
async def test_ollama_is_available():
    """is_available correctly verifies server and model presence."""
    provider = OllamaProvider(OllamaSettings(model="llama3.2"))

    # When model is present
    mock_tags = httpx.Response(
        200,
        json={"models": [{"name": "llama3.2:latest"}, {"name": "nomic-embed-text:latest"}]},
        request=httpx.Request("GET", "http://localhost:11434/api/tags"),
    )
    with patch.object(httpx.AsyncClient, "get", return_value=mock_tags):
        assert await provider.is_available() is True

    # When model is not present
    mock_tags_missing = httpx.Response(
        200,
        json={"models": [{"name": "mistral:latest"}]},
        request=httpx.Request("GET", "http://localhost:11434/api/tags"),
    )
    with patch.object(httpx.AsyncClient, "get", return_value=mock_tags_missing):
        assert await provider.is_available() is False

    # When server is down
    with patch.object(
        httpx.AsyncClient, "get", side_effect=httpx.ConnectError("Connection refused")
    ):
        assert await provider.is_available() is False

    await provider.close()
