"""Unit tests for OllamaSystemOneProvider with mocked HTTP transport."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from vuln_ai.ai.models import AnalysisContext
from vuln_ai.ai.ollama_systemone_provider import OllamaSystemOneProvider
from vuln_ai.ai.questions import get_default_decision_questions
from vuln_ai.config import DecisionSettings
from vuln_ai.core.exceptions import (
    AIResponseParseError,
    DecisionError,
    DecisionProviderUnavailableError,
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
async def test_systemone_decide_success(
    sample_context: AnalysisContext,
    ollama_systemone_success_data: dict,
):
    """Successful SystemOne decision parses noul, choice, and score questions."""
    provider = OllamaSystemOneProvider(DecisionSettings(model="tev1:4b"))
    questions = get_default_decision_questions()

    mock_resp = httpx.Response(
        200,
        json=ollama_systemone_success_data,
        request=httpx.Request("POST", "http://localhost:11434/v1/systemone"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        decision = await provider.decide(sample_context, questions)

        assert decision.provider == "OllamaSystemOneProvider"
        assert decision.model == "tev1:4b"
        assert decision.applicability_probability == 0.85
        assert decision.urgency_score == 8.5
        assert decision.responses["exposure"] == "direct"
        assert decision.decision_probabilities["exposure"]["direct"] == 0.75
        assert decision.latency_seconds >= 0.0

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_decide_connection_refused(sample_context: AnalysisContext):
    """Connection failure raises DecisionProviderUnavailableError."""
    provider = OllamaSystemOneProvider()
    questions = get_default_decision_questions()

    with (
        patch.object(
            httpx.AsyncClient, "post", side_effect=httpx.ConnectError("Connection refused")
        ),
        pytest.raises(DecisionProviderUnavailableError, match="connection refused"),
    ):
        await provider.decide(sample_context, questions)

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_decide_timeout(sample_context: AnalysisContext):
    """Timeout raises DecisionProviderUnavailableError."""
    provider = OllamaSystemOneProvider(DecisionSettings(timeout_seconds=5))
    questions = get_default_decision_questions()

    with (
        patch.object(
            httpx.AsyncClient, "post", side_effect=httpx.TimeoutException("Read timed out")
        ),
        pytest.raises(DecisionProviderUnavailableError, match="timed out"),
    ):
        await provider.decide(sample_context, questions)

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_decide_model_not_found(sample_context: AnalysisContext):
    """HTTP 404 raises DecisionProviderUnavailableError."""
    provider = OllamaSystemOneProvider(DecisionSettings(model="tev1:unknown"))
    questions = get_default_decision_questions()
    req = httpx.Request("POST", "http://localhost:11434/v1/systemone")
    resp = httpx.Response(404, request=req, text="model not found")

    with (
        patch.object(
            httpx.AsyncClient,
            "post",
            side_effect=httpx.HTTPStatusError("Not Found", request=req, response=resp),
        ),
        pytest.raises(DecisionProviderUnavailableError, match="not found"),
    ):
        await provider.decide(sample_context, questions)

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_decide_server_error(sample_context: AnalysisContext):
    """HTTP 500 error raises DecisionError."""
    provider = OllamaSystemOneProvider()
    questions = get_default_decision_questions()
    req = httpx.Request("POST", "http://localhost:11434/v1/systemone")
    resp = httpx.Response(500, request=req, text="Internal Error")

    with (
        patch.object(
            httpx.AsyncClient,
            "post",
            side_effect=httpx.HTTPStatusError("Internal Error", request=req, response=resp),
        ),
        pytest.raises(DecisionError, match="HTTP 500"),
    ):
        await provider.decide(sample_context, questions)

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_decide_malformed_answers(sample_context: AnalysisContext):
    """Non-dict answers structure raises AIResponseParseError."""
    provider = OllamaSystemOneProvider()
    questions = get_default_decision_questions()

    mock_resp = httpx.Response(
        200,
        json={"answers": "invalid_string_instead_of_dict"},
        request=httpx.Request("POST", "http://localhost:11434/v1/systemone"),
    )

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(AIResponseParseError, match="Expected dictionary"):
            await provider.decide(sample_context, questions)

    await provider.close()


@pytest.mark.asyncio
async def test_systemone_is_available():
    """is_available checks service and target decision model."""
    provider = OllamaSystemOneProvider(DecisionSettings(model="tev1:4b"))

    # When model is present
    mock_tags = httpx.Response(
        200,
        json={"models": [{"name": "tev1:4b"}, {"name": "nimble:latest"}]},
        request=httpx.Request("GET", "http://localhost:11434/api/tags"),
    )
    with patch.object(httpx.AsyncClient, "get", return_value=mock_tags):
        assert await provider.is_available() is True

    # When model is absent
    mock_tags_missing = httpx.Response(
        200,
        json={"models": [{"name": "other:latest"}]},
        request=httpx.Request("GET", "http://localhost:11434/api/tags"),
    )
    with patch.object(httpx.AsyncClient, "get", return_value=mock_tags_missing):
        assert await provider.is_available() is False

    await provider.close()
