"""Ollama LLM provider for contextual vulnerability analysis."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, Field, ValidationError

from vuln_ai.ai.base import AIProvider
from vuln_ai.ai.models import AIAnalysis, AnalysisContext
from vuln_ai.config import OllamaSettings
from vuln_ai.core.exceptions import (
    AIError,
    AIProviderUnavailableError,
    AIResponseParseError,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _StructuredAnalysisResponse(BaseModel):
    """Internal validation schema for the LLM JSON output."""

    explanation: str = Field(description="Contextual explanation of findings")
    evidence: list[str] = Field(
        default_factory=list, description="Specific supporting evidence points"
    )
    contextual_findings: list[str] = Field(
        default_factory=list, description="Specific findings or nuances identified"
    )
    requires_human_review: bool = Field(
        default=True, description="Flag indicating human triage is recommended"
    )


class OllamaProvider(AIProvider):
    """LLM provider that communicates with a local Ollama instance."""

    def __init__(self, settings: OllamaSettings | None = None) -> None:
        self._settings = settings or OllamaSettings()
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "OllamaProvider"

    @property
    def provider_type(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._settings.model

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._settings.base_url.rstrip("/"),
                timeout=float(self._settings.timeout_seconds),
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client session."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def is_available(self) -> bool:
        """Check if Ollama server is reachable and if the configured model is installed."""
        if not self._settings.enabled:
            return False

        try:
            client = self._get_client()
            resp = await client.get("/api/tags")
            if resp.status_code != 200:
                return False

            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            # Match model name or tag (e.g., 'llama3.2' matches 'llama3.2:latest')
            target_model = self._settings.model
            return any(
                m == target_model or m.startswith(f"{target_model}:") or target_model.startswith(m)
                for m in models
            )
        except Exception as exc:
            logger.debug("Ollama is_available check failed: %s", exc)
            return False

    def _build_system_prompt(self) -> str:
        return (
            "You are a local software security analyst assistant in the 'Local Vulnerability AI' system.\n"
            "Your role is to analyze the relationship between a detected software component and a cataloged vulnerability.\n"
            "You do NOT make the final decision whether a package is vulnerable. You provide contextual reasoning.\n"
            "CRITICAL RULES:\n"
            "1. Respond ONLY with valid JSON strictly conforming to this schema:\n"
            "{\n"
            '  "explanation": "concise explanation of whether and how this vulnerability relates to the detected component",\n'
            '  "evidence": ["point 1", "point 2"],\n'
            '  "contextual_findings": ["finding 1", "finding 2"],\n'
            '  "requires_human_review": true/false\n'
            "}\n"
            "2. Do NOT output any markdown, explanations, or text outside the JSON object.\n"
            "3. If version ranges are uncertain, set requires_human_review to true."
        )

    def _build_user_prompt(self, context: AnalysisContext) -> str:
        return (
            f"Component Detected:\n"
            f"- Name: {context.component_name}\n"
            f"- Version: {context.component_version or 'Unknown'}\n"
            f"- Version Constraint: {context.version_constraint or 'None'}\n"
            f"- Ecosystem: {context.ecosystem}\n"
            f"- Source File: {context.source_file}\n\n"
            f"Vulnerability Catalog Record:\n"
            f"- CVE: {context.cve_id}\n"
            f"- Source: {context.source_name}\n"
            f"- Vendor/Project: {context.vendor_project}\n"
            f"- Product: {context.product}\n"
            f"- Title: {context.vulnerability_name}\n"
            f"- Short Description: {context.short_description}\n"
            f"- Required Action: {context.required_action}\n"
            f"- CWEs: {', '.join(context.cwes) if context.cwes else 'None'}\n"
            f"- Known Ransomware Use: {context.known_ransomware_use}\n\n"
            f"Deterministic Match:\n"
            f"- Type: {context.match_type}\n"
            f"- Confidence: {context.match_confidence:.2f}\n"
            f"- Evidence: {'; '.join(context.match_evidence)}\n\n"
            "Provide your structured analysis in JSON."
        )

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        """Call Ollama LLM to analyze the context and return validated AIAnalysis."""
        start_time = time.monotonic()
        client = self._get_client()

        payload = {
            "model": self._settings.model,
            "messages": [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user", "content": self._build_user_prompt(context)},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self._settings.temperature,
            },
        }

        try:
            resp = await client.post("/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.ConnectError as exc:
            raise AIProviderUnavailableError(
                f"Cannot connect to Ollama at {self._settings.base_url}: connection refused"
            ) from exc
        except httpx.TimeoutException as exc:
            raise AIProviderUnavailableError(
                f"Ollama request timed out after {self._settings.timeout_seconds}s"
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise AIProviderUnavailableError(
                    f"Ollama model '{self._settings.model}' not found on server"
                ) from exc
            raise AIError(
                f"Ollama server returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except Exception as exc:
            raise AIError(f"Unexpected error communicating with Ollama: {exc}") from exc

        duration = time.monotonic() - start_time
        content = data.get("message", {}).get("content", "")

        try:
            parsed_json = json.loads(content)
            validated = _StructuredAnalysisResponse.model_validate(parsed_json)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise AIResponseParseError(
                f"Ollama response failed schema validation: {exc} | Raw content: {content[:200]}"
            ) from exc

        # Calculate token metrics if returned by Ollama
        tokens_used: int | None = None
        eval_count = data.get("eval_count")
        prompt_eval_count = data.get("prompt_eval_count")
        if eval_count is not None or prompt_eval_count is not None:
            tokens_used = (eval_count or 0) + (prompt_eval_count or 0)

        logger.info(
            "Ollama analysis complete for %s / %s in %.2fs (tokens: %s)",
            context.component_name,
            context.cve_id,
            duration,
            tokens_used,
        )

        return AIAnalysis(
            provider=self.name,
            model=self._settings.model,
            explanation=validated.explanation,
            evidence=validated.evidence,
            contextual_findings=validated.contextual_findings,
            requires_human_review=validated.requires_human_review,
            analysis_duration_seconds=duration,
            tokens_used=tokens_used,
            analyzed_at=_utcnow(),
        )
