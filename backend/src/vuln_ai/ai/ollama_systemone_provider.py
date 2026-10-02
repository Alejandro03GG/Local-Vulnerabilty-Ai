"""Ollama SystemOne provider for structured probabilistic decision evaluation."""

from __future__ import annotations

import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from vuln_ai.ai.base import DecisionProvider
from vuln_ai.ai.models import (
    AnalysisContext,
    DecisionQuestion,
    DecisionResult,
    QuestionType,
)
from vuln_ai.config import DecisionSettings
from vuln_ai.core.exceptions import (
    AIResponseParseError,
    DecisionError,
    DecisionProviderUnavailableError,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class OllamaSystemOneProvider(DecisionProvider):
    """Decision provider that consumes Ollama's POST /v1/systemone endpoint.

    Supports models such as 'nimble', 'tev1:4b', 'tev1:0.8b', configured dynamically.
    Evaluates questions of type 'noul', 'choice', and 'score'.
    """

    def __init__(self, settings: DecisionSettings | None = None) -> None:
        self._settings = settings or DecisionSettings()
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "OllamaSystemOneProvider"

    @property
    def provider_type(self) -> str:
        return "ollama_systemone"

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
        """Check if the Ollama SystemOne service and target model are reachable."""
        if not self._settings.enabled:
            return False

        try:
            client = self._get_client()
            # Check server availability via /api/tags
            resp = await client.get("/api/tags")
            if resp.status_code != 200:
                return False

            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            target = self._settings.model
            return any(
                m == target or m.startswith(f"{target}:") or target.startswith(m) for m in models
            )
        except Exception as exc:
            logger.debug("OllamaSystemOne is_available check failed: %s", exc)
            return False

    def _format_context_text(self, context: AnalysisContext) -> str:
        return (
            f"Component: {context.component_name} (version: {context.component_version or 'unknown'})\n"
            f"Ecosystem: {context.ecosystem} | Source file: {context.source_file}\n"
            f"Vulnerability: {context.cve_id} ({context.source_name})\n"
            f"Vendor/Product: {context.vendor_project} / {context.product}\n"
            f"Description: {context.short_description}\n"
            f"Required Action: {context.required_action}\n"
            f"CWEs: {', '.join(context.cwes) if context.cwes else 'None'}\n"
            f"Match Type: {context.match_type} (confidence: {context.match_confidence:.2f})\n"
            f"Evidence: {'; '.join(context.match_evidence)}"
        )

    def _format_questions_payload(self, questions: list[DecisionQuestion]) -> list[dict[str, Any]]:
        formatted = []
        for q in questions:
            item: dict[str, Any] = {
                "id": q.id,
                "question": q.question,
                "type": q.question_type.value,
            }
            if q.question_type == QuestionType.CHOICE and q.options:
                item["options"] = q.options
            elif q.question_type == QuestionType.SCORE:
                if q.min_score is not None:
                    item["min_score"] = q.min_score
                if q.max_score is not None:
                    item["max_score"] = q.max_score
            formatted.append(item)
        return formatted

    async def decide(
        self,
        context: AnalysisContext,
        questions: list[DecisionQuestion],
    ) -> DecisionResult:
        """Call POST /v1/systemone to obtain structured probabilistic decisions."""
        start_time = time.monotonic()
        client = self._get_client()

        payload = {
            "model": self._settings.model,
            "context": self._format_context_text(context),
            "questions": self._format_questions_payload(questions),
        }

        try:
            resp = await client.post("/v1/systemone", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.ConnectError as exc:
            raise DecisionProviderUnavailableError(
                f"Cannot connect to SystemOne at {self._settings.base_url}: connection refused"
            ) from exc
        except httpx.TimeoutException as exc:
            raise DecisionProviderUnavailableError(
                f"SystemOne decision request timed out after {self._settings.timeout_seconds}s"
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise DecisionProviderUnavailableError(
                    f"SystemOne endpoint or model '{self._settings.model}' not found (HTTP 404)"
                ) from exc
            raise DecisionError(
                f"SystemOne server returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except Exception as exc:
            raise DecisionError(f"Unexpected error communicating with SystemOne: {exc}") from exc

        duration = time.monotonic() - start_time

        # Parse answers and distributions
        responses: dict[str, Any] = {}
        probabilities: dict[str, dict[str, float]] = {}
        applicability_prob: float | None = None
        urgency_score: float | None = None

        raw_answers = data.get("answers") or data.get("results") or data.get("responses") or {}

        if not isinstance(raw_answers, dict):
            raise AIResponseParseError(
                f"Expected dictionary in SystemOne answers, got {type(raw_answers).__name__}"
            )

        for q in questions:
            q_data = raw_answers.get(q.id)
            if q_data is None:
                continue

            if isinstance(q_data, dict):
                val = q_data.get("value") or q_data.get("answer") or q_data.get("selected")
                dist = (
                    q_data.get("distribution")
                    or q_data.get("probabilities")
                    or q_data.get("scores")
                    or {}
                )
                responses[q.id] = val
                if isinstance(dist, dict):
                    probabilities[q.id] = {k: float(v) for k, v in dist.items()}

                if q.id == "applicability":
                    # Extract probability for 'yes' or direct probability field
                    prob = q_data.get("probability")
                    if prob is not None:
                        applicability_prob = float(prob)
                    elif "yes" in probabilities.get(q.id, {}):
                        applicability_prob = probabilities[q.id]["yes"]

                elif q.id == "urgency":
                    score = q_data.get("score") or val
                    if score is not None:
                        with contextlib.suppress(ValueError, TypeError):
                            urgency_score = float(score)

            else:
                responses[q.id] = q_data
                if q.id == "urgency":
                    with contextlib.suppress(ValueError, TypeError):
                        urgency_score = float(q_data)

        logger.info(
            "SystemOne decision complete for %s / %s in %.2fs (model: %s)",
            context.component_name,
            context.cve_id,
            duration,
            self._settings.model,
        )

        return DecisionResult(
            provider=self.name,
            model=self._settings.model,
            responses=responses,
            decision_probabilities=probabilities,
            applicability_probability=applicability_prob,
            urgency_score=urgency_score,
            latency_seconds=duration,
            timestamp=_utcnow(),
            raw_response=data,
        )
