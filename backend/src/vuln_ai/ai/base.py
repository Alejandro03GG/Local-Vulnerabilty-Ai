"""Protocols for AI and Decision providers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vuln_ai.ai.models import (
    AIAnalysis,
    AnalysisContext,
    DecisionQuestion,
    DecisionResult,
)


@runtime_checkable
class AIProvider(Protocol):
    """Protocol for LLM providers generating contextual vulnerability analysis."""

    @property
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @property
    def provider_type(self) -> str:
        """Identifier for the provider type (e.g., 'ollama', 'mock')."""
        ...

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        """Generate structured contextual analysis for a matched vulnerability."""
        ...

    async def is_available(self) -> bool:
        """Check if the provider service and model are reachable and ready."""
        ...


@runtime_checkable
class DecisionProvider(Protocol):
    """Protocol for probabilistic decision providers evaluating structured questions."""

    @property
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @property
    def provider_type(self) -> str:
        """Identifier for the decision provider type (e.g., 'ollama_systemone')."""
        ...

    async def decide(
        self,
        context: AnalysisContext,
        questions: list[DecisionQuestion],
    ) -> DecisionResult:
        """Evaluate decision questions against the provided context."""
        ...

    async def is_available(self) -> bool:
        """Check if the decision service and model are reachable and ready."""
        ...
