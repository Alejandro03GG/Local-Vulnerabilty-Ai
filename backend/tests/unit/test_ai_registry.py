"""Unit tests for AIRegistry."""

from __future__ import annotations

from vuln_ai.ai.models import AIAnalysis, AnalysisContext, DecisionQuestion, DecisionResult
from vuln_ai.ai.registry import AIRegistry


class DummyAIProvider:
    def __init__(self, name: str = "DummyAI"):
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "dummy_ai"

    async def analyze(self, context: AnalysisContext) -> AIAnalysis:
        raise NotImplementedError

    async def is_available(self) -> bool:
        return True


class DummyDecisionProvider:
    def __init__(self, name: str = "DummyDecision"):
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "dummy_decision"

    async def decide(
        self, context: AnalysisContext, questions: list[DecisionQuestion]
    ) -> DecisionResult:
        raise NotImplementedError

    async def is_available(self) -> bool:
        return True


def test_ai_registry_lifecycle():
    """Register, retrieve, and list AI and Decision providers."""
    registry = AIRegistry()

    # Empty registry returns None
    assert registry.get_ai_provider() is None
    assert registry.get_decision_provider() is None
    assert registry.list_ai_providers() == []
    assert registry.list_decision_providers() == []

    # Register AI providers
    ai1 = DummyAIProvider("ProviderA")
    ai2 = DummyAIProvider("ProviderB")
    registry.register_ai_provider(ai1)
    registry.register_ai_provider(ai2, is_default=True)

    assert registry.get_ai_provider() is ai2  # Default is ProviderB
    assert registry.get_ai_provider("ProviderA") is ai1
    assert len(registry.list_ai_providers()) == 2

    # Register Decision providers
    dec1 = DummyDecisionProvider("DecA")
    dec2 = DummyDecisionProvider("DecB")
    registry.register_decision_provider(dec1)
    registry.register_decision_provider(dec2)

    assert registry.get_decision_provider() is dec1  # First is default if not specified
    assert registry.get_decision_provider("DecB") is dec2
    assert len(registry.list_decision_providers()) == 2
