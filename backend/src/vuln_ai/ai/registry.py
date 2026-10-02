"""Registry for AI and Decision providers."""

from __future__ import annotations

import logging

from vuln_ai.ai.base import AIProvider, DecisionProvider

logger = logging.getLogger(__name__)


class AIRegistry:
    """Registry managing available AI contextual providers and probabilistic decision providers."""

    def __init__(self) -> None:
        self._ai_providers: dict[str, AIProvider] = {}
        self._decision_providers: dict[str, DecisionProvider] = {}
        self._default_ai_provider: str | None = None
        self._default_decision_provider: str | None = None

    def register_ai_provider(self, provider: AIProvider, is_default: bool = False) -> None:
        """Register an LLM contextual provider."""
        self._ai_providers[provider.name] = provider
        if is_default or self._default_ai_provider is None:
            self._default_ai_provider = provider.name
        logger.debug("Registered AI provider: %s", provider.name)

    def register_decision_provider(
        self, provider: DecisionProvider, is_default: bool = False
    ) -> None:
        """Register a probabilistic decision provider."""
        self._decision_providers[provider.name] = provider
        if is_default or self._default_decision_provider is None:
            self._default_decision_provider = provider.name
        logger.debug("Registered Decision provider: %s", provider.name)

    def get_ai_provider(self, name: str | None = None) -> AIProvider | None:
        """Get an AI provider by name or the default provider."""
        if name is not None:
            return self._ai_providers.get(name)
        if self._default_ai_provider:
            return self._ai_providers.get(self._default_ai_provider)
        return next(iter(self._ai_providers.values()), None)

    def get_decision_provider(self, name: str | None = None) -> DecisionProvider | None:
        """Get a decision provider by name or the default provider."""
        if name is not None:
            return self._decision_providers.get(name)
        if self._default_decision_provider:
            return self._decision_providers.get(self._default_decision_provider)
        return next(iter(self._decision_providers.values()), None)

    def list_ai_providers(self) -> list[AIProvider]:
        """List all registered AI providers."""
        return list(self._ai_providers.values())

    def list_decision_providers(self) -> list[DecisionProvider]:
        """List all registered decision providers."""
        return list(self._decision_providers.values())
