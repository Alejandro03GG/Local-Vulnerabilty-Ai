"""Custom exceptions for Local Vulnerability AI."""


class VulnAIError(Exception):
    """Base exception for the application."""


class ScanError(VulnAIError):
    """Error during project scanning."""


class SourceError(VulnAIError):
    """Error interacting with a vulnerability source."""


class SourceSyncError(SourceError):
    """Error synchronizing vulnerability data."""


class SourceParseError(SourceError):
    """Error parsing vulnerability data."""


class MatchingError(VulnAIError):
    """Error during vulnerability matching."""


class DatabaseError(VulnAIError):
    """Error interacting with the database."""


class ConfigurationError(VulnAIError):
    """Invalid configuration."""


class AIError(VulnAIError):
    """Base error for AI providers."""


class AIProviderUnavailableError(AIError):
    """AI provider or model is not reachable/available."""


class AIResponseParseError(AIError):
    """Failed to parse or validate AI structured output."""


class DecisionError(AIError):
    """Base error for decision providers."""


class DecisionProviderUnavailableError(DecisionError):
    """Decision model or service is not reachable/available."""


class RiskEngineError(VulnAIError):
    """Error evaluating risk rules."""
