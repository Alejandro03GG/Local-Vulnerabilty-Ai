"""Exceptions for Policy & Suppression Engine."""

from __future__ import annotations


class PolicyError(Exception):
    """Base exception for all policy and suppression operations."""

    pass


class PolicyParseError(PolicyError):
    """Raised when policy file cannot be parsed as valid YAML or violates size limits."""

    pass


class PolicyValidationError(PolicyError):
    """Raised when policy structure violates schema constraints."""

    pass


class SuppressionError(PolicyError):
    """Raised when a suppression operation is invalid."""

    pass


class SuppressionValidationError(SuppressionError):
    """Raised when suppression parameters violate validation rules."""

    pass
