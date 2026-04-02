"""
core/exceptions.py

Domain-specific exceptions for AetherGuard.
Raising these instead of generic exceptions gives FastAPI
clean HTTP error responses and keeps agent logic readable.
"""

from __future__ import annotations


class AetherGuardError(Exception):
    """Base exception for all AetherGuard errors."""
    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


# ── Agent errors ─────────────────────────────────────────────────────────────

class AgentError(AetherGuardError):
    """Raised when an agent encounters an unrecoverable error."""


class AgentTimeoutError(AgentError):
    """Raised when an agent exceeds its time budget."""


class LLMCallError(AgentError):
    """Raised when the LLM API call fails."""


# ── Incident errors ───────────────────────────────────────────────────────────

class IncidentNotFoundError(AetherGuardError):
    """Raised when an incident ID cannot be found."""


class InvalidStatusTransitionError(AetherGuardError):
    """Raised when an invalid status transition is attempted."""


# ── Approval errors ───────────────────────────────────────────────────────────

class ApprovalDeniedError(AetherGuardError):
    """Raised when a remediation action is denied by human reviewer."""


class ApprovalTimeoutError(AetherGuardError):
    """Raised when the approval gate times out."""


class NoApprovalGateError(AetherGuardError):
    """Raised when approval is attempted on an incident without a gate."""


# ── Simulator errors ──────────────────────────────────────────────────────────

class ScenarioNotFoundError(AetherGuardError):
    """Raised when a requested chaos scenario file does not exist."""


class SimulatorError(AetherGuardError):
    """Raised when a simulator encounters an unexpected error."""


# ── Remediation errors ────────────────────────────────────────────────────────

class RemediationError(AetherGuardError):
    """Raised when a remediation action fails to execute."""


class CostCalculationError(AetherGuardError):
    """Raised when cost estimation fails."""