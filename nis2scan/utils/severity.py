"""Severity scoring utilities."""

from nis2scan.engine.models.finding import Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_weight(severity: Severity) -> int:
    """Get numerical weight for a severity level."""
    return SEVERITY_WEIGHTS.get(severity, 0)
