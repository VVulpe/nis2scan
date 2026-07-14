"""Check model — base class and result types for all check modules."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from nis2scan.engine.models.finding import CloudProvider, Finding, FindingStatus


class CheckError(BaseModel):
    """Error that occurred during check execution."""

    message: str
    error_type: str = "APIError"
    details: dict[str, Any] = Field(default_factory=dict)
    # Optional context — many checks pass these; without declared fields
    # Pydantic silently dropped them from the error output.
    check_id: str | None = None
    region: str | None = None


class CheckOutcome(StrEnum):
    """Overall state of one check execution (ADR-0007).

    Derived deterministically from findings/errors via derive_outcome() —
    never set independently, so outcome and findings cannot contradict.
    """

    PASSED = "passed"  # >=1 Prüfobjekt, all findings compliant
    FAILED = "failed"  # >=1 non-compliant finding
    NOT_APPLICABLE = "not_applicable"  # no resources of this type in the environment
    MANUAL_REQUIRED = "manual_required"  # not automatable -> attestation checklist
    ERROR = "error"  # execution failed, result unknown — never silent
    NOT_IN_SCOPE = "not_in_scope"  # excluded via config


class CheckResult(BaseModel):
    """Result of a single check execution."""

    check_id: str
    findings: list[Finding] = Field(default_factory=list)
    errors: list[CheckError] = Field(default_factory=list)
    # Derived by the scanner via derive_outcome(); None only before derivation.
    outcome: CheckOutcome | None = None
    # DEPRECATED (ADR-0007): replaced by outcome. Kept until the checks
    # migration wave completes, then removed before the 1.0 schema freeze.
    skipped: bool = False
    skip_reason: str | None = None
    duration_ms: int = 0


def derive_outcome(result: "CheckResult") -> CheckOutcome:
    """Derive the CheckOutcome from a CheckResult (ADR-0007; fail-safe per ADR-0016).

    Rules, in order:
    1. skipped (config exclusion / provider disabled) -> NOT_IN_SCOPE
    2. any non-compliant finding -> FAILED (defects are real even when errors
       occurred; the errors stay visible in result.errors)
    3. any error -> ERROR — never PASSED when in doubt
    4. >=1 compliant finding -> PASSED (positive evidence present)
    5. empty result -> NOT_APPLICABLE. Since the positive-evidence migration
       (ADR-0006, all 154 checks) every evaluated Prüfobjekt yields a finding,
       so an empty result means zero objects were evaluated — no resources of
       this type, or state unknowable without error. Never PASSED (ADR-0016):
       NOT_APPLICABLE counts neither as fulfilled nor as failed and leaves the
       area NICHT_BEWERTBAR when nothing else was evaluated.
    """
    if result.skipped:
        return CheckOutcome.NOT_IN_SCOPE
    if any(f.status == FindingStatus.NON_COMPLIANT for f in result.findings):
        return CheckOutcome.FAILED
    if result.errors:
        return CheckOutcome.ERROR
    if result.findings:
        return CheckOutcome.PASSED
    return CheckOutcome.NOT_APPLICABLE


class BaseCheck(ABC):
    """Abstract base class for all check modules.

    Every check is stateless: config in, CheckResult out.
    No globals, no singletons, no side effects.
    """

    check_id: str
    title: str
    description: str
    bsig_30_nr: int
    provider: CloudProvider
    required_permissions: list[str]
    # Known limitations (ADR-0016 rule 2): what this check does NOT verify,
    # in German — printed next to the result in every report. Checks that
    # silently skip unknowable states (e.g. inaccessible APIs) MUST declare
    # that here instead of leaving a silent gap.
    pruefgrenzen: str | None = None

    @abstractmethod
    async def execute(self, session: Any) -> CheckResult:
        """Execute the check and return findings.

        Args:
            session: Provider-specific session (boto3 Session or Azure credential).

        Returns:
            CheckResult with findings and/or errors.
        """
        ...
