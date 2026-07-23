"""Finding model — the core data unit of every scan."""

from datetime import date, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(StrEnum):
    """Supported cloud providers."""

    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class FindingStatus(StrEnum):
    """Compliance status of a single finding (ADR-0006).

    A Finding is an assessed statement per check x Prüfobjekt — compliant
    findings are first-class positive evidence, not just defects.
    """

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"


class FindingExceptionInfo(BaseModel):
    """Documented, time-boxed exception applied to a non-compliant finding (ADR-0026).

    Set by the engine (nis2scan.engine.finding_exceptions.apply_exceptions)
    when a matching, non-expired rule from a customer-owned exceptions file
    applies — never set by checks themselves, and never on a COMPLIANT
    finding (an exception can only accept a documented defect, it can never
    manufacture compliance, ADR-0016 fail-safe).
    """

    reason: str = Field(description="Documented rationale for accepting this finding, in German")
    expires: date = Field(description="Due date of the exception (UTC calendar date)")
    author: str | None = Field(default=None, description="Person who documented the exception")
    ticket: str | None = Field(default=None, description="Reference to a ticket/ticket system, if any")


class Finding(BaseModel):
    """A single compliance finding from a check execution.

    Every finding maps to a specific §30 BSIG area and includes
    audit-ready evidence and remediation guidance in German.
    """

    check_id: str = Field(description="Unique check identifier, e.g. AWS-NR8-001")
    # ADR-0006: default NON_COMPLIANT matches legacy semantics (checks emitted
    # only defects). Checks are migrated area-by-area to also emit COMPLIANT
    # findings as positive evidence.
    status: FindingStatus = FindingStatus.NON_COMPLIANT
    # ADR-0010: stable identity across scans — HMAC over (provider, account_id,
    # check_id, resource_id). Computed centrally by the scanner, never by checks.
    finding_key: str = ""
    title: str = Field(description="Short finding title in German")
    description: str = Field(description="Detailed description of what was found, in German")

    # Legal mapping
    bsig_30_nr: int = Field(ge=1, le=10, description="§30 Abs. 2 Nr. (1-10)")
    bsig_30_text: str = Field(description="§30 BSIG section text reference")
    iso27001_control: str | None = Field(default=None, description="ISO 27001:2022 control, e.g. A.8.24")

    # Classification
    severity: Severity
    provider: CloudProvider
    region: str = Field(description="Cloud region, e.g. eu-central-1 or westeurope")

    # Resource
    resource_id: str = Field(description="ARN or Azure Resource ID")
    resource_type: str = Field(description="Resource type, e.g. AWS::S3::Bucket")
    account_id: str = Field(description="AWS Account ID or Azure Subscription ID")

    # Evidence
    current_state: dict[str, Any] = Field(default_factory=dict, description="Current state as evidence")
    expected_state: str = Field(description="Expected compliant state, in German")
    remediation: str = Field(description="Recommended remediation action, in German")
    remediation_effort: str = Field(description="Estimated effort: LOW / MEDIUM / HIGH")
    audit_evidence: str = Field(default="", description="Machine-readable audit evidence")

    # Documented exception (ADR-0026): additive, optional, applied only to
    # NON_COMPLIANT findings by the engine — see FindingExceptionInfo.
    exception: FindingExceptionInfo | None = Field(
        default=None, description="Documented, time-boxed exception accepting this defect, if any"
    )
    # Ablauf-Hinweis (ADR-0026 decision 3): set instead of `exception` when
    # this finding was matched ONLY by an already-expired rule — the defect
    # counts again in full (never suppressed), but the report can still name
    # the exception that used to apply and when it lapsed.
    expired_exception: FindingExceptionInfo | None = Field(
        default=None, description="A previously matching exception that has since expired, if any"
    )

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
