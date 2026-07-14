"""Finding model — the core data unit of every scan."""

from datetime import datetime
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

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
