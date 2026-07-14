"""Configuration models for scan execution."""

from pydantic import BaseModel, Field, field_validator

# ADR-0004/0012: German legal terms, never translated. Legacy English values
# are migrated transparently (EU directive: important = wichtig,
# essential = besonders wichtig).
_LEGACY_CATEGORY_MAP = {"important": "wichtig", "essential": "besonders_wichtig"}


class CompanyInfo(BaseModel):
    """Company metadata for report generation.

    nis2_category is the customer's SELF-declaration (ADR-0012) — pure report
    metadata, never derived by the tool and never affecting scan behavior.
    """

    name: str = "Unbekannt"
    sector: str = ""  # descriptive metadata only — no category derivation (ADR-0012)
    nis2_category: str = Field(default="wichtig", pattern=r"^(wichtig|besonders_wichtig)$")

    @field_validator("nis2_category", mode="before")
    @classmethod
    def _migrate_legacy_category(cls, v: str) -> str:
        return _LEGACY_CATEGORY_MAP.get(v, v)


class ProviderConfig(BaseModel):
    """Configuration for a single cloud provider."""

    enabled: bool = False
    profile: str | None = None
    accounts: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    subscription_ids: list[str] = Field(default_factory=list)
    # Cross-account access (AWS): assume this role instead of using the ambient
    # credentials directly. external_id is the shared secret in the role's trust
    # policy (confused-deputy protection) — the SaaS backend fills these per
    # tenant so no long-lived tenant keys are ever stored.
    assume_role_arn: str | None = None
    external_id: str | None = None
    role_session_name: str = "nis2scan"
    # Cross-tenant access (Azure): authenticate the scanner's multi-tenant app
    # registration against THIS customer tenant (admin-consent model). The
    # app's client id/secret stay scanner-side (env), never per customer.
    azure_tenant_id: str | None = None


class ScanConfig(BaseModel):
    """Top-level scan configuration, typically loaded from YAML."""

    company: CompanyInfo = Field(default_factory=CompanyInfo)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    bsig_30_scope: list[int] = Field(default_factory=lambda: list(range(1, 11)))
    # severity_threshold was removed with the 1.0 schema freeze (ADR-0008 audit
    # finding: dead config, never applied). Unknown keys in loaded configs are
    # ignored by pydantic, so old YAML/JSON payloads keep working.
    output_formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])
    output_dir: str = "./reports"
    include_evidence: bool = True
