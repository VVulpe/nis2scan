"""Findings-Exceptions — documented, time-boxed exceptions for accepted defects (ADR-0026).

Context: every scan produces findings that an organization consciously
decides not to remediate (false positives, accepted risks, documented
special cases). Without an exception mechanism these findings drown out
every subsequent report. An exception is never a delete button, though —
for an audit tool every exception must itself be auditable (who, why, until
when), so it is documented in a customer-owned YAML file and applied by the
engine, never silently.

Design per ADR-0026:
- Exceptions are opt-in only (`--exceptions PATH`, engine field
  `ScanConfig.exceptions_path`) — there is no implicit default file, so
  nothing is ever suppressed by surprise.
- A rule matches on `check_id` + `resource_id` (exact), optionally narrowed
  further by `account_id`/`region` when the rule sets them.
- `expires` is mandatory (no unlimited exceptions). Rules running longer
  than ~12 months trigger a warning (Wiedervorlage-Prinzip) but are never
  rejected.
- Expired rules never annotate a finding again — the defect counts in full
  again — but are reported separately so the report can surface an
  "Abgelaufene Ausnahmen" hint.
- Exceptions apply ONLY to NON_COMPLIANT findings (Mängel). Positive
  evidence, CheckError, and NOT_APPLICABLE outcomes can never be excepted
  (ADR-0016 fail-safe stays untouched) — an exception can accept a
  documented defect, it can never manufacture compliance.
- A broken exceptions file aborts the scan (fail-safe) rather than being
  silently ignored — a customer who points nis2scan at an exceptions file
  expects it to actually be read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING

import structlog
import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, ValidationError

from nis2scan.engine.models.finding import Finding, FindingExceptionInfo, FindingStatus

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger()

# ADR-0026 decision 3: "über 12 Monaten" is approximated as 366 days (leap-year
# safe) rather than exact calendar-month arithmetic — good enough for a
# Wiedervorlage warning, not a legal deadline computation.
_WARN_AFTER_DAYS = 366


class ExceptionsFileError(Exception):
    """Raised when an exceptions file is missing, malformed, or fails validation.

    Fail-safe (ADR-0026/ADR-0016): callers MUST abort the scan on this error
    instead of proceeding without exceptions applied. A silently-ignored
    exceptions file would look identical to "no exceptions configured" and
    could mask a customer's explicit intent — a broken file must be loud.
    """


class FindingExceptionRule(BaseModel):
    """A single documented, time-boxed exception rule (ADR-0026).

    `reason` and `expires` are mandatory: an exception without a documented
    rationale and a due date is not auditable and defeats the purpose of the
    mechanism (see ADR-0026 context).
    """

    check_id: str = Field(description="Check identifier the rule applies to, e.g. AWS-NR9-001")
    resource_id: str = Field(description="Exact resource identifier (ARN/ID) the rule applies to")
    reason: str = Field(description="Documented rationale, in German, for why the finding is accepted")
    expires: date = Field(description="Due date after which the exception no longer applies (UTC calendar date)")
    author: str | None = Field(default=None, description="Person who documented the exception")
    ticket: str | None = Field(default=None, description="Reference to a ticket/ticket system, if any")
    account_id: str | None = Field(default=None, description="Narrows the match to this account/subscription/project")
    region: str | None = Field(default=None, description="Narrows the match to this cloud region")

    def matches(self, finding: Finding) -> bool:
        """Whether this rule targets the given finding (ADR-0026 matching rule).

        check_id and resource_id must match exactly. account_id/region only
        narrow the match further when the rule sets them — unset means "any".
        Expiry is NOT considered here; see is_expired().
        """
        if self.check_id != finding.check_id or self.resource_id != finding.resource_id:
            return False
        if self.account_id is not None and self.account_id != finding.account_id:
            return False
        return self.region is None or self.region == finding.region

    def is_expired(self, as_of: date) -> bool:
        """Whether the rule's due date has passed as of the given (scan) date."""
        return self.expires < as_of


class ExceptionsFile(BaseModel):
    """Parsed exceptions file — the top-level YAML document (ADR-0026)."""

    version: int = 1
    exceptions: list[FindingExceptionRule] = Field(default_factory=list)


def load_exceptions_file(path: Path) -> ExceptionsFile:
    """Load and validate an exceptions YAML file.

    Also logs a structlog warning (visible in the CLI's default console
    output) for every rule running longer than ~12 months from today
    (Wiedervorlage-Prinzip, ADR-0026 decision 3) — the tool never rejects
    these, only flags them.

    Raises:
        ExceptionsFileError: the file is missing/unreadable, not valid YAML,
            or fails schema validation — always with a German, human-readable
            message. Callers MUST treat this as fatal (see module docstring).
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExceptionsFileError(f"Ausnahmen-Datei nicht lesbar: {path} ({exc})") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ExceptionsFileError(f"Ausnahmen-Datei ungültig: kein gültiges YAML ({exc})") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ExceptionsFileError(
            "Ausnahmen-Datei ungültig: Wurzelelement muss ein Objekt mit dem Schlüssel 'exceptions' sein."
        )

    try:
        exceptions_file = ExceptionsFile.model_validate(data)
    except ValidationError as exc:
        raise ExceptionsFileError(_format_validation_error(exc)) from exc

    for rule in find_long_running_rules(exceptions_file, datetime.now(UTC).date()):
        logger.warning(
            "exceptions.long_runtime",
            check_id=rule.check_id,
            resource_id=rule.resource_id,
            expires=rule.expires.isoformat(),
            hint="Ausnahme läuft ab heute noch länger als 12 Monate — Wiedervorlage empfohlen.",
        )

    return exceptions_file


def find_long_running_rules(exceptions_file: ExceptionsFile, today: date) -> list[FindingExceptionRule]:
    """Return rules whose runtime from today exceeds ~12 months (ADR-0026 decision 3).

    Exposed separately so the CLI can also surface these prominently
    (structlog output alone may not be visible depending on log level).
    """
    return [rule for rule in exceptions_file.exceptions if (rule.expires - today).days > _WARN_AFTER_DAYS]


def _format_validation_error(exc: ValidationError) -> str:
    """Turn a Pydantic ValidationError into one understandable German message.

    Only the first error is reported — enough to point the customer at the
    problem; they re-run after fixing it. Example:
    "Ausnahmen-Datei ungültig: Eintrag 3 hat kein Pflichtfeld 'expires'".
    """
    first = exc.errors()[0]
    loc = first["loc"]
    field_name = str(loc[-1]) if loc else "?"

    if len(loc) >= 2 and loc[0] == "exceptions" and isinstance(loc[1], int):
        entry_no = loc[1] + 1  # 1-based for the human reader
        if first["type"] == "missing":
            return f"Ausnahmen-Datei ungültig: Eintrag {entry_no} hat kein Pflichtfeld '{field_name}'."
        return f"Ausnahmen-Datei ungültig: Eintrag {entry_no}, Feld '{field_name}': {first['msg']}."

    if first["type"] == "missing":
        return f"Ausnahmen-Datei ungültig: kein Pflichtfeld '{field_name}'."
    return f"Ausnahmen-Datei ungültig: Feld '{field_name}': {first['msg']}."


@dataclass
class ExceptionApplication:
    """Result of applying an exceptions file to a scan's findings (ADR-0026)."""

    applied_count: int = 0
    expired_matches: list[FindingExceptionRule] = field(default_factory=list)


def apply_exceptions(
    findings: list[Finding],
    exceptions_file: ExceptionsFile,
    scan_date: date,
) -> ExceptionApplication:
    """Annotate non-compliant findings in place with matching, active exception rules.

    Fail-safe (ADR-0016/0026): only findings with status NON_COMPLIANT are
    ever considered — positive evidence (COMPLIANT) is never touched, even if
    a rule's check_id/resource_id happens to match it, because an exception
    can only accept a documented defect, never manufacture compliance.

    For each eligible finding, the first matching rule (in file order) that
    is not yet expired is applied via `finding.exception`. If a finding is
    matched only by expired rule(s), no acceptance is made — the defect
    counts in full again — but `finding.expired_exception` is set to the
    first such rule so the report can name it under "Abgelaufene Ausnahmen"
    (ADR-0026 decision 3), and the matching rule(s) are also collected
    (deduplicated across findings) in the returned ExceptionApplication.

    Args:
        findings: Findings to annotate in place (mutated).
        exceptions_file: Parsed, validated exceptions file.
        scan_date: The scan's reference date (UTC) — determines expiry.

    Returns:
        ExceptionApplication with the count of newly annotated findings and
        the list of expired rules that matched at least one still-open finding.
    """
    applied_count = 0
    expired_by_key: dict[tuple[str, str, str, str | None, str | None], FindingExceptionRule] = {}

    for finding in findings:
        if finding.status != FindingStatus.NON_COMPLIANT:
            continue

        active_rule: FindingExceptionRule | None = None
        expired_for_finding: list[FindingExceptionRule] = []
        for rule in exceptions_file.exceptions:
            if not rule.matches(finding):
                continue
            if rule.is_expired(scan_date):
                expired_for_finding.append(rule)
            elif active_rule is None:
                active_rule = rule

        if active_rule is not None:
            finding.exception = FindingExceptionInfo(
                reason=active_rule.reason,
                expires=active_rule.expires,
                author=active_rule.author,
                ticket=active_rule.ticket,
            )
            applied_count += 1
        elif expired_for_finding:
            first_expired = expired_for_finding[0]
            finding.expired_exception = FindingExceptionInfo(
                reason=first_expired.reason,
                expires=first_expired.expires,
                author=first_expired.author,
                ticket=first_expired.ticket,
            )
            for rule in expired_for_finding:
                key = (rule.check_id, rule.resource_id, rule.expires.isoformat(), rule.account_id, rule.region)
                expired_by_key[key] = rule

    return ExceptionApplication(applied_count=applied_count, expired_matches=list(expired_by_key.values()))
