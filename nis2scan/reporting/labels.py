"""German display labels for contract enums (ADR-0004: output German, code English).

Single source for CLI, Markdown/HTML/PDF reports. The JSON contract keeps the
technical enum values; these labels are presentation only.
"""

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.models.result import Erfuellungsgrad

ERFUELLUNGSGRAD_LABELS: dict[Erfuellungsgrad, str] = {
    Erfuellungsgrad.ERFUELLT: "Erfüllt",
    Erfuellungsgrad.TEILWEISE_ERFUELLT: "Teilweise erfüllt",
    Erfuellungsgrad.NICHT_ERFUELLT: "Nicht erfüllt",
    Erfuellungsgrad.NICHT_BEWERTBAR: "Nicht bewertbar",
}

OUTCOME_LABELS: dict[CheckOutcome, str] = {
    CheckOutcome.PASSED: "Bestanden",
    CheckOutcome.FAILED: "Nicht bestanden",
    CheckOutcome.NOT_APPLICABLE: "Nicht anwendbar",
    CheckOutcome.MANUAL_REQUIRED: "Manuelle Prüfung erforderlich",
    CheckOutcome.ERROR: "Fehler — nicht ausgewertet",
    CheckOutcome.NOT_IN_SCOPE: "Nicht im Prüfumfang",
}

FINDING_STATUS_LABELS: dict[FindingStatus, str] = {
    FindingStatus.COMPLIANT: "Konform (Positivnachweis)",
    FindingStatus.NON_COMPLIANT: "Mangel",
}

# ADR-0012: the category is the customer's self-declaration — the label says so.
NIS2_CATEGORY_LABELS: dict[str, str] = {
    "wichtig": "Wichtige Einrichtung (Selbsteinstufung)",
    "besonders_wichtig": "Besonders wichtige Einrichtung (Selbsteinstufung)",
}
