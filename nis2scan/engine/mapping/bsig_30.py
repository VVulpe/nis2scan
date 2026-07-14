"""§30 Abs. 2 BSIG mapping — the 10 mandatory NIS2 measures.

This is the core legal mapping between §30 BSIG and ISO 27001:2022 controls.
Used for report generation and check registration.
"""

from pydantic import BaseModel, Field

# Legal-basis versioning (ADR-0013): every ScanResult and report states which
# mapping version and Rechtsstand it was checked against.
# 2026.07: law_text_de verified verbatim against the primary source
# (gesetze-im-internet.de/bsig_2025, retrieved 2026-07-11) and Rechtsquelle
# added per ADR-0018; title_de Nr. 7/9 aligned to the statutory wording and the
# Nr. 2/10 descriptions corrected after the second-line review (legal-reviewer
# PASS, 2026-07-12). abdeckung_de Nr. 2 extended to cover reaction/analysis
# building blocks (batch review Nr. 2, B-Nr.2-12). Vier-Augen-Gate closed for
# all areas 2026-07-13 (both sign-offs, see docs/rechtsgrundlagen-review.md).
# nis2umsvo_refs removed 2026-07-13: no promulgated German ordinance with an
# "Anhang I" exists (§ 30 Abs. 5 BSIG authorization not yet exercised).
MAPPING_VERSION = "2026.07"
RECHTSSTAND = "BSIG i. d. F. des NIS2UmsuCG (BGBl. 2025 I Nr. 301), in Kraft seit 06.12.2025"

# Primary source for all §30 Abs. 2 quotes (ADR-0018 Quellenpflicht)
BSIG_30_QUELLE_URL = "https://www.gesetze-im-internet.de/bsig_2025/__30.html"
BSIG_30_ABGERUFEN_AM = "2026-07-11"


class Rechtsquelle(BaseModel):
    """Structured legal-source citation (ADR-0018): primary source only."""

    fundstelle: str = Field(description="Citation, e.g. '§ 30 Abs. 2 Nr. 8 BSIG'")
    url: str = Field(description="URL of the primary source (gesetze-im-internet.de, BGBl, EUR-Lex)")
    abgerufen_am: str = Field(description="Retrieval date (ISO), when the quote was verified")
    zitat: str = Field(description="Verbatim norm text as retrieved from the primary source")


class Bsig30Area(BaseModel):
    """A single §30 BSIG measure area with cross-references.

    Coverage model (ADR-0009): every area declares which partial aspect the
    tool can verify automatically (abdeckung_de) and which evidence must be
    provided manually (attestierungspunkte) — the report prints both, so a
    passed area is never mistaken for full compliance with the measure.
    """

    nr: int = Field(ge=1, le=10, description="§30 Abs. 2 Nr.")
    title_de: str = Field(description="German short title; verbatim statutory wording is in law_text_de")
    title_en: str = Field(description="English translation")
    law_text_de: str = Field(description="Abbreviated German legal text")
    iso27001_controls: list[str] = Field(default_factory=list, description="ISO 27001:2022 control references")
    description_de: str = Field(default="", description="Description in German")
    abdeckung_de: str = Field(
        default="",
        description="German description of the automatically verifiable partial aspect and its boundary (ADR-0009)",
    )
    attestierungspunkte: list[str] = Field(
        default_factory=list,
        description="German checklist of evidence that must be provided manually (ADR-0009/0020)",
    )
    quelle: Rechtsquelle | None = Field(
        default=None,
        description="Primary-source citation for law_text_de (ADR-0018 Quellenpflicht)",
    )


BSIG_30_AREAS: list[Bsig30Area] = [
    Bsig30Area(
        nr=1,
        title_de="Risikoanalyse und IT-Sicherheitskonzepte",
        title_en="Risk analysis and IT security concepts",
        law_text_de=("Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"),
        iso27001_controls=["A.5.1", "A.6.1", "A.8.1"],
        description_de=(
            "Umfasst die systematische Identifikation, Bewertung und Behandlung von Risiken "
            "für die Informationssicherheit. Erfordert eine dokumentierte Sicherheitsleitlinie "
            "und ein Risikoanalyse-Verfahren."
        ),
        abdeckung_de=(
            "Automatisiert geprüft wird ausschließlich, ob technische Grundlagen für die "
            "Risikoerkennung in der Cloud-Umgebung aktiv sind (z. B. Konfigurations-Aufzeichnung, "
            "Bedrohungserkennungsdienste, zentrale Sicherheitsauswertung). Ob eine Risikoanalyse "
            "tatsächlich durchgeführt, dokumentiert und aktuell gehalten wird, kann ein "
            "Cloud-API-Scan strukturell nicht feststellen — aktivierte Dienste sind ein Indiz, "
            "kein Nachweis."
        ),
        attestierungspunkte=[
            "Dokumentierte Informationssicherheitsleitlinie liegt vor und ist von der Leitung freigegeben",
            "Risikoanalyse-Verfahren ist dokumentiert und wird regelmäßig durchgeführt",
            "Risikobehandlungsplan mit Verantwortlichkeiten und Terminen existiert und ist aktuell",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 1 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=("Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik,"),
        ),
    ),
    Bsig30Area(
        nr=2,
        title_de="Bewältigung von Sicherheitsvorfällen",
        title_en="Incident handling",
        law_text_de=("Bewältigung von Sicherheitsvorfällen"),
        iso27001_controls=["A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.5.28"],
        description_de=(
            "Erfordert Prozesse zur Erkennung, Analyse, Eindämmung und Nachbereitung "
            "von Sicherheitsvorfällen. Der Umgang mit Sicherheitsvorfällen muss zudem "
            "die Meldepflichten nach § 32 BSIG berücksichtigen."
        ),
        abdeckung_de=(
            "Automatisiert geprüft wird nur der technische Detektionsunterbau in der "
            "Cloud-Umgebung (Bedrohungserkennung, Alarmierung, Ereignis-Routing) sowie "
            "das Vorhandensein in der Cloud hinterlegter technischer Reaktions- und "
            "Analysebausteine (z. B. Response-Pläne, Automatisierungs-Playbooks, "
            "Forensik-Dienste). Nicht prüfbar sind der Incident-Response-Prozess selbst, "
            "die organisatorische Reaktionsfähigkeit und die Einhaltung der "
            "Meldepflichten nach §32 BSIG."
        ),
        attestierungspunkte=[
            "Incident-Response-Plan ist dokumentiert und wurde in den letzten 12 Monaten geübt",
            "Meldewege an das BSI (§32 BSIG) sind definiert, Fristen und Zuständigkeiten bekannt",
            "Rollen, Eskalationswege und Erreichbarkeiten für Sicherheitsvorfälle sind festgelegt",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 2 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=("Bewältigung von Sicherheitsvorfällen,"),
        ),
    ),
    Bsig30Area(
        nr=3,
        title_de="Aufrechterhaltung des Betriebs",
        title_en="Business continuity management",
        law_text_de=(
            "Aufrechterhaltung des Betriebs, wie Backup-Management und Wiederherstellung "
            "nach einem Notfall, und Krisenmanagement"
        ),
        iso27001_controls=["A.5.29", "A.5.30", "A.8.13", "A.8.14"],
        description_de=(
            "Business Continuity Management inkl. Backup-Strategie, Disaster Recovery, "
            "Wiederanlaufplanung und Krisenmanagement."
        ),
        abdeckung_de=(
            "Automatisiert geprüft werden technische BCM-Bausteine in der Cloud "
            "(Backups, Versionierung, Redundanz über Verfügbarkeitszonen, Health-Checks). "
            "Nicht prüfbar sind das BCM-Konzept, Wiederanlaufpläne, definierte Wiederherstellungsziele "
            "(RTO/RPO) und ob Wiederherstellungen tatsächlich geübt werden."
        ),
        attestierungspunkte=[
            "BCM-/Notfallkonzept ist dokumentiert und von der Leitung freigegeben",
            "Wiederherstellungsziele (RTO/RPO) sind je kritischem System definiert",
            "Wiederherstellungsübungen (Restore-Tests) sind durchgeführt und dokumentiert",
            "Krisenmanagement-Organisation (Stab, Kommunikation) ist festgelegt",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 3 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Aufrechterhaltung des Betriebs, wie Backup-Management und Wiederherstellung "
                "nach einem Notfall, und Krisenmanagement,"
            ),
        ),
    ),
    Bsig30Area(
        nr=4,
        title_de="Sicherheit der Lieferkette",
        title_en="Supply chain security",
        law_text_de=(
            "Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte der "
            "Beziehungen zu unmittelbaren Anbietern oder Diensteanbietern"
        ),
        iso27001_controls=["A.5.19", "A.5.20", "A.5.21", "A.5.22", "A.5.23"],
        description_de=(
            "Bewertung und Management von Sicherheitsrisiken in der Lieferkette, "
            "insbesondere bei Cloud-Providern als Dienstleister."
        ),
        abdeckung_de=(
            "Automatisiert geprüft werden nur technische Lieferketten-Aspekte innerhalb der "
            "Cloud-Umgebung (Ressourcen-Freigaben, organisationsweite Richtlinien, "
            "Cross-Account-Zugriffe). Die eigentliche Lieferkettensicherheit — Bewertung und "
            "vertragliche Steuerung von Anbietern und Dienstleistern — ist organisatorisch "
            "und nicht per Cloud-API prüfbar."
        ),
        attestierungspunkte=[
            "Verzeichnis der unmittelbaren Anbieter und Diensteanbieter mit Risikobewertung liegt vor",
            "Sicherheitsanforderungen an Lieferanten sind vertraglich vereinbart",
            "Kritische Anbieter werden regelmäßig überprüft (Nachweise, Zertifikate, Audits)",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 4 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte der "
                "Beziehungen zu unmittelbaren Anbietern oder Diensteanbietern,"
            ),
        ),
    ),
    Bsig30Area(
        nr=5,
        title_de="Sicherheit bei Erwerb, Entwicklung und Wartung",
        title_en="Security in acquisition, development and maintenance",
        law_text_de=(
            "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von "
            "informationstechnischen Systemen, Komponenten und Prozessen, einschließlich "
            "Management und Offenlegung von Schwachstellen"
        ),
        iso27001_controls=["A.8.25", "A.8.26", "A.8.27", "A.8.28", "A.8.29", "A.8.30", "A.8.31"],
        description_de=(
            "Patch-Management, Schwachstellenmanagement, Secure Development Lifecycle, Change Management und Hardening."
        ),
        abdeckung_de=(
            "Automatisiert geprüft werden technische Indikatoren wie aktivierte "
            "Schwachstellen-Scans, Image-Scanning, Patch-Automatisierung und das Alter von "
            "Betriebssystem-Images. Nicht prüfbar sind der Secure Development Lifecycle, "
            "das Change-Management-Verfahren und der Prozess zur Offenlegung von Schwachstellen."
        ),
        attestierungspunkte=[
            "Patch-Management-Prozess ist dokumentiert (Fristen nach Kritikalität)",
            "Verfahren zum Umgang mit gemeldeten Schwachstellen (inkl. Offenlegung) ist geregelt",
            "Change-Management-Verfahren für IT-Systeme ist dokumentiert und wird angewendet",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 5 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von "
                "informationstechnischen Systemen, Komponenten und Prozessen, einschließlich "
                "Management und Offenlegung von Schwachstellen,"
            ),
        ),
    ),
    Bsig30Area(
        nr=6,
        title_de="Bewertung der Wirksamkeit von Risikomanagementmaßnahmen",
        title_en="Assessment of effectiveness of risk management measures",
        law_text_de=(
            "Konzepte und Verfahren zur Bewertung der Wirksamkeit von "
            "Risikomanagementmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
        ),
        iso27001_controls=["A.5.35", "A.5.36"],
        description_de=(
            "Regelmäßige Überprüfung und Bewertung der Wirksamkeit der Sicherheitsmaßnahmen "
            "durch KPIs, interne Audits und Management-Reviews."
        ),
        abdeckung_de=(
            "Automatisiert geprüft wird nur, ob technische Grundlagen für Wirksamkeitsbewertung "
            "vorhanden sind (manipulationssichere Audit-Protokolle, Regel-Auswertungen, "
            "Sicherheits-Dashboards). Ob Wirksamkeit tatsächlich bewertet wird — interne Audits, "
            "Kennzahlen, Management-Bewertungen — ist organisatorisch und nicht per API prüfbar."
        ),
        attestierungspunkte=[
            "Auditprogramm (interne Überprüfungen) ist festgelegt und wird durchgeführt",
            "Management-Bewertung der Informationssicherheit findet regelmäßig statt und ist dokumentiert",
            "Kennzahlen zur Wirksamkeit der Maßnahmen sind definiert und werden erhoben",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 6 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Konzepte und Verfahren zur Bewertung der Wirksamkeit von "
                "Risikomanagementmaßnahmen im Bereich der Sicherheit in der "
                "Informationstechnik,"
            ),
        ),
    ),
    Bsig30Area(
        nr=7,
        title_de="Grundlegende Schulungen und Sensibilisierung",
        title_en="Basic training and security awareness",
        law_text_de=(
            "grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der "
            "Sicherheit in der Informationstechnik"
        ),
        iso27001_controls=["A.6.3", "A.6.8"],
        description_de=(
            "Schulungsprogramme für alle Mitarbeiter, insbesondere Security-Awareness, "
            "Phishing-Prävention und grundlegende Cyberhygiene."
        ),
        abdeckung_de=(
            "Automatisiert geprüft werden technische Cyberhygiene-Grundlagen in der "
            "Cloud-Umgebung (Passwort-/Kontorichtlinien, sicherheitsrelevante "
            "Organisationsrichtlinien, Sicherheits-Ansprechpartner). Schulungen und "
            "Awareness-Maßnahmen — der Kern dieser Maßnahme — sind nicht per Cloud-API prüfbar."
        ),
        attestierungspunkte=[
            "Schulungsprogramm zur Informationssicherheit existiert; Teilnahmenachweise liegen vor",
            "Auch Geschäftsleitung/Leitungsorgane nehmen nachweislich an Schulungen teil",
            "Regelmäßige Awareness-Maßnahmen (z. B. Phishing-Simulationen) werden durchgeführt",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 7 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der "
                "Sicherheit in der Informationstechnik,"
            ),
        ),
    ),
    Bsig30Area(
        nr=8,
        title_de="Kryptographie",
        title_en="Cryptography",
        law_text_de=("Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"),
        iso27001_controls=["A.8.24"],
        description_de=(
            "Einsatz kryptographischer Verfahren für Verschlüsselung at Rest und in Transit, "
            "Key-Management, Zertifikatsmanagement."
        ),
        abdeckung_de=(
            "Dieser Bereich ist cloud-technisch gut prüfbar: Verschlüsselung at Rest und in "
            "Transit, Schlüsselrotation, TLS-Mindestversionen und Zertifikatsgültigkeit werden "
            "automatisiert geprüft. Nicht prüfbar ist das Kryptokonzept selbst — welche Verfahren "
            "wofür einzusetzen sind und wie Schlüssel organisatorisch verwaltet werden."
        ),
        attestierungspunkte=[
            "Kryptokonzept ist dokumentiert (Verfahren, Schlüssellängen, Einsatzbereiche)",
            "Prozess für Schlüsselverwaltung und -wechsel ist festgelegt (auch außerhalb der Cloud)",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 8 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=("Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren,"),
        ),
    ),
    Bsig30Area(
        nr=9,
        title_de="Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung",
        title_en="Personnel security, access control and ICT management",
        law_text_de=(
            "Erstellung von Konzepten für die Sicherheit des Personals, die "
            "Zugriffskontrolle und für die Verwaltung von IKT-Systemen, -Produkten und "
            "-Prozessen"
        ),
        iso27001_controls=[
            "A.5.9",
            "A.5.10",
            "A.5.11",
            "A.5.12",
            "A.5.13",
            "A.5.14",
            "A.5.15",
            "A.5.16",
            "A.5.17",
            "A.5.18",
        ],
        description_de=(
            "Asset-Inventar, Zugriffskontrollkonzept (Least Privilege, Need-to-Know), "
            "IAM-Governance, Joiner/Mover/Leaver-Prozesse."
        ),
        abdeckung_de=(
            "Automatisiert geprüft wird die technische Zugriffskontrolle in der Cloud "
            "(IAM-Rollen und -Richtlinien, Schlüsselhygiene, Netzwerkzugriffe, öffentliche "
            "Freigaben). Nicht prüfbar sind Personalsicherheit, das Zugriffskontrollkonzept "
            "als Dokument, Joiner/Mover/Leaver-Prozesse und das Asset-Inventar außerhalb "
            "der gescannten Cloud-Umgebung."
        ),
        attestierungspunkte=[
            "Zugriffskontrollkonzept (Least Privilege, Need-to-Know) ist dokumentiert",
            "Prozess für Eintritt/Wechsel/Austritt (Joiner/Mover/Leaver) inkl. Rechteentzug ist geregelt",
            "Asset-Inventar umfasst auch Systeme außerhalb der gescannten Cloud-Umgebung",
            "Maßnahmen zur Personalsicherheit (Verpflichtungen, Vertraulichkeit) sind umgesetzt",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 9 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Erstellung von Konzepten für die Sicherheit des Personals, die "
                "Zugriffskontrolle und für die Verwaltung von IKT-Systemen, -Produkten und "
                "-Prozessen,"
            ),
        ),
    ),
    Bsig30Area(
        nr=10,
        title_de="MFA und gesicherte Kommunikation",
        title_en="MFA and secured communication",
        law_text_de=(
            "Verwendung von Lösungen zur Multi-Faktor-Authentifizierung oder "
            "kontinuierlichen Authentifizierung, gesicherte Sprach-, Video- und "
            "Textkommunikation sowie gegebenenfalls gesicherte Notfallkommunikationssysteme "
            "innerhalb der Einrichtung"
        ),
        iso27001_controls=["A.8.5", "A.5.14"],
        description_de=(
            "Multi-Faktor- oder kontinuierliche Authentifizierung für Zugänge, gesicherte "
            "Kommunikationskanäle, Notfallkommunikation bei kompromittierten Systemen."
        ),
        abdeckung_de=(
            "Automatisiert geprüft wird die MFA-Konfiguration der Cloud-Zugänge und die "
            "Absicherung administrativer Zugriffswege. Nicht prüfbar sind MFA außerhalb der "
            "Cloud (z. B. VPN, lokale Systeme), gesicherte Sprach-, Video- und Textkommunikation "
            "sowie Notfallkommunikationssysteme."
        ),
        attestierungspunkte=[
            "MFA oder kontinuierliche Authentifizierung ist für Zugänge geregelt; der "
            "Geltungsbereich (auch außerhalb der gescannten Cloud-Umgebung) ist dokumentiert",
            "Gesicherte Kommunikationsmittel (Sprache, Video, Text) sind festgelegt und im Einsatz",
            "Notfallkommunikationssystem für den Fall kompromittierter Systeme ist definiert",
        ],
        quelle=Rechtsquelle(
            fundstelle="§ 30 Abs. 2 Nr. 10 BSIG",
            url=BSIG_30_QUELLE_URL,
            abgerufen_am=BSIG_30_ABGERUFEN_AM,
            zitat=(
                "Verwendung von Lösungen zur Multi-Faktor-Authentifizierung oder "
                "kontinuierlichen Authentifizierung, gesicherte Sprach-, Video- und "
                "Textkommunikation sowie gegebenenfalls gesicherte Notfallkommunikationssysteme "
                "innerhalb der Einrichtung."
            ),
        ),
    ),
]

BSIG_30_BY_NR: dict[int, Bsig30Area] = {area.nr: area for area in BSIG_30_AREAS}


def get_area(nr: int) -> Bsig30Area:
    """Get a §30 area by number."""
    return BSIG_30_BY_NR[nr]


def get_all_areas() -> list[Bsig30Area]:
    """Get all §30 areas."""
    return BSIG_30_AREAS
