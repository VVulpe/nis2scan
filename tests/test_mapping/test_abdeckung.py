"""Tests for the coverage model in the §30 mapping (ADR-0009/0020)."""

from nis2scan.engine.mapping.bsig_30 import BSIG_30_AREAS


class TestAbdeckungsmodell:
    def test_every_area_declares_its_automatable_partial_aspect(self):
        for area in BSIG_30_AREAS:
            assert area.abdeckung_de, f"Nr. {area.nr} ohne Abdeckungsangabe (ADR-0009)"
            assert "prüf" in area.abdeckung_de.lower(), f"Nr. {area.nr}: Abdeckungstext benennt keine Prüfaussage"

    def test_every_area_has_attestation_checklist(self):
        for area in BSIG_30_AREAS:
            assert len(area.attestierungspunkte) >= 2, f"Nr. {area.nr} ohne Attestierungspunkte (ADR-0020)"

    def test_coverage_texts_never_claim_full_compliance(self):
        # Sprachregel (ADR-0009): der Teilaspekt wird bewertet, nie die Maßnahme als Ganzes
        for area in BSIG_30_AREAS:
            assert "vollständig erfüllt" not in area.abdeckung_de.lower()
            assert "nis2-konform" not in area.abdeckung_de.lower()
