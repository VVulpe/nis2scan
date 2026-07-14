"""Tests for the Quellenpflicht in the §30 mapping (ADR-0018)."""

from nis2scan.engine.mapping.bsig_30 import BSIG_30_AREAS

PRIMARY_SOURCE_HOSTS = ("gesetze-im-internet.de", "recht.bund.de", "eur-lex.europa.eu")


class TestQuellenpflicht:
    def test_every_area_has_primary_source(self):
        for area in BSIG_30_AREAS:
            assert area.quelle is not None, f"Nr. {area.nr} ohne Rechtsquelle (ADR-0018)"
            assert any(h in area.quelle.url for h in PRIMARY_SOURCE_HOSTS), (
                f"Nr. {area.nr}: keine Primärquelle: {area.quelle.url}"
            )
            assert area.quelle.abgerufen_am, f"Nr. {area.nr} ohne Abrufdatum"
            assert area.quelle.zitat, f"Nr. {area.nr} ohne Normtext-Zitat"

    def test_law_text_matches_verbatim_quote(self):
        # law_text_de is the quote minus the enumeration punctuation — any
        # drift between report text and primary-source quote fails here
        for area in BSIG_30_AREAS:
            assert area.law_text_de == area.quelle.zitat.rstrip(",."), (
                f"Nr. {area.nr}: law_text_de weicht vom Primärquellen-Zitat ab"
            )

    def test_fundstelle_names_the_area(self):
        for area in BSIG_30_AREAS:
            assert f"Nr. {area.nr}" in area.quelle.fundstelle
            assert "BSIG" in area.quelle.fundstelle
