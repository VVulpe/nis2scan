# ADR-0022: GCP als experimenteller Provider

Status: Akzeptiert (2026-07-05, Grilling-Runde 6 / Audit)

> **Banner-Bedingung erfüllt (2026-07-13):** Alle 51 GCP-Checks haben den
> Rechtsgrundlagen-Review (ADR-0018, W4-Kampagne, Batches Nr. 1–10) mit beiden
> Vermerken durchlaufen — das unten geforderte Experimental-Banner ist damit
> gegenstandslos, bevor es implementiert werden musste. Die Paritäts-Invariante
> aus ADR-0017 gilt ab jetzt für drei Provider. Launch-Kommunikation 0.1
> bleibt AWS + Azure zuerst (unverändert).

Das Code-Audit fand 51 fertige, integrationsgetestete GCP-Checks — ein dritter
Provider, der in keinem Plan und keinem ADR vorkam. Entscheidung: **behalten,
ehrlich labeln.**

- Die GCP-Checks bleiben im Code und sind nutzbar.
- Die 0.1-Launch-Kommunikation nennt **AWS + Azure**; GCP wird nicht beworben.
- Solange die GCP-Checks den Rechtsgrundlagen-Review (ADR-0018) nicht durchlaufen
  haben, tragen GCP-Ergebnisse in Report und CLI ein sichtbares Banner:
  „GCP-Unterstützung ist experimentell — Rechtsgrundlagen-Review ausstehend."
  Das folgt derselben Ehrlichkeitslinie wie ADR-0016: nie mehr behaupten, als
  geprüft ist.
- Nach Abschluss der Review-Kampagne (Audit-Welle W4) auch für GCP fällt das
  Banner; ADR-0017s Paritäts-Invariante gilt dann für drei Provider.

## Konsequenz

ADR-0017 ist entsprechend zu lesen: Zielbild = volle Abdeckung AWS + Azure + GCP;
Launch-Anspruch und Review-Reihenfolge bleiben AWS + Azure zuerst.
