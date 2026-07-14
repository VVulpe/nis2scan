# ADR-0003: Scanner strikt read-only

Status: Akzeptiert (nachträglich dokumentiert, 2026-07-04)

## Kontext

Das Tool läuft mit Cloud-Credentials des Kunden in produktiven Umgebungen. Die
Zielgruppe (Mittelstand ohne GRC-Team) muss dem Tool eines Einzelanbieters
vertrauen können; ein einziger schreibender Vorfall wäre das Ende des Produkts.

## Entscheidung

Der Scanner liest ausschließlich. Er schreibt, ändert oder löscht niemals
Cloud-Ressourcen. Jeder Check deklariert `required_permissions` explizit
(Permission-as-Code); daraus wird die minimale IAM-Policy/RBAC-Rolle generiert
(`nis2scan permissions`), die ausschließlich Read-Berechtigungen enthält.

## Konsequenzen

- Remediation bleibt Sache des Kunden; das Tool liefert nur Empfehlungstexte.
- Der Permission-Generator ist zugleich der Nachweis der Harmlosigkeit —
  Vertriebsargument gegenüber IT-Admins.
- Kein Check darf Berechtigungen anfordern, die über Describe/Get/List
  hinausgehen; das ist im Review jedes Check-Moduls zu prüfen.
