# ADR-0020: Launch-Definition und Definition of Done für Release 0.1

Status: Akzeptiert (2026-07-05, Grilling-Runde 5)

**Launch-Entkopplung:** „Repo öffentlich" und „Launch" sind zwei verschiedene
Ereignisse. Das Repo `nis2scan` wird früh öffentlich und wächst sichtbar
(Build in Public: Commits, Issues, erste Checks). Der **Launch** — Product Hunt,
Hacker News, Pressezeile „scannt AWS & Azure gegen §30 BSIG" — findet erst statt,
wenn Release 0.1 vollständig ist.

**Release 0.1 ist fertig, wenn:**

1. Checks für **AWS und Azure × Nr. 8/9/10** implementiert sind (ADR-0017,
   Option B) — jeder einzelne verifiziert per Integrationstest gegen echte,
   absichtlich teil-nicht-konforme Infrastruktur (ADR-0016) und rechtsgeprüft im
   Vier-Augen-Review (ADR-0018).
2. Der **Permissions-Generator** beide Provider bedient (`nis2scan permissions`:
   AWS IAM Policy und Azure RBAC Role).
3. Die **Attestierungs-Checkliste** ausgegeben wird (MANUAL_REQUIRED /
   NOT_IN_SCOPE mit Attestierungspunkten) — sie ist zugleich der
   Template-Upsell-Pfad.
4. Markdown- und JSON-Report vollständig deutsch sind und `schema_version` **1.0**
   eingefroren ist (Evolutionspolitik: ADR-0021; davor eine dedizierte
   Schema-Review-Session gegen die Phase-2-Bedürfnisse).

**Ausdrücklich nicht in 0.1:** PDF-Report (Premium, kommt mit erstem zahlendem
Bedarf), API/Dashboard (Phase 2), Scheduled Scans (Premium).
