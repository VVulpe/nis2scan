---
name: nis2-legal-review
description: Mandatory legal-source review for changes to §30 BSIG mappings, checks, or report texts that state legal requirements. Use when creating or modifying mapping entries, check modules, remediation texts, or report wording referencing BSIG, NIS2UmsVO, the NIS2 directive, or ISO 27001. Triggers on Rechtsgrundlage, Quelle, Fundstelle, §30, BSIG, NIS2UmsVO, Gesetz, legal, mapping, Normtext.
allowed-tools: Read, Grep, Glob, WebFetch, WebSearch
---

# Rechtsgrundlagen-Review (ADR-0018)

nis2scan must never drift from the actual legal requirements. Every legal claim in
mapping data, check metadata, or report text needs a verifiable primary source.
No merge of mapping/check changes without this review.

## Quellenpflicht — legal basis as data

Every mapping entry and every check declares:

```yaml
legal_basis:
  bsig_ref: "§30 Abs. 2 Nr. 8 BSIG"
  iso_ref: "A.8.24"                   # cross-reference only, never a compliance claim
  source_url: "https://www.gesetze-im-internet.de/..."
  retrieved_at: "2026-07-05"
  quote: "exakter Normtext-Auszug, auf den sich der Check stützt"
```

## Zulässige Quellen (Rangfolge)

1. **Primärquellen:** gesetze-im-internet.de (BSIG), Bundesgesetzblatt (bgbl.de),
   EUR-Lex (RL (EU) 2022/2555)
2. **Behördliche Sekundärquellen:** BSI-Veröffentlichungen und -FAQ
3. **Nie alleinige Grundlage:** Blogposts, Berater-Whitepaper, Modellwissen ohne Quelle

## Review-Checkliste (vor jedem Merge)

1. **Normtext-Abgleich:** `source_url` per WebFetch abrufen; stimmen Nummer und
   Wortlaut mit `quote` überein? Bei Abweichung: stoppen, nicht raten.
2. **Rechtsstand:** Passt der Eintrag zum deklarierten Rechtsstand des Mappings
   (ADR-0013)? `retrieved_at` aktuell?
3. **Teilaspekt-Grenze:** Macht ein Text eine Aussage über die §30-Maßnahme als
   Ganzes statt über den cloud-technischen Teilaspekt? Verboten (ADR-0009).
4. **Keine Rechtsberatung:** Remediation = technische Empfehlung. Aussagen über
   Rechtsfolgen, Betroffenheit oder Kategorien sind verboten (ADR-0012).
5. **Formulierungsregel bei Unsicherheit:** „technisches Indiz für …" — niemals
   „erfüllt §…".

## Review-Vermerk

Jede geprüfte Änderung bekommt einen kurzen Vermerk in PR- oder Commit-Message:
geprüfte Quellen (URLs), Ergebnis, offene Zweifel. Ohne Vermerk kein Merge.
