---
name: nis2-report
description: Generate or modify NIS2 compliance reports. Use when working on Markdown report templates, PDF generation, JSON export, or the Jinja2 report template. Triggers on report, template, markdown, PDF, Jinja, output, Bericht, Nachweis.
allowed-tools: Read, Write, Edit, Bash, Grep
---

# NIS2 Report Generation

## Report Flow (ALWAYS follow this)

```
ScanResult (Pydantic) → JSON file → Jinja2 template → Markdown → (optional) PDF
```

NEVER generate report content directly from check results. Always go through the JSON intermediate format. This ensures JSON and report are always consistent.

## Report Language
- ALL report text is in GERMAN
- Technical identifiers (ARNs, resource IDs, API names) remain in English
- Use formal German ("Sie" not "du")

## Markdown Report Structure

```markdown
# NIS2 Compliance-Bericht — §30 BSIG
## Unternehmen: {{ company.name }}
## Datum: {{ scan_timestamp | format_date }}
## Scope: {{ config.providers | format_scope }}

### Zusammenfassung
- Gesamtstatus: {{ summary.overall_status }}
- Findings: {{ summary.total }} ({{ summary.critical }} kritisch, {{ summary.high }} hoch)
- §30-Abdeckung: {{ summary.areas_scanned }}/10

### Compliance-Matrix
[Table: Nr | Bereich | Status-Emoji | Findings | Höchste Severity]

### Detailergebnisse nach §30-Bereich
[For each §30 area: legal text, ISO reference, then findings sorted by severity]

### Anhang A: Methodik
### Anhang B: Geprüfte Ressourcen ({{ total_resources }} Ressourcen)
### Anhang C: §30 BSIG Volltext
### Anhang D: Scan-Konfiguration
```

## Status Emojis (for Markdown)
- ✅ COMPLIANT — no findings HIGH or above
- ⚠️ PARTIALLY_COMPLIANT — findings exist but none CRITICAL
- ❌ NON_COMPLIANT — CRITICAL findings exist
- ⏭️ NOT_SCANNED — area was excluded from scan config

## Audit Evidence Rules
- Include raw API response (sanitized) as code blocks
- Remove any PII (IAM usernames → pseudonymized)
- Timestamp every evidence block
- Evidence must be sufficient for an external auditor to verify the finding independently
