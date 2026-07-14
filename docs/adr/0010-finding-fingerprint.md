# ADR-0010: Stabiler Finding-Fingerprint ab Phase 1

Status: Akzeptiert (2026-07-04, Grilling-Runde 2)

Verlaufs-Tracking (`first_seen` / `resolved`, Phase 2) braucht eine stabile Identität
desselben Findings über Scans hinweg — und die muss im Phase-1-JSON-Vertrag liegen,
sonst ist die früh gesammelte Scan-Historie wertlos. Jedes Finding trägt deshalb einen
`finding_key`: HMAC-SHA-256 (kundenspezifisches Secret, ENV `NIS2SCAN_SECRET`) über
`(provider, account_id, check_id, kanonische Prüfobjekt-ID)`.

Regeln:

- Kanonische Prüfobjekt-ID ist die unveränderliche native Ressourcen-ID (AWS ARN,
  Azure Resource ID) — nie der Anzeigename.
- Gelöscht und gleichnamig neu erstellt (neue native ID) = **neues** Finding; das alte
  gilt als resolved. Bekannte Grenzfälle, bewusst akzeptiert: S3-ARNs sind
  namensbasiert (Neuanlage ⇒ gleicher Key); Azure-Resource-IDs enthalten die Resource
  Group (Verschieben ⇒ neuer Key).
- Bei Checks auf Account-/Subscription-Ebene (z. B. Root-MFA) ist das Prüfobjekt der
  Account selbst; kanonische ID = Account-/Subscription-ID.
- HMAC statt Klartext-Tupel oder ungesalzenem Hash, damit der Key in extern
  weitergegebenen Reports keine Identifikatoren (IAM-Usernamen!) leakt und nicht per
  Wörterbuch angreifbar ist. Dasselbe Secret erzeugt auch die Pseudonyme (ADR-0011) —
  ein Secret, zwei Verwendungen.

## Konsequenzen

- Verlust des Kunden-Secrets bricht die Tracking-Historie; das Secret gehört in die
  gesicherte Kundenkonfiguration (ENV/Secret-Store, nie in die YAML).
- Die Phase-2-Tabelle `findings` bekommt eine `finding_key`-Spalte samt Index.
