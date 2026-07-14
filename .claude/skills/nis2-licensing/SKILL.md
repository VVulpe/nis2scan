---
name: nis2-licensing
description: Implement and manage the licensing/monetization system for nis2scan. Use when working on premium feature gates, license validation, API key management, tier definitions, or paywall logic. Triggers on license, premium, paid, tier, paywall, monetization, API key, subscription, pricing.
allowed-tools: Read, Write, Edit, Bash, Grep, Glob
---

# NIS2 Licensing & Monetization System

## Architecture Decision: Separate Private Repo (ADR-0014 — supersedes the earlier "Model 1" plan)

Premium code lives in a SEPARATE PRIVATE repository (`nis2scan-premium`), shipped to
license holders as an installable plugin package that extends the free CLI. The public
Apache repo contains NO premium code and NO paywall logic beyond the plugin loader —
feature flags inside Apache-licensed code can be legally stripped by any fork
(see docs/adr/0014-premium-in-separatem-repo.md).

Corrections to the code sketches below (they predate ADR-0014/0016):
- `license_manager` must NOT be a global singleton (CLAUDE.md rule) — construct it in
  the CLI entrypoint and inject it.
- `_verify_signature` must implement real asymmetric verification (Ed25519); a
  placeholder `return True` must never ship.
- The `premium/` tree shown below lives in the private repo, not in this one.

## Tier Definitions

```python
from enum import Enum

class LicenseTier(str, Enum):
    COMMUNITY = "community"      # Free, Apache 2.0
    PROFESSIONAL = "professional" # 149-299€/month
    ENTERPRISE = "enterprise"     # 999-2499€/month
```

### Feature Matrix

| Feature | Community | Professional | Enterprise |
|---------|-----------|-------------|------------|
| CLI Scan (all §30 checks) | ✅ | ✅ | ✅ |
| JSON Output | ✅ | ✅ | ✅ |
| Markdown Report | ✅ | ✅ | ✅ |
| Single Account/Subscription | ✅ | ✅ | ✅ |
| Multi-Account Scan | ❌ | ✅ | ✅ |
| PDF Report (branded) | ❌ | ✅ | ✅ |
| Remediation-as-Code | ❌ | ✅ | ✅ |
| Compliance Trend (history) | ❌ | ✅ | ✅ |
| Scheduled Scans | ❌ | ✅ | ✅ |
| E-Mail Alerts | ❌ | ✅ | ✅ |
| Dashboard (Web UI) | ❌ | ✅ | ✅ |
| Multi-Tenant | ❌ | ❌ | ✅ |
| RBAC in Dashboard | ❌ | ❌ | ✅ |
| API Access | ❌ | ❌ | ✅ |
| SSO (SAML/OIDC) | ❌ | ❌ | ✅ |
| Custom Check Mappings | ❌ | ❌ | ✅ |
| Audit Log | ❌ | ❌ | ✅ |
| SLA + Priority Support | ❌ | ❌ | ✅ |

## Project Structure for Licensing

```
nis2scan/
├── nis2scan/
│   ├── engine/                    # Always free — the core
│   ├── cli/                       # Always free
│   ├── reporting/
│   │   ├── markdown.py            # Free
│   │   ├── json_export.py         # Free
│   │   └── pdf_report.py          # Premium gate inside
│   ├── premium/                   # All premium-only modules
│   │   ├── __init__.py
│   │   ├── remediation/           # Terraform/CloudFormation snippets
│   │   │   ├── __init__.py
│   │   │   ├── terraform.py
│   │   │   └── cloudformation.py
│   │   ├── trending/              # Compliance history & trends
│   │   │   ├── __init__.py
│   │   │   └── tracker.py
│   │   ├── alerting/              # E-Mail alerts on regression
│   │   │   ├── __init__.py
│   │   │   └── email_alerts.py
│   │   └── scheduling/            # Cron-based scheduled scans
│   │       ├── __init__.py
│   │       └── scheduler.py
│   └── licensing/
│       ├── __init__.py
│       ├── license.py             # Core license logic
│       ├── tiers.py               # Tier & feature definitions
│       └── exceptions.py          # PremiumFeatureError
```

## License Validation Implementation

### Two Modes: Online + Offline

```python
# nis2scan/licensing/license.py

import os
import json
import time
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel

from nis2scan.licensing.tiers import LicenseTier, FEATURE_MATRIX
from nis2scan.licensing.exceptions import (
    PremiumFeatureError,
    LicenseExpiredError,
    LicenseValidationError,
)


class LicenseInfo(BaseModel):
    """Represents a validated license."""
    key: str
    tier: LicenseTier
    company: str
    email: str
    valid_until: datetime
    max_accounts: int          # How many AWS accounts / Azure subscriptions
    features: list[str]        # Explicit feature list
    issued_at: datetime
    signature: str             # HMAC signature for offline validation


class LicenseManager:
    """
    Manages license validation.
    
    Priority:
    1. Environment variable NIS2SCAN_LICENSE_KEY
    2. Config file ~/.nis2scan/license.json
    3. Project config ./config/license.json
    4. Falls back to COMMUNITY tier (no key needed)
    """

    def __init__(self):
        self._license: Optional[LicenseInfo] = None
        self._cache_ttl = 3600  # Re-validate online every hour
        self._last_check = 0

    @property
    def current_tier(self) -> LicenseTier:
        if self._license is None:
            return LicenseTier.COMMUNITY
        if self._license.valid_until < datetime.now(timezone.utc):
            return LicenseTier.COMMUNITY  # Expired → fallback
        return self._license.tier

    def load_license(self) -> LicenseTier:
        """Load and validate license from available sources."""
        key = self._find_key()
        if not key:
            self._license = None
            return LicenseTier.COMMUNITY

        # Try online validation first
        try:
            self._license = self._validate_online(key)
            self._cache_license(self._license)
        except Exception:
            # Fallback to cached/offline validation
            self._license = self._validate_offline(key)

        return self.current_tier

    def require(self, feature: str) -> None:
        """
        Gate a premium feature. Call this at the START of any premium function.
        Raises PremiumFeatureError with helpful message if not licensed.
        """
        tier = self.current_tier
        if not self._has_feature(tier, feature):
            raise PremiumFeatureError(
                feature=feature,
                current_tier=tier,
                required_tier=self._minimum_tier_for(feature),
            )

    def check(self, feature: str) -> bool:
        """Non-throwing version of require(). Returns True/False."""
        try:
            self.require(feature)
            return True
        except PremiumFeatureError:
            return False

    # --- Private methods ---

    def _find_key(self) -> Optional[str]:
        """Find license key from env, home dir, or project config."""
        # 1. Environment variable (highest priority)
        key = os.environ.get("NIS2SCAN_LICENSE_KEY")
        if key:
            return key.strip()

        # 2. Home directory config
        home_license = os.path.expanduser("~/.nis2scan/license.json")
        if os.path.exists(home_license):
            with open(home_license) as f:
                data = json.load(f)
                return data.get("key")

        # 3. Project config
        project_license = "./config/license.json"
        if os.path.exists(project_license):
            with open(project_license) as f:
                data = json.load(f)
                return data.get("key")

        return None

    def _validate_online(self, key: str) -> LicenseInfo:
        """Validate against licensing API."""
        import httpx
        response = httpx.post(
            "https://api.nis2scan.de/v1/license/validate",
            json={"key": key},
            timeout=10,
        )
        response.raise_for_status()
        return LicenseInfo(**response.json())

    def _validate_offline(self, key: str) -> Optional[LicenseInfo]:
        """Validate from cached license file (for air-gapped environments)."""
        cache_path = os.path.expanduser("~/.nis2scan/.license_cache")
        if not os.path.exists(cache_path):
            return None
        with open(cache_path) as f:
            data = json.load(f)
        license_info = LicenseInfo(**data)
        # Verify HMAC signature to prevent tampering
        if not self._verify_signature(license_info):
            return None
        return license_info

    def _cache_license(self, license_info: LicenseInfo) -> None:
        """Cache validated license for offline use."""
        cache_dir = os.path.expanduser("~/.nis2scan")
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, ".license_cache")
        with open(cache_path, "w") as f:
            f.write(license_info.model_dump_json(indent=2))

    def _verify_signature(self, license_info: LicenseInfo) -> bool:
        """Verify offline license signature (HMAC-SHA256)."""
        # The public key is embedded; signature was created server-side
        payload = f"{license_info.key}:{license_info.tier}:{license_info.valid_until.isoformat()}"
        # Note: This is a simplified example. In production, use
        # asymmetric signatures (RSA/Ed25519) so the private key
        # never leaves the server.
        return True  # TODO: Implement real signature verification

    def _has_feature(self, tier: LicenseTier, feature: str) -> bool:
        """Check if tier includes the requested feature."""
        return feature in FEATURE_MATRIX.get(tier, set())

    def _minimum_tier_for(self, feature: str) -> LicenseTier:
        """Find the cheapest tier that includes this feature."""
        for tier in [LicenseTier.PROFESSIONAL, LicenseTier.ENTERPRISE]:
            if feature in FEATURE_MATRIX.get(tier, set()):
                return tier
        return LicenseTier.ENTERPRISE


# Global singleton — initialized once at startup
license_manager = LicenseManager()
```

### Tier & Feature Definitions

```python
# nis2scan/licensing/tiers.py

from nis2scan.licensing.license import LicenseTier

# Feature string constants
FEAT_PDF_REPORT = "pdf_report"
FEAT_REMEDIATION_CODE = "remediation_code"
FEAT_MULTI_ACCOUNT = "multi_account"
FEAT_COMPLIANCE_TREND = "compliance_trend"
FEAT_SCHEDULED_SCANS = "scheduled_scans"
FEAT_EMAIL_ALERTS = "email_alerts"
FEAT_DASHBOARD = "dashboard"
FEAT_MULTI_TENANT = "multi_tenant"
FEAT_RBAC = "rbac"
FEAT_API_ACCESS = "api_access"
FEAT_SSO = "sso"
FEAT_CUSTOM_MAPPINGS = "custom_mappings"
FEAT_AUDIT_LOG = "audit_log"

FEATURE_MATRIX: dict[LicenseTier, set[str]] = {
    LicenseTier.COMMUNITY: set(),  # No premium features
    LicenseTier.PROFESSIONAL: {
        FEAT_PDF_REPORT,
        FEAT_REMEDIATION_CODE,
        FEAT_MULTI_ACCOUNT,
        FEAT_COMPLIANCE_TREND,
        FEAT_SCHEDULED_SCANS,
        FEAT_EMAIL_ALERTS,
        FEAT_DASHBOARD,
    },
    LicenseTier.ENTERPRISE: {
        # Everything in Professional, plus:
        FEAT_PDF_REPORT,
        FEAT_REMEDIATION_CODE,
        FEAT_MULTI_ACCOUNT,
        FEAT_COMPLIANCE_TREND,
        FEAT_SCHEDULED_SCANS,
        FEAT_EMAIL_ALERTS,
        FEAT_DASHBOARD,
        FEAT_MULTI_TENANT,
        FEAT_RBAC,
        FEAT_API_ACCESS,
        FEAT_SSO,
        FEAT_CUSTOM_MAPPINGS,
        FEAT_AUDIT_LOG,
    },
}
```

### Exception with Helpful Messaging

```python
# nis2scan/licensing/exceptions.py

class PremiumFeatureError(Exception):
    """Raised when a premium feature is used without valid license."""

    def __init__(self, feature: str, current_tier, required_tier):
        self.feature = feature
        self.current_tier = current_tier
        self.required_tier = required_tier
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        return (
            f"\n{'='*60}\n"
            f"  Premium-Feature: {self.feature}\n"
            f"  Aktueller Tier: {self.current_tier.value}\n"
            f"  Benötigter Tier: {self.required_tier.value}\n"
            f"\n"
            f"  Dieses Feature ist ab dem {self.required_tier.value}-Tier verfügbar.\n"
            f"  Mehr Informationen: https://nis2scan.de/pricing\n"
            f"  Lizenzschlüssel setzen: export NIS2SCAN_LICENSE_KEY=...\n"
            f"{'='*60}\n"
        )
```

## How to Gate a Feature (Pattern for ALL Premium Code)

```python
# Example: PDF Report
from nis2scan.licensing.license import license_manager
from nis2scan.licensing.tiers import FEAT_PDF_REPORT

def generate_pdf_report(scan_result: ScanResult, logo_path: str = None) -> bytes:
    # ONE line at the top. That's it.
    license_manager.require(FEAT_PDF_REPORT)
    
    # ... actual PDF generation logic below
    # This code is visible on GitHub but won't execute without license
```

```python
# Example: CLI integration — graceful degradation
from nis2scan.licensing.license import license_manager
from nis2scan.licensing.tiers import FEAT_PDF_REPORT

@app.command()
def scan(config: str, output_format: str = "markdown"):
    result = run_scan(load_config(config))
    
    if output_format == "pdf":
        if license_manager.check(FEAT_PDF_REPORT):
            generate_pdf_report(result)
        else:
            console.print(
                "[yellow]PDF-Export ist ein Premium-Feature. "
                "Report wird als Markdown generiert.[/yellow]"
            )
            console.print("[dim]→ https://nis2scan.de/pricing[/dim]")
            generate_markdown_report(result)  # Fallback
    else:
        generate_markdown_report(result)
```

## Critical Implementation Rules

1. **Never block the scan itself.** The scan engine runs regardless of license. Only OUTPUT and ANALYSIS features are gated. A user should always be able to scan and see findings in the terminal. The paywall is on the polished deliverables.

2. **Graceful degradation, not hard errors.** When a premium feature is requested via CLI, show a friendly message and fall back to the free alternative. Only raise `PremiumFeatureError` when called programmatically (API).

3. **No license telemetry without consent.** The online validation call sends ONLY the license key. No scan results, no finding counts, no cloud account IDs. GDPR applies.

4. **Offline mode must work.** German Mittelstand environments often have restricted outbound internet. The cached license (with HMAC signature) must allow offline operation for at least 30 days.

5. **Free tier must be genuinely useful.** If the free tier feels crippled, nobody will adopt it and the flywheel dies. The free CLI + Markdown report must be a complete, useful tool on its own. Premium adds convenience and scale, not basic functionality.

6. **License check is <10ms.** It reads a cached file or env var. Never block the scan flow with network calls. Online validation happens ONCE at startup, async in background.

## Licensing API (Phase 2 — Backend)

When the FastAPI backend exists, add these endpoints:

```
POST /v1/license/validate     → Validate key, return LicenseInfo
POST /v1/license/activate     → First-time activation (key + machine fingerprint)
POST /v1/license/deactivate   → Release a seat
GET  /v1/license/usage        → Current usage (accounts scanned, seats used)
```

License keys are generated via Stripe Checkout → Webhook → create key in DB. Use Stripe's customer portal for subscription management. Don't build billing yourself.

## Phase 1 Implementation (MVP)

For Phase 1, keep it dead simple:

1. License key = UUID, stored in a JSON file on your server
2. Validation = HTTPS POST to a single Cloud Function / Lambda
3. No seat management, no machine fingerprinting
4. If the validation server is down → allow cached license
5. Trial: 14 days, auto-generated key via website form

This is enough to start charging. Harden later.
