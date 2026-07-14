"""Customer secret for finding fingerprints and pseudonyms (ADR-0010/0011).

The secret keys the HMAC-SHA256 used for finding_key (stable cross-scan
identity) and for export-time pseudonyms. It is never stored in the YAML
config — resolution order:

1. NIS2SCAN_SECRET environment variable (CI, secret stores)
2. Secret file ~/.nis2scan/secret, created by `nis2scan init`
"""

import os
import secrets
import stat
from pathlib import Path

SECRET_ENV = "NIS2SCAN_SECRET"
SECRET_FILE = Path.home() / ".nis2scan" / "secret"


def resolve_secret() -> bytes | None:
    """Resolve the customer secret: environment first, then the secret file."""
    env_value = os.environ.get(SECRET_ENV)
    if env_value:
        return env_value.encode("utf-8")
    try:
        file_value = SECRET_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return file_value.encode("utf-8") if file_value else None


def generate_secret() -> str:
    """Generate a new 256-bit secret as hex string."""
    return secrets.token_hex(32)


def persist_secret(value: str) -> Path:
    """Write the secret to the secret file, owner-readable only."""
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_FILE.write_text(value + "\n", encoding="utf-8")
    if os.name == "posix":
        SECRET_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return SECRET_FILE
