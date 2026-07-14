"""JSON report exporter — serializes ScanResult to file."""

from pathlib import Path

from nis2scan.engine.models.result import ScanResult
from nis2scan.reporting.pseudonymize import ReportProfile, apply_profile


def export_json(result: ScanResult, output_dir: Path, profile: ReportProfile = ReportProfile.INTERN) -> Path:
    """Export ScanResult as JSON file.

    Args:
        result: Complete scan result.
        output_dir: Directory to write the JSON file to.
        profile: Export profile (ADR-0011) — EXTERN pseudonymizes identifiers.

    Returns:
        Path to the written JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = result.scan_timestamp.strftime("%Y%m%d_%H%M%S")
    filename = f"nis2scan_report_{timestamp}.json"
    filepath = output_dir / filename

    filepath.write_text(apply_profile(result, profile).to_json(), encoding="utf-8")
    return filepath
