"""Markdown report generator — generates audit-ready compliance reports from ScanResult."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from nis2scan.engine.models.result import ScanResult
from nis2scan.reporting.context import build_report_context
from nis2scan.reporting.pseudonymize import ReportProfile, apply_profile

TEMPLATE_DIR = Path(__file__).parent / "templates"


def export_markdown(result: ScanResult, output_dir: Path, profile: ReportProfile = ReportProfile.INTERN) -> Path:
    """Export ScanResult as Markdown report.

    Args:
        result: Complete scan result.
        output_dir: Directory to write the Markdown file to.
        profile: Export profile (ADR-0011) — EXTERN pseudonymizes identifiers.

    Returns:
        Path to the written Markdown file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = result.scan_timestamp.strftime("%Y%m%d_%H%M%S")
    filename = f"nis2scan_report_{timestamp}.md"
    filepath = output_dir / filename

    content = render_report(result, profile)
    filepath.write_text(content, encoding="utf-8")
    return filepath


def render_report(result: ScanResult, profile: ReportProfile = ReportProfile.INTERN) -> str:
    """Render the Markdown report from a ScanResult."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("report.md.j2")
    return template.render(**build_report_context(apply_profile(result, profile), profile))
