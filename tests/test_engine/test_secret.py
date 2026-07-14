"""Tests for customer-secret resolution and nis2scan init (ADR-0010)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from nis2scan.engine import secret as secret_module
from nis2scan.engine.secret import generate_secret, persist_secret, resolve_secret

runner = CliRunner()


@pytest.fixture
def secret_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / ".nis2scan" / "secret"
    monkeypatch.setattr(secret_module, "SECRET_FILE", path)
    monkeypatch.delenv("NIS2SCAN_SECRET", raising=False)
    return path


class TestResolveSecret:
    def test_env_wins_over_file(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        persist_secret("from-file")
        monkeypatch.setenv("NIS2SCAN_SECRET", "from-env")

        assert resolve_secret() == b"from-env"

    def test_file_fallback(self, secret_file: Path):
        persist_secret("from-file")

        assert resolve_secret() == b"from-file"

    def test_none_when_nothing_configured(self, secret_file: Path):
        assert resolve_secret() is None

    def test_empty_file_is_none(self, secret_file: Path):
        secret_file.parent.mkdir(parents=True)
        secret_file.write_text("\n", encoding="utf-8")

        assert resolve_secret() is None


class TestGeneratePersist:
    def test_generate_is_256_bit_hex(self):
        value = generate_secret()

        assert len(value) == 64
        int(value, 16)  # must be valid hex

    def test_persist_creates_parent_dir(self, secret_file: Path):
        path = persist_secret("abc123")

        assert path == secret_file
        assert path.read_text(encoding="utf-8").strip() == "abc123"


class TestInitCommand:
    def test_init_creates_secret(self, secret_file: Path, monkeypatch: pytest.MonkeyPatch):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert secret_file.exists()
        assert len(secret_file.read_text(encoding="utf-8").strip()) == 64

    def test_init_refuses_overwrite_without_force(self, secret_file: Path):
        from nis2scan.cli.cli import app

        persist_secret("existing")
        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert secret_file.read_text(encoding="utf-8").strip() == "existing"

    def test_init_force_overwrites(self, secret_file: Path):
        from nis2scan.cli.cli import app

        persist_secret("existing")
        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == 0
        assert secret_file.read_text(encoding="utf-8").strip() != "existing"
