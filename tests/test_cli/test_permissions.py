"""Tests for the permissions generators — AWS IAM, Azure RBAC, GCP custom role (ADR-0020)."""

from typer.testing import CliRunner

from nis2scan.cli.cli import (
    _generate_azure_rbac_terraform,
    _generate_gcp_role_terraform,
    _generate_terraform_policy,
)

runner = CliRunner()


class TestAzureRbacGenerator:
    def test_arm_actions_in_role_definition(self):
        tf = _generate_azure_rbac_terraform(
            ["Microsoft.Security/securityContacts/read", "Microsoft.Insights/actionGroups/read"]
        )

        assert 'resource "azurerm_role_definition" "nis2scan_readonly"' in tf
        assert '"Microsoft.Security/securityContacts/read"' in tf
        assert '"Microsoft.Insights/actionGroups/read"' in tf
        assert "not_actions = []" in tf

    def test_graph_permissions_separated_from_rbac(self):
        tf = _generate_azure_rbac_terraform(["Microsoft.Storage/storageAccounts/read", "Policy.Read.All"])

        assert '"Microsoft.Storage/storageAccounts/read"' in tf
        # Graph permissions must not land in the RBAC actions list.
        assert '"Policy.Read.All"' not in tf
        assert "#   - Policy.Read.All" in tf
        assert "admin-consent" in tf

    def test_no_graph_section_without_graph_permissions(self):
        tf = _generate_azure_rbac_terraform(["Microsoft.Storage/storageAccounts/read"])

        assert "Microsoft-Graph" not in tf


class TestGcpRoleGenerator:
    def test_custom_role_and_binding(self):
        tf = _generate_gcp_role_terraform(["compute.instances.list", "resourcemanager.projects.getIamPolicy"])

        assert 'resource "google_project_iam_custom_role" "nis2scan_readonly"' in tf
        assert '"compute.instances.list"' in tf
        assert '"resourcemanager.projects.getIamPolicy"' in tf
        assert 'resource "google_project_iam_member" "nis2scan_readonly"' in tf
        assert "serviceAccount:${var.nis2scan_service_account}" in tf


class TestAwsGeneratorUnchanged:
    def test_iam_policy(self):
        tf = _generate_terraform_policy(["s3:GetBucketLocation", "iam:ListUsers"])

        assert 'resource "aws_iam_policy" "nis2scan_readonly"' in tf
        assert '"s3:GetBucketLocation"' in tf


class TestPermissionsCommand:
    def test_azure_terraform_via_cli(self):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "azure", "--format", "terraform"])

        assert result.exit_code == 0
        assert "azurerm_role_definition" in result.output

    def test_gcp_terraform_via_cli(self):
        from nis2scan.cli.cli import app

        result = runner.invoke(app, ["permissions", "--provider", "gcp", "--format", "terraform"])

        assert result.exit_code == 0
        assert "google_project_iam_custom_role" in result.output
