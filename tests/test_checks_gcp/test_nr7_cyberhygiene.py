"""Tests for §30 Nr. 7 — Cyberhygiene GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from unittest.mock import MagicMock

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr7_cyberhygiene import (
    CheckEssentialContacts,
    CheckOrgSecurityPolicies,
)

from .conftest import PROJECT_ID, FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckOrgSecurityPolicies:
    def _session(self, constraints: list[tuple[str, bool]]) -> FakeGcpSession:
        """constraints: list of (constraint_name, enforce) tuples."""
        svc = MagicMock()
        svc.projects.return_value.policies.return_value.list.return_value.execute.return_value = {
            "policies": [
                {
                    "name": f"projects/{PROJECT_ID}/policies/{c}",
                    "spec": {"rules": [{"enforce": enforce}]},
                }
                for c, enforce in constraints
            ]
        }
        return FakeGcpSession(services={"orgpolicy": svc})

    def test_security_constraints_produce_positive_evidence(self):
        session = self._session(
            [
                ("iam.disableServiceAccountKeyCreation", True),
                ("compute.requireOsLogin", True),
            ]
        )

        result = asyncio.run(CheckOrgSecurityPolicies().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_constraints_found"] == 2
        assert not _maengel(result)

    def test_no_security_constraints_produces_finding(self):
        session = self._session([("gcp.resourceLocations", True)])

        result = asyncio.run(CheckOrgSecurityPolicies().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_constraint_present_but_not_enforced_produces_finding(self):
        session = self._session([("iam.disableServiceAccountKeyCreation", False)])

        result = asyncio.run(CheckOrgSecurityPolicies().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("orgpolicy", "v2")
        service.projects.return_value.policies.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckOrgSecurityPolicies().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckEssentialContacts:
    def _session(self, categories: list[str], validation_state: str = "VALID") -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.contacts.return_value.list.return_value.execute.return_value = {
            "contacts": [
                {
                    "email": "x@example.com",
                    "notificationCategorySubscriptions": categories,
                    "validationState": validation_state,
                }
            ]
        }
        return FakeGcpSession(services={"essentialcontacts": svc})

    def test_valid_security_contact_produces_positive_evidence(self):
        result = asyncio.run(CheckEssentialContacts().execute(self._session(["SECURITY"], validation_state="VALID")))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_contacts_valid"] == 1
        assert not _maengel(result)

    def test_invalid_security_contact_produces_finding(self):
        result = asyncio.run(CheckEssentialContacts().execute(self._session(["SECURITY"], validation_state="INVALID")))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["security_contacts_valid"] == 0
        assert not _compliant(result)

    def test_no_security_contact_produces_finding(self):
        result = asyncio.run(CheckEssentialContacts().execute(self._session(["BILLING"])))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(["SECURITY"])
        service = session.service("essentialcontacts", "v1")
        service.projects.return_value.contacts.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckEssentialContacts().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
