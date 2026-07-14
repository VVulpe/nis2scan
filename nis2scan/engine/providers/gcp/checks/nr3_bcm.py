"""§30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs & Backup-Management checks for GCP.

Checks Cloud SQL Backups, GCS Versioning, GCS Retention Policies, Multi-Zone Deployments,
Disk Snapshot Schedules, Cloud SQL High Availability, and DNS Health Checks.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 3
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 3 BSIG — Aufrechterhaltung des Betriebs, wie Backup-Management "
    "und Wiederherstellung nach einem Notfall, und Krisenmanagement"
)


class CheckCloudSqlBackups(BaseCheck):
    """Prüft ob automatische Backups für Cloud SQL Instanzen aktiviert sind."""

    check_id = "GCP-NR3-001"
    title = "Cloud SQL automatische Backups aktiviert"
    description = "Prüft ob alle Cloud SQL Instanzen automatische Backups aktiviert haben."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudsql.instances.list"]
    pruefgrenzen = (
        "Prüft nur das Backup-Flag der Cloud-SQL-Instanzen. Backup-Erfolg und "
        "Wiederherstellbarkeit werden nicht getestet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("sqladmin", "v1beta4")
                result = service.instances().list(project=project_id).execute()
                instances = result.get("items", [])

                for instance in instances:
                    instance_name = instance.get("name", "unknown")
                    settings = instance.get("settings", {})
                    backup_config = settings.get("backupConfiguration", {})
                    backup_enabled = backup_config.get("enabled", False)

                    if backup_enabled:
                        findings.append(
                            compliant_finding(
                                self,
                                title="Cloud SQL Backups aktiviert",
                                description=(
                                    f"Cloud SQL Instanz {instance_name} in Projekt {project_id} "
                                    f"hat automatische Backups aktiviert."
                                ),
                                region=instance.get("region", "unknown"),
                                resource_id=f"projects/{project_id}/instances/{instance_name}",
                                resource_type="gcp.sqladmin.DatabaseInstance",
                                account_id=project_id,
                                current_state={"backup_enabled": True},
                                expected_state="Automatische Backups für Cloud SQL aktiviert",
                                audit_evidence=(
                                    f"instances.list() instance {instance_name} backupConfiguration.enabled=true"
                                ),
                                iso27001_control="A.8.13 Datensicherung",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Cloud SQL Backup nicht aktiviert",
                                description=(
                                    f"Cloud SQL Instanz {instance_name} "
                                    f"in Projekt {project_id} hat keine "
                                    "automatischen Backups aktiviert. Ohne Backups "
                                    "droht Datenverlust bei Ausfällen."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.13 Datensicherung",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region=instance.get("region", "unknown"),
                                resource_id=f"projects/{project_id}/instances/{instance_name}",
                                resource_type="gcp.sqladmin.DatabaseInstance",
                                account_id=project_id,
                                current_state={"backup_enabled": False},
                                expected_state="Automatische Backups für Cloud SQL aktiviert",
                                remediation=(
                                    "Aktivieren Sie automatische Backups: "
                                    "gcloud sql instances patch <INSTANCE_NAME> "
                                    "--backup-start-time=02:00 --project=<PROJECT_ID>"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=(
                                    f"instances.list() instance {instance_name} backupConfiguration.enabled=false"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckGcsVersioning(BaseCheck):
    """Prüft ob GCS Buckets Versionierung aktiviert haben."""

    check_id = "GCP-NR3-002"
    title = "GCS Bucket-Versionierung aktiviert"
    description = (
        "Prüft ob Google Cloud Storage Buckets die Objekt-Versionierung "
        "für den Schutz vor versehentlichem Löschen aktiviert haben."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["storage.buckets.list", "storage.buckets.get"]
    pruefgrenzen = (
        "Prüft nur den Versionierungs-Status der Buckets. Lifecycle-Regeln, die "
        "alte Versionen löschen, werden nicht berücksichtigt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import storage  # type: ignore[attr-defined]

                client = storage.Client(
                    credentials=session.credentials,
                    project=project_id,
                )
                buckets = list(client.list_buckets())

                for bucket in buckets:
                    if bucket.versioning_enabled:
                        findings.append(
                            compliant_finding(
                                self,
                                title="GCS Bucket mit Versionierung",
                                description=(
                                    f"Bucket {bucket.name} in Projekt {project_id} hat Objekt-Versionierung aktiviert."
                                ),
                                region=bucket.location or "global",
                                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={"versioning_enabled": True},
                                expected_state="Objekt-Versionierung für den Bucket aktiviert",
                                audit_evidence=f"bucket {bucket.name} versioning_enabled=true",
                                iso27001_control="A.8.13 Datensicherung",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="GCS Bucket ohne Versionierung",
                                description=(
                                    f"Bucket {bucket.name} in Projekt "
                                    f"{project_id} hat keine "
                                    "Objekt-Versionierung aktiviert. Ohne Versionierung "
                                    "können gelöschte Objekte nicht wiederhergestellt werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.13 Datensicherung",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region=bucket.location or "global",
                                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={"versioning_enabled": False},
                                expected_state="Objekt-Versionierung für den Bucket aktiviert",
                                remediation=(
                                    "Aktivieren Sie die Versionierung: "
                                    "gcloud storage buckets update gs://<BUCKET_NAME> "
                                    "--versioning"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"bucket {bucket.name} versioning_enabled=false",
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckGcsRetentionPolicy(BaseCheck):
    """Prüft ob GCS Buckets Aufbewahrungsrichtlinien konfiguriert haben."""

    check_id = "GCP-NR3-003"
    title = "GCS Bucket-Aufbewahrungsrichtlinie vorhanden"
    description = (
        "Prüft ob Google Cloud Storage Buckets Aufbewahrungsrichtlinien "
        "(Retention Policies) für den Schutz vor vorzeitigem Löschen haben."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["storage.buckets.list", "storage.buckets.get"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Aufbewahrungsrichtlinien. Ob die Dauer den "
        "eigenen Anforderungen entspricht, ist organisatorisch festzulegen."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import storage  # type: ignore[attr-defined]

                client = storage.Client(
                    credentials=session.credentials,
                    project=project_id,
                )
                buckets = list(client.list_buckets())

                for bucket in buckets:
                    if bucket.retention_policy is not None:
                        findings.append(
                            compliant_finding(
                                self,
                                title="GCS Bucket mit Aufbewahrungsrichtlinie",
                                description=(
                                    f"Bucket {bucket.name} in Projekt {project_id} hat eine "
                                    f"Aufbewahrungsrichtlinie konfiguriert."
                                ),
                                region=bucket.location or "global",
                                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={"retention_policy": "configured"},
                                expected_state=(
                                    "Aufbewahrungsrichtlinie konfiguriert (Dauer organisatorisch festzulegen)"
                                ),
                                audit_evidence=f"bucket {bucket.name} retention_policy configured",
                                iso27001_control="A.8.13 Datensicherung",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="GCS Bucket ohne Aufbewahrungsrichtlinie",
                                description=(
                                    f"Bucket {bucket.name} in Projekt "
                                    f"{project_id} hat keine "
                                    "Aufbewahrungsrichtlinie. Ohne Retention Policy "
                                    "können Objekte jederzeit gelöscht werden."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.8.13 Datensicherung",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.GCP,
                                region=bucket.location or "global",
                                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                                resource_type="gcp.storage.Bucket",
                                account_id=project_id,
                                current_state={"retention_policy": None},
                                expected_state=(
                                    "Aufbewahrungsrichtlinie konfiguriert (Dauer organisatorisch festzulegen)"
                                ),
                                remediation=(
                                    "Konfigurieren Sie eine Aufbewahrungsrichtlinie: "
                                    "gcloud storage buckets update gs://<BUCKET_NAME> "
                                    "--retention-period=365d"
                                ),
                                remediation_effort="LOW",
                                audit_evidence=f"bucket {bucket.name} retention_policy=None",
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckMultiZoneDeployments(BaseCheck):
    """Prüft ob Compute-Instanzen über mehrere Zonen verteilt sind."""

    check_id = "GCP-NR3-004"
    title = "Multi-Zonen-Verteilung der Instanzen"
    description = (
        "Prüft ob Compute Engine Instanzen über mehrere Verfügbarkeitszonen "
        "verteilt sind, um Hochverfügbarkeit sicherzustellen."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.instances.list"]
    pruefgrenzen = (
        "Prüft nur die Zonenverteilung der Compute-Instanzen. Welche Workloads "
        "produktionskritisch sind, kann der Scan nicht wissen."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import InstancesClient

                client = InstancesClient(credentials=session.credentials)
                zones_with_instances: set[str] = set()

                for zone, response in client.aggregated_list(
                    request={"project": project_id},
                ):
                    instances = response.instances
                    if instances:
                        running = [i for i in instances if i.status == "RUNNING"]
                        if running:
                            zones_with_instances.add(zone)

                if len(zones_with_instances) >= 2:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Instanzen über mehrere Zonen verteilt",
                            description=(
                                f"Projekt {project_id} hat laufende Instanzen in "
                                f"{len(zones_with_instances)} Verfügbarkeitszonen."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.compute.Instance",
                            account_id=project_id,
                            current_state={"zones_with_instances": len(zones_with_instances)},
                            expected_state="Instanzen über mindestens zwei Verfügbarkeitszonen verteilt",
                            audit_evidence=(
                                f"aggregated_list() found running instances in {len(zones_with_instances)} zone(s)"
                            ),
                            iso27001_control=("A.5.29, A.8.14 Redundanz von Informationsverarbeitungseinrichtungen"),
                        )
                    )
                elif len(zones_with_instances) == 1:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Instanzen nur in einer Zone",
                            description=(
                                f"Projekt {project_id} hat laufende "
                                "Instanzen nur in einer einzigen Zone. Bei einem "
                                "Zonenausfall sind alle Instanzen betroffen."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.29, A.8.14 Redundanz von Informationsverarbeitungseinrichtungen",
                            severity=Severity.HIGH,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.compute.Instance",
                            account_id=project_id,
                            current_state={"zones_with_instances": len(zones_with_instances)},
                            expected_state="Instanzen über mindestens zwei Verfügbarkeitszonen verteilt",
                            remediation=(
                                "Verteilen Sie Instanzen über mehrere Zonen: "
                                "gcloud compute instances create <NAME> "
                                "--zone=<ZONE_B> --project=<PROJECT_ID> "
                                "oder verwenden Sie Managed Instance Groups mit "
                                "regionaler Verteilung"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=(
                                f"aggregated_list() found running instances in {len(zones_with_instances)} zone(s)"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckDiskSnapshotSchedules(BaseCheck):
    """Prüft ob geplante Disk-Snapshot-Richtlinien existieren."""

    check_id = "GCP-NR3-005"
    title = "Geplante Disk-Snapshot-Richtlinien vorhanden"
    description = (
        "Prüft ob Resource Policies vom Typ SNAPSHOT für die automatische "
        "Erstellung von Disk-Snapshots konfiguriert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["compute.resourcePolicies.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Snapshot-Zeitplänen. Snapshot-Erfolg und "
        "Wiederherstellbarkeit werden nicht getestet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud.compute_v1 import ResourcePoliciesClient

                client = ResourcePoliciesClient(credentials=session.credentials)
                snapshot_policies_found = False

                for _region, response in client.aggregated_list(
                    request={"project": project_id},
                ):
                    policies = response.resource_policies
                    if policies:
                        for policy in policies:
                            if policy.snapshot_schedule_policy:
                                snapshot_policies_found = True
                                break
                    if snapshot_policies_found:
                        break

                if snapshot_policies_found:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Geplante Snapshot-Richtlinien vorhanden",
                            description=(
                                f"Projekt {project_id} hat mindestens eine Resource Policy für geplante Disk-Snapshots."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.compute.ResourcePolicy",
                            account_id=project_id,
                            current_state={"snapshot_schedule_policies_found": True},
                            expected_state="Mindestens eine geplante Snapshot-Richtlinie konfiguriert",
                            audit_evidence="aggregated_list() found >=1 snapshot schedule policy",
                            iso27001_control="A.8.13 Datensicherung",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine geplanten Snapshot-Richtlinien",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Resource Policies für geplante Disk-Snapshots. "
                                "Ohne automatisierte Snapshots fehlt die regelmäßige "
                                "Datensicherung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.13 Datensicherung",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.compute.ResourcePolicy",
                            account_id=project_id,
                            current_state={"snapshot_schedule_policies": 0},
                            expected_state="Mindestens eine geplante Snapshot-Richtlinie konfiguriert",
                            remediation=(
                                "Erstellen Sie eine Snapshot-Richtlinie: "
                                "gcloud compute resource-policies create snapshot-schedule "
                                "<NAME> --project=<PROJECT_ID> --region=<REGION> "
                                "--max-retention-days=30 --daily-schedule "
                                "--start-time=02:00"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="aggregated_list() found 0 snapshot schedule policies",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckCloudSqlHighAvailability(BaseCheck):
    """Prüft ob Cloud SQL Instanzen Hochverfügbarkeit konfiguriert haben."""

    check_id = "GCP-NR3-006"
    title = "Cloud SQL Hochverfügbarkeit konfiguriert"
    description = (
        "Prüft ob Cloud SQL Instanzen mit regionaler Hochverfügbarkeit (REGIONAL availability type) konfiguriert sind."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["cloudsql.instances.list"]
    pruefgrenzen = (
        "Prüft nur das Hochverfügbarkeits-Flag der Cloud-SQL-Instanzen. Failover-Verhalten wird nicht getestet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("sqladmin", "v1beta4")
                result = service.instances().list(project=project_id).execute()
                instances = result.get("items", [])

                for instance in instances:
                    instance_name = instance.get("name", "unknown")
                    settings = instance.get("settings", {})
                    availability_type = settings.get("availabilityType", "ZONAL")

                    if availability_type == "REGIONAL":
                        findings.append(
                            compliant_finding(
                                self,
                                title="Cloud SQL mit Hochverfügbarkeit",
                                description=(
                                    f"Cloud SQL Instanz {instance_name} in Projekt {project_id} "
                                    f"ist für regionale Hochverfügbarkeit konfiguriert."
                                ),
                                region=instance.get("region", "unknown"),
                                resource_id=f"projects/{project_id}/instances/{instance_name}",
                                resource_type="gcp.sqladmin.DatabaseInstance",
                                account_id=project_id,
                                current_state={"availability_type": "REGIONAL"},
                                expected_state="Cloud SQL Instanz mit availabilityType=REGIONAL",
                                audit_evidence=(f"instances.list() instance {instance_name} availabilityType=REGIONAL"),
                                iso27001_control="A.5.29 Informationssicherheit bei Störungen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Cloud SQL ohne Hochverfügbarkeit",
                                description=(
                                    f"Cloud SQL Instanz {instance_name} "
                                    f"in Projekt {project_id} ist nicht "
                                    "für regionale Hochverfügbarkeit konfiguriert. "
                                    "Bei einem Zonenausfall ist die Datenbank nicht erreichbar."
                                ),
                                bsig_30_nr=BSIG_30_NR,
                                bsig_30_text=BSIG_30_TEXT,
                                iso27001_control="A.5.29 Informationssicherheit bei Störungen",
                                severity=Severity.HIGH,
                                provider=CloudProvider.GCP,
                                region=instance.get("region", "unknown"),
                                resource_id=f"projects/{project_id}/instances/{instance_name}",
                                resource_type="gcp.sqladmin.DatabaseInstance",
                                account_id=project_id,
                                current_state={"availability_type": availability_type},
                                expected_state="Cloud SQL Instanz mit availabilityType=REGIONAL",
                                remediation=(
                                    "Aktivieren Sie Hochverfügbarkeit: "
                                    "gcloud sql instances patch <INSTANCE_NAME> "
                                    "--availability-type=REGIONAL "
                                    "--project=<PROJECT_ID>"
                                ),
                                remediation_effort="MEDIUM",
                                audit_evidence=(
                                    f"instances.list() instance {instance_name} availabilityType={availability_type}"
                                ),
                            )
                        )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckDnsHealthChecks(BaseCheck):
    """Prüft ob Cloud DNS verwaltete Zonen existieren."""

    check_id = "GCP-NR3-007"
    title = "Cloud DNS verwaltete Zonen vorhanden"
    description = "Prüft ob Cloud DNS verwaltete Zonen existieren — Grundvoraussetzung für DNS-basiertes Failover."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["dns.managedZones.list"]
    pruefgrenzen = (
        "Prüft nur die Existenz verwalteter DNS-Zonen als Indiz für gesteuertes "
        "Failover. Externe DNS-Anbieter werden nicht erkannt."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                from google.cloud import dns  # type: ignore[attr-defined]

                client = dns.Client(
                    credentials=session.credentials,
                    project=project_id,
                )
                zones = list(client.list_zones())

                if zones:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Cloud DNS verwaltete Zonen vorhanden",
                            description=(f"Projekt {project_id} hat {len(zones)} Cloud DNS verwaltete Zone(n)."),
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.dns.ManagedZone",
                            account_id=project_id,
                            current_state={"managed_zones": len(zones)},
                            expected_state="Mindestens eine Cloud DNS verwaltete Zone konfiguriert",
                            audit_evidence=f"list_zones() returned {len(zones)} managed zone(s)",
                            iso27001_control="A.8.14 Redundanz von Informationsverarbeitungseinrichtungen",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Cloud DNS verwalteten Zonen",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Cloud DNS verwalteten Zonen. Ohne DNS-Zonen können "
                                "keine DNS-basierten Failover-Mechanismen genutzt werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.14 Redundanz von Informationsverarbeitungseinrichtungen",
                            severity=Severity.LOW,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}",
                            resource_type="gcp.dns.ManagedZone",
                            account_id=project_id,
                            current_state={"managed_zones": 0},
                            expected_state="Mindestens eine Cloud DNS verwaltete Zone konfiguriert",
                            remediation=(
                                "Erstellen Sie eine Cloud DNS Zone: "
                                "gcloud dns managed-zones create <ZONE_NAME> "
                                "--dns-name=<DNS_NAME> --description='Produktionszone' "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="list_zones() returned 0 managed zones",
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
