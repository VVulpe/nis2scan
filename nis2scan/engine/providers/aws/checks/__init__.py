"""AWS check modules for §30 BSIG compliance."""

from nis2scan.engine.registry import CheckRegistry


def register_all_aws_checks() -> None:
    """Register all AWS checks with the global registry."""
    registry = CheckRegistry.get_instance()

    # Nr. 1 — Risikoanalyse
    from nis2scan.engine.providers.aws.checks.nr1_risikoanalyse import (
        CheckCloudTrail,
        CheckConfigRecorder,
        CheckGuardDutyRiskAnalysis,
        CheckOrganizationsScp,
        CheckSecurityHub,
    )

    registry.register(CheckConfigRecorder())
    registry.register(CheckSecurityHub())
    registry.register(CheckCloudTrail())
    registry.register(CheckOrganizationsScp())
    registry.register(CheckGuardDutyRiskAnalysis())

    # Nr. 2 — Bewältigung von Sicherheitsvorfällen
    from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
        CheckCloudWatchAlarms,
        CheckDetectiveEnabled,
        CheckGuardDutyEnabled,
        CheckIncidentManagerResponsePlans,
        CheckSecurityHubFindings,
    )

    registry.register(CheckGuardDutyEnabled())
    registry.register(CheckCloudWatchAlarms())
    registry.register(CheckSecurityHubFindings())
    registry.register(CheckIncidentManagerResponsePlans())
    registry.register(CheckDetectiveEnabled())

    # Nr. 3 — Aufrechterhaltung des Betriebs (BCM)
    from nis2scan.engine.providers.aws.checks.nr3_bcm import (
        CheckBackupPlans,
        CheckEbsSnapshotEncryption,
        CheckRdsBackupRetention,
        CheckRdsMultiAz,
        CheckRoute53HealthChecks,
        CheckS3ObjectLock,
        CheckS3Versioning,
    )

    registry.register(CheckRdsBackupRetention())
    registry.register(CheckS3Versioning())
    registry.register(CheckS3ObjectLock())
    registry.register(CheckEbsSnapshotEncryption())
    registry.register(CheckRdsMultiAz())
    registry.register(CheckBackupPlans())
    registry.register(CheckRoute53HealthChecks())

    # Nr. 4 — Sicherheit der Lieferkette
    from nis2scan.engine.providers.aws.checks.nr4_lieferkette import (
        CheckCrossAccountRoles,
        CheckOrganizationsExternalAccounts,
        CheckRamSharingPolicies,
        CheckScpForThirdPartyOus,
        CheckTrustedAdvisorAccess,
    )

    registry.register(CheckTrustedAdvisorAccess())
    registry.register(CheckRamSharingPolicies())
    registry.register(CheckOrganizationsExternalAccounts())
    registry.register(CheckCrossAccountRoles())
    registry.register(CheckScpForThirdPartyOus())

    # Nr. 5 — Schwachstellenmanagement
    from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
        CheckAmiAge,
        CheckEcrImageScanning,
        CheckLambdaRuntimeDeprecation,
        CheckSsmPatchCompliance,
        CheckSsmPatchManagerCompliance,
    )

    registry.register(CheckEcrImageScanning())
    registry.register(CheckSsmPatchCompliance())
    registry.register(CheckLambdaRuntimeDeprecation())
    registry.register(CheckSsmPatchManagerCompliance())
    registry.register(CheckAmiAge())

    # Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen
    from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import (
        CheckCloudTrailLogIntegrity,
        CheckCloudWatchLogRetention,
        CheckConfigRulesCompliance,
        CheckSecurityHubComplianceScore,
    )

    registry.register(CheckCloudTrailLogIntegrity())
    registry.register(CheckConfigRulesCompliance())
    registry.register(CheckCloudWatchLogRetention())
    registry.register(CheckSecurityHubComplianceScore())

    # Nr. 7 — Cyberhygiene
    from nis2scan.engine.providers.aws.checks.nr7_cyberhygiene import (
        CheckIamPasswordPolicy,
        CheckRootAccessKeys,
    )

    registry.register(CheckIamPasswordPolicy())
    registry.register(CheckRootAccessKeys())

    # Nr. 8 — Kryptographie
    from nis2scan.engine.providers.aws.checks.nr8_kryptographie import (
        CheckAcmCertificateExpiry,
        CheckEbsEncryption,
        CheckElbTlsMinVersion,
        CheckKmsKeyRotation,
        CheckRdsEncryption,
        CheckS3DefaultEncryption,
        CheckTlsPolicy,
    )

    registry.register(CheckS3DefaultEncryption())
    registry.register(CheckEbsEncryption())
    registry.register(CheckRdsEncryption())
    registry.register(CheckKmsKeyRotation())
    registry.register(CheckTlsPolicy())
    registry.register(CheckElbTlsMinVersion())
    registry.register(CheckAcmCertificateExpiry())

    # Nr. 9 — Zugriffskontrolle
    from nis2scan.engine.providers.aws.checks.nr9_zugriffskontrolle import (
        CheckIamAccessKeyAge,
        CheckIamMfa,
        CheckIamWildcardPolicy,
        CheckS3BucketPolicy,
        CheckS3PublicAccessBlock,
        CheckSecurityGroupOpenAccess,
        CheckUnusedIamCredentials,
    )

    registry.register(CheckIamMfa())
    registry.register(CheckIamAccessKeyAge())
    registry.register(CheckS3PublicAccessBlock())
    registry.register(CheckSecurityGroupOpenAccess())
    registry.register(CheckIamWildcardPolicy())
    registry.register(CheckS3BucketPolicy())
    registry.register(CheckUnusedIamCredentials())

    # Nr. 10 — MFA & gesicherte Kommunikation
    from nis2scan.engine.providers.aws.checks.nr10_mfa_kommunikation import (
        CheckBreakGlassProcedure,
        CheckIamUserMfaEnforcement,
        CheckRootMfa,
        CheckSesSnsTls,
        CheckVpnAdminAccess,
    )

    registry.register(CheckRootMfa())
    registry.register(CheckIamUserMfaEnforcement())
    registry.register(CheckVpnAdminAccess())
    registry.register(CheckSesSnsTls())
    registry.register(CheckBreakGlassProcedure())
