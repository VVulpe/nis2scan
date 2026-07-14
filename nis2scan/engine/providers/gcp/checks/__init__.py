"""GCP check modules for §30 BSIG compliance."""

from nis2scan.engine.registry import CheckRegistry


def register_all_gcp_checks() -> None:
    """Register all GCP checks with the global registry."""
    registry = CheckRegistry.get_instance()

    # Nr. 1 — Risikoanalyse
    from nis2scan.engine.providers.gcp.checks.nr1_risikoanalyse import (
        CheckAssetInventory,
        CheckAuditLogConfig,
        CheckOrgPolicies,
        CheckSecurityCommandCenter,
    )

    registry.register(CheckSecurityCommandCenter())
    registry.register(CheckOrgPolicies())
    registry.register(CheckAuditLogConfig())
    registry.register(CheckAssetInventory())

    # Nr. 2 — Vorfallsbewältigung
    from nis2scan.engine.providers.gcp.checks.nr2_vorfallsbewaltigung import (
        CheckLogBasedAlerts,
        CheckLoggingSinks,
        CheckMonitoringAlertPolicies,
        CheckNotificationChannels,
        CheckSccNotifications,
    )

    registry.register(CheckSccNotifications())
    registry.register(CheckMonitoringAlertPolicies())
    registry.register(CheckNotificationChannels())
    registry.register(CheckLogBasedAlerts())
    registry.register(CheckLoggingSinks())

    # Nr. 3 — BCM
    from nis2scan.engine.providers.gcp.checks.nr3_bcm import (
        CheckCloudSqlBackups,
        CheckCloudSqlHighAvailability,
        CheckDiskSnapshotSchedules,
        CheckDnsHealthChecks,
        CheckGcsRetentionPolicy,
        CheckGcsVersioning,
        CheckMultiZoneDeployments,
    )

    registry.register(CheckCloudSqlBackups())
    registry.register(CheckGcsVersioning())
    registry.register(CheckGcsRetentionPolicy())
    registry.register(CheckMultiZoneDeployments())
    registry.register(CheckDiskSnapshotSchedules())
    registry.register(CheckCloudSqlHighAvailability())
    registry.register(CheckDnsHealthChecks())

    # Nr. 4 — Lieferkette
    from nis2scan.engine.providers.gcp.checks.nr4_lieferkette import (
        CheckBinaryAuthorization,
        CheckCrossProjectBindings,
        CheckServiceAccountKeys,
        CheckVpcServiceControlsSupplyChain,
        CheckWorkloadIdentity,
    )

    registry.register(CheckCrossProjectBindings())
    registry.register(CheckServiceAccountKeys())
    registry.register(CheckWorkloadIdentity())
    registry.register(CheckBinaryAuthorization())
    registry.register(CheckVpcServiceControlsSupplyChain())

    # Nr. 5 — Schwachstellen
    from nis2scan.engine.providers.gcp.checks.nr5_schwachstellen import (
        CheckArtifactRegistryScanning,
        CheckContainerAnalysis,
        CheckGkeNodeVersions,
        CheckOsConfigPatchManagement,
        CheckWebSecurityScanner,
    )

    registry.register(CheckContainerAnalysis())
    registry.register(CheckOsConfigPatchManagement())
    registry.register(CheckWebSecurityScanner())
    registry.register(CheckArtifactRegistryScanning())
    registry.register(CheckGkeNodeVersions())

    # Nr. 6 — Wirksamkeit
    from nis2scan.engine.providers.gcp.checks.nr6_wirksamkeit import (
        CheckAuditLogIntegrity,
        CheckMonitoringDashboards,
        CheckPolicyIntelligence,
        CheckSecurityHealthAnalytics,
    )

    registry.register(CheckAuditLogIntegrity())
    registry.register(CheckSecurityHealthAnalytics())
    registry.register(CheckPolicyIntelligence())
    registry.register(CheckMonitoringDashboards())

    # Nr. 7 — Cyberhygiene
    from nis2scan.engine.providers.gcp.checks.nr7_cyberhygiene import (
        CheckEssentialContacts,
        CheckOrgSecurityPolicies,
    )

    registry.register(CheckOrgSecurityPolicies())
    registry.register(CheckEssentialContacts())

    # Nr. 8 — Kryptographie
    from nis2scan.engine.providers.gcp.checks.nr8_kryptographie import (
        CheckCertificateManager,
        CheckCloudSqlSsl,
        CheckCmekEncryption,
        CheckDiskEncryption,
        CheckKmsKeyRotation,
        CheckSslPolicyLoadBalancer,
    )

    registry.register(CheckKmsKeyRotation())
    registry.register(CheckCmekEncryption())
    registry.register(CheckSslPolicyLoadBalancer())
    registry.register(CheckCloudSqlSsl())
    registry.register(CheckDiskEncryption())
    registry.register(CheckCertificateManager())

    # Nr. 9 — Zugriffskontrolle
    from nis2scan.engine.providers.gcp.checks.nr9_zugriffskontrolle import (
        CheckIamLeastPrivilege,
        CheckIdentityAwareProxy,
        CheckInactivePrincipals,
        CheckOrgConstraints,
        CheckServiceAccountHygiene,
        CheckStorageBucketPublicAccess,
        CheckVpcFirewallRules,
        CheckVpcServiceControls,
    )

    registry.register(CheckIamLeastPrivilege())
    registry.register(CheckServiceAccountHygiene())
    registry.register(CheckIdentityAwareProxy())
    registry.register(CheckVpcFirewallRules())
    registry.register(CheckStorageBucketPublicAccess())
    registry.register(CheckOrgConstraints())
    registry.register(CheckInactivePrincipals())
    registry.register(CheckVpcServiceControls())

    # Nr. 10 — MFA & gesicherte Kommunikation
    from nis2scan.engine.providers.gcp.checks.nr10_mfa_kommunikation import (
        CheckIapAdminAccess,
        CheckOsLoginWith2fa,
        CheckSecureLdap,
        CheckTwoStepVerification,
        CheckVpnGateways,
    )

    registry.register(CheckTwoStepVerification())
    registry.register(CheckIapAdminAccess())
    registry.register(CheckVpnGateways())
    registry.register(CheckOsLoginWith2fa())
    registry.register(CheckSecureLdap())
