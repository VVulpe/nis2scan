"""Azure check modules — registration of all Azure compliance checks."""

from nis2scan.engine.registry import CheckRegistry


def register_all_azure_checks() -> None:
    """Register all Azure check modules with the global registry."""
    registry = CheckRegistry.get_instance()

    # §30 Nr. 1 — Risikoanalyse
    from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import (
        CheckActivityLogRetention,
        CheckAzurePolicyAssignments,
        CheckDefenderForCloud,
        CheckManagementGroups,
        CheckSentinelWorkspace,
    )

    registry.register(CheckDefenderForCloud())
    registry.register(CheckAzurePolicyAssignments())
    registry.register(CheckManagementGroups())
    registry.register(CheckActivityLogRetention())
    registry.register(CheckSentinelWorkspace())

    # §30 Nr. 2 — Bewältigung von Sicherheitsvorfällen
    from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import (
        CheckActionGroups,
        CheckAlertProcessingRules,
        CheckDefenderAlertNotifications,
        CheckSentinelAnalyticsRules,
        CheckSentinelPlaybooks,
    )

    registry.register(CheckDefenderAlertNotifications())
    registry.register(CheckSentinelAnalyticsRules())
    registry.register(CheckSentinelPlaybooks())
    registry.register(CheckActionGroups())
    registry.register(CheckAlertProcessingRules())

    # §30 Nr. 3 — Aufrechterhaltung des Betriebs (BCM)
    from nis2scan.engine.providers.azure.checks.nr3_bcm import (
        CheckAvailabilityZones,
        CheckBackupVaults,
        CheckGeoRedundantStorage,
        CheckImmutableBlobStorage,
        CheckSiteRecovery,
        CheckSqlBackupRetention,
        CheckTrafficManagerFrontDoor,
    )

    registry.register(CheckBackupVaults())
    registry.register(CheckSqlBackupRetention())
    registry.register(CheckGeoRedundantStorage())
    registry.register(CheckAvailabilityZones())
    registry.register(CheckSiteRecovery())
    registry.register(CheckImmutableBlobStorage())
    registry.register(CheckTrafficManagerFrontDoor())

    # §30 Nr. 4 — Sicherheit der Lieferkette
    from nis2scan.engine.providers.azure.checks.nr4_lieferkette import (
        CheckGuestUsersConditionalAccess,
        CheckLighthouseDelegations,
        CheckMarketplaceImageTrust,
        CheckPrivateEndpoints,
        CheckServicePrincipalCredentials,
    )

    registry.register(CheckLighthouseDelegations())
    registry.register(CheckGuestUsersConditionalAccess())
    registry.register(CheckPrivateEndpoints())
    registry.register(CheckServicePrincipalCredentials())
    registry.register(CheckMarketplaceImageTrust())

    # §30 Nr. 5 — Schwachstellenmanagement
    from nis2scan.engine.providers.azure.checks.nr5_schwachstellen import (
        CheckAppServiceRuntime,
        CheckContainerRegistryScan,
        CheckDefenderVulnAssessment,
        CheckSqlVulnAssessment,
        CheckUpdateManagement,
    )

    registry.register(CheckDefenderVulnAssessment())
    registry.register(CheckUpdateManagement())
    registry.register(CheckContainerRegistryScan())
    registry.register(CheckAppServiceRuntime())
    registry.register(CheckSqlVulnAssessment())

    # §30 Nr. 6 — Bewertung der Wirksamkeit
    from nis2scan.engine.providers.azure.checks.nr6_wirksamkeit import (
        CheckDefenderSecureScore,
        CheckDiagnosticSettings,
        CheckLogRetention,
        CheckPolicyComplianceState,
    )

    registry.register(CheckDefenderSecureScore())
    registry.register(CheckPolicyComplianceState())
    registry.register(CheckLogRetention())
    registry.register(CheckDiagnosticSettings())

    # §30 Nr. 7 — Cyberhygiene & Schulungen
    from nis2scan.engine.providers.azure.checks.nr7_cyberhygiene import (
        CheckPasswordProtection,
        CheckSecurityDefaults,
    )

    registry.register(CheckPasswordProtection())
    registry.register(CheckSecurityDefaults())

    # §30 Nr. 8 — Kryptographie
    from nis2scan.engine.providers.azure.checks.nr8_kryptographie import (
        CheckAppGatewayTls,
        CheckAppServiceHttps,
        CheckDiskEncryption,
        CheckKeyVaultRotation,
        CheckSqlTde,
        CheckStorageEncryption,
    )

    registry.register(CheckStorageEncryption())
    registry.register(CheckDiskEncryption())
    registry.register(CheckSqlTde())
    registry.register(CheckKeyVaultRotation())
    registry.register(CheckAppServiceHttps())
    registry.register(CheckAppGatewayTls())

    # §30 Nr. 9 — Zugriffskontrolle & Asset-Management
    from nis2scan.engine.providers.azure.checks.nr9_zugriffskontrolle import (
        CheckClassicAdmins,
        CheckConditionalAccess,
        CheckGuestAccessRestrictions,
        CheckNsgOpenAccess,
        CheckPim,
        CheckStaleServicePrincipals,
        CheckStoragePublicAccess,
    )

    registry.register(CheckConditionalAccess())
    registry.register(CheckPim())
    registry.register(CheckNsgOpenAccess())
    registry.register(CheckStoragePublicAccess())
    registry.register(CheckClassicAdmins())
    registry.register(CheckGuestAccessRestrictions())
    registry.register(CheckStaleServicePrincipals())

    # §30 Nr. 10 — MFA & gesicherte Kommunikation
    from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import (
        CheckBreakGlassAccounts,
        CheckMfaAllUsers,
        CheckO365TlsEnforcement,
        CheckPhishingResistantMfa,
        CheckVpnBastion,
    )

    registry.register(CheckMfaAllUsers())
    registry.register(CheckPhishingResistantMfa())
    registry.register(CheckVpnBastion())
    registry.register(CheckO365TlsEnforcement())
    registry.register(CheckBreakGlassAccounts())
