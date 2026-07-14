"""Check registry — singleton that collects all available check modules."""

from nis2scan.engine.models.check import BaseCheck


class CheckRegistry:
    """Registry of all available checks, organized by provider.

    Usage:
        registry = CheckRegistry.get_instance()
        registry.register(MyCheck())
        checks = registry.get_checks_for_provider("aws")
    """

    _instance: "CheckRegistry | None" = None

    def __init__(self) -> None:
        self._checks: dict[str, list[BaseCheck]] = {}

    @classmethod
    def get_instance(cls) -> "CheckRegistry":
        """Get or create the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        cls._instance = None

    def register(self, check: BaseCheck) -> None:
        """Register a check module (idempotent per check_id).

        Long-lived processes (SaaS API/worker) call register_all_*_checks()
        once per scan — re-registration must replace, never duplicate,
        otherwise every additional scan re-runs all checks n times.
        """
        provider = check.provider.value.lower()
        checks = self._checks.setdefault(provider, [])
        for i, existing in enumerate(checks):
            if existing.check_id == check.check_id:
                checks[i] = check
                return
        checks.append(check)

    def get_checks_for_provider(self, provider: str) -> list[BaseCheck]:
        """Get all registered checks for a provider."""
        return self._checks.get(provider.lower(), [])

    def get_all_checks(self) -> list[BaseCheck]:
        """Get all registered checks across all providers."""
        all_checks: list[BaseCheck] = []
        for checks in self._checks.values():
            all_checks.extend(checks)
        return all_checks

    def get_required_permissions(self, provider: str) -> list[str]:
        """Get deduplicated list of all required permissions for a provider."""
        perms: set[str] = set()
        for check in self.get_checks_for_provider(provider):
            perms.update(check.required_permissions)
        return sorted(perms)
