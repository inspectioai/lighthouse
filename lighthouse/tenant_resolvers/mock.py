"""Mock tenant resolver for testing."""

from __future__ import annotations

from typing import Dict

import structlog

from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.exceptions import TenantNotFoundError
from lighthouse.models import TenantConfig

log = structlog.get_logger()


class MockTenantResolver(TenantConfigResolver):
    """
    Mock tenant resolver for testing.

    Stores tenant configurations in memory. Perfect for unit tests
    that need to verify token resolution logic without AWS dependencies.

    Example:
        resolver = MockTenantResolver(tenants={
            "test-tenant": TenantConfig(
                tenant_id="test-tenant",
                issuer="http://localhost/mock",
                jwks_url="http://localhost/mock/.well-known/jwks.json",
                audience="mock-client",
                pool_id="mock-pool",
                client_id="mock-client",
                region="mock",
            )
        })
        config = resolver.get_tenant_config_by_issuer_sync("test-tenant")
    """

    def __init__(self, tenants: Dict[str, TenantConfig] = None):
        """Initialize mock tenant resolver.

        Args:
            tenants: Optional dict of tenant_id -> TenantConfig. If not provided,
                     starts with empty tenant dict.
        """
        self._tenants: Dict[str, TenantConfig] = tenants or {}
        self._issuer_index: Dict[str, str] = {}
        self._pool_id_index: Dict[str, str] = {}

        # Build indices from initial tenants
        for tenant_id, config in self._tenants.items():
            self._issuer_index[config.issuer] = tenant_id
            self._pool_id_index[config.pool_id] = tenant_id

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Return all tenants in memory.

        Returns:
            Dict mapping tenant_id to TenantConfig
        """
        log.debug("Discovering mock tenants", count=len(self._tenants))
        return self._tenants.copy()

    def get_tenant_config_by_issuer_sync(self, tenant_id: str) -> TenantConfig:
        """Synchronous lookup from memory (called by TokenVerifier).

        Args:
            tenant_id: Tenant identifier from JWT custom:tenant_id claim

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found
        """
        if tenant_id in self._tenants:
            return self._tenants[tenant_id]

        log.warning("Mock tenant not found", tenant_id=tenant_id)
        raise TenantNotFoundError(f"Mock tenant not found: {tenant_id}")

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get tenant configuration by tenant ID.

        Args:
            tenant_id: Tenant identifier

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found
        """
        if tenant_id in self._tenants:
            return self._tenants[tenant_id]

        log.warning("Mock tenant not found", tenant_id=tenant_id)
        raise TenantNotFoundError(f"Mock tenant not found: {tenant_id}")

    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant configuration by JWT issuer.

        Args:
            issuer: JWT issuer URL

        Returns:
            TenantConfig for the issuer

        Raises:
            TenantNotFoundError: If issuer not found
        """
        tenant_id = self._issuer_index.get(issuer)
        if tenant_id:
            return self._tenants[tenant_id]

        log.warning("Mock issuer not found", issuer=issuer)
        raise TenantNotFoundError(f"Mock issuer not found: {issuer}")

    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant configuration by pool ID.

        Args:
            pool_id: Pool identifier

        Returns:
            TenantConfig for the pool

        Raises:
            TenantNotFoundError: If pool not found
        """
        tenant_id = self._pool_id_index.get(pool_id)
        if tenant_id:
            return self._tenants[tenant_id]

        log.warning("Mock pool not found", pool_id=pool_id)
        raise TenantNotFoundError(f"Mock pool not found: {pool_id}")

    def add_tenant(self, config: TenantConfig) -> None:
        """Add a tenant configuration to the mock resolver.

        Useful for dynamically adding tenants during tests.

        Args:
            config: TenantConfig to add
        """
        self._tenants[config.tenant_id] = config
        self._issuer_index[config.issuer] = config.tenant_id
        self._pool_id_index[config.pool_id] = config.tenant_id
        log.debug("Added mock tenant", tenant_id=config.tenant_id)

    def remove_tenant(self, tenant_id: str) -> None:
        """Remove a tenant configuration from the mock resolver.

        Args:
            tenant_id: Tenant identifier to remove
        """
        if tenant_id in self._tenants:
            config = self._tenants[tenant_id]
            del self._tenants[tenant_id]
            del self._issuer_index[config.issuer]
            del self._pool_id_index[config.pool_id]
            log.debug("Removed mock tenant", tenant_id=tenant_id)
