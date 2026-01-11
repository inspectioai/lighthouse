"""Mock implementation of TenantConfigResolver for testing.

This module provides an in-memory tenant resolver for local testing and development.
No AWS credentials or network access required.
"""

from __future__ import annotations

from typing import Dict

from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.exceptions import TenantNotFoundError
from lighthouse.models import TenantConfig


class MockTenantResolver(TenantConfigResolver):
    """Mock implementation of tenant configuration resolver.

    Provides in-memory tenant configuration for testing without AWS.
    Comes pre-configured with test tenants: "inspectio", "demo", "test".

    Example:
        >>> resolver = MockTenantResolver()
        >>> await resolver.discover_tenants()
        >>> config = resolver.get_tenant_config_by_issuer_sync(
        ...     "http://localhost:8000/mock/inspectio"
        ... )
    """

    def __init__(self, tenants: Dict[str, TenantConfig] | None = None):
        """Initialize with optional tenant configurations.

        Args:
            tenants: Optional dict of tenant configurations. If not provided,
                uses default test tenants.
        """
        if tenants is not None:
            self._tenants = tenants
        else:
            # Pre-configured test tenants
            self._tenants: Dict[str, TenantConfig] = {
                "inspectio": TenantConfig(
                    tenant_id="inspectio",
                    issuer="http://localhost:8000/mock/inspectio",
                    jwks_url="http://localhost:8000/mock/inspectio/.well-known/jwks.json",
                    audience="mock-inspectio-client",
                    pool_id="mock-pool-inspectio",
                    client_id="mock-inspectio-client",
                    region="mock",
                    status="active",
                ),
                "demo": TenantConfig(
                    tenant_id="demo",
                    issuer="http://localhost:8000/mock/demo",
                    jwks_url="http://localhost:8000/mock/demo/.well-known/jwks.json",
                    audience="mock-demo-client",
                    pool_id="mock-pool-demo",
                    client_id="mock-demo-client",
                    region="mock",
                    status="active",
                ),
                "test": TenantConfig(
                    tenant_id="test",
                    issuer="http://localhost:8000/mock/test",
                    jwks_url="http://localhost:8000/mock/test/.well-known/jwks.json",
                    audience="mock-test-client",
                    pool_id="mock-pool-test",
                    client_id="mock-test-client",
                    region="mock",
                    status="active",
                ),
            }

        # Build indexes for fast lookup
        self._issuer_index: Dict[str, str] = {}
        self._pool_id_index: Dict[str, str] = {}
        for config in self._tenants.values():
            self._issuer_index[config.issuer] = config.tenant_id
            self._pool_id_index[config.pool_id] = config.tenant_id

    def add_tenant(self, config: TenantConfig) -> None:
        """Add a tenant configuration.

        Args:
            config: TenantConfig to add
        """
        self._tenants[config.tenant_id] = config
        self._issuer_index[config.issuer] = config.tenant_id
        self._pool_id_index[config.pool_id] = config.tenant_id

    def remove_tenant(self, tenant_id: str) -> bool:
        """Remove a tenant configuration.

        Args:
            tenant_id: The tenant to remove

        Returns:
            True if removed, False if not found
        """
        if tenant_id not in self._tenants:
            return False

        config = self._tenants[tenant_id]
        del self._tenants[tenant_id]
        self._issuer_index.pop(config.issuer, None)
        self._pool_id_index.pop(config.pool_id, None)
        return True

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Return all mock tenants."""
        return self._tenants.copy()

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get tenant config by ID."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)
        return self._tenants[tenant_id]

    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant config by issuer URL."""
        if issuer in self._issuer_index:
            tenant_id = self._issuer_index[issuer]
            return self._tenants[tenant_id]
        raise TenantNotFoundError(f"No tenant found for issuer: {issuer}")

    def get_tenant_config_by_issuer_sync(self, issuer: str) -> TenantConfig:
        """Synchronous version of get_tenant_config_by_issuer."""
        if issuer in self._issuer_index:
            tenant_id = self._issuer_index[issuer]
            return self._tenants[tenant_id]
        raise TenantNotFoundError(f"No tenant found for issuer: {issuer}")

    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant config by pool ID."""
        if pool_id in self._pool_id_index:
            tenant_id = self._pool_id_index[pool_id]
            return self._tenants[tenant_id]
        raise TenantNotFoundError(f"No tenant found for pool_id: {pool_id}")
