"""Abstract interface for tenant configuration resolution.

This module defines a lightweight interface for resolving tenant configurations
from identity providers. Unlike IdentityProvider which handles user management
and authentication, TenantConfigResolver only handles tenant discovery and lookup.

Use TenantConfigResolver when you only need to verify tokens (Portolan, Magellan)
without the overhead of full IdentityProvider capabilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict

from lighthouse.models import TenantConfig


class TenantConfigResolver(ABC):
    """Abstract interface for resolving tenant configurations.

    This lightweight interface provides tenant discovery and lookup without
    the full capabilities of IdentityProvider. Use this when you only need
    to verify tokens and don't need user management or authentication flows.

    The interface supports both async and sync methods to accommodate different
    use cases:
    - Async methods for initialization and discovery
    - Sync methods for token verification (JWT validation is synchronous)

    Implementations:
        - CognitoTenantResolver: AWS Cognito (reads pool metadata)
        - MockTenantResolver: In-memory for testing

    Example:
        >>> from lighthouse import create_factory
        >>> factory = create_factory("cognito", region="us-east-1")
        >>> resolver = factory.create_tenant_resolver()
        >>> await resolver.discover_tenants()
        >>> config = resolver.get_tenant_config_by_issuer_sync(issuer)
    """

    @abstractmethod
    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Discover all tenant configurations.

        Scans the identity provider for all tenants/user pools and returns
        their configurations. This should be called during application startup
        to populate the tenant cache.

        Returns:
            Dict mapping tenant_id to TenantConfig

        Raises:
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get configuration for a specific tenant.

        Args:
            tenant_id: The tenant identifier

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant doesn't exist
        """

    @abstractmethod
    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant configuration by JWT issuer URL.

        Used during JWT validation to resolve tenant from token issuer.

        Args:
            issuer: The JWT issuer URL
                For Cognito: https://cognito-idp.{region}.amazonaws.com/{pool_id}

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If no tenant matches the issuer
        """

    @abstractmethod
    def get_tenant_config_by_issuer_sync(self, issuer: str) -> TenantConfig:
        """Synchronous version of get_tenant_config_by_issuer.

        Used by TokenVerifier for JWT validation which cannot be async.
        This method should only check the cache and not make API calls.

        Args:
            issuer: JWT issuer URL

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If no tenant matches issuer in cache

        Note:
            This method requires that tenant configurations have been loaded
            into the cache (via discover_tenants()). If called before tenant
            discovery, it will raise TenantNotFoundError.
        """

    @abstractmethod
    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant configuration by pool ID.

        Args:
            pool_id: The identity provider's pool ID
                For Cognito: The User Pool ID (e.g., us-east-1_ABC123)

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If no tenant matches the pool ID
        """
