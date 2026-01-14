"""AWS Cognito implementation of TenantConfigResolver.

This module provides a lightweight tenant resolution implementation that only
reads Cognito User Pool metadata. Unlike CognitoIdentityProvider, this class
does not handle user management or authentication - only tenant discovery.

Use this when you only need to verify tokens without full identity provider capabilities.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import boto3
import structlog
from botocore.exceptions import ClientError

from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.exceptions import IdentityProviderError, TenantNotFoundError
from lighthouse.models import TenantConfig

log = structlog.get_logger()


class CognitoTenantResolver(TenantConfigResolver):
    """AWS Cognito implementation of tenant configuration resolver.

    Provides lightweight tenant discovery and lookup by reading Cognito User Pool
    metadata. This class only needs read permissions for pool metadata:
    - cognito-idp:ListUserPools
    - cognito-idp:DescribeUserPool
    - cognito-idp:ListUserPoolClients
    - cognito-idp:DescribeUserPoolClient

    Use this when you only need to verify tokens and don't need user management.

    Args:
        region: AWS region where Cognito user pools are located.
        endpoint_url: Optional custom endpoint URL for LocalStack testing.

    Example:
        >>> resolver = CognitoTenantResolver(region="us-east-1")
        >>> await resolver.discover_tenants()
        >>> config = resolver.get_tenant_config_by_issuer_sync(issuer)
    """

    def __init__(
        self,
        region: str,
        endpoint_url: Optional[str] = None,
    ):
        self.region = region
        self._endpoint_url = endpoint_url

        # Create client with optional custom endpoint
        client_kwargs: Dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        self._client = boto3.client("cognito-idp", **client_kwargs)

        # Tenant configuration cache
        self._tenant_configs: Dict[str, TenantConfig] = {}
        # Index by issuer for fast lookup
        self._issuer_index: Dict[str, str] = {}  # issuer -> tenant_id
        # Index by pool_id for fast lookup
        self._pool_id_index: Dict[str, str] = {}  # pool_id -> tenant_id

    def _extract_tenant_id(self, pool_name: str) -> Optional[str]:
        """Extract tenant ID from pool name.

        The pool name IS the tenant_id (no prefix).
        Returns the pool name lowercased as the tenant ID.
        """
        return pool_name.lower() if pool_name else None

    def _find_app_client(self, pool_id: str) -> Optional[str]:
        """Find the first app client for a user pool."""
        try:
            paginator = self._client.get_paginator("list_user_pool_clients")
            for page in paginator.paginate(UserPoolId=pool_id, MaxResults=60):
                for app_client in page.get("UserPoolClients", []):
                    return app_client["ClientId"]
        except ClientError:
            pass
        return None

    def _create_tenant_config(
        self, tenant_id: str, pool_id: str, pool_name: str, client_id: str
    ) -> TenantConfig:
        """Create a TenantConfig from pool details."""
        issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{pool_id}"
        return TenantConfig(
            tenant_id=tenant_id,
            issuer=issuer,
            jwks_url=f"{issuer}/.well-known/jwks.json",
            audience=client_id,
            pool_id=pool_id,
            client_id=client_id,
            region=self.region,
            status="active",
        )

    def _cache_tenant_config(self, config: TenantConfig) -> None:
        """Add a tenant config to the cache with all indexes."""
        self._tenant_configs[config.tenant_id] = config
        self._issuer_index[config.issuer] = config.tenant_id
        self._pool_id_index[config.pool_id] = config.tenant_id

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Discover all tenant configurations from Cognito."""
        log.info("discovering_tenants", region=self.region)

        try:
            tenant_configs: Dict[str, TenantConfig] = {}
            paginator = self._client.get_paginator("list_user_pools")

            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    pool_name = pool["Name"]
                    pool_id = pool["Id"]

                    tenant_id = self._extract_tenant_id(pool_name)
                    if not tenant_id:
                        continue

                    client_id = self._find_app_client(pool_id)
                    if not client_id:
                        log.warning("no_app_client_found", pool_id=pool_id, pool_name=pool_name)
                        continue

                    config = self._create_tenant_config(tenant_id, pool_id, pool_name, client_id)
                    tenant_configs[tenant_id] = config
                    self._cache_tenant_config(config)

            log.info("tenants_discovered", count=len(tenant_configs))
            return tenant_configs

        except ClientError as e:
            log.error("tenant_discovery_failed", error=str(e))
            raise IdentityProviderError(f"Failed to discover tenants: {e}", "discover_tenants")

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get configuration for a specific tenant."""
        # Check cache first
        if tenant_id in self._tenant_configs:
            return self._tenant_configs[tenant_id]

        # Not in cache - search Cognito
        log.debug("tenant_cache_miss", tenant_id=tenant_id)

        try:
            paginator = self._client.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    pool_name = pool["Name"]
                    pool_id = pool["Id"]

                    extracted_tenant = self._extract_tenant_id(pool_name)
                    if extracted_tenant == tenant_id:
                        client_id = self._find_app_client(pool_id)
                        if client_id:
                            config = self._create_tenant_config(
                                tenant_id, pool_id, pool_name, client_id
                            )
                            self._cache_tenant_config(config)
                            return config

            raise TenantNotFoundError(tenant_id)

        except TenantNotFoundError:
            raise
        except ClientError as e:
            log.error("get_tenant_config_failed", tenant_id=tenant_id, error=str(e))
            raise IdentityProviderError(f"Failed to get tenant config: {e}", "get_tenant_config")

    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant configuration by JWT issuer URL."""
        # Check index first
        if issuer in self._issuer_index:
            tenant_id = self._issuer_index[issuer]
            return self._tenant_configs[tenant_id]

        # Extract pool_id from issuer URL and search
        # Issuer format: https://cognito-idp.{region}.amazonaws.com/{pool_id}
        try:
            pool_id = issuer.split("/")[-1]
        except Exception:
            raise TenantNotFoundError(f"Invalid issuer format: {issuer}")

        log.debug("tenant_issuer_cache_miss", issuer=issuer)

        try:
            paginator = self._client.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    if pool["Id"] == pool_id:
                        pool_name = pool["Name"]
                        tenant_id = self._extract_tenant_id(pool_name)
                        if tenant_id:
                            client_id = self._find_app_client(pool_id)
                            if client_id:
                                config = self._create_tenant_config(
                                    tenant_id, pool_id, pool_name, client_id
                                )
                                self._cache_tenant_config(config)
                                return config

            raise TenantNotFoundError(f"No tenant found for issuer: {issuer}")

        except TenantNotFoundError:
            raise
        except ClientError as e:
            log.error("get_tenant_by_issuer_failed", issuer=issuer, error=str(e))
            raise IdentityProviderError(
                f"Failed to get tenant by issuer: {e}", "get_tenant_config_by_issuer"
            )

    def get_tenant_config_by_issuer_sync(self, tenant_id: str) -> TenantConfig:
        """Synchronous version of get_tenant_config.

        Used by CognitoVerifier for JWT validation which cannot be async.
        This method only checks the cache and does not make API calls.

        Args:
            tenant_id: Tenant identifier from JWT custom:tenant_id claim

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not in cache
        """
        # Direct lookup by tenant_id (O(1))
        if tenant_id in self._tenant_configs:
            return self._tenant_configs[tenant_id]

        log.warning("tenant_not_in_cache_sync", tenant_id=tenant_id)
        raise TenantNotFoundError(
            f"No tenant found for tenant_id: {tenant_id}. "
            f"Ensure discover_tenants() was called at startup."
        )

    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant configuration by pool ID."""
        # Check index first
        if pool_id in self._pool_id_index:
            tenant_id = self._pool_id_index[pool_id]
            return self._tenant_configs[tenant_id]

        log.debug("tenant_pool_id_cache_miss", pool_id=pool_id)

        try:
            paginator = self._client.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    if pool["Id"] == pool_id:
                        pool_name = pool["Name"]
                        tenant_id = self._extract_tenant_id(pool_name)
                        if tenant_id:
                            client_id = self._find_app_client(pool_id)
                            if client_id:
                                config = self._create_tenant_config(
                                    tenant_id, pool_id, pool_name, client_id
                                )
                                self._cache_tenant_config(config)
                                return config

            raise TenantNotFoundError(f"No tenant found for pool_id: {pool_id}")

        except TenantNotFoundError:
            raise
        except ClientError as e:
            log.error("get_tenant_by_pool_id_failed", pool_id=pool_id, error=str(e))
            raise IdentityProviderError(
                f"Failed to get tenant by pool_id: {e}", "get_tenant_config_by_pool_id"
            )
