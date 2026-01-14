"""Harbor API-based tenant resolver for external services."""

from __future__ import annotations

import asyncio
from typing import Dict, Optional

import requests
import structlog

from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.exceptions import TenantNotFoundError
from lighthouse.models import TenantConfig

log = structlog.get_logger()


class HarborTenantResolver(TenantConfigResolver):
    """
    Discovers tenant configurations by calling Harbor's public API.

    This resolver is designed for external services (Faro, Magellan, etc.) that need
    tenant metadata but don't have direct access to Harbor's DynamoDB table.
    Uses API key authentication to call Harbor endpoints.

    Harbor itself should use DynamoDBTenantResolver for direct database access.

    Example:
        resolver = HarborTenantResolver(
            harbor_url="https://harbor.inspectio.ai",
            api_key="secret-key",
            cache_ttl=600
        )
        await resolver.discover_tenants()
    """

    def __init__(
        self,
        harbor_url: str,
        api_key: str,
        cache_ttl: int = 600,  # 10 minutes default
        timeout: float = 10.0,  # 10 seconds default
    ):
        """Initialize Harbor API tenant resolver.

        Args:
            harbor_url: Base URL of Harbor service (e.g., "https://harbor.example.com")
            api_key: API key for service-to-service authentication
            cache_ttl: Cache time-to-live in seconds (default: 600)
            timeout: HTTP request timeout in seconds (default: 10.0)
        """
        self._harbor_url = harbor_url.rstrip('/')
        self._api_key = api_key
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: Dict[str, TenantConfig] = {}
        self._issuer_index: Dict[str, str] = {}
        self._pool_id_index: Dict[str, str] = {}
        log.info("Initialized Harbor API tenant resolver", harbor_url=harbor_url)

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Fetch all tenants from Harbor API (admin endpoint).

        This is optional - HarborTenantResolver will fetch tenants on-demand
        if not pre-warmed. This method uses the admin endpoint which accepts
        API key authentication.

        Returns:
            Dict mapping tenant_id to TenantConfig

        Raises:
            TenantNotFoundError: If API call fails or returns invalid data
        """
        log.info("Discovering tenants from Harbor API", harbor_url=self._harbor_url)

        def _fetch_tenants():
            """Synchronous function to fetch tenants using requests."""
            response = requests.get(
                f"{self._harbor_url}/api/v1/admin/tenants",
                headers={"X-API-Key": self._api_key},
                timeout=self._timeout
            )
            response.raise_for_status()
            return response.json()

        try:
            # Run synchronous requests call in thread pool
            tenants = await asyncio.to_thread(_fetch_tenants)

            if not isinstance(tenants, list):
                log.error("Invalid response from Harbor API", response_type=type(tenants))
                raise TenantNotFoundError("Harbor API returned invalid response format")

            configs = {}
            tenant_count = 0

            for tenant in tenants:
                try:
                    # Skip inactive tenants
                    if not tenant.get("isActive", True):
                        log.debug("Skipping inactive tenant", tenant_id=tenant.get("tenantId"))
                        continue

                    tenant_id = tenant["tenantId"]
                    pool_id = tenant["poolId"]
                    client_id = tenant["clientId"]
                    pool_region = tenant["poolRegion"]

                    issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
                    jwks_url = f"{issuer}/.well-known/jwks.json"

                    config = TenantConfig(
                        tenant_id=tenant_id,
                        issuer=issuer,
                        jwks_url=jwks_url,
                        audience=client_id,  # Harbor's trusted client_id
                        pool_id=pool_id,
                        client_id=client_id,
                        region=pool_region,
                        status="active"
                    )

                    configs[tenant_id] = config
                    self._issuer_index[issuer] = tenant_id
                    self._pool_id_index[pool_id] = tenant_id
                    tenant_count += 1

                    log.debug(
                        "Discovered tenant from Harbor API",
                        tenant_id=tenant_id,
                        pool_id=pool_id,
                        pool_region=pool_region
                    )
                except KeyError as e:
                    log.warning(
                        "Skipping tenant with missing attributes",
                        tenant=tenant,
                        missing_key=str(e)
                    )
                    continue

            self._cache = configs
            log.info(
                "Tenant discovery from Harbor API complete",
                tenant_count=tenant_count
            )
            return configs

        except requests.HTTPError as e:
            log.error(
                "Harbor API returned error",
                status_code=e.response.status_code if e.response else None,
                error=str(e)
            )
            status = e.response.status_code if e.response else "unknown"
            raise TenantNotFoundError(
                f"Failed to discover tenants from Harbor API: HTTP {status}"
            ) from e
        except requests.RequestException as e:
            log.error(
                "Failed to connect to Harbor API",
                harbor_url=self._harbor_url,
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Failed to connect to Harbor API: {e}"
            ) from e
        except Exception as e:
            log.error(
                "Unexpected error discovering tenants from Harbor",
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Unexpected error discovering tenants: {e}"
            ) from e

    def get_tenant_config_by_issuer_sync(self, tenant_id: str) -> TenantConfig:
        """Synchronous lookup with on-demand fetching (called by TokenVerifier).

        This method first checks the cache. If the tenant is not found, it fetches
        the tenant directly from Harbor API using the tenant_id extracted from the JWT.

        Args:
            tenant_id: Tenant identifier from JWT custom:tenant_id claim

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found in Harbor
        """
        # Check cache first (fast path)
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        # Cache miss - fetch from Harbor API by tenant_id
        log.info("Tenant not in cache, fetching from Harbor API", tenant_id=tenant_id)

        try:
            # Fetch tenant by ID from Harbor
            response = requests.get(
                f"{self._harbor_url}/api/v1/tenants/{tenant_id}",
                headers={"X-API-Key": self._api_key},
                timeout=self._timeout
            )

            if response.status_code == 404:
                log.warning("Tenant not found in Harbor", tenant_id=tenant_id)
                raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

            response.raise_for_status()
            tenant = response.json()

            # Skip inactive tenants
            if not tenant.get("is_active", True):
                log.info("Tenant found but inactive", tenant_id=tenant_id)
                raise TenantNotFoundError(f"Tenant inactive: {tenant_id}")

            # Build TenantConfig from Harbor response (camelCase fields)
            pool_id = tenant["poolId"]
            client_id = tenant["clientId"]
            pool_region = tenant["poolRegion"]

            issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
            jwks_url = f"{issuer}/.well-known/jwks.json"

            config = TenantConfig(
                tenant_id=tenant_id,
                issuer=issuer,
                jwks_url=jwks_url,
                audience=client_id,  # Harbor's trusted client_id
                pool_id=pool_id,
                client_id=client_id,
                region=pool_region,
                status="active"
            )

            # Add to cache for future requests
            self._cache[tenant_id] = config
            self._issuer_index[issuer] = tenant_id
            self._pool_id_index[pool_id] = tenant_id

            log.info("Tenant fetched from Harbor API and cached", tenant_id=tenant_id)

            return config

        except requests.HTTPError as e:
            if e.response and e.response.status_code == 404:
                # Already handled above
                raise
            log.error(
                "Harbor API returned error",
                status_code=e.response.status_code if e.response else None,
                tenant_id=tenant_id,
                error=str(e)
            )
            status = e.response.status_code if e.response else "unknown"
            raise TenantNotFoundError(
                f"Failed to fetch tenant from Harbor API: HTTP {status}"
            ) from e
        except requests.RequestException as e:
            log.error(
                "Failed to connect to Harbor API",
                harbor_url=self._harbor_url,
                tenant_id=tenant_id,
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Failed to connect to Harbor API: {e}"
            ) from e
        except KeyError as e:
            log.error("Harbor response missing required field", field=str(e), tenant=tenant)
            raise TenantNotFoundError(
                f"Invalid Harbor response (missing {e})"
            ) from e
        except Exception as e:
            log.error("Unexpected error fetching tenant", tenant_id=tenant_id, error=str(e))
            raise TenantNotFoundError(f"Unexpected error: {e}") from e

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get tenant configuration by tenant ID.

        Fetches directly from Harbor API using the single-tenant endpoint.
        This avoids the need for admin JWT (which discover_tenants requires).

        Args:
            tenant_id: Tenant identifier

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found
        """
        # Check cache first
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        # Fetch single tenant from Harbor (uses sync method implementation)
        # This is async-safe since we're calling the sync method in a thread
        config = await asyncio.to_thread(
            self.get_tenant_config_by_issuer_sync, tenant_id
        )
        return config

    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant configuration by JWT issuer.

        Note: This method cannot extract tenant_id from issuer, so it will
        raise an error. Use get_tenant_config(tenant_id) instead.

        Args:
            issuer: JWT issuer URL

        Returns:
            TenantConfig for the issuer

        Raises:
            TenantNotFoundError: Always raises - use get_tenant_config instead
        """
        # Check cache first
        tenant_id = self._issuer_index.get(issuer)
        if tenant_id:
            return self._cache[tenant_id]

        # Cannot extract tenant_id from issuer reliably
        log.error("get_tenant_config_by_issuer called but requires tenant_id", issuer=issuer)
        raise TenantNotFoundError(
            f"Cannot resolve tenant from issuer. Use get_tenant_config(tenant_id) instead."
        )

    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant configuration by Cognito pool ID.

        Only checks cache - cannot fetch by pool_id from Harbor API.
        Use get_tenant_config(tenant_id) instead.

        Args:
            pool_id: Cognito user pool ID

        Returns:
            TenantConfig for the pool

        Raises:
            TenantNotFoundError: If pool not in cache
        """
        # Check cache only
        tenant_id = self._pool_id_index.get(pool_id)
        if tenant_id:
            return self._cache[tenant_id]

        log.warning("Unknown pool_id (not in cache)", pool_id=pool_id)
        raise TenantNotFoundError(
            f"Pool not in cache: {pool_id}. Use get_tenant_config(tenant_id) instead."
        )

    async def refresh_tenant(self, tenant_id: str) -> None:
        """Refresh single tenant from Harbor API.

        This method fetches the specific tenant from Harbor and updates the cache.
        Note: Harbor API doesn't have a single-tenant endpoint, so this re-fetches
        all tenants. Consider implementing a single-tenant endpoint in Harbor for
        better performance.

        Args:
            tenant_id: Tenant identifier to refresh
        """
        log.info("Refreshing tenant from Harbor API", tenant_id=tenant_id)

        def _fetch_tenant():
            """Synchronous function to fetch single tenant using requests."""
            return requests.get(
                f"{self._harbor_url}/api/v1/tenants/{tenant_id}",
                headers={"X-API-Key": self._api_key},
                timeout=self._timeout
            )

        try:
            # Run synchronous requests call in thread pool
            response = await asyncio.to_thread(_fetch_tenant)

            if response.status_code == 404:
                # Tenant deleted - remove from cache
                if tenant_id in self._cache:
                    config = self._cache[tenant_id]
                    del self._cache[tenant_id]
                    del self._issuer_index[config.issuer]
                    del self._pool_id_index[config.pool_id]
                    log.info("Removed deleted tenant from cache", tenant_id=tenant_id)
                return

            response.raise_for_status()
            tenant = response.json()

            # Check if tenant is active
            if not tenant.get("is_active", True):
                # Tenant deactivated - remove from cache
                if tenant_id in self._cache:
                    config = self._cache[tenant_id]
                    del self._cache[tenant_id]
                    del self._issuer_index[config.issuer]
                    del self._pool_id_index[config.pool_id]
                    log.info("Removed inactive tenant from cache", tenant_id=tenant_id)
                return

            # Remove old indices if tenant existed
            if tenant_id in self._cache:
                old_config = self._cache[tenant_id]
                del self._issuer_index[old_config.issuer]
                del self._pool_id_index[old_config.pool_id]

            # Update cache with new data
            pool_id = tenant["pool_id"]
            client_id = tenant["client_id"]
            pool_region = tenant["pool_region"]

            issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
            jwks_url = f"{issuer}/.well-known/jwks.json"

            config = TenantConfig(
                tenant_id=tenant_id,
                issuer=issuer,
                jwks_url=jwks_url,
                audience=client_id,
                pool_id=pool_id,
                client_id=client_id,
                region=pool_region,
                status="active"
            )

            self._cache[tenant_id] = config
            self._issuer_index[issuer] = tenant_id
            self._pool_id_index[pool_id] = tenant_id

            log.info("Refreshed tenant in cache", tenant_id=tenant_id)

        except requests.HTTPError as e:
            if e.response and e.response.status_code != 404:
                log.error(
                    "Failed to refresh tenant from Harbor API",
                    tenant_id=tenant_id,
                    status_code=e.response.status_code
                )
        except Exception as e:
            log.error(
                "Unexpected error refreshing tenant",
                tenant_id=tenant_id,
                error=str(e)
            )
