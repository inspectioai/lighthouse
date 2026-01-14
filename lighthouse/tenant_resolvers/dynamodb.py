"""DynamoDB-based tenant resolver for reading tenant configurations from DynamoDB."""

from __future__ import annotations

from typing import Dict, Optional

import boto3
import structlog
from botocore.exceptions import ClientError

from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.exceptions import TenantNotFoundError
from lighthouse.models import TenantConfig

log = structlog.get_logger()


class DynamoDBTenantResolver(TenantConfigResolver):
    """
    Discovers tenant configurations from a DynamoDB table.

    Expects table schema:
    - PK: TENANT#{tenant_id}
    - SK: METADATA
    - Attributes: tenant_id, pool_id, client_id, pool_region, is_active, entity_type

    Requires AWS credentials with dynamodb:Scan and dynamodb:GetItem permissions.
    This resolver is designed for services that own the DynamoDB table (e.g., Harbor).
    External services should use HarborTenantResolver (API-based) instead.

    Example:
        resolver = DynamoDBTenantResolver(
            table_name="inspectio-harbor-prod",
            region="us-east-1"
        )
        await resolver.discover_tenants()
    """

    def __init__(
        self,
        table_name: str,
        region: str,
        endpoint_url: Optional[str] = None,  # For LocalStack testing
    ):
        """Initialize DynamoDB tenant resolver.

        Args:
            table_name: Name of the DynamoDB table containing tenant data
            region: AWS region where the table is located
            endpoint_url: Optional endpoint URL for LocalStack/testing
        """
        self._table_name = table_name
        self._region = region
        self._dynamodb = boto3.client(
            'dynamodb',
            region_name=region,
            endpoint_url=endpoint_url
        )
        self._cache: Dict[str, TenantConfig] = {}
        self._issuer_index: Dict[str, str] = {}
        self._pool_id_index: Dict[str, str] = {}
        log.info("Initialized DynamoDB tenant resolver", table_name=table_name, region=region)

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Scan DynamoDB table for all active tenants.

        Returns:
            Dict mapping tenant_id to TenantConfig
        """
        log.info("Discovering tenants from DynamoDB", table_name=self._table_name)

        try:
            # Use pagination for large tables
            paginator = self._dynamodb.get_paginator('scan')
            page_iterator = paginator.paginate(
                TableName=self._table_name,
                FilterExpression="entity_type = :type AND is_active = :active",
                ExpressionAttributeValues={
                    ":type": {"S": "TENANT"},
                    ":active": {"BOOL": True}
                }
            )

            configs = {}
            tenant_count = 0

            for page in page_iterator:
                for item in page.get('Items', []):
                    try:
                        tenant_id = item['tenant_id']['S']
                        pool_id = item['pool_id']['S']
                        client_id = item['client_id']['S']
                        pool_region = item['pool_region']['S']

                        issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
                        jwks_url = f"{issuer}/.well-known/jwks.json"

                        config = TenantConfig(
                            tenant_id=tenant_id,
                            issuer=issuer,
                            jwks_url=jwks_url,
                            audience=client_id,  # The trusted client_id from Harbor
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
                            "Discovered tenant",
                            tenant_id=tenant_id,
                            pool_id=pool_id,
                            pool_region=pool_region
                        )
                    except KeyError as e:
                        log.warning(
                            "Skipping tenant with missing attributes",
                            item=item,
                            missing_key=str(e)
                        )
                        continue

            self._cache = configs
            log.info(
                "Tenant discovery complete",
                tenant_count=tenant_count,
                table_name=self._table_name
            )
            return configs

        except ClientError as e:
            log.error(
                "Failed to discover tenants from DynamoDB",
                table_name=self._table_name,
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Failed to discover tenants from DynamoDB: {e}"
            ) from e

    def get_tenant_config_by_issuer_sync(self, tenant_id: str) -> TenantConfig:
        """Synchronous lookup with on-demand fetching (called by TokenVerifier).

        This method first checks the cache. If the tenant is not found, it queries
        DynamoDB directly using GetItem (O(1) operation) with the tenant_id extracted
        from the JWT. This is much faster than scanning by pool_id.

        Args:
            tenant_id: Tenant identifier from JWT custom:tenant_id claim

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found in DynamoDB
        """
        # Check cache first (fast path)
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        # Cache miss - query DynamoDB directly by tenant_id (GetItem - O(1))
        log.info("Tenant not in cache, querying DynamoDB", tenant_id=tenant_id)

        try:
            response = self._dynamodb.get_item(
                TableName=self._table_name,
                Key={
                    'PK': {'S': f'TENANT#{tenant_id}'},
                    'SK': {'S': 'METADATA'}
                }
            )

            if 'Item' not in response:
                log.warning("Tenant not found in DynamoDB", tenant_id=tenant_id)
                raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

            item = response['Item']

            # Check if tenant is active
            is_active = item.get('is_active', {}).get('BOOL', False)
            if not is_active:
                log.info("Tenant found but inactive", tenant_id=tenant_id)
                raise TenantNotFoundError(f"Tenant inactive: {tenant_id}")

            # Parse tenant configuration from DynamoDB item
            pool_id = item['pool_id']['S']
            client_id = item['client_id']['S']
            pool_region = item['pool_region']['S']

            issuer = f"https://cognito-idp.{pool_region}.amazonaws.com/{pool_id}"
            jwks_url = f"{issuer}/.well-known/jwks.json"

            config = TenantConfig(
                tenant_id=tenant_id,
                issuer=issuer,
                jwks_url=jwks_url,
                audience=client_id,  # The trusted client_id from Harbor
                pool_id=pool_id,
                client_id=client_id,
                region=pool_region,
                status="active"
            )

            # Add to cache for future requests
            self._cache[tenant_id] = config
            self._issuer_index[issuer] = tenant_id
            self._pool_id_index[pool_id] = tenant_id

            log.info("Tenant fetched from DynamoDB and cached", tenant_id=tenant_id)

            return config

        except ClientError as e:
            log.error(
                "DynamoDB query failed",
                tenant_id=tenant_id,
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Failed to query tenant from DynamoDB: {e}"
            ) from e
        except KeyError as e:
            log.error(
                "DynamoDB item missing required field",
                tenant_id=tenant_id,
                field=str(e)
            )
            raise TenantNotFoundError(
                f"Invalid tenant data in DynamoDB (missing {e})"
            ) from e

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get tenant configuration by tenant ID.

        Args:
            tenant_id: Tenant identifier

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant not found
        """
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        log.warning("Tenant not found in cache", tenant_id=tenant_id)
        raise TenantNotFoundError(f"Tenant not found: {tenant_id}")

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
        if not tenant_id:
            log.warning("Unknown issuer", issuer=issuer)
            raise TenantNotFoundError(f"Unknown issuer: {issuer}")

        return self._cache[tenant_id]

    async def get_tenant_config_by_pool_id(self, pool_id: str) -> TenantConfig:
        """Get tenant configuration by Cognito pool ID.

        Args:
            pool_id: Cognito user pool ID

        Returns:
            TenantConfig for the pool

        Raises:
            TenantNotFoundError: If pool not found
        """
        tenant_id = self._pool_id_index.get(pool_id)
        if not tenant_id:
            log.warning("Unknown pool_id", pool_id=pool_id)
            raise TenantNotFoundError(f"Unknown pool_id: {pool_id}")

        return self._cache[tenant_id]

    async def refresh_tenant(self, tenant_id: str) -> None:
        """Refresh single tenant from DynamoDB after update.

        This method fetches the latest tenant data from DynamoDB and updates
        the cache. If the tenant is deleted or inactive, it's removed from cache.

        Args:
            tenant_id: Tenant identifier to refresh
        """
        log.info("Refreshing tenant", tenant_id=tenant_id)

        try:
            response = self._dynamodb.get_item(
                TableName=self._table_name,
                Key={
                    'PK': {'S': f'TENANT#{tenant_id}'},
                    'SK': {'S': 'METADATA'}
                }
            )

            if 'Item' not in response:
                # Tenant deleted - remove from cache
                if tenant_id in self._cache:
                    config = self._cache[tenant_id]
                    del self._cache[tenant_id]
                    del self._issuer_index[config.issuer]
                    del self._pool_id_index[config.pool_id]
                    log.info("Removed deleted tenant from cache", tenant_id=tenant_id)
                return

            item = response['Item']

            # Check if tenant is active
            is_active = item.get('is_active', {}).get('BOOL', False)
            if not is_active:
                # Tenant deactivated - remove from cache
                if tenant_id in self._cache:
                    config = self._cache[tenant_id]
                    del self._cache[tenant_id]
                    del self._issuer_index[config.issuer]
                    del self._pool_id_index[config.pool_id]
                    log.info("Removed inactive tenant from cache", tenant_id=tenant_id)
                return

            # Tenant updated - refresh cache
            pool_id = item['pool_id']['S']
            client_id = item['client_id']['S']
            pool_region = item['pool_region']['S']

            # Remove old indices if tenant existed
            if tenant_id in self._cache:
                old_config = self._cache[tenant_id]
                del self._issuer_index[old_config.issuer]
                del self._pool_id_index[old_config.pool_id]

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

        except ClientError as e:
            log.error(
                "Failed to refresh tenant from DynamoDB",
                tenant_id=tenant_id,
                error=str(e)
            )
            raise TenantNotFoundError(
                f"Failed to refresh tenant {tenant_id}: {e}"
            ) from e
