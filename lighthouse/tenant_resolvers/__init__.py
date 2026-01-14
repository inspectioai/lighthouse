"""Tenant resolver implementations for discovering tenant configurations."""

from lighthouse.tenant_resolvers.cognito import CognitoTenantResolver
from lighthouse.tenant_resolvers.dynamodb import DynamoDBTenantResolver
from lighthouse.tenant_resolvers.harbor import HarborTenantResolver
from lighthouse.tenant_resolvers.mock import MockTenantResolver

__all__ = [
    "CognitoTenantResolver",
    "DynamoDBTenantResolver",
    "HarborTenantResolver",
    "MockTenantResolver",
]
