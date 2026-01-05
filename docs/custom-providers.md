# Building Custom Providers

Learn how to implement your own identity provider for Lighthouse.

## Overview

Lighthouse's provider-agnostic design allows you to implement support for any identity service (Auth0, Keycloak, Azure AD, etc.) by implementing the `IdentityProvider` interface.

## Interface Contract

Implement the abstract `IdentityProvider` class with 14 async methods:

```python
from lighthouse.base import IdentityProvider
from lighthouse.models import (
    PoolInfo,
    PoolConfig,
    InviteResult,
    IdentityUser,
    PaginatedUsers,
)
from typing import Optional


class MyCustomProvider(IdentityProvider):
    """Your custom identity provider implementation."""

    def __init__(self, **config):
        # Initialize your provider
        pass

    async def create_pool(
        self,
        pool_name: str,
        config: Optional[PoolConfig] = None,
    ) -> PoolInfo:
        # Create a new user pool
        pass

    async def delete_pool(self, pool_id: str) -> bool:
        # Delete pool and all users
        pass

    async def get_pool_info(self, pool_id: str) -> Optional[PoolInfo]:
        # Get pool metadata
        pass

    async def invite_user(
        self,
        pool_id: str,
        email: str,
        role: str,
        display_name: Optional[str] = None,
        send_invite: bool = True,
    ) -> InviteResult:
        # Create and optionally invite user
        pass

    async def get_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> Optional[IdentityUser]:
        # Get user by ID
        pass

    async def get_user_by_email(
        self,
        pool_id: str,
        email: str,
    ) -> Optional[IdentityUser]:
        # Get user by email
        pass

    async def list_users(
        self,
        pool_id: str,
        limit: int = 60,
        next_token: Optional[str] = None,
    ) -> PaginatedUsers:
        # List users with pagination
        pass

    async def update_user_role(
        self,
        pool_id: str,
        user_id: str,
        role: str,
    ) -> Optional[IdentityUser]:
        # Update user's role
        pass

    async def update_user_display_name(
        self,
        pool_id: str,
        user_id: str,
        display_name: str,
    ) -> Optional[IdentityUser]:
        # Update user's display name
        pass

    async def disable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        # Disable user account
        pass

    async def enable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        # Enable user account
        pass

    async def delete_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        # Delete user permanently
        pass

    async def resend_invite(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        # Resend invitation email
        pass
```

## Example: Auth0 Provider (Skeleton)

```python
from lighthouse.base import IdentityProvider
from lighthouse.models import PoolInfo, PoolConfig, InviteResult, IdentityUser, PaginatedUsers
from lighthouse.exceptions import PoolExistsError, UserExistsError, IdentityProviderError
from typing import Optional
import httpx


class Auth0IdentityProvider(IdentityProvider):
    """Auth0 implementation of IdentityProvider."""

    def __init__(self, domain: str, client_id: str, client_secret: str):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = f"https://{domain}/api/v2"
        self._access_token = None

    async def _get_management_token(self) -> str:
        """Get Auth0 Management API token."""
        if self._access_token:
            return self._access_token

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": f"https://{self.domain}/api/v2/",
                    "grant_type": "client_credentials",
                },
            )
            data = response.json()
            self._access_token = data["access_token"]
            return self._access_token

    async def create_pool(
        self,
        pool_name: str,
        config: Optional[PoolConfig] = None,
    ) -> PoolInfo:
        """Create an Auth0 connection/database."""
        token = await self._get_management_token()

        # Auth0 doesn't have "pools" - use custom database connections
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/connections",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": pool_name,
                    "strategy": "auth0",
                    "enabled_clients": [self.client_id],
                    # Map PoolConfig to Auth0 password policy
                },
            )

            if response.status_code == 409:
                raise PoolExistsError(pool_name)

            data = response.json()

            return PoolInfo(
                pool_id=data["id"],
                pool_name=pool_name,
                client_id=self.client_id,
                region="",  # Auth0 is cloud-hosted
            )

    async def invite_user(
        self,
        pool_id: str,
        email: str,
        role: str,
        display_name: Optional[str] = None,
        send_invite: bool = True,
    ) -> InviteResult:
        """Create user in Auth0."""
        token = await self._get_management_token()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/users",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "email": email,
                    "connection": pool_id,
                    "email_verified": False,
                    "app_metadata": {"role": role},
                    "user_metadata": {"display_name": display_name},
                    "verify_email": send_invite,
                },
            )

            if response.status_code == 409:
                raise UserExistsError(email)

            data = response.json()

            return InviteResult(
                user_id=data["user_id"],
                email=email,
                display_name=display_name,
                temporary_password=None,  # Auth0 sends reset link
            )

    # Implement remaining methods...
```

## Testing Your Provider

Create comprehensive tests using pytest:

```python
import pytest
from my_provider import MyCustomProvider


@pytest.mark.asyncio
async def test_create_pool():
    provider = MyCustomProvider(...)

    pool = await provider.create_pool("test-pool")

    assert pool.pool_id
    assert pool.pool_name == "test-pool"


@pytest.mark.asyncio
async def test_invite_user():
    provider = MyCustomProvider(...)
    pool = await provider.create_pool("test-pool")

    result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
    )

    assert result.user_id
    assert result.email == "user@example.com"
```

## Best Practices

### 1. Exception Handling

Always raise appropriate Lighthouse exceptions:

```python
from lighthouse.exceptions import (
    PoolExistsError,
    UserExistsError,
    IdentityProviderError,
)

try:
    # Provider-specific operation
    pass
except ProviderSpecificError as e:
    if e.code == "already_exists":
        raise PoolExistsError(pool_name)
    else:
        raise IdentityProviderError(str(e), "create_pool")
```

### 2. Logging

Use structlog for consistent logging:

```python
import structlog

log = structlog.get_logger()

async def create_pool(self, pool_name: str, config: Optional[PoolConfig] = None) -> PoolInfo:
    log.info("provider_pool_create_start", pool_name=pool_name)
    try:
        # Create pool
        log.info("provider_pool_created", pool_id=pool_id, pool_name=pool_name)
        return pool_info
    except Exception as e:
        log.error("provider_pool_create_error", error=str(e), pool_name=pool_name)
        raise
```

### 3. Idempotency

Make operations idempotent where possible:

```python
async def create_pool(self, pool_name: str, config: Optional[PoolConfig] = None) -> PoolInfo:
    # Check if pool exists
    existing = await self._find_pool_by_name(pool_name)
    if existing:
        raise PoolExistsError(pool_name)

    # Create new pool
    return await self._create_new_pool(pool_name, config)
```

### 4. Return None for Not Found

Return `None` for not-found scenarios, don't raise exceptions:

```python
async def get_user(self, pool_id: str, user_id: str) -> Optional[IdentityUser]:
    try:
        user = await self._fetch_user(pool_id, user_id)
        return user
    except UserNotFoundException:
        return None  # Not found is not an error
    except Exception as e:
        raise IdentityProviderError(str(e), "get_user")
```

### 5. Pagination

Implement proper pagination:

```python
async def list_users(
    self,
    pool_id: str,
    limit: int = 60,
    next_token: Optional[str] = None,
) -> PaginatedUsers:
    # Fetch users from provider
    users_data, next_token = await self._fetch_users(pool_id, limit, next_token)

    users = [self._map_to_identity_user(u) for u in users_data]

    return PaginatedUsers(
        users=users,
        next_token=next_token,
        has_more=next_token is not None,
    )
```

## Contributing Your Provider

To add your provider to Lighthouse:

1. Create `lighthouse/providers/your_provider/provider.py`
2. Implement `IdentityProvider` interface
3. Add comprehensive tests
4. Update documentation
5. Submit pull request

## Questions?

Open an issue on GitHub or check existing providers for reference:
- `lighthouse/providers/cognito/` - AWS Cognito reference implementation
