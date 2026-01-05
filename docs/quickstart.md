# Lighthouse Quick Start Guide

This guide will walk you through using Lighthouse to manage identity providers.

## Installation

```bash
pip install git+https://github.com/inspectioai/lighthouse.git
```

## Basic Workflow

### 1. Initialize Provider

```python
from lighthouse import CognitoIdentityProvider

provider = CognitoIdentityProvider(region="us-east-1")
```

### 2. Create a User Pool

```python
from lighthouse import PoolConfig

pool = await provider.create_pool(
    pool_name="my-app-prod",
    config=PoolConfig(
        minimum_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_symbols=True,
        mfa_enabled=False,
    )
)

print(f"Pool created: {pool.pool_id}")
print(f"Client ID: {pool.client_id}")
```

### 3. Invite Users

```python
# With email invitation
result = await provider.invite_user(
    pool_id=pool.pool_id,
    email="admin@example.com",
    role="admin",
    display_name="Admin User",
    send_invite=True,  # Sends email
)

# Without email (returns temp password)
result = await provider.invite_user(
    pool_id=pool.pool_id,
    email="user@example.com",
    role="viewer",
    display_name="Regular User",
    send_invite=False,
)

print(f"User created: {result.user_id}")
print(f"Temp password: {result.temporary_password}")
```

### 4. List Users

```python
paginated = await provider.list_users(
    pool_id=pool.pool_id,
    limit=50,
)

for user in paginated.users:
    print(f"{user.email} - {user.role} - {user.status}")

# Handle pagination
if paginated.has_more:
    next_page = await provider.list_users(
        pool_id=pool.pool_id,
        limit=50,
        next_token=paginated.next_token,
    )
```

### 5. Get User

```python
# By email
user = await provider.get_user_by_email(
    pool_id=pool.pool_id,
    email="admin@example.com",
)

# By ID (sub)
user = await provider.get_user(
    pool_id=pool.pool_id,
    user_id="user-uuid-here",
)

if user:
    print(f"User: {user.email}")
    print(f"Role: {user.role}")
    print(f"Status: {user.status}")
```

### 6. Update User

```python
# Update role
updated = await provider.update_user_role(
    pool_id=pool.pool_id,
    user_id=user.user_id,
    role="editor",
)

# Update display name
updated = await provider.update_user_display_name(
    pool_id=pool.pool_id,
    user_id=user.user_id,
    display_name="New Name",
)
```

### 7. Disable/Enable User

```python
# Disable user (prevent login)
await provider.disable_user(
    pool_id=pool.pool_id,
    user_id=user.user_id,
)

# Enable user
await provider.enable_user(
    pool_id=pool.pool_id,
    user_id=user.user_id,
)
```

### 8. Delete User

```python
deleted = await provider.delete_user(
    pool_id=pool.pool_id,
    user_id=user.user_id,
)
```

### 9. Delete Pool

```python
# Deletes pool and all users
deleted = await provider.delete_pool(pool.pool_id)
```

## Error Handling

```python
from lighthouse.exceptions import (
    PoolExistsError,
    UserExistsError,
    IdentityProviderError,
)

try:
    pool = await provider.create_pool("my-pool")
except PoolExistsError as e:
    print(f"Pool already exists: {e.pool_name}")
except IdentityProviderError as e:
    print(f"Provider error: {e.message}")

try:
    result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
    )
except UserExistsError as e:
    print(f"User already exists: {e.email}")
```

## Complete Example

```python
import asyncio
from lighthouse import CognitoIdentityProvider, PoolConfig
from lighthouse.exceptions import PoolExistsError, UserExistsError


async def main():
    # Initialize
    provider = CognitoIdentityProvider(region="us-east-1")

    # Create pool
    try:
        pool = await provider.create_pool(
            pool_name="example-app",
            config=PoolConfig(minimum_length=12),
        )
        print(f"Created pool: {pool.pool_id}")
    except PoolExistsError:
        print("Pool already exists, fetching...")
        # Would need to store pool_id or list pools

    # Invite admin user
    try:
        admin = await provider.invite_user(
            pool_id=pool.pool_id,
            email="admin@example.com",
            role="admin",
            display_name="Admin User",
            send_invite=True,
        )
        print(f"Invited admin: {admin.user_id}")
    except UserExistsError:
        print("Admin already exists")

    # List all users
    users = await provider.list_users(pool.pool_id)
    print(f"Total users: {len(users.users)}")

    # Cleanup (optional)
    # await provider.delete_pool(pool.pool_id)


if __name__ == "__main__":
    asyncio.run(main())
```

## Next Steps

- [Cognito Provider Details](cognito-provider.md)
- [Building Custom Providers](custom-providers.md)
- [Migrating from Harbor](migration-from-harbor.md)
