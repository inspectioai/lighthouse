# AWS Cognito Provider

Detailed documentation for Lighthouse's Cognito provider implementation.

## Overview

The `CognitoIdentityProvider` is a batteries-included implementation of the `IdentityProvider` interface for AWS Cognito User Pools.

## Initialization

```python
from lighthouse import CognitoIdentityProvider

provider = CognitoIdentityProvider(region="us-east-1")
```

The provider uses boto3 under the hood and respects standard AWS credential resolution:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- AWS credentials file (`~/.aws/credentials`)
- IAM role (when running on EC2/ECS)

## Pool Configuration

Cognito pools are created with the following characteristics:

### Username Configuration
- Username attribute: **email**
- Case-insensitive
- Users login with their email address

### Password Policy
Configurable via `PoolConfig`:
- Minimum length (default: 8)
- Require uppercase (default: True)
- Require lowercase (default: True)
- Require numbers (default: True)
- Require symbols (default: False)

### Custom Attributes
- `custom:role` - Stores user role (admin, editor, viewer, etc.)
- `name` - Standard attribute for display name

### Email Verification
- Auto-verified by default
- Users receive verification code on signup

### User Creation
- Admin-only creation (no self-signup)
- Custom welcome email template

## User Lifecycle

### 1. User Creation (Invite)

```python
result = await provider.invite_user(
    pool_id=pool.pool_id,
    email="user@example.com",
    role="admin",
    display_name="User Name",
    send_invite=True,  # or False
)
```

**With `send_invite=True` (default):**
- Sends email with username and temporary password
- User must click link and change password on first login
- Status: `FORCE_CHANGE_PASSWORD`

**With `send_invite=False`:**
- Suppresses email
- Returns temporary password in `InviteResult`
- Useful for programmatic user creation
- Status: `FORCE_CHANGE_PASSWORD`

### 2. User Status States

Cognito user statuses mapped to Lighthouse `UserStatus`:

| Cognito Status | Lighthouse Status | Description |
|----------------|-------------------|-------------|
| `UNCONFIRMED` | `UNCONFIRMED` | Email not verified |
| `CONFIRMED` | `CONFIRMED` | Active user, password changed |
| `FORCE_CHANGE_PASSWORD` | `FORCE_CHANGE_PASSWORD` | Temp password, must change |
| `RESET_REQUIRED` | `RESET_REQUIRED` | Password reset required |
| `ARCHIVED` | `ARCHIVED` | User archived |
| `COMPROMISED` | `COMPROMISED` | Account compromised |
| `UNKNOWN` | `UNKNOWN` | Unknown status |

### 3. User Retrieval

Two methods available:

```python
# By email (faster - direct lookup)
user = await provider.get_user_by_email(pool_id, "user@example.com")

# By sub/UUID (slower - uses filter)
user = await provider.get_user(pool_id, "user-sub-uuid")
```

**Note:** `get_user()` by sub uses `list_users` with filter internally because Cognito's `admin_get_user` requires username (email), not sub.

### 4. Disabling Users

```python
# Disable (prevent login, keep data)
await provider.disable_user(pool_id, user_id)

# Enable
await provider.enable_user(pool_id, user_id)
```

Disabled users:
- Cannot log in
- Retain all data and attributes
- Can be re-enabled at any time

### 5. Deleting Users

```python
await provider.delete_user(pool_id, user_id)
```

**Hard delete:**
- Permanently removes user from pool
- Cannot be undone
- User must be re-invited to regain access

## Resending Invitations

```python
success = await provider.resend_invite(pool_id, user_id)
```

Requirements:
- User must be in `FORCE_CHANGE_PASSWORD` status
- Generates new temporary password
- Sends new welcome email

Implementation details:
- Uses `admin_set_user_password` to set new temp password
- Uses `admin_create_user` with `MessageAction=RESEND`
- Ignores `UsernameExistsException` (expected when resending)

## Pagination

```python
result = await provider.list_users(
    pool_id=pool.pool_id,
    limit=60,  # Max 60 for Cognito
    next_token=None,
)

# Check for more
if result.has_more:
    next_page = await provider.list_users(
        pool_id=pool.pool_id,
        limit=60,
        next_token=result.next_token,
    )
```

Cognito limits:
- Maximum 60 users per page
- Use pagination for larger user bases

## Pool Deletion

```python
await provider.delete_pool(pool_id)
```

**Cascading delete:**
- Deletes pool and all users
- Deletes app clients
- Cannot be undone

## Error Handling

Common Cognito errors mapped to Lighthouse exceptions:

```python
from lighthouse.exceptions import (
    PoolExistsError,
    UserExistsError,
    IdentityProviderError,
)

try:
    pool = await provider.create_pool("my-pool")
except PoolExistsError:
    # Pool name already exists
    pass

try:
    user = await provider.invite_user(...)
except UserExistsError:
    # User email already exists in pool
    pass

try:
    result = await provider.some_operation()
except IdentityProviderError as e:
    # General provider error
    print(f"Operation {e.operation} failed: {e.message}")
```

## Logging

The Cognito provider uses structlog for structured logging:

```python
log.info("cognito_pool_created", pool_id=pool_id, pool_name=pool_name)
log.info("cognito_user_invited", pool_id=pool_id, email=email, role=role)
log.error("cognito_create_pool_error", error=str(e), pool_name=pool_name)
```

Configure structlog in your application:

```python
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
```

## Security Considerations

### Temporary Password Generation

Lighthouse generates secure temporary passwords:
- 12 characters (configurable)
- Includes uppercase, lowercase, digits, symbols
- Uses `secrets` module for cryptographic randomness
- Shuffled to avoid predictable patterns

### IAM Permissions

Minimum required permissions:
- `cognito-idp:CreateUserPool`
- `cognito-idp:DeleteUserPool`
- `cognito-idp:DescribeUserPool`
- `cognito-idp:Admin*` operations

See README for complete IAM policy.

## Idempotency

Pool creation is idempotent using pool name:
- Same pool name → `PoolExistsError`
- Harbor uses `tenant_id` as pool name for safe retries

User creation uses email as unique key:
- Same email → `UserExistsError`

## Performance

### Optimization Tips

1. **Use email lookup when possible:**
   ```python
   # Faster
   user = await provider.get_user_by_email(pool_id, email)

   # Slower (uses list_users filter)
   user = await provider.get_user(pool_id, user_id)
   ```

2. **Batch user retrieval:**
   ```python
   users = await provider.list_users(pool_id, limit=60)
   # Process all users at once
   ```

3. **Cache pool info:**
   ```python
   # Expensive - calls Cognito API
   pool = await provider.get_pool_info(pool_id)

   # Cache pool_id, client_id in your app
   ```

## Limitations

### Cognito-Specific Limits
- Max 60 users per list_users call
- Email must be unique per pool
- Custom attributes limited to 50 characters
- Pool names must be unique per region

### Not Supported
- Self-signup (admin-only creation)
- Multi-factor authentication configuration per user
- Custom email templates per invitation
- Group management (use roles instead)

## Troubleshooting

### "Pool already exists" on creation
Solution: Use unique pool names or handle `PoolExistsError`

### "User not found" by sub
Issue: `get_user()` may be slow with large user bases
Solution: Use `get_user_by_email()` when possible

### "Cannot resend invite"
Issue: User not in `FORCE_CHANGE_PASSWORD` status
Solution: Check `user.status` before resending

### "Invalid password policy"
Issue: PoolConfig requirements too strict
Solution: Adjust PoolConfig parameters
