# Lighthouse

**Provider-agnostic identity management library with batteries-included AWS Cognito support.**

Lighthouse provides a unified interface for identity provider operations, making it easy to manage user pools and users across different identity providers without changing your application logic.

## Features

- **Provider-Agnostic Interface**: Abstract base class for implementing any identity provider
- **Async-First**: All operations use async/await for high performance
- **Type-Safe**: Full type hints with mypy support
- **Batteries-Included**: AWS Cognito provider included in core package
- **Well-Tested**: Comprehensive test suite using moto for AWS mocking
- **Maritime-Themed**: Named after lighthouses that guide ships safely to harbor

## Quick Start

### Installation

```bash
# From git repository
pip install git+https://github.com/inspectioai/lighthouse.git

# For development
git clone https://github.com/inspectioai/lighthouse.git
cd lighthouse
pip install -e ".[dev]"
```

### Basic Usage

```python
from lighthouse import CognitoIdentityProvider, PoolConfig

# Initialize provider
provider = CognitoIdentityProvider(region="us-east-1")

# Create a user pool
pool = await provider.create_pool(
    pool_name="my-app-users",
    config=PoolConfig(
        minimum_length=12,
        require_symbols=True,
        mfa_enabled=False,
    )
)

# Invite a user
result = await provider.invite_user(
    pool_id=pool.pool_id,
    email="user@example.com",
    role="admin",
    display_name="Jane Doe",
    send_invite=True,
)

# List users
paginated = await provider.list_users(
    pool_id=pool.pool_id,
    limit=50,
)
for user in paginated.users:
    print(f"{user.email} - {user.role} - {user.status}")

# Update user role
await provider.update_user_role(
    pool_id=pool.pool_id,
    user_id=result.user_id,
    role="editor",
)

# Delete pool (and all users)
await provider.delete_pool(pool.pool_id)
```

## Architecture

Lighthouse uses the Strategy pattern with a provider-agnostic interface:

```
lighthouse/
├── base.py          # IdentityProvider ABC with 14 async methods
├── models.py        # Provider-agnostic data models
├── exceptions.py    # Library exceptions
└── providers/
    └── cognito/     # AWS Cognito implementation
```

### Core Abstractions

**IdentityProvider Interface** - Abstract base class with 14 methods:

**Pool Operations:**
- `create_pool()` - Create a new user pool
- `delete_pool()` - Delete a pool and all users
- `get_pool_info()` - Get pool metadata

**User Operations:**
- `invite_user()` - Create and invite a user
- `get_user()` - Get user by ID
- `get_user_by_email()` - Get user by email
- `list_users()` - List users with pagination
- `update_user_role()` - Update user's role
- `update_user_display_name()` - Update user's display name
- `disable_user()` - Disable user account
- `enable_user()` - Enable user account
- `delete_user()` - Delete user
- `resend_invite()` - Resend invitation email

### Data Models

- **PoolConfig** - Configuration for pool creation
- **PoolInfo** - Pool metadata
- **IdentityUser** - User representation
- **InviteResult** - Result of user invitation
- **PaginatedUsers** - Paginated user list
- **UserStatus** - User status enum

## AWS Cognito Provider

The included Cognito implementation uses:
- Email as username (case-insensitive)
- Custom `custom:role` attribute for roles
- Standard `name` attribute for display names
- Secure temporary password generation
- Admin-only user creation

### Required AWS Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:CreateUserPool",
        "cognito-idp:DeleteUserPool",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminDeleteUser",
        "cognito-idp:AdminUpdateUserAttributes",
        "cognito-idp:AdminDisableUser",
        "cognito-idp:AdminEnableUser",
        "cognito-idp:AdminSetUserPassword",
        "cognito-idp:ListUsers"
      ],
      "Resource": "*"
    }
  ]
}
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=lighthouse --cov-report=term-missing

# Run type checking
mypy lighthouse/

# Run linting
ruff check lighthouse/
```

## Documentation

- [Quick Start Guide](docs/quickstart.md) - Step-by-step tutorial
- [Cognito Provider](docs/cognito-provider.md) - AWS Cognito details
- [Custom Providers](docs/custom-providers.md) - Build your own provider
- [Migration from Harbor](docs/migration-from-harbor.md) - Harbor migration guide

## Requirements

- Python 3.11+
- boto3 (for Cognito provider)
- structlog (for logging)

## Development

```bash
# Clone repository
git clone https://github.com/inspectioai/lighthouse.git
cd lighthouse

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Type check
mypy lighthouse/

# Lint
ruff check lighthouse/
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or pull request.

## Related Projects

- **Harbor** - Tenant management service that uses Lighthouse
- **Panorama** - Authentication service built on Lighthouse
- **Faro** - Permissions service that integrates with Lighthouse
