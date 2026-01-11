"""Lighthouse - Provider-agnostic identity management library.

Lighthouse provides a unified interface for identity provider operations
with support for AWS Cognito out of the box.

Features:
- User pool/tenant management (create, delete, configure)
- User management (invite, list, update, delete)
- Authentication flows (login, refresh, password reset)
- JWT token verification with JWKS caching
- Multi-tenant support with tenant discovery
"""

from lighthouse.cognito import CognitoIdentityProvider, CognitoTenantResolver, CognitoVerifier
from lighthouse.cognito.factory import CognitoFactory
from lighthouse.core.factory import LighthouseFactory, create_factory
from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.core.token_verifier import TokenVerifier
from lighthouse.exceptions import (
    AuthenticationError,
    IdentityProviderError,
    InvalidCredentialsError,
    InvalidIssuerError,
    InvalidPasswordError,
    InvalidSignatureError,
    InvalidTokenError,
    LighthouseError,
    PoolExistsError,
    PoolNotFoundError,
    SessionExpiredError,
    TenantNotFoundError,
    TokenExpiredError,
    TooManyRequestsError,
    UserExistsError,
    UserNotConfirmedError,
    UserNotFoundError,
)
from lighthouse.mock import MockIdentityProvider, MockVerifier
from lighthouse.mock.factory import MockFactory
from lighthouse.models import (
    AuthChallenge,
    AuthResult,
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
    TenantConfig,
    TokenClaims,
    UserStatus,
)

__version__ = "0.3.0"

__all__ = [
    # Core interfaces
    "IdentityProvider",
    "TenantConfigResolver",
    "TokenVerifier",
    # Factory (recommended entry point)
    "create_factory",
    "LighthouseFactory",
    "CognitoFactory",
    "MockFactory",
    # Models
    "AuthChallenge",
    "AuthResult",
    "IdentityUser",
    "InviteResult",
    "PaginatedUsers",
    "PoolConfig",
    "PoolInfo",
    "TenantConfig",
    "TokenClaims",
    "UserStatus",
    # Exceptions - Base
    "LighthouseError",
    "IdentityProviderError",
    # Exceptions - Pool/User
    "PoolExistsError",
    "PoolNotFoundError",
    "UserExistsError",
    "UserNotFoundError",
    # Exceptions - Authentication
    "AuthenticationError",
    "InvalidCredentialsError",
    "InvalidPasswordError",
    "SessionExpiredError",
    "TooManyRequestsError",
    "UserNotConfirmedError",
    # Exceptions - Token
    "InvalidTokenError",
    "InvalidIssuerError",
    "InvalidSignatureError",
    "TokenExpiredError",
    # Exceptions - Tenant
    "TenantNotFoundError",
    # Providers
    "CognitoIdentityProvider",
    "CognitoTenantResolver",
    "CognitoVerifier",
    "MockIdentityProvider",
    "MockVerifier",
]
