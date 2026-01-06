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

from lighthouse.auth import CognitoVerifier, TokenVerifier
from lighthouse.base import IdentityProvider
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
from lighthouse.providers.cognito import CognitoIdentityProvider

__version__ = "0.2.0"

__all__ = [
    # Core interfaces
    "IdentityProvider",
    "TokenVerifier",
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
    "CognitoVerifier",
]
