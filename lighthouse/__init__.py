"""Lighthouse - Provider-agnostic identity management library.

Lighthouse provides a unified interface for identity provider operations
with support for AWS Cognito out of the box.
"""

from lighthouse.base import IdentityProvider
from lighthouse.exceptions import (
    LighthouseError,
    IdentityProviderError,
    PoolExistsError,
    PoolNotFoundError,
    UserExistsError,
    UserNotFoundError,
)
from lighthouse.models import (
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
    UserStatus,
)
from lighthouse.providers.cognito import CognitoIdentityProvider

__version__ = "0.1.0"

__all__ = [
    # Core interfaces
    "IdentityProvider",
    # Models
    "IdentityUser",
    "InviteResult",
    "PaginatedUsers",
    "PoolConfig",
    "PoolInfo",
    "UserStatus",
    # Exceptions
    "LighthouseError",
    "IdentityProviderError",
    "PoolExistsError",
    "PoolNotFoundError",
    "UserExistsError",
    "UserNotFoundError",
    # Providers
    "CognitoIdentityProvider",
]
