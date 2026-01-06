"""Identity provider models - provider-agnostic data structures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class UserStatus(str, Enum):
    """User account status in identity provider."""

    UNCONFIRMED = "UNCONFIRMED"
    CONFIRMED = "CONFIRMED"
    ARCHIVED = "ARCHIVED"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"
    RESET_REQUIRED = "RESET_REQUIRED"
    FORCE_CHANGE_PASSWORD = "FORCE_CHANGE_PASSWORD"


@dataclass
class PoolConfig:
    """Configuration for creating a new user pool."""

    # Password policy
    minimum_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_symbols: bool = False

    # MFA settings
    mfa_enabled: bool = False

    # Email verification
    auto_verify_email: bool = True

    # Custom attributes to create
    custom_attributes: list[str] | None = None


@dataclass
class PoolInfo:
    """Information about an existing user pool."""

    pool_id: str
    pool_name: str
    client_id: str
    region: str
    created_at: Optional[datetime] = None
    user_count: int = 0
    metadata: dict[str, Any] | None = None


@dataclass
class IdentityUser:
    """User representation from identity provider."""

    user_id: str  # Sub/UUID
    email: str
    role: str
    status: UserStatus
    display_name: Optional[str] = None
    email_verified: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    enabled: bool = True
    metadata: dict[str, Any] | None = None


@dataclass
class InviteResult:
    """Result of inviting a user to a pool."""

    user_id: str
    email: str
    display_name: Optional[str] = None
    temporary_password: Optional[str] = None
    status: UserStatus = UserStatus.FORCE_CHANGE_PASSWORD


@dataclass
class PaginatedUsers:
    """Paginated list of users from identity provider."""

    users: list[IdentityUser]
    next_token: Optional[str] = None
    has_more: bool = False


@dataclass
class TenantConfig:
    """Configuration for a tenant (used for JWT validation and auth flows).

    This model contains all information needed to authenticate users
    and validate JWT tokens for a specific tenant.
    """

    tenant_id: str
    issuer: str  # e.g., https://cognito-idp.{region}.amazonaws.com/{pool_id}
    jwks_url: str  # e.g., {issuer}/.well-known/jwks.json
    audience: str  # Client ID for token validation
    pool_id: str  # Provider-specific pool identifier
    client_id: str  # Provider-specific client identifier
    region: str  # Provider region
    status: str = "active"
    metadata: dict[str, Any] | None = None


@dataclass
class AuthResult:
    """Result of a successful authentication."""

    access_token: str
    id_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"


@dataclass
class AuthChallenge:
    """Authentication challenge requiring additional action."""

    challenge_name: str  # e.g., NEW_PASSWORD_REQUIRED, MFA_REQUIRED
    session: str
    challenge_parameters: dict[str, Any] | None = None


@dataclass
class TokenClaims:
    """Extracted claims from a validated JWT token."""

    sub: str  # User ID
    email: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    raw_claims: dict[str, Any] | None = None
