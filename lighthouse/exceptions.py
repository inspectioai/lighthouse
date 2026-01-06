"""Lighthouse exceptions.

All exceptions inherit from LighthouseError for easy catching.
"""

from __future__ import annotations


class LighthouseError(Exception):
    """Base exception for Lighthouse errors."""

    def __init__(self, message: str, code: str):
        self.message = message
        self.code = code
        super().__init__(message)


class IdentityProviderError(LighthouseError):
    """Raised when identity provider operations fail."""

    def __init__(self, message: str, operation: str):
        super().__init__(message=message, code="IDENTITY_PROVIDER_ERROR")
        self.operation = operation


class PoolExistsError(LighthouseError):
    """Raised when attempting to create a pool that already exists."""

    def __init__(self, pool_name: str):
        super().__init__(
            message=f"User pool with name '{pool_name}' already exists",
            code="POOL_EXISTS",
        )
        self.pool_name = pool_name


class PoolNotFoundError(LighthouseError):
    """Raised when a pool is not found."""

    def __init__(self, pool_id: str):
        super().__init__(
            message=f"User pool '{pool_id}' not found",
            code="POOL_NOT_FOUND",
        )
        self.pool_id = pool_id


class UserExistsError(LighthouseError):
    """Raised when attempting to create a user that already exists."""

    def __init__(self, email: str, pool_id: str | None = None):
        if pool_id:
            message = f"User with email '{email}' already exists in pool '{pool_id}'"
        else:
            message = f"User with email '{email}' already exists"
        super().__init__(message=message, code="USER_EXISTS")
        self.email = email
        self.pool_id = pool_id


class UserNotFoundError(LighthouseError):
    """Raised when a user is not found."""

    def __init__(self, user_id: str, pool_id: str):
        super().__init__(
            message=f"User '{user_id}' not found in pool '{pool_id}'",
            code="USER_NOT_FOUND",
        )
        self.user_id = user_id
        self.pool_id = pool_id


# ==================== Authentication Errors ====================


class AuthenticationError(LighthouseError):
    """Base class for authentication errors."""

    def __init__(self, message: str, code: str = "AUTHENTICATION_ERROR"):
        super().__init__(message=message, code=code)


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""

    def __init__(self, message: str = "Invalid username or password"):
        super().__init__(message=message, code="INVALID_CREDENTIALS")


class UserNotConfirmedError(AuthenticationError):
    """Raised when user has not confirmed their account."""

    def __init__(self, username: str):
        super().__init__(
            message=f"User '{username}' has not confirmed their account",
            code="USER_NOT_CONFIRMED",
        )
        self.username = username


class PasswordResetRequiredError(AuthenticationError):
    """Raised when user must reset their password."""

    def __init__(self, username: str):
        super().__init__(
            message=f"Password reset required for user '{username}'",
            code="PASSWORD_RESET_REQUIRED",
        )
        self.username = username


class SessionExpiredError(AuthenticationError):
    """Raised when session has expired."""

    def __init__(self, message: str = "Session has expired. Please login again."):
        super().__init__(message=message, code="SESSION_EXPIRED")


class InvalidPasswordError(AuthenticationError):
    """Raised when password does not meet requirements."""

    def __init__(self, message: str = "Password does not meet requirements"):
        super().__init__(message=message, code="INVALID_PASSWORD")


class TooManyRequestsError(AuthenticationError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Too many requests. Please try again later."):
        super().__init__(message=message, code="TOO_MANY_REQUESTS")


# ==================== Token Errors ====================


class InvalidTokenError(LighthouseError):
    """Raised when a JWT token is invalid."""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(message=message, code="INVALID_TOKEN")


class InvalidIssuerError(LighthouseError):
    """Raised when token issuer is unknown."""

    def __init__(self, issuer: str):
        super().__init__(
            message=f"Unknown token issuer: {issuer}",
            code="INVALID_ISSUER",
        )
        self.issuer = issuer


class InvalidSignatureError(LighthouseError):
    """Raised when token signature verification fails."""

    def __init__(self, message: str = "Token signature verification failed"):
        super().__init__(message=message, code="INVALID_SIGNATURE")


class TokenExpiredError(LighthouseError):
    """Raised when token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message=message, code="TOKEN_EXPIRED")


# ==================== Tenant Errors ====================


class TenantNotFoundError(LighthouseError):
    """Raised when a tenant is not found."""

    def __init__(self, tenant_id: str):
        super().__init__(
            message=f"Tenant '{tenant_id}' not found",
            code="TENANT_NOT_FOUND",
        )
        self.tenant_id = tenant_id
