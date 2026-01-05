"""Lighthouse exceptions.

All exceptions inherit from LighthouseError for easy catching.
"""


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
