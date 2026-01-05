"""Abstract identity provider interface.

This module defines the interface that any identity provider must implement.
The interface is provider-agnostic - implementations can use Cognito, Auth0,
Keycloak, or any other identity service.
"""

from abc import ABC, abstractmethod
from typing import Optional

from lighthouse.models import (
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
)


class IdentityProvider(ABC):
    """Abstract identity provider for user pool management.

    This interface supports:
    - Pool lifecycle (create, delete, get info)
    - User management (invite, list, get, update, delete)
    - Role management via custom attributes

    Implementations:
        - CognitoIdentityProvider: AWS Cognito
        - Auth0IdentityProvider: Auth0 (future)
    """

    # ==================== Pool Operations ====================

    @abstractmethod
    async def create_pool(
        self,
        pool_name: str,
        config: Optional[PoolConfig] = None,
    ) -> PoolInfo:
        """Create a new user pool.

        Args:
            pool_name: Unique identifier for the pool (used for idempotency)
            config: Pool configuration options

        Returns:
            PoolInfo with pool_id, client_id, and other details

        Raises:
            PoolExistsError: If pool with this name already exists
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def delete_pool(self, pool_id: str) -> bool:
        """Delete a user pool and all its users.

        Args:
            pool_id: The pool identifier

        Returns:
            True if deleted, False if not found

        Raises:
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def get_pool_info(self, pool_id: str) -> Optional[PoolInfo]:
        """Get information about a user pool.

        Args:
            pool_id: The pool identifier

        Returns:
            PoolInfo if found, None otherwise
        """

    # ==================== User Operations ====================

    @abstractmethod
    async def invite_user(
        self,
        pool_id: str,
        email: str,
        role: str,
        display_name: Optional[str] = None,
        send_invite: bool = True,
    ) -> InviteResult:
        """Invite a new user to the pool.

        Creates the user with a temporary password. If send_invite is True,
        sends an email with login instructions.

        Args:
            pool_id: The pool to add the user to
            email: User's email address
            role: User's role (stored in custom:role attribute)
            display_name: User's display name (stored in name attribute)
            send_invite: Whether to send invitation email

        Returns:
            InviteResult with user_id and temporary password

        Raises:
            UserExistsError: If user with this email already exists in pool
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def get_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> Optional[IdentityUser]:
        """Get a user by their ID (sub).

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)

        Returns:
            IdentityUser if found, None otherwise
        """

    @abstractmethod
    async def get_user_by_email(
        self,
        pool_id: str,
        email: str,
    ) -> Optional[IdentityUser]:
        """Get a user by their email address.

        Args:
            pool_id: The pool containing the user
            email: The user's email address

        Returns:
            IdentityUser if found, None otherwise
        """

    @abstractmethod
    async def list_users(
        self,
        pool_id: str,
        limit: int = 60,
        next_token: Optional[str] = None,
    ) -> PaginatedUsers:
        """List users in a pool with pagination.

        Args:
            pool_id: The pool to list users from
            limit: Maximum number of users to return (max 60 for Cognito)
            next_token: Pagination token from previous call

        Returns:
            PaginatedUsers with users list and pagination info
        """

    @abstractmethod
    async def update_user_role(
        self,
        pool_id: str,
        user_id: str,
        role: str,
    ) -> Optional[IdentityUser]:
        """Update a user's role.

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)
            role: The new role value

        Returns:
            Updated IdentityUser if found, None otherwise

        Raises:
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def disable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Disable a user account (prevent login).

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)

        Returns:
            True if disabled, False if not found
        """

    @abstractmethod
    async def enable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Enable a disabled user account.

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)

        Returns:
            True if enabled, False if not found
        """

    @abstractmethod
    async def delete_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Delete a user from the pool.

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)

        Returns:
            True if deleted, False if not found

        Raises:
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def update_user_display_name(
        self,
        pool_id: str,
        user_id: str,
        display_name: str,
    ) -> Optional[IdentityUser]:
        """Update a user's display name.

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)
            display_name: The new display name value

        Returns:
            Updated IdentityUser if found, None otherwise

        Raises:
            IdentityProviderError: On provider errors
        """

    @abstractmethod
    async def resend_invite(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Resend invitation email to a user.

        Only works for users in FORCE_CHANGE_PASSWORD status.

        Args:
            pool_id: The pool containing the user
            user_id: The user's unique ID (sub)

        Returns:
            True if sent, False if user not found or not eligible
        """
