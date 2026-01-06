"""Abstract identity provider interface.

This module defines the interface that any identity provider must implement.
The interface is provider-agnostic - implementations can use Cognito, Auth0,
Keycloak, or any other identity service.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from lighthouse.models import (
    AuthChallenge,
    AuthResult,
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
    TenantConfig,
)


class IdentityProvider(ABC):
    """Abstract identity provider for user pool and authentication management.

    This interface supports:
    - Pool lifecycle (create, delete, get info)
    - User management (invite, list, get, update, delete)
    - Role management via custom attributes
    - Tenant discovery and configuration
    - Authentication flows (login, refresh, password reset)

    Implementations:
        - CognitoIdentityProvider: AWS Cognito
        - Auth0IdentityProvider: Auth0 (future)
        - OktaIdentityProvider: Okta (future)
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

    # ==================== Tenant Discovery ====================

    @abstractmethod
    async def discover_tenants(self) -> dict[str, TenantConfig]:
        """Discover all tenant configurations from the identity provider.

        Scans the provider for all user pools/tenants and returns their
        configurations. Used for initializing tenant caches and JWT validation.

        Returns:
            Dict mapping tenant_id to TenantConfig
        """

    @abstractmethod
    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get configuration for a specific tenant.

        Args:
            tenant_id: The tenant identifier

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If tenant doesn't exist
        """

    @abstractmethod
    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant configuration by JWT issuer URL.

        Used during JWT validation to resolve tenant from token issuer.

        Args:
            issuer: The JWT issuer URL (e.g., https://cognito-idp.{region}.amazonaws.com/{pool_id})

        Returns:
            TenantConfig for the tenant

        Raises:
            TenantNotFoundError: If no tenant matches the issuer
        """

    # ==================== Authentication Flows ====================

    @abstractmethod
    async def authenticate(
        self,
        tenant_id: str,
        username: str,
        password: str,
    ) -> AuthResult | AuthChallenge:
        """Authenticate a user and return tokens or challenge.

        Args:
            tenant_id: The tenant to authenticate against
            username: User's username/email
            password: User's password

        Returns:
            AuthResult with tokens if successful, or
            AuthChallenge if additional action required (e.g., new password)

        Raises:
            InvalidCredentialsError: If credentials are invalid
            UserNotConfirmedError: If user hasn't confirmed account
            TenantNotFoundError: If tenant doesn't exist
        """

    @abstractmethod
    async def respond_to_challenge(
        self,
        tenant_id: str,
        username: str,
        challenge_name: str,
        session: str,
        challenge_responses: dict[str, str],
    ) -> AuthResult | AuthChallenge:
        """Respond to an authentication challenge.

        Args:
            tenant_id: The tenant
            username: User's username
            challenge_name: The challenge type (e.g., NEW_PASSWORD_REQUIRED)
            session: Session token from the challenge
            challenge_responses: Challenge-specific responses (e.g., NEW_PASSWORD)

        Returns:
            AuthResult with tokens if successful, or another AuthChallenge

        Raises:
            SessionExpiredError: If session has expired
            InvalidPasswordError: If new password doesn't meet requirements
        """

    @abstractmethod
    async def refresh_tokens(
        self,
        tenant_id: str,
        refresh_token: str,
    ) -> AuthResult:
        """Refresh access token using a refresh token.

        Args:
            tenant_id: The tenant
            refresh_token: The refresh token from previous authentication

        Returns:
            AuthResult with new access and id tokens

        Raises:
            SessionExpiredError: If refresh token has expired
            TenantNotFoundError: If tenant doesn't exist
        """

    @abstractmethod
    async def initiate_password_reset(
        self,
        tenant_id: str,
        username: str,
    ) -> dict[str, str]:
        """Initiate password reset flow - sends verification code to user.

        Args:
            tenant_id: The tenant
            username: User's username/email

        Returns:
            Dict with delivery info (delivery_medium, destination)

        Raises:
            TenantNotFoundError: If tenant doesn't exist
            TooManyRequestsError: If rate limited
        """

    @abstractmethod
    async def confirm_password_reset(
        self,
        tenant_id: str,
        username: str,
        confirmation_code: str,
        new_password: str,
    ) -> bool:
        """Confirm password reset with verification code.

        Args:
            tenant_id: The tenant
            username: User's username/email
            confirmation_code: The code sent to user
            new_password: The new password

        Returns:
            True if password was reset successfully

        Raises:
            InvalidCredentialsError: If code is invalid
            SessionExpiredError: If code has expired
            InvalidPasswordError: If password doesn't meet requirements
        """
