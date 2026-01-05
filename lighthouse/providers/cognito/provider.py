"""AWS Cognito implementation of IdentityProvider."""

import secrets
import string
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
import structlog
from botocore.exceptions import ClientError

from lighthouse.exceptions import IdentityProviderError, PoolExistsError, UserExistsError
from lighthouse.base import IdentityProvider
from lighthouse.models import (
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
    UserStatus,
)

log = structlog.get_logger()

# Custom attribute for role
ROLE_ATTRIBUTE = "custom:role"
# Standard attribute for display name
NAME_ATTRIBUTE = "name"


class CognitoIdentityProvider(IdentityProvider):
    """AWS Cognito implementation of identity provider.

    Uses Cognito User Pools for user management with custom:role attribute
    for storing user roles.
    """

    def __init__(self, region: str):
        self.region = region
        self._client = boto3.client("cognito-idp", region_name=region)

    def _generate_temp_password(self, length: int = 12) -> str:
        """Generate a secure temporary password meeting Cognito requirements."""
        # Ensure we have at least one of each required type
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*"),
        ]
        # Fill the rest with random characters
        remaining = length - len(password)
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password.extend(secrets.choice(all_chars) for _ in range(remaining))
        # Shuffle to avoid predictable pattern
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    def _parse_user_attributes(self, attributes: list[dict[str, str]]) -> dict[str, Any]:
        """Parse Cognito user attributes into a dictionary."""
        return {attr["Name"]: attr["Value"] for attr in attributes}

    def _cognito_user_to_identity_user(
        self, user: dict[str, Any], pool_id: str
    ) -> IdentityUser:
        """Convert Cognito user response to IdentityUser model."""
        attrs = self._parse_user_attributes(user.get("Attributes", []))

        # Map Cognito status to our status enum
        status_map = {
            "UNCONFIRMED": UserStatus.UNCONFIRMED,
            "CONFIRMED": UserStatus.CONFIRMED,
            "ARCHIVED": UserStatus.ARCHIVED,
            "COMPROMISED": UserStatus.COMPROMISED,
            "UNKNOWN": UserStatus.UNKNOWN,
            "RESET_REQUIRED": UserStatus.RESET_REQUIRED,
            "FORCE_CHANGE_PASSWORD": UserStatus.FORCE_CHANGE_PASSWORD,
        }
        cognito_status = user.get("UserStatus", "UNKNOWN")
        status = status_map.get(cognito_status, UserStatus.UNKNOWN)

        return IdentityUser(
            user_id=attrs.get("sub", user.get("Username", "")),
            email=attrs.get("email", ""),
            role=attrs.get(ROLE_ATTRIBUTE, "viewer"),
            status=status,
            display_name=attrs.get(NAME_ATTRIBUTE),
            email_verified=attrs.get("email_verified", "false").lower() == "true",
            created_at=user.get("UserCreateDate"),
            updated_at=user.get("UserLastModifiedDate"),
            enabled=user.get("Enabled", True),
        )

    # ==================== Pool Operations ====================

    async def create_pool(
        self,
        pool_name: str,
        config: Optional[PoolConfig] = None,
    ) -> PoolInfo:
        """Create a new Cognito user pool with app client."""
        config = config or PoolConfig()

        try:
            # Create user pool
            pool_response = self._client.create_user_pool(
                PoolName=pool_name,
                Policies={
                    "PasswordPolicy": {
                        "MinimumLength": config.minimum_length,
                        "RequireUppercase": config.require_uppercase,
                        "RequireLowercase": config.require_lowercase,
                        "RequireNumbers": config.require_numbers,
                        "RequireSymbols": config.require_symbols,
                    }
                },
                AutoVerifiedAttributes=["email"] if config.auto_verify_email else [],
                UsernameAttributes=["email"],
                UsernameConfiguration={"CaseSensitive": False},
                Schema=[
                    {
                        "Name": "email",
                        "AttributeDataType": "String",
                        "Required": True,
                        "Mutable": True,
                    },
                    {
                        "Name": "role",
                        "AttributeDataType": "String",
                        "Required": False,
                        "Mutable": True,
                        "StringAttributeConstraints": {
                            "MinLength": "1",
                            "MaxLength": "50",
                        },
                    },
                ],
                MfaConfiguration="OFF" if not config.mfa_enabled else "OPTIONAL",
                AdminCreateUserConfig={
                    "AllowAdminCreateUserOnly": True,
                    "InviteMessageTemplate": {
                        "EmailSubject": "Welcome to Inspectio",
                        "EmailMessage": (
                            "You have been invited to Inspectio. "
                            "Your username is {username} and temporary password is {####}. "
                            "Please login and change your password."
                        ),
                    },
                },
            )

            pool_id = pool_response["UserPool"]["Id"]
            log.info("cognito_pool_created", pool_id=pool_id, pool_name=pool_name)

            # Create app client (no secret for public client)
            client_response = self._client.create_user_pool_client(
                UserPoolId=pool_id,
                ClientName=f"{pool_name}-client",
                GenerateSecret=False,
                ExplicitAuthFlows=[
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH",
                    "ALLOW_USER_SRP_AUTH",
                ],
                PreventUserExistenceErrors="ENABLED",
                ReadAttributes=[
                    "email",
                    "email_verified",
                    "sub",
                    NAME_ATTRIBUTE,
                    ROLE_ATTRIBUTE,
                ],
                WriteAttributes=["email", NAME_ATTRIBUTE, ROLE_ATTRIBUTE],
            )

            client_id = client_response["UserPoolClient"]["ClientId"]
            log.info("cognito_client_created", pool_id=pool_id, client_id=client_id)

            return PoolInfo(
                pool_id=pool_id,
                pool_name=pool_name,
                client_id=client_id,
                region=self.region,
                created_at=pool_response["UserPool"].get("CreationDate"),
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceExistsException":
                raise PoolExistsError(pool_name)
            log.error("cognito_create_pool_error", error=str(e), pool_name=pool_name)
            raise IdentityProviderError(f"Failed to create pool: {e}", "create_pool")

    async def delete_pool(self, pool_id: str) -> bool:
        """Delete a Cognito user pool."""
        try:
            self._client.delete_user_pool(UserPoolId=pool_id)
            log.info("cognito_pool_deleted", pool_id=pool_id)
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                return False
            log.error("cognito_delete_pool_error", error=str(e), pool_id=pool_id)
            raise IdentityProviderError(f"Failed to delete pool: {e}", "delete_pool")

    async def get_pool_info(self, pool_id: str) -> Optional[PoolInfo]:
        """Get information about a Cognito user pool."""
        try:
            response = self._client.describe_user_pool(UserPoolId=pool_id)
            pool = response["UserPool"]

            # Get the first app client
            clients_response = self._client.list_user_pool_clients(
                UserPoolId=pool_id, MaxResults=1
            )
            client_id = ""
            if clients_response.get("UserPoolClients"):
                client_id = clients_response["UserPoolClients"][0]["ClientId"]

            return PoolInfo(
                pool_id=pool_id,
                pool_name=pool.get("Name", ""),
                client_id=client_id,
                region=self.region,
                created_at=pool.get("CreationDate"),
                user_count=pool.get("EstimatedNumberOfUsers", 0),
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                return None
            log.error("cognito_get_pool_error", error=str(e), pool_id=pool_id)
            raise IdentityProviderError(f"Failed to get pool info: {e}", "get_pool_info")

    # ==================== User Operations ====================

    async def invite_user(
        self,
        pool_id: str,
        email: str,
        role: str,
        display_name: Optional[str] = None,
        send_invite: bool = True,
    ) -> InviteResult:
        """Invite a user to the Cognito pool."""
        temp_password = self._generate_temp_password()

        try:
            # Build user attributes
            user_attributes = [
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
                {"Name": ROLE_ATTRIBUTE, "Value": role},
            ]
            if display_name:
                user_attributes.append({"Name": NAME_ATTRIBUTE, "Value": display_name})

            # Build params - only include MessageAction if suppressing
            create_params: dict[str, Any] = {
                "UserPoolId": pool_id,
                "Username": email,
                "UserAttributes": user_attributes,
                "TemporaryPassword": temp_password,
                "DesiredDeliveryMediums": ["EMAIL"],
            }
            # Only suppress if explicitly not sending invite
            # Default behavior (no MessageAction) sends the welcome email
            if not send_invite:
                create_params["MessageAction"] = "SUPPRESS"

            response = self._client.admin_create_user(**create_params)

            user = response["User"]
            attrs = self._parse_user_attributes(user.get("Attributes", []))

            log.info(
                "cognito_user_invited",
                pool_id=pool_id,
                email=email,
                role=role,
                send_invite=send_invite,
            )

            return InviteResult(
                user_id=attrs.get("sub", user.get("Username", "")),
                email=email,
                display_name=display_name,
                temporary_password=temp_password if not send_invite else None,
                status=UserStatus.FORCE_CHANGE_PASSWORD,
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "UsernameExistsException":
                raise UserExistsError(email)
            log.error("cognito_invite_error", error=str(e), pool_id=pool_id, email=email)
            raise IdentityProviderError(f"Failed to invite user: {e}", "invite_user")

    async def get_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> Optional[IdentityUser]:
        """Get a user by their sub (UUID)."""
        try:
            # Cognito requires username, but we have sub
            # Use list_users with filter to find by sub
            response = self._client.list_users(
                UserPoolId=pool_id,
                Filter=f'sub = "{user_id}"',
                Limit=1,
            )
            users = response.get("Users", [])
            if not users:
                return None
            return self._cognito_user_to_identity_user(users[0], pool_id)

        except ClientError as e:
            log.error("cognito_get_user_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to get user: {e}", "get_user")

    async def get_user_by_email(
        self,
        pool_id: str,
        email: str,
    ) -> Optional[IdentityUser]:
        """Get a user by their email address."""
        try:
            response = self._client.admin_get_user(
                UserPoolId=pool_id,
                Username=email,
            )
            # admin_get_user returns slightly different structure
            user = {
                "Username": response["Username"],
                "Attributes": response.get("UserAttributes", []),
                "UserStatus": response.get("UserStatus"),
                "Enabled": response.get("Enabled", True),
                "UserCreateDate": response.get("UserCreateDate"),
                "UserLastModifiedDate": response.get("UserLastModifiedDate"),
            }
            return self._cognito_user_to_identity_user(user, pool_id)

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "UserNotFoundException":
                return None
            log.error("cognito_get_user_by_email_error", error=str(e), pool_id=pool_id, email=email)
            raise IdentityProviderError(f"Failed to get user by email: {e}", "get_user_by_email")

    async def list_users(
        self,
        pool_id: str,
        limit: int = 60,
        next_token: Optional[str] = None,
    ) -> PaginatedUsers:
        """List users in a Cognito pool."""
        try:
            params: dict[str, Any] = {
                "UserPoolId": pool_id,
                "Limit": min(limit, 60),  # Cognito max is 60
            }
            if next_token:
                params["PaginationToken"] = next_token

            response = self._client.list_users(**params)
            users = [
                self._cognito_user_to_identity_user(u, pool_id)
                for u in response.get("Users", [])
            ]

            return PaginatedUsers(
                users=users,
                next_token=response.get("PaginationToken"),
                has_more="PaginationToken" in response,
            )

        except ClientError as e:
            log.error("cognito_list_users_error", error=str(e), pool_id=pool_id)
            raise IdentityProviderError(f"Failed to list users: {e}", "list_users")

    async def update_user_role(
        self,
        pool_id: str,
        user_id: str,
        role: str,
    ) -> Optional[IdentityUser]:
        """Update a user's role attribute."""
        # First get the user to find their username (email)
        user = await self.get_user(pool_id, user_id)
        if not user:
            return None

        try:
            self._client.admin_update_user_attributes(
                UserPoolId=pool_id,
                Username=user.email,
                UserAttributes=[{"Name": ROLE_ATTRIBUTE, "Value": role}],
            )
            log.info("cognito_role_updated", pool_id=pool_id, user_id=user_id, role=role)

            # Return updated user
            user.role = role
            user.updated_at = datetime.now(timezone.utc)
            return user

        except ClientError as e:
            log.error("cognito_update_role_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to update role: {e}", "update_user_role")

    async def update_user_display_name(
        self,
        pool_id: str,
        user_id: str,
        display_name: str,
    ) -> Optional[IdentityUser]:
        """Update a user's display name attribute."""
        user = await self.get_user(pool_id, user_id)
        if not user:
            return None

        try:
            self._client.admin_update_user_attributes(
                UserPoolId=pool_id,
                Username=user.email,
                UserAttributes=[{"Name": NAME_ATTRIBUTE, "Value": display_name}],
            )
            log.info("cognito_display_name_updated", pool_id=pool_id, user_id=user_id, display_name=display_name)

            # Return updated user
            user.display_name = display_name
            user.updated_at = datetime.now(timezone.utc)
            return user

        except ClientError as e:
            log.error("cognito_update_display_name_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to update display name: {e}", "update_user_display_name")

    async def disable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Disable a user account."""
        user = await self.get_user(pool_id, user_id)
        if not user:
            return False

        try:
            self._client.admin_disable_user(
                UserPoolId=pool_id,
                Username=user.email,
            )
            log.info("cognito_user_disabled", pool_id=pool_id, user_id=user_id)
            return True

        except ClientError as e:
            log.error("cognito_disable_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to disable user: {e}", "disable_user")

    async def enable_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Enable a disabled user account."""
        user = await self.get_user(pool_id, user_id)
        if not user:
            return False

        try:
            self._client.admin_enable_user(
                UserPoolId=pool_id,
                Username=user.email,
            )
            log.info("cognito_user_enabled", pool_id=pool_id, user_id=user_id)
            return True

        except ClientError as e:
            log.error("cognito_enable_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to enable user: {e}", "enable_user")

    async def delete_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Delete a user from the pool."""
        user = await self.get_user(pool_id, user_id)
        if not user:
            return False

        try:
            self._client.admin_delete_user(
                UserPoolId=pool_id,
                Username=user.email,
            )
            log.info("cognito_user_deleted", pool_id=pool_id, user_id=user_id)
            return True

        except ClientError as e:
            log.error("cognito_delete_user_error", error=str(e), pool_id=pool_id, user_id=user_id)
            raise IdentityProviderError(f"Failed to delete user: {e}", "delete_user")

    async def resend_invite(
        self,
        pool_id: str,
        user_id: str,
    ) -> bool:
        """Resend invitation email to a user."""
        user = await self.get_user(pool_id, user_id)
        if not user:
            return False

        if user.status != UserStatus.FORCE_CHANGE_PASSWORD:
            log.warning(
                "cognito_resend_not_eligible",
                pool_id=pool_id,
                user_id=user_id,
                status=user.status,
            )
            return False

        try:
            # Generate new temporary password and resend
            temp_password = self._generate_temp_password()
            self._client.admin_set_user_password(
                UserPoolId=pool_id,
                Username=user.email,
                Password=temp_password,
                Permanent=False,
            )
            # Trigger resend of welcome message
            self._client.admin_create_user(
                UserPoolId=pool_id,
                Username=user.email,
                MessageAction="RESEND",
            )
            log.info("cognito_invite_resent", pool_id=pool_id, user_id=user_id)
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            # UsernameExistsException is expected when resending
            if error_code != "UsernameExistsException":
                log.error("cognito_resend_error", error=str(e), pool_id=pool_id, user_id=user_id)
                raise IdentityProviderError(f"Failed to resend invite: {e}", "resend_invite")
            return True
