"""Mock identity provider for local development without AWS Cognito.

Implements lighthouse's IdentityProvider interface for local testing.
"""

import base64
import binascii
import json
import secrets
import string
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from lighthouse.auth import TokenVerifier
from lighthouse.base import IdentityProvider
from lighthouse.exceptions import (
    InvalidCredentialsError,
    TenantNotFoundError,
    UserExistsError,
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

# Mock confirmation code for development - intentionally simple
MOCK_CONFIRMATION_CODE = "123456"


class MockVerifier(TokenVerifier):
    """Mock token verifier that validates mock JWT tokens.

    Implements lighthouse's TokenVerifier interface.
    """

    def __init__(self, tenant_configs: Dict[str, TenantConfig]):
        self._tenant_configs = tenant_configs

    def verify(self, token: str) -> Tuple[str, TokenClaims]:
        """
        Verify a mock token and return (tenant_id, TokenClaims).

        Mock tokens are base64-encoded JSON with format:
        {"tenant": "demo", "sub": "user-123", "username": "admin", "exp": timestamp}
        """
        try:
            # Decode the mock token
            decoded = base64.b64decode(token).decode("utf-8")
            claims = json.loads(decoded)

            tenant_id = claims.get("tenant")
            if not tenant_id or tenant_id not in self._tenant_configs:
                raise ValueError(f"Unknown tenant: {tenant_id}")

            # Check expiration
            exp = claims.get("exp", 0)
            if exp < time.time():
                raise ValueError("Token expired")

            return tenant_id, TokenClaims(
                sub=claims.get("sub", ""),
                email=claims.get("email"),
                role=claims.get("role"),
                tenant_id=tenant_id,
                exp=claims.get("exp"),
                iat=claims.get("iat"),
                raw_claims=claims,
            )

        except (json.JSONDecodeError, binascii.Error) as e:
            raise ValueError(f"Invalid mock token format: {e}")

    def get_unverified_claims(self, token: str) -> TokenClaims:
        """Extract claims from a token WITHOUT verifying."""
        try:
            decoded = base64.b64decode(token).decode("utf-8")
            claims = json.loads(decoded)
            return TokenClaims(
                sub=claims.get("sub", ""),
                email=claims.get("email"),
                role=claims.get("role"),
                tenant_id=claims.get("tenant"),
                exp=claims.get("exp"),
                iat=claims.get("iat"),
                raw_claims=claims,
            )
        except (json.JSONDecodeError, binascii.Error) as e:
            raise ValueError(f"Invalid mock token format: {e}")


class MockIdentityProvider(IdentityProvider):
    """
    Mock identity provider for local development.

    Provides in-memory tenant and user storage without requiring AWS Cognito.
    Useful for local development and testing.

    Implements lighthouse's IdentityProvider interface (async methods).
    """

    def __init__(self) -> None:
        # Pre-configured test tenants using lighthouse's TenantConfig format
        self._tenants: Dict[str, TenantConfig] = {
            "inspectio": TenantConfig(
                tenant_id="inspectio",
                issuer="http://localhost:8000/mock/inspectio",
                jwks_url="http://localhost:8000/mock/inspectio/.well-known/jwks.json",
                audience="mock-inspectio-client",
                pool_id="mock-pool-inspectio",
                client_id="mock-inspectio-client",
                region="mock",
                status="active",
            ),
            "demo": TenantConfig(
                tenant_id="demo",
                issuer="http://localhost:8000/mock/demo",
                jwks_url="http://localhost:8000/mock/demo/.well-known/jwks.json",
                audience="mock-demo-client",
                pool_id="mock-pool-demo",
                client_id="mock-demo-client",
                region="mock",
                status="active",
            ),
            "test": TenantConfig(
                tenant_id="test",
                issuer="http://localhost:8000/mock/test",
                jwks_url="http://localhost:8000/mock/test/.well-known/jwks.json",
                audience="mock-test-client",
                pool_id="mock-pool-test",
                client_id="mock-test-client",
                region="mock",
                status="active",
            ),
        }

        # In-memory user store: {pool_id: {email: IdentityUser}}
        self._users: Dict[str, Dict[str, IdentityUser]] = {
            "mock-pool-inspectio": {
                "admin+local@inspectio.ai": IdentityUser(
                    user_id="inspectio-admin-001",
                    email="admin+local@inspectio.ai",
                    role="admin",
                    status=UserStatus.CONFIRMED,
                    enabled=True,
                    created_at=datetime.now(timezone.utc),
                ),
            },
            "mock-pool-demo": {
                "admin@demo.example.com": IdentityUser(
                    user_id="demo-admin-001",
                    email="admin@demo.example.com",
                    role="admin",
                    status=UserStatus.CONFIRMED,
                    enabled=True,
                    created_at=datetime.now(timezone.utc),
                ),
            },
            "mock-pool-test": {
                "admin@test.example.com": IdentityUser(
                    user_id="test-admin-001",
                    email="admin@test.example.com",
                    role="admin",
                    status=UserStatus.CONFIRMED,
                    enabled=True,
                    created_at=datetime.now(timezone.utc),
                ),
            },
        }

        # Store passwords for authentication (pool_id -> {email: password})
        self._passwords: Dict[str, Dict[str, str]] = {
            "mock-pool-inspectio": {"admin+local@inspectio.ai": "qwerty123456"},
            "mock-pool-demo": {"admin@demo.example.com": "admin123"},
            "mock-pool-test": {"admin@test.example.com": "admin123"},
        }

        self._verifier: MockVerifier | None = None

    # ==================== Pool Operations ====================

    async def create_pool(
        self,
        pool_name: str,
        config: Optional[PoolConfig] = None,
    ) -> PoolInfo:
        """Create a new mock pool."""
        pool_id = f"mock-pool-{pool_name}"
        client_id = f"mock-client-{pool_name}"

        # Add tenant config
        self._tenants[pool_name] = TenantConfig(
            tenant_id=pool_name,
            issuer=f"http://localhost:8000/mock/{pool_name}",
            jwks_url=f"http://localhost:8000/mock/{pool_name}/.well-known/jwks.json",
            audience=client_id,
            pool_id=pool_id,
            client_id=client_id,
            region="mock",
            status="active",
        )

        # Initialize user store
        self._users[pool_id] = {}
        self._passwords[pool_id] = {}

        return PoolInfo(
            pool_id=pool_id,
            pool_name=pool_name,
            client_id=client_id,
            region="mock",
            created_at=datetime.now(timezone.utc),
        )

    async def delete_pool(self, pool_id: str) -> bool:
        """Delete a mock pool."""
        tenant_id = pool_id.replace("mock-pool-", "")
        if tenant_id in self._tenants:
            del self._tenants[tenant_id]
            self._users.pop(pool_id, None)
            self._passwords.pop(pool_id, None)
            return True
        return False

    async def get_pool_info(self, pool_id: str) -> Optional[PoolInfo]:
        """Get pool information."""
        tenant_id = pool_id.replace("mock-pool-", "")
        if tenant_id in self._tenants:
            config = self._tenants[tenant_id]
            return PoolInfo(
                pool_id=pool_id,
                pool_name=tenant_id,
                client_id=config.client_id,
                region="mock",
            )
        return None

    # ==================== User Operations ====================

    async def invite_user(
        self,
        pool_id: str,
        email: str,
        role: str,
        display_name: Optional[str] = None,
        send_invite: bool = True,
    ) -> InviteResult:
        """Invite a user to the mock pool."""
        if pool_id not in self._users:
            self._users[pool_id] = {}
            self._passwords[pool_id] = {}

        if email in self._users[pool_id]:
            raise UserExistsError(email)

        user_id = f"mock-{uuid.uuid4().hex[:8]}"
        temp_password = self._generate_temp_password()

        self._users[pool_id][email] = IdentityUser(
            user_id=user_id,
            email=email,
            role=role,
            display_name=display_name,
            status=UserStatus.FORCE_CHANGE_PASSWORD,
            enabled=True,
            created_at=datetime.now(timezone.utc),
        )
        self._passwords[pool_id][email] = temp_password

        return InviteResult(
            user_id=user_id,
            email=email,
            display_name=display_name,
            temporary_password=temp_password if not send_invite else None,
            status=UserStatus.FORCE_CHANGE_PASSWORD,
        )

    async def get_user(
        self,
        pool_id: str,
        user_id: str,
    ) -> Optional[IdentityUser]:
        """Get user by ID."""
        if pool_id not in self._users:
            return None
        for user in self._users[pool_id].values():
            if user.user_id == user_id:
                return user
        return None

    async def get_user_by_email(
        self,
        pool_id: str,
        email: str,
    ) -> Optional[IdentityUser]:
        """Get user by email."""
        if pool_id not in self._users:
            return None
        return self._users[pool_id].get(email)

    async def list_users(
        self,
        pool_id: str,
        limit: int = 60,
        next_token: Optional[str] = None,
    ) -> PaginatedUsers:
        """List users in pool."""
        if pool_id not in self._users:
            return PaginatedUsers(users=[], has_more=False)
        users = list(self._users[pool_id].values())[:limit]
        return PaginatedUsers(users=users, has_more=False)

    async def update_user_role(
        self,
        pool_id: str,
        user_id: str,
        role: str,
    ) -> Optional[IdentityUser]:
        """Update user role."""
        user = await self.get_user(pool_id, user_id)
        if user:
            # Create new user with updated role
            for email, u in self._users[pool_id].items():
                if u.user_id == user_id:
                    self._users[pool_id][email] = IdentityUser(
                        user_id=user.user_id,
                        email=user.email,
                        role=role,
                        display_name=user.display_name,
                        status=user.status,
                        enabled=user.enabled,
                        created_at=user.created_at,
                        updated_at=datetime.now(timezone.utc),
                    )
                    return self._users[pool_id][email]
        return None

    async def update_user_display_name(
        self,
        pool_id: str,
        user_id: str,
        display_name: str,
    ) -> Optional[IdentityUser]:
        """Update user display name."""
        user = await self.get_user(pool_id, user_id)
        if user:
            for email, u in self._users[pool_id].items():
                if u.user_id == user_id:
                    self._users[pool_id][email] = IdentityUser(
                        user_id=user.user_id,
                        email=user.email,
                        role=user.role,
                        display_name=display_name,
                        status=user.status,
                        enabled=user.enabled,
                        created_at=user.created_at,
                        updated_at=datetime.now(timezone.utc),
                    )
                    return self._users[pool_id][email]
        return None

    async def disable_user(self, pool_id: str, user_id: str) -> bool:
        """Disable user."""
        user = await self.get_user(pool_id, user_id)
        if user:
            for email, u in self._users[pool_id].items():
                if u.user_id == user_id:
                    self._users[pool_id][email] = IdentityUser(
                        user_id=user.user_id,
                        email=user.email,
                        role=user.role,
                        display_name=user.display_name,
                        status=user.status,
                        enabled=False,
                        created_at=user.created_at,
                        updated_at=datetime.now(timezone.utc),
                    )
                    return True
        return False

    async def enable_user(self, pool_id: str, user_id: str) -> bool:
        """Enable user."""
        user = await self.get_user(pool_id, user_id)
        if user:
            for email, u in self._users[pool_id].items():
                if u.user_id == user_id:
                    self._users[pool_id][email] = IdentityUser(
                        user_id=user.user_id,
                        email=user.email,
                        role=user.role,
                        display_name=user.display_name,
                        status=user.status,
                        enabled=True,
                        created_at=user.created_at,
                        updated_at=datetime.now(timezone.utc),
                    )
                    return True
        return False

    async def delete_user(self, pool_id: str, user_id: str) -> bool:
        """Delete user."""
        if pool_id not in self._users:
            return False
        for email, user in list(self._users[pool_id].items()):
            if user.user_id == user_id:
                del self._users[pool_id][email]
                self._passwords[pool_id].pop(email, None)
                return True
        return False

    async def resend_invite(self, pool_id: str, user_id: str) -> bool:
        """Resend invite (mock just returns True)."""
        user = await self.get_user(pool_id, user_id)
        return user is not None and user.status == UserStatus.FORCE_CHANGE_PASSWORD

    # ==================== Tenant Discovery ====================

    async def discover_tenants(self) -> Dict[str, TenantConfig]:
        """Return all mock tenants."""
        return self._tenants.copy()

    async def get_tenant_config(self, tenant_id: str) -> TenantConfig:
        """Get tenant config by ID."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)
        return self._tenants[tenant_id]

    async def get_tenant_config_by_issuer(self, issuer: str) -> TenantConfig:
        """Get tenant config by issuer URL."""
        for config in self._tenants.values():
            if config.issuer == issuer:
                return config
        raise TenantNotFoundError(f"No tenant found for issuer: {issuer}")

    # ==================== Authentication Flows ====================

    async def authenticate(
        self,
        tenant_id: str,
        username: str,
        password: str,
    ) -> AuthResult | AuthChallenge:
        """Authenticate user."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)

        config = self._tenants[tenant_id]
        pool_id = config.pool_id

        if pool_id not in self._users:
            raise InvalidCredentialsError()

        user = self._users[pool_id].get(username)
        if not user:
            raise InvalidCredentialsError()

        if not user.enabled:
            raise InvalidCredentialsError()

        stored_password = self._passwords[pool_id].get(username)
        if stored_password != password:
            raise InvalidCredentialsError()

        # Check if user needs to change password
        if user.status == UserStatus.FORCE_CHANGE_PASSWORD:
            return AuthChallenge(
                challenge_name="NEW_PASSWORD_REQUIRED",
                session=f"mock-session-{tenant_id}-{username}",
            )

        # Generate mock tokens
        return self._create_auth_result(tenant_id, user)

    async def respond_to_challenge(
        self,
        tenant_id: str,
        username: str,
        challenge_name: str,
        session: str,
        challenge_responses: Dict[str, str],
    ) -> AuthResult | AuthChallenge:
        """Respond to auth challenge."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)

        config = self._tenants[tenant_id]
        pool_id = config.pool_id
        user = self._users[pool_id].get(username)

        if not user:
            raise InvalidCredentialsError()

        # Handle NEW_PASSWORD_REQUIRED
        if challenge_name == "NEW_PASSWORD_REQUIRED":
            new_password = challenge_responses.get("NEW_PASSWORD")
            if new_password:
                self._passwords[pool_id][username] = new_password
                # Update user status to CONFIRMED
                self._users[pool_id][username] = IdentityUser(
                    user_id=user.user_id,
                    email=user.email,
                    role=user.role,
                    display_name=user.display_name,
                    status=UserStatus.CONFIRMED,
                    enabled=True,
                    created_at=user.created_at,
                    updated_at=datetime.now(timezone.utc),
                )
                user = self._users[pool_id][username]

        return self._create_auth_result(tenant_id, user)

    async def refresh_tokens(
        self,
        tenant_id: str,
        refresh_token: str,
    ) -> AuthResult:
        """Refresh tokens."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)

        # Just return new tokens for mock
        config = self._tenants[tenant_id]
        pool_id = config.pool_id

        # Find any user for this tenant to generate tokens
        if pool_id in self._users and self._users[pool_id]:
            user = list(self._users[pool_id].values())[0]
            return self._create_auth_result(tenant_id, user)

        raise InvalidCredentialsError()

    async def initiate_password_reset(
        self,
        tenant_id: str,
        username: str,
    ) -> Dict[str, str]:
        """Initiate password reset (mock always succeeds)."""
        return {
            "message": "Verification code sent",
            "delivery_medium": "EMAIL",
            "destination": "***@mock.local",
        }

    async def confirm_password_reset(
        self,
        tenant_id: str,
        username: str,
        confirmation_code: str,
        new_password: str,
    ) -> bool:
        """Confirm password reset."""
        if tenant_id not in self._tenants:
            raise TenantNotFoundError(tenant_id)

        config = self._tenants[tenant_id]
        pool_id = config.pool_id

        if pool_id in self._passwords and username in self._passwords[pool_id]:
            self._passwords[pool_id][username] = new_password
            return True

        return False

    # ==================== Sync methods for backwards compatibility ====================

    def get_tenant_config_sync(self, tenant_id: str) -> TenantConfig:
        """Synchronous version of get_tenant_config for backwards compatibility."""
        if tenant_id not in self._tenants:
            raise ValueError(f"Tenant not found: {tenant_id}")
        return self._tenants[tenant_id]

    def get_tenant_config_by_issuer_sync(self, issuer: str) -> TenantConfig:
        """Synchronous version of get_tenant_config_by_issuer."""
        for config in self._tenants.values():
            if config.issuer == issuer:
                return config
        raise ValueError(f"Tenant not found for issuer: {issuer}")

    def discover_tenants_sync(self) -> Dict[str, TenantConfig]:
        """Synchronous version of discover_tenants."""
        return self._tenants.copy()

    def create_verifier(self, token_use: str = "access") -> MockVerifier:
        """Create mock token verifier."""
        if self._verifier is None:
            self._verifier = MockVerifier(self._tenants)
        return self._verifier

    # ==================== Helper Methods ====================

    def _generate_temp_password(self, length: int = 12) -> str:
        """Generate a temporary password."""
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*"),
        ]
        remaining = length - len(password)
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password.extend(secrets.choice(all_chars) for _ in range(remaining))
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    def _create_auth_result(self, tenant_id: str, user: IdentityUser) -> AuthResult:
        """Create auth result with mock tokens."""
        exp = int(time.time()) + 3600
        claims = {
            "tenant": tenant_id,
            "sub": user.user_id,
            "email": user.email,
            "role": user.role,
            "exp": exp,
            "iat": int(time.time()),
        }
        token = base64.b64encode(json.dumps(claims).encode()).decode()

        return AuthResult(
            access_token=token,
            id_token=token,
            refresh_token=f"mock-refresh-{tenant_id}-{user.email}",
            expires_in=3600,
            token_type="Bearer",
        )
