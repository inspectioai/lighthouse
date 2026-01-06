"""Tests for lighthouse models."""

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


def test_pool_config_defaults():
    """Test PoolConfig has sensible defaults."""
    config = PoolConfig()
    assert config.minimum_length == 8
    assert config.require_uppercase is True
    assert config.require_lowercase is True
    assert config.require_numbers is True
    assert config.require_symbols is False
    assert config.mfa_enabled is False
    assert config.auto_verify_email is True
    assert config.custom_attributes is None


def test_pool_config_custom_values():
    """Test PoolConfig with custom values."""
    config = PoolConfig(
        minimum_length=12,
        require_symbols=True,
        mfa_enabled=True,
    )
    assert config.minimum_length == 12
    assert config.require_symbols is True
    assert config.mfa_enabled is True


def test_pool_info_creation():
    """Test PoolInfo dataclass."""
    pool = PoolInfo(
        pool_id="us-east-1_ABC123",
        pool_name="test-pool",
        client_id="client123",
        region="us-east-1",
    )
    assert pool.pool_id == "us-east-1_ABC123"
    assert pool.pool_name == "test-pool"
    assert pool.client_id == "client123"
    assert pool.region == "us-east-1"
    assert pool.user_count == 0  # Default
    assert pool.created_at is None  # Default
    assert pool.metadata is None  # Default


def test_identity_user_creation():
    """Test IdentityUser dataclass."""
    user = IdentityUser(
        user_id="user-123",
        email="test@example.com",
        role="admin",
        status=UserStatus.CONFIRMED,
    )
    assert user.user_id == "user-123"
    assert user.email == "test@example.com"
    assert user.role == "admin"
    assert user.status == UserStatus.CONFIRMED
    assert user.enabled is True  # Default
    assert user.email_verified is False  # Default
    assert user.display_name is None  # Default


def test_user_status_enum():
    """Test UserStatus enum values."""
    assert UserStatus.UNCONFIRMED == "UNCONFIRMED"
    assert UserStatus.CONFIRMED == "CONFIRMED"
    assert UserStatus.ARCHIVED == "ARCHIVED"
    assert UserStatus.COMPROMISED == "COMPROMISED"
    assert UserStatus.UNKNOWN == "UNKNOWN"
    assert UserStatus.RESET_REQUIRED == "RESET_REQUIRED"
    assert UserStatus.FORCE_CHANGE_PASSWORD == "FORCE_CHANGE_PASSWORD"


def test_invite_result_creation():
    """Test InviteResult dataclass."""
    result = InviteResult(
        user_id="user-123",
        email="test@example.com",
        display_name="Test User",
        temporary_password="TempPass123!",
    )
    assert result.user_id == "user-123"
    assert result.email == "test@example.com"
    assert result.display_name == "Test User"
    assert result.temporary_password == "TempPass123!"
    assert result.status == UserStatus.FORCE_CHANGE_PASSWORD  # Default


def test_paginated_users_creation():
    """Test PaginatedUsers dataclass."""
    user1 = IdentityUser(
        user_id="user-1",
        email="user1@example.com",
        role="admin",
        status=UserStatus.CONFIRMED,
    )
    user2 = IdentityUser(
        user_id="user-2",
        email="user2@example.com",
        role="viewer",
        status=UserStatus.CONFIRMED,
    )

    paginated = PaginatedUsers(
        users=[user1, user2],
        next_token="token123",
        has_more=True,
    )

    assert len(paginated.users) == 2
    assert paginated.next_token == "token123"
    assert paginated.has_more is True


def test_paginated_users_defaults():
    """Test PaginatedUsers with defaults."""
    paginated = PaginatedUsers(users=[])
    assert paginated.users == []
    assert paginated.next_token is None
    assert paginated.has_more is False


# ==================== New Models Tests ====================


def test_tenant_config_creation():
    """Test TenantConfig dataclass."""
    config = TenantConfig(
        tenant_id="acme-12345678",
        issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123",
        jwks_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123/.well-known/jwks.json",
        audience="client123",
        pool_id="us-east-1_ABC123",
        client_id="client123",
        region="us-east-1",
    )
    assert config.tenant_id == "acme-12345678"
    assert config.issuer == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123"
    assert "jwks.json" in config.jwks_url
    assert config.audience == "client123"
    assert config.pool_id == "us-east-1_ABC123"
    assert config.client_id == "client123"
    assert config.region == "us-east-1"
    assert config.status == "active"  # Default
    assert config.metadata is None  # Default


def test_tenant_config_with_custom_status():
    """Test TenantConfig with custom status and metadata."""
    config = TenantConfig(
        tenant_id="acme-12345678",
        issuer="https://example.com",
        jwks_url="https://example.com/.well-known/jwks.json",
        audience="client123",
        pool_id="pool123",
        client_id="client123",
        region="us-east-1",
        status="inactive",
        metadata={"custom_key": "custom_value"},
    )
    assert config.status == "inactive"
    assert config.metadata == {"custom_key": "custom_value"}


def test_auth_result_creation():
    """Test AuthResult dataclass."""
    result = AuthResult(
        access_token="access-token-123",
        id_token="id-token-456",
        refresh_token="refresh-token-789",
        expires_in=3600,
    )
    assert result.access_token == "access-token-123"
    assert result.id_token == "id-token-456"
    assert result.refresh_token == "refresh-token-789"
    assert result.expires_in == 3600
    assert result.token_type == "Bearer"  # Default


def test_auth_result_with_custom_token_type():
    """Test AuthResult with custom token type."""
    result = AuthResult(
        access_token="access-token-123",
        id_token="id-token-456",
        refresh_token="refresh-token-789",
        expires_in=3600,
        token_type="MAC",
    )
    assert result.token_type == "MAC"


def test_auth_challenge_creation():
    """Test AuthChallenge dataclass."""
    challenge = AuthChallenge(
        challenge_name="NEW_PASSWORD_REQUIRED",
        session="session-token-abc",
    )
    assert challenge.challenge_name == "NEW_PASSWORD_REQUIRED"
    assert challenge.session == "session-token-abc"
    assert challenge.challenge_parameters is None  # Default


def test_auth_challenge_with_parameters():
    """Test AuthChallenge with parameters."""
    challenge = AuthChallenge(
        challenge_name="MFA_REQUIRED",
        session="session-token-abc",
        challenge_parameters={"MFA_CODE_DELIVERY_DESTINATION": "+1*******1234"},
    )
    assert challenge.challenge_name == "MFA_REQUIRED"
    assert challenge.challenge_parameters["MFA_CODE_DELIVERY_DESTINATION"] == "+1*******1234"


def test_token_claims_creation():
    """Test TokenClaims dataclass."""
    claims = TokenClaims(
        sub="user-uuid-12345",
        email="user@example.com",
        role="admin",
        tenant_id="acme-12345678",
        exp=1704067200,
        iat=1704063600,
    )
    assert claims.sub == "user-uuid-12345"
    assert claims.email == "user@example.com"
    assert claims.role == "admin"
    assert claims.tenant_id == "acme-12345678"
    assert claims.exp == 1704067200
    assert claims.iat == 1704063600
    assert claims.raw_claims is None  # Default


def test_token_claims_minimal():
    """Test TokenClaims with only required field."""
    claims = TokenClaims(sub="user-uuid-12345")
    assert claims.sub == "user-uuid-12345"
    assert claims.email is None
    assert claims.role is None
    assert claims.tenant_id is None
    assert claims.exp is None
    assert claims.iat is None
    assert claims.raw_claims is None


def test_token_claims_with_raw_claims():
    """Test TokenClaims with raw claims."""
    raw = {
        "sub": "user-uuid-12345",
        "email": "user@example.com",
        "custom:role": "admin",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123",
        "aud": "client123",
    }
    claims = TokenClaims(
        sub="user-uuid-12345",
        email="user@example.com",
        role="admin",
        raw_claims=raw,
    )
    assert claims.raw_claims == raw
    assert claims.raw_claims["iss"] == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123"
