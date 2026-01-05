"""Tests for lighthouse models."""

from lighthouse.models import (
    IdentityUser,
    InviteResult,
    PaginatedUsers,
    PoolConfig,
    PoolInfo,
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
