"""Integration tests for CognitoIdentityProvider using moto."""

import pytest
from lighthouse import CognitoIdentityProvider, PoolConfig, UserStatus
from lighthouse.exceptions import PoolExistsError, UserExistsError


@pytest.mark.asyncio
async def test_create_pool(mock_cognito, region):
    """Test creating a Cognito user pool."""
    provider = CognitoIdentityProvider(region=region)

    pool_info = await provider.create_pool(
        pool_name="test-pool",
        config=PoolConfig(minimum_length=10),
    )

    assert pool_info.pool_id
    assert pool_info.pool_name == "test-pool"
    assert pool_info.client_id
    assert pool_info.region == region


@pytest.mark.asyncio
async def test_create_pool_duplicate_raises_error(mock_cognito, region):
    """Test creating duplicate pool raises PoolExistsError."""
    provider = CognitoIdentityProvider(region=region)

    await provider.create_pool(pool_name="test-pool")

    with pytest.raises(PoolExistsError) as exc:
        await provider.create_pool(pool_name="test-pool")

    assert exc.value.pool_name == "test-pool"


@pytest.mark.asyncio
async def test_get_pool_info(mock_cognito, region):
    """Test getting pool information."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    pool_info = await provider.get_pool_info(pool.pool_id)

    assert pool_info is not None
    assert pool_info.pool_id == pool.pool_id
    assert pool_info.pool_name == "test-pool"


@pytest.mark.asyncio
async def test_get_pool_info_not_found(mock_cognito, region):
    """Test getting non-existent pool returns None."""
    provider = CognitoIdentityProvider(region=region)

    pool_info = await provider.get_pool_info("nonexistent-pool")

    assert pool_info is None


@pytest.mark.asyncio
async def test_delete_pool(mock_cognito, region):
    """Test deleting a pool."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    result = await provider.delete_pool(pool.pool_id)

    assert result is True

    # Verify pool is deleted
    pool_info = await provider.get_pool_info(pool.pool_id)
    assert pool_info is None


@pytest.mark.asyncio
async def test_delete_pool_not_found(mock_cognito, region):
    """Test deleting non-existent pool returns False."""
    provider = CognitoIdentityProvider(region=region)

    result = await provider.delete_pool("nonexistent-pool")

    assert result is False


@pytest.mark.asyncio
async def test_invite_user(mock_cognito, region):
    """Test inviting a user to a pool."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        display_name="Test User",
        send_invite=False,
    )

    assert result.user_id
    assert result.email == "user@example.com"
    assert result.display_name == "Test User"
    assert result.temporary_password  # Only present when send_invite=False
    assert result.status == UserStatus.FORCE_CHANGE_PASSWORD


@pytest.mark.asyncio
async def test_invite_user_duplicate_raises_error(mock_cognito, region):
    """Test inviting duplicate user raises UserExistsError."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    with pytest.raises(UserExistsError) as exc:
        await provider.invite_user(
            pool_id=pool.pool_id,
            email="user@example.com",
            role="admin",
            send_invite=False,
        )

    assert exc.value.email == "user@example.com"


@pytest.mark.asyncio
async def test_get_user_by_email(mock_cognito, region):
    """Test getting a user by email."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        display_name="Test User",
        send_invite=False,
    )

    user = await provider.get_user_by_email(pool.pool_id, "user@example.com")

    assert user is not None
    assert user.email == "user@example.com"
    assert user.role == "admin"
    assert user.display_name == "Test User"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(mock_cognito, region):
    """Test getting non-existent user by email returns None."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    user = await provider.get_user_by_email(pool.pool_id, "nonexistent@example.com")

    assert user is None


@pytest.mark.asyncio
async def test_get_user(mock_cognito, region):
    """Test getting a user by ID."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    user = await provider.get_user(pool.pool_id, invite_result.user_id)

    assert user is not None
    assert user.user_id == invite_result.user_id
    assert user.email == "user@example.com"


@pytest.mark.asyncio
async def test_list_users(mock_cognito, region):
    """Test listing users in a pool."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    # Create multiple users
    await provider.invite_user(pool.pool_id, "user1@example.com", "admin", send_invite=False)
    await provider.invite_user(pool.pool_id, "user2@example.com", "viewer", send_invite=False)

    paginated = await provider.list_users(pool.pool_id, limit=50)

    assert len(paginated.users) == 2
    emails = {user.email for user in paginated.users}
    assert "user1@example.com" in emails
    assert "user2@example.com" in emails


@pytest.mark.asyncio
async def test_update_user_role(mock_cognito, region):
    """Test updating a user's role."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="viewer",
        send_invite=False,
    )

    updated_user = await provider.update_user_role(
        pool.pool_id, invite_result.user_id, "admin"
    )

    assert updated_user is not None
    assert updated_user.role == "admin"


@pytest.mark.asyncio
async def test_update_user_display_name(mock_cognito, region):
    """Test updating a user's display name."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    updated_user = await provider.update_user_display_name(
        pool.pool_id, invite_result.user_id, "New Name"
    )

    assert updated_user is not None
    assert updated_user.display_name == "New Name"


@pytest.mark.asyncio
async def test_disable_and_enable_user(mock_cognito, region):
    """Test disabling and enabling a user."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    # Disable user
    disabled = await provider.disable_user(pool.pool_id, invite_result.user_id)
    assert disabled is True

    # Enable user
    enabled = await provider.enable_user(pool.pool_id, invite_result.user_id)
    assert enabled is True


@pytest.mark.asyncio
async def test_delete_user(mock_cognito, region):
    """Test deleting a user."""
    provider = CognitoIdentityProvider(region=region)
    pool = await provider.create_pool(pool_name="test-pool")

    invite_result = await provider.invite_user(
        pool_id=pool.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    deleted = await provider.delete_user(pool.pool_id, invite_result.user_id)
    assert deleted is True

    # Verify user is deleted
    user = await provider.get_user(pool.pool_id, invite_result.user_id)
    assert user is None
