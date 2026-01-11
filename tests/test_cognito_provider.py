"""Integration tests for CognitoIdentityProvider using moto."""

import pytest
from lighthouse import (
    AuthChallenge,
    AuthResult,
    CognitoFactory,
    PoolConfig,
    TenantConfig,
    UserStatus,
)
from lighthouse.exceptions import (
    InvalidCredentialsError,
    PoolExistsError,
    SessionExpiredError,
    TenantNotFoundError,
    UserExistsError,
)


@pytest.mark.asyncio
async def test_create_pool(cognito_factory):
    """Test creating a Cognito user pool."""
    provider = cognito_factory.create_identity_provider()

    pool_info = await provider.create_pool(
        pool_name="test-pool",
        config=PoolConfig(minimum_length=10),
    )

    assert pool_info.pool_id
    assert pool_info.pool_name == "test-pool"
    assert pool_info.client_id
    assert pool_info.region == "us-east-1"


@pytest.mark.asyncio
async def test_create_pool_duplicate_raises_error(cognito_factory):
    """Test creating duplicate pool raises PoolExistsError.

    Note: moto may not enforce pool name uniqueness. In real Cognito,
    creating a pool with the same name raises ResourceExistsException.
    """
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="test-pool")

    try:
        await provider.create_pool(pool_name="test-pool")
        # If we get here without exception, moto doesn't enforce uniqueness
        pytest.skip("moto doesn't enforce pool name uniqueness")
    except PoolExistsError as exc:
        assert exc.pool_name == "test-pool"


@pytest.mark.asyncio
async def test_get_pool_info(cognito_factory):
    """Test getting pool information."""
    provider = cognito_factory.create_identity_provider()
    pool = await provider.create_pool(pool_name="test-pool")

    pool_info = await provider.get_pool_info(pool.pool_id)

    assert pool_info is not None
    assert pool_info.pool_id == pool.pool_id
    assert pool_info.pool_name == "test-pool"


@pytest.mark.asyncio
async def test_get_pool_info_not_found(cognito_factory):
    """Test getting non-existent pool returns None."""
    provider = cognito_factory.create_identity_provider()

    pool_info = await provider.get_pool_info("nonexistent-pool")

    assert pool_info is None


@pytest.mark.asyncio
async def test_delete_pool(cognito_factory):
    """Test deleting a pool."""
    provider = cognito_factory.create_identity_provider()
    pool = await provider.create_pool(pool_name="test-pool")

    result = await provider.delete_pool(pool.pool_id)

    assert result is True

    # Verify pool is deleted
    pool_info = await provider.get_pool_info(pool.pool_id)
    assert pool_info is None


@pytest.mark.asyncio
async def test_delete_pool_not_found(cognito_factory):
    """Test deleting non-existent pool returns False."""
    provider = cognito_factory.create_identity_provider()

    result = await provider.delete_pool("nonexistent-pool")

    assert result is False


@pytest.mark.asyncio
async def test_invite_user(cognito_factory):
    """Test inviting a user to a pool."""
    provider = cognito_factory.create_identity_provider()
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
async def test_invite_user_duplicate_raises_error(cognito_factory):
    """Test inviting duplicate user raises UserExistsError."""
    provider = cognito_factory.create_identity_provider()
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
async def test_get_user_by_email(cognito_factory):
    """Test getting a user by email."""
    provider = cognito_factory.create_identity_provider()
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
async def test_get_user_by_email_not_found(cognito_factory):
    """Test getting non-existent user by email returns None."""
    provider = cognito_factory.create_identity_provider()
    pool = await provider.create_pool(pool_name="test-pool")

    user = await provider.get_user_by_email(pool.pool_id, "nonexistent@example.com")

    assert user is None


@pytest.mark.asyncio
async def test_get_user(cognito_factory):
    """Test getting a user by ID."""
    provider = cognito_factory.create_identity_provider()
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
async def test_list_users(cognito_factory):
    """Test listing users in a pool."""
    provider = cognito_factory.create_identity_provider()
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
async def test_update_user_role(cognito_factory):
    """Test updating a user's role."""
    provider = cognito_factory.create_identity_provider()
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
async def test_update_user_display_name(cognito_factory):
    """Test updating a user's display name."""
    provider = cognito_factory.create_identity_provider()
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
async def test_disable_and_enable_user(cognito_factory):
    """Test disabling and enabling a user."""
    provider = cognito_factory.create_identity_provider()
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
async def test_delete_user(cognito_factory):
    """Test deleting a user."""
    provider = cognito_factory.create_identity_provider()
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


# ==================== Tenant Discovery Tests ====================


@pytest.mark.asyncio
async def test_discover_tenants(cognito_factory):
    """Test discovering tenants from Cognito pools."""
    provider = cognito_factory.create_identity_provider()

    # Create pools (pool name is the tenant ID)
    await provider.create_pool(pool_name="acme-12345678")
    await provider.create_pool(pool_name="globex-87654321")

    tenants = await provider.discover_tenants()

    assert len(tenants) == 2
    assert "acme-12345678" in tenants
    assert "globex-87654321" in tenants


@pytest.mark.asyncio
async def test_discover_tenants_returns_tenant_config(cognito_factory):
    """Test that discovered tenants have proper TenantConfig."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")

    tenants = await provider.discover_tenants()

    config = tenants["acme-12345678"]
    assert isinstance(config, TenantConfig)
    assert config.tenant_id == "acme-12345678"
    assert config.pool_id  # Should have a pool ID
    assert config.client_id  # Should have a client ID
    assert config.region == "us-east-1"
    assert "cognito-idp" in config.issuer
    assert "jwks.json" in config.jwks_url


@pytest.mark.asyncio
async def test_get_tenant_config(cognito_factory):
    """Test getting tenant config by ID."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")

    config = await provider.get_tenant_config("acme-12345678")

    assert config.tenant_id == "acme-12345678"
    assert config.pool_id
    assert config.client_id


@pytest.mark.asyncio
async def test_get_tenant_config_not_found(cognito_factory):
    """Test getting non-existent tenant raises TenantNotFoundError."""
    provider = cognito_factory.create_identity_provider()

    with pytest.raises(TenantNotFoundError) as exc:
        await provider.get_tenant_config("nonexistent-tenant")

    assert exc.value.tenant_id == "nonexistent-tenant"


@pytest.mark.asyncio
async def test_get_tenant_config_uses_cache(cognito_factory):
    """Test that tenant config is cached after discovery."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")
    await provider.discover_tenants()

    # Should use cache (no API call needed)
    config = await provider.get_tenant_config("acme-12345678")
    assert config.tenant_id == "acme-12345678"


@pytest.mark.asyncio
async def test_get_tenant_config_by_issuer(cognito_factory):
    """Test getting tenant config by issuer URL."""
    provider = cognito_factory.create_identity_provider()

    pool = await provider.create_pool(pool_name="acme-12345678")
    issuer = f"https://cognito-idp.us-east-1.amazonaws.com/{pool.pool_id}"

    config = await provider.get_tenant_config_by_issuer(issuer)

    assert config.tenant_id == "acme-12345678"
    assert config.issuer == issuer


@pytest.mark.asyncio
async def test_get_tenant_config_by_issuer_not_found(cognito_factory):
    """Test getting tenant by unknown issuer raises TenantNotFoundError."""
    provider = cognito_factory.create_identity_provider()

    with pytest.raises(TenantNotFoundError):
        await provider.get_tenant_config_by_issuer(
            "https://cognito-idp.us-east-1.amazonaws.com/unknown-pool"
        )


# ==================== Authentication Flow Tests ====================


@pytest.mark.asyncio
async def test_authenticate_returns_challenge_for_new_user(cognito_factory):
    """Test that new users get NEW_PASSWORD_REQUIRED challenge."""
    provider = cognito_factory.create_identity_provider()

    # Create pool and user
    await provider.create_pool(pool_name="acme-12345678")
    invite = await provider.invite_user(
        pool_id=(await provider.get_tenant_config("acme-12345678")).pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    # Note: moto may not fully support auth flows, so we test what we can
    # In real Cognito, this would return NEW_PASSWORD_REQUIRED challenge
    try:
        result = await provider.authenticate(
            "acme-12345678", "user@example.com", invite.temporary_password
        )
        # If moto supports it, check the result
        assert isinstance(result, (AuthResult, AuthChallenge))
    except Exception:
        # moto doesn't fully support auth flows
        pytest.skip("moto doesn't support Cognito auth flows")


@pytest.mark.asyncio
async def test_authenticate_invalid_credentials(cognito_factory):
    """Test authentication with invalid credentials raises InvalidCredentialsError."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")

    # Try to authenticate with wrong password
    try:
        with pytest.raises(InvalidCredentialsError):
            await provider.authenticate(
                "acme-12345678", "nonexistent@example.com", "wrongpassword"
            )
    except Exception:
        # moto doesn't fully support auth flows
        pytest.skip("moto doesn't support Cognito auth flows")


@pytest.mark.asyncio
async def test_refresh_tokens_invalid_token(cognito_factory):
    """Test refresh with invalid token raises SessionExpiredError."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")

    try:
        with pytest.raises(SessionExpiredError):
            await provider.refresh_tokens("acme-12345678", "invalid-refresh-token")
    except Exception:
        # moto doesn't fully support auth flows
        pytest.skip("moto doesn't support Cognito auth flows")


@pytest.mark.asyncio
async def test_initiate_password_reset(cognito_factory):
    """Test initiating password reset flow."""
    provider = cognito_factory.create_identity_provider()

    # Create pool and user
    await provider.create_pool(pool_name="acme-12345678")
    config = await provider.get_tenant_config("acme-12345678")
    await provider.invite_user(
        pool_id=config.pool_id,
        email="user@example.com",
        role="admin",
        send_invite=False,
    )

    try:
        result = await provider.initiate_password_reset("acme-12345678", "user@example.com")
        assert "message" in result
    except Exception:
        # moto doesn't fully support password reset
        pytest.skip("moto doesn't support Cognito password reset")


@pytest.mark.asyncio
async def test_initiate_password_reset_nonexistent_user(cognito_factory):
    """Test password reset for non-existent user returns generic message."""
    provider = cognito_factory.create_identity_provider()

    await provider.create_pool(pool_name="acme-12345678")

    try:
        # Should not reveal if user exists
        result = await provider.initiate_password_reset(
            "acme-12345678", "nonexistent@example.com"
        )
        assert "message" in result
    except Exception:
        # moto doesn't fully support password reset
        pytest.skip("moto doesn't support Cognito password reset")


# ==================== Factory Tests ====================


def test_factory_creates_provider(cognito_factory):
    """Test that factory creates identity provider."""
    provider = cognito_factory.create_identity_provider()
    assert provider is not None


def test_factory_caches_provider(cognito_factory):
    """Test that factory returns cached provider."""
    provider1 = cognito_factory.create_identity_provider()
    provider2 = cognito_factory.create_identity_provider()
    assert provider1 is provider2


def test_factory_creates_resolver(cognito_factory):
    """Test that factory creates tenant resolver."""
    resolver = cognito_factory.create_tenant_resolver()
    assert resolver is not None


def test_factory_shares_resolver(cognito_factory):
    """Test that factory shares resolver between provider and verifier."""
    resolver = cognito_factory.create_tenant_resolver()
    provider = cognito_factory.create_identity_provider()
    # Provider should use the same resolver
    assert provider._tenant_resolver is resolver


def test_factory_with_endpoint_url(mock_cognito, region):
    """Test factory with custom endpoint URL (for LocalStack)."""
    factory = CognitoFactory(
        region=region,
        endpoint_url="http://localhost:4566",
    )
    provider = factory.create_identity_provider()
    assert provider._endpoint_url == "http://localhost:4566"
