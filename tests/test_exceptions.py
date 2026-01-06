"""Tests for lighthouse exceptions."""

from lighthouse.exceptions import (
    AuthenticationError,
    IdentityProviderError,
    InvalidCredentialsError,
    InvalidIssuerError,
    InvalidPasswordError,
    InvalidSignatureError,
    InvalidTokenError,
    LighthouseError,
    PoolExistsError,
    PoolNotFoundError,
    SessionExpiredError,
    TenantNotFoundError,
    TokenExpiredError,
    TooManyRequestsError,
    UserExistsError,
    UserNotConfirmedError,
    UserNotFoundError,
)


# ==================== Base Exceptions ====================


def test_lighthouse_error():
    """Test base LighthouseError."""
    error = LighthouseError("Test error", "TEST_CODE")
    assert str(error) == "Test error"
    assert error.message == "Test error"
    assert error.code == "TEST_CODE"


def test_identity_provider_error():
    """Test IdentityProviderError."""
    error = IdentityProviderError("Failed to create pool", "create_pool")
    assert "Failed to create pool" in str(error)
    assert error.code == "IDENTITY_PROVIDER_ERROR"
    assert error.operation == "create_pool"


# ==================== Pool/User Exceptions ====================


def test_pool_exists_error():
    """Test PoolExistsError."""
    error = PoolExistsError("my-pool")
    assert "my-pool" in str(error)
    assert error.code == "POOL_EXISTS"
    assert error.pool_name == "my-pool"


def test_pool_not_found_error():
    """Test PoolNotFoundError."""
    error = PoolNotFoundError("us-east-1_ABC123")
    assert "us-east-1_ABC123" in str(error)
    assert error.code == "POOL_NOT_FOUND"
    assert error.pool_id == "us-east-1_ABC123"


def test_user_exists_error():
    """Test UserExistsError."""
    error = UserExistsError("user@example.com")
    assert "user@example.com" in str(error)
    assert error.code == "USER_EXISTS"
    assert error.email == "user@example.com"


def test_user_exists_error_with_pool():
    """Test UserExistsError with pool_id."""
    error = UserExistsError("user@example.com", pool_id="us-east-1_ABC123")
    assert "user@example.com" in str(error)
    assert "us-east-1_ABC123" in str(error)
    assert error.pool_id == "us-east-1_ABC123"


def test_user_not_found_error():
    """Test UserNotFoundError."""
    error = UserNotFoundError("user-123", "us-east-1_ABC123")
    assert "user-123" in str(error)
    assert "us-east-1_ABC123" in str(error)
    assert error.code == "USER_NOT_FOUND"
    assert error.user_id == "user-123"
    assert error.pool_id == "us-east-1_ABC123"


# ==================== Authentication Exceptions ====================


def test_authentication_error():
    """Test base AuthenticationError."""
    error = AuthenticationError("Auth failed")
    assert str(error) == "Auth failed"
    assert error.code == "AUTHENTICATION_ERROR"


def test_invalid_credentials_error():
    """Test InvalidCredentialsError."""
    error = InvalidCredentialsError()
    assert "Invalid username or password" in str(error)
    assert error.code == "INVALID_CREDENTIALS"


def test_invalid_credentials_error_custom_message():
    """Test InvalidCredentialsError with custom message."""
    error = InvalidCredentialsError("Invalid verification code")
    assert "Invalid verification code" in str(error)


def test_user_not_confirmed_error():
    """Test UserNotConfirmedError."""
    error = UserNotConfirmedError("user@example.com")
    assert "user@example.com" in str(error)
    assert error.code == "USER_NOT_CONFIRMED"
    assert error.username == "user@example.com"


def test_session_expired_error():
    """Test SessionExpiredError."""
    error = SessionExpiredError()
    assert "Session has expired" in str(error)
    assert error.code == "SESSION_EXPIRED"


def test_session_expired_error_custom_message():
    """Test SessionExpiredError with custom message."""
    error = SessionExpiredError("Refresh token expired")
    assert "Refresh token expired" in str(error)


def test_invalid_password_error():
    """Test InvalidPasswordError."""
    error = InvalidPasswordError()
    assert "does not meet requirements" in str(error)
    assert error.code == "INVALID_PASSWORD"


def test_too_many_requests_error():
    """Test TooManyRequestsError."""
    error = TooManyRequestsError()
    assert "Too many requests" in str(error)
    assert error.code == "TOO_MANY_REQUESTS"


# ==================== Token Exceptions ====================


def test_invalid_token_error():
    """Test InvalidTokenError."""
    error = InvalidTokenError()
    assert "Invalid token" in str(error)
    assert error.code == "INVALID_TOKEN"


def test_invalid_token_error_custom_message():
    """Test InvalidTokenError with custom message."""
    error = InvalidTokenError("Token missing kid header")
    assert "Token missing kid header" in str(error)


def test_invalid_issuer_error():
    """Test InvalidIssuerError."""
    error = InvalidIssuerError("https://unknown-issuer.com")
    assert "https://unknown-issuer.com" in str(error)
    assert error.code == "INVALID_ISSUER"
    assert error.issuer == "https://unknown-issuer.com"


def test_invalid_signature_error():
    """Test InvalidSignatureError."""
    error = InvalidSignatureError()
    assert "signature verification failed" in str(error)
    assert error.code == "INVALID_SIGNATURE"


def test_token_expired_error():
    """Test TokenExpiredError."""
    error = TokenExpiredError()
    assert "Token has expired" in str(error)
    assert error.code == "TOKEN_EXPIRED"


# ==================== Tenant Exceptions ====================


def test_tenant_not_found_error():
    """Test TenantNotFoundError."""
    error = TenantNotFoundError("acme-12345678")
    assert "acme-12345678" in str(error)
    assert error.code == "TENANT_NOT_FOUND"
    assert error.tenant_id == "acme-12345678"


# ==================== Exception Hierarchy ====================


def test_exception_inheritance():
    """Test that all exceptions inherit from LighthouseError."""
    assert issubclass(IdentityProviderError, LighthouseError)
    assert issubclass(PoolExistsError, LighthouseError)
    assert issubclass(PoolNotFoundError, LighthouseError)
    assert issubclass(UserExistsError, LighthouseError)
    assert issubclass(UserNotFoundError, LighthouseError)
    assert issubclass(AuthenticationError, LighthouseError)
    assert issubclass(InvalidCredentialsError, AuthenticationError)
    assert issubclass(SessionExpiredError, AuthenticationError)
    assert issubclass(InvalidTokenError, LighthouseError)
    assert issubclass(TenantNotFoundError, LighthouseError)
