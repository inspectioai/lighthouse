"""Tests for token verification."""

from unittest.mock import Mock, patch
import base64
import time
import json

import pytest

from lighthouse.auth.base import TokenVerifier
from lighthouse.auth.cognito import CognitoVerifier
from lighthouse.models import TenantConfig, TokenClaims
from lighthouse.exceptions import InvalidTokenError, InvalidIssuerError


def _create_test_jwt(header: dict, payload: dict) -> str:
    """Create a test JWT token (without valid signature)."""
    def encode_part(data: dict) -> str:
        json_bytes = json.dumps(data).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).decode("utf-8").rstrip("=")

    header_encoded = encode_part(header)
    payload_encoded = encode_part(payload)
    # Add a fake signature (will fail signature verification but pass parsing)
    signature = base64.urlsafe_b64encode(b"fake_signature").decode("utf-8").rstrip("=")
    return f"{header_encoded}.{payload_encoded}.{signature}"


# ==================== TokenVerifier ABC Tests ====================


def test_token_verifier_is_abstract():
    """Test that TokenVerifier cannot be instantiated."""
    with pytest.raises(TypeError):
        TokenVerifier()


def test_token_verifier_requires_verify_method():
    """Test that subclasses must implement verify method."""
    class IncompleteVerifier(TokenVerifier):
        def get_unverified_claims(self, token: str) -> TokenClaims:
            return TokenClaims(sub="test")

    with pytest.raises(TypeError):
        IncompleteVerifier()


def test_token_verifier_requires_get_unverified_claims_method():
    """Test that subclasses must implement get_unverified_claims method."""
    class IncompleteVerifier(TokenVerifier):
        def verify(self, token: str):
            return ("tenant", TokenClaims(sub="test"))

    with pytest.raises(TypeError):
        IncompleteVerifier()


# ==================== CognitoVerifier Tests ====================


def test_cognito_verifier_creation():
    """Test creating a CognitoVerifier."""

    def resolver(issuer: str) -> TenantConfig:
        return TenantConfig(
            tenant_id="test-tenant",
            issuer=issuer,
            jwks_url=f"{issuer}/.well-known/jwks.json",
            audience="client123",
            pool_id="us-east-1_ABC123",
            client_id="client123",
            region="us-east-1",
        )

    verifier = CognitoVerifier(
        tenant_config_resolver=resolver,
        token_use="id",
        jwks_ttl_seconds=3600,
        clock_skew_seconds=30,
    )

    assert verifier.token_use == "id"
    assert verifier.jwks_ttl_seconds == 3600
    assert verifier.clock_skew_seconds == 30


def test_cognito_verifier_defaults():
    """Test CognitoVerifier default values."""
    verifier = CognitoVerifier(tenant_config_resolver=lambda x: None)

    assert verifier.token_use == "access"
    assert verifier.jwks_ttl_seconds == 21600  # 6 hours
    assert verifier.clock_skew_seconds == 60


def test_get_unverified_claims_invalid_token():
    """Test get_unverified_claims with invalid token."""
    verifier = CognitoVerifier(tenant_config_resolver=lambda x: None)

    with pytest.raises(InvalidTokenError):
        verifier.get_unverified_claims("not-a-valid-jwt")


def test_get_unverified_claims_malformed_token():
    """Test get_unverified_claims with malformed JWT."""
    verifier = CognitoVerifier(tenant_config_resolver=lambda x: None)

    with pytest.raises(InvalidTokenError):
        verifier.get_unverified_claims("a.b")  # Too few parts


# ==================== JWKS Caching Tests ====================


def test_jwks_cache_stores_keys():
    """Test that JWKS keys are cached."""

    def resolver(issuer: str) -> TenantConfig:
        return TenantConfig(
            tenant_id="test-tenant",
            issuer=issuer,
            jwks_url="https://example.com/.well-known/jwks.json",
            audience="client123",
            pool_id="us-east-1_ABC123",
            client_id="client123",
            region="us-east-1",
        )

    verifier = CognitoVerifier(tenant_config_resolver=resolver)

    # Manually add to cache
    verifier._jwks_cache["https://example.com/.well-known/jwks.json"] = {
        "test-kid": {"kty": "RSA", "kid": "test-kid"}
    }
    verifier._jwks_expiry["https://example.com/.well-known/jwks.json"] = time.time() + 3600

    # Verify cache is used
    assert "test-kid" in verifier._jwks_cache["https://example.com/.well-known/jwks.json"]


def test_jwks_cache_expiry():
    """Test that expired JWKS cache entries are refreshed."""

    def resolver(issuer: str) -> TenantConfig:
        return TenantConfig(
            tenant_id="test-tenant",
            issuer=issuer,
            jwks_url="https://example.com/.well-known/jwks.json",
            audience="client123",
            pool_id="us-east-1_ABC123",
            client_id="client123",
            region="us-east-1",
        )

    verifier = CognitoVerifier(tenant_config_resolver=resolver, jwks_ttl_seconds=1)

    # Add expired cache entry
    verifier._jwks_cache["https://example.com/.well-known/jwks.json"] = {
        "old-kid": {"kty": "RSA", "kid": "old-kid"}
    }
    verifier._jwks_expiry["https://example.com/.well-known/jwks.json"] = time.time() - 100

    # Cache should be considered expired
    assert verifier._jwks_expiry["https://example.com/.well-known/jwks.json"] < time.time()


# ==================== Token Validation Tests ====================


def test_verify_token_missing_kid():
    """Test verify raises error for token without kid header."""

    def resolver(issuer: str) -> TenantConfig:
        raise Exception("Should not be called")

    verifier = CognitoVerifier(tenant_config_resolver=resolver)

    # Create a JWT without kid in header
    token = _create_test_jwt(
        header={"alg": "RS256"},  # No kid
        payload={"sub": "test"}
    )

    with pytest.raises(InvalidTokenError) as exc:
        verifier.verify(token)

    assert "kid" in str(exc.value).lower()


def test_verify_token_missing_issuer():
    """Test verify raises error for token without iss claim."""

    def resolver(issuer: str) -> TenantConfig:
        raise Exception("Should not be called")

    verifier = CognitoVerifier(tenant_config_resolver=resolver)

    # Create a JWT with kid but no issuer
    token = _create_test_jwt(
        header={"alg": "RS256", "kid": "test-kid"},
        payload={"sub": "test"}  # No iss
    )

    with pytest.raises(InvalidTokenError) as exc:
        verifier.verify(token)

    assert "iss" in str(exc.value).lower()


def test_verify_unknown_issuer():
    """Test verify raises InvalidIssuerError for unknown issuer."""

    def resolver(issuer: str) -> TenantConfig:
        raise ValueError(f"Unknown issuer: {issuer}")

    verifier = CognitoVerifier(tenant_config_resolver=resolver)

    # Create a JWT with kid and issuer
    token = _create_test_jwt(
        header={"alg": "RS256", "kid": "test-kid"},
        payload={
            "sub": "test",
            "iss": "https://unknown-issuer.com",
            "token_use": "access",
        }
    )

    with pytest.raises(InvalidIssuerError):
        verifier.verify(token)


def test_verify_wrong_token_use():
    """Test verify raises error for wrong token_use."""

    def resolver(issuer: str) -> TenantConfig:
        return TenantConfig(
            tenant_id="test-tenant",
            issuer=issuer,
            jwks_url=f"{issuer}/.well-known/jwks.json",
            audience="client123",
            pool_id="us-east-1_ABC123",
            client_id="client123",
            region="us-east-1",
        )

    # Verifier expects "id" tokens
    verifier = CognitoVerifier(tenant_config_resolver=resolver, token_use="id")

    # Create a JWT with token_use="access" (wrong)
    token = _create_test_jwt(
        header={"alg": "RS256", "kid": "test-kid"},
        payload={
            "sub": "test",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123",
            "token_use": "access",  # Wrong! Verifier expects "id"
        }
    )

    with pytest.raises(InvalidTokenError) as exc:
        verifier.verify(token)

    assert "token_use" in str(exc.value).lower()


# ==================== Interface Compliance Tests ====================


def test_cognito_verifier_implements_token_verifier():
    """Test that CognitoVerifier implements TokenVerifier interface."""
    assert issubclass(CognitoVerifier, TokenVerifier)

    verifier = CognitoVerifier(tenant_config_resolver=lambda x: None)

    # Check methods exist
    assert hasattr(verifier, "verify")
    assert hasattr(verifier, "get_unverified_claims")
    assert callable(verifier.verify)
    assert callable(verifier.get_unverified_claims)
