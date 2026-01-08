"""Mock token verifier for local development without AWS Cognito.

Implements lighthouse's TokenVerifier interface for local testing.
"""

import base64
import binascii
import json
import time
from typing import Dict, Tuple

from lighthouse.core.token_verifier import TokenVerifier
from lighthouse.models import TenantConfig, TokenClaims


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
