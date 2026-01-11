"""Mock token verifier for local development without AWS Cognito.

Implements lighthouse's TokenVerifier interface for local testing.
"""

import base64
import binascii
import json
import time
from typing import Dict, Tuple, TYPE_CHECKING, Union

from lighthouse.core.token_verifier import TokenVerifier
from lighthouse.models import TenantConfig, TokenClaims

if TYPE_CHECKING:
    from lighthouse.core.tenant_resolver import TenantConfigResolver


class MockVerifier(TokenVerifier):
    """Mock token verifier that validates mock JWT tokens.

    Implements lighthouse's TokenVerifier interface.
    Can accept either a TenantConfigResolver or a dict of TenantConfigs for
    backwards compatibility.
    """

    def __init__(
        self,
        tenant_source: Union["TenantConfigResolver", Dict[str, TenantConfig]],
    ):
        """Initialize MockVerifier.

        Args:
            tenant_source: Either a TenantConfigResolver or a dict mapping
                tenant_id to TenantConfig for backwards compatibility.
        """
        self._tenant_source = tenant_source
        self._is_resolver = hasattr(tenant_source, "get_tenant_config_by_issuer_sync")

    def _get_tenant_config(self, tenant_id: str) -> TenantConfig | None:
        """Get tenant config by ID from source."""
        if self._is_resolver:
            try:
                # Use resolver - tenants are indexed by tenant_id
                # For mock tokens, we get tenant directly by ID from the resolver's internal dict
                from lighthouse.mock.tenant_resolver import MockTenantResolver
                if isinstance(self._tenant_source, MockTenantResolver):
                    if tenant_id in self._tenant_source._tenants:
                        return self._tenant_source._tenants[tenant_id]
                return None
            except Exception:
                return None
        else:
            # Dict of tenant configs
            return self._tenant_source.get(tenant_id)

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
            if not tenant_id:
                raise ValueError("Token missing tenant claim")

            config = self._get_tenant_config(tenant_id)
            if config is None:
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
