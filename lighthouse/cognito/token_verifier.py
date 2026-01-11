"""AWS Cognito JWT token verifier.

This module provides JWT verification for Cognito-issued tokens with:
- JWKS caching with configurable TTL
- Automatic key refresh on cache miss (handles key rotation)
- Multi-tenant support via issuer-to-tenant mapping
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Optional, Tuple

import jwt
import structlog
from jwt.algorithms import RSAAlgorithm

from lighthouse.core.token_verifier import TokenVerifier
from lighthouse.exceptions import InvalidIssuerError, InvalidTokenError
from lighthouse.models import TenantConfig, TokenClaims

log = structlog.get_logger()

# Custom attribute names in Cognito
ROLE_ATTRIBUTE = "custom:role"


class CognitoVerifier(TokenVerifier):
    """AWS Cognito JWT token verifier.

    Verifies JWTs issued by Cognito User Pools with support for:
    - Multi-tenant environments (resolves tenant from issuer)
    - JWKS caching with automatic refresh
    - Both access and id token validation

    Args:
        tenant_config_resolver: Callable that takes an issuer URL and returns TenantConfig.
                               This allows flexible tenant lookup (from cache, database, etc.)
        token_use: Expected token type - "access" or "id". Defaults to "access".
                   Use "id" if you need custom attributes like custom:role.
        jwks_ttl_seconds: How long to cache JWKS keys. Defaults to 6 hours.
        clock_skew_seconds: Allowed clock skew for exp/iat validation. Defaults to 60.
    """

    def __init__(
        self,
        tenant_config_resolver: Callable[[str], TenantConfig],
        token_use: str = "access",
        jwks_ttl_seconds: int = 21600,  # 6 hours
        clock_skew_seconds: int = 60,
    ):
        self.tenant_config_resolver = tenant_config_resolver
        self.token_use = token_use
        self.jwks_ttl_seconds = jwks_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

        # JWKS cache: {jwks_url: {kid: key_data}}
        self._jwks_cache: Dict[str, Dict[str, Any]] = {}
        self._jwks_expiry: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _fetch_jwks(self, jwks_url: str) -> Dict[str, Any]:
        """Fetch JWKS from URL and cache the keys."""
        import requests

        with self._lock:
            now = time.time()

            # Check cache first
            if jwks_url in self._jwks_cache and self._jwks_expiry.get(jwks_url, 0) > now:
                return self._jwks_cache[jwks_url]

            # Fetch fresh JWKS
            try:
                resp = requests.get(jwks_url, timeout=5)
                resp.raise_for_status()
                jwks = resp.json()
            except Exception as e:
                log.error("jwks_fetch_failed", jwks_url=jwks_url, error=str(e))
                raise InvalidTokenError(f"Failed to fetch JWKS: {e}")

            # Index keys by kid
            keys = {k["kid"]: k for k in jwks.get("keys", [])}
            self._jwks_cache[jwks_url] = keys
            self._jwks_expiry[jwks_url] = now + self.jwks_ttl_seconds

            log.debug("jwks_cached", jwks_url=jwks_url, key_count=len(keys))
            return keys

    def _get_signing_key(self, jwks_url: str, kid: str) -> Any:
        """Get the signing key for a specific kid, refreshing cache if needed."""
        keys = self._fetch_jwks(jwks_url)
        jwk = keys.get(kid)

        if not jwk:
            # Key not found - force refresh (handles key rotation)
            log.debug("key_not_found_refreshing", kid=kid, jwks_url=jwks_url)
            with self._lock:
                self._jwks_expiry[jwks_url] = 0
            keys = self._fetch_jwks(jwks_url)
            jwk = keys.get(kid)

        if not jwk:
            log.warning("signing_key_not_found", kid=kid, available_kids=list(keys.keys()))
            raise InvalidTokenError(f"Signing key not found for kid: {kid}")

        return RSAAlgorithm.from_jwk(json.dumps(jwk))

    def _resolve_tenant(self, issuer: str) -> TenantConfig:
        """Resolve tenant configuration from issuer URL."""
        try:
            return self.tenant_config_resolver(issuer)
        except Exception as e:
            log.warning("tenant_resolution_failed", issuer=issuer, error=str(e))
            raise InvalidIssuerError(issuer)

    def verify(self, token: str) -> Tuple[str, TokenClaims]:
        """Verify a Cognito JWT token and return tenant ID and claims."""
        try:
            # Decode header to get kid
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                raise InvalidTokenError("Token missing kid header")

            # Decode claims without verification to get issuer
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_aud": False},
            )
            issuer = unverified.get("iss")
            if not issuer:
                raise InvalidTokenError("Token missing iss claim")

            # Validate token_use
            token_use = unverified.get("token_use")
            if token_use != self.token_use:
                log.warning(
                    "token_use_mismatch",
                    expected=self.token_use,
                    got=token_use,
                )
                raise InvalidTokenError(
                    f"Invalid token_use: expected {self.token_use}, got {token_use}"
                )

            # Resolve tenant from issuer
            tenant_config = self._resolve_tenant(issuer)

            # Get signing key and verify
            key = self._get_signing_key(tenant_config.jwks_url, kid)

            # Verify signature and standard claims
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                issuer=tenant_config.issuer,
                options={"verify_aud": False},  # Cognito uses client_id, not aud
                leeway=self.clock_skew_seconds,
            )

            # Validate audience (client_id for access tokens, aud for id tokens)
            if self.token_use == "id":
                aud = claims.get("aud")
                if isinstance(aud, list):
                    if tenant_config.audience not in aud:
                        raise InvalidTokenError("Token audience mismatch")
                elif aud != tenant_config.audience:
                    raise InvalidTokenError("Token audience mismatch")
            else:
                client_id = claims.get("client_id")
                if client_id != tenant_config.audience:
                    raise InvalidTokenError("Token client_id mismatch")

            # Extract standard claims
            token_claims = TokenClaims(
                sub=claims.get("sub", ""),
                email=claims.get("email"),
                role=claims.get(ROLE_ATTRIBUTE),
                tenant_id=tenant_config.tenant_id,
                exp=claims.get("exp"),
                iat=claims.get("iat"),
                raw_claims=claims,
            )

            log.debug(
                "token_verified",
                tenant_id=tenant_config.tenant_id,
                sub=token_claims.sub,
            )

            return tenant_config.tenant_id, token_claims

        except jwt.ExpiredSignatureError:
            raise InvalidTokenError("Token has expired")
        except jwt.InvalidIssuerError:
            raise InvalidIssuerError(issuer if "issuer" in dir() else "unknown")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {e}")

    def get_unverified_claims(self, token: str) -> TokenClaims:
        """Extract claims from a token WITHOUT verifying the signature."""
        try:
            claims = jwt.decode(
                token,
                options={"verify_signature": False, "verify_aud": False},
            )
            return TokenClaims(
                sub=claims.get("sub", ""),
                email=claims.get("email"),
                role=claims.get(ROLE_ATTRIBUTE),
                tenant_id=None,  # Can't resolve without verification
                exp=claims.get("exp"),
                iat=claims.get("iat"),
                raw_claims=claims,
            )
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Failed to decode token: {e}")
