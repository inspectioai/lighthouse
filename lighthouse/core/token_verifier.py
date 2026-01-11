"""Abstract token verifier interface.

This module defines the interface for JWT token verification.
The interface is provider-agnostic - implementations can verify tokens
from Cognito, Auth0, Okta, or any other identity provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Tuple

from lighthouse.models import TokenClaims


class TokenVerifier(ABC):
    """Abstract interface for JWT token verification.

    Implementations handle:
    - JWKS fetching and caching
    - Token signature verification
    - Claims extraction
    - Tenant resolution from token issuer

    Implementations:
        - CognitoVerifier: AWS Cognito tokens
        - OktaVerifier: Okta tokens (future)
    """

    @abstractmethod
    def verify(self, token: str) -> Tuple[str, TokenClaims]:
        """Verify a JWT token and return tenant ID and claims.

        Args:
            token: The JWT token to verify (without 'Bearer ' prefix)

        Returns:
            Tuple of (tenant_id, TokenClaims)

        Raises:
            InvalidTokenError: If token is invalid, expired, or malformed
            InvalidIssuerError: If issuer is unknown/not registered
            InvalidSignatureError: If signature verification fails
        """

    @abstractmethod
    def get_unverified_claims(self, token: str) -> TokenClaims:
        """Extract claims from a token WITHOUT verifying the signature.

        WARNING: Only use this for debugging or logging purposes.
        Never trust unverified claims for authorization decisions.

        Args:
            token: The JWT token

        Returns:
            TokenClaims with extracted (but unverified) claims
        """
