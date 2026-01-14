"""Factory for mock/testing components."""

from typing import Dict, Optional

from lighthouse.core.factory import LighthouseFactory
from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.token_verifier import TokenVerifier
from lighthouse.models import TenantConfig


# Default test tenants
def _create_default_tenants() -> Dict[str, TenantConfig]:
    """Create default test tenants."""
    return {
        "inspectio": TenantConfig(
            tenant_id="inspectio",
            issuer="http://localhost:8000/mock/inspectio",
            jwks_url="http://localhost:8000/mock/inspectio/.well-known/jwks.json",
            audience="mock-inspectio-client",
            pool_id="mock-pool-inspectio",
            client_id="mock-inspectio-client",
            region="mock",
            status="active",
        ),
        "demo": TenantConfig(
            tenant_id="demo",
            issuer="http://localhost:8000/mock/demo",
            jwks_url="http://localhost:8000/mock/demo/.well-known/jwks.json",
            audience="mock-demo-client",
            pool_id="mock-pool-demo",
            client_id="mock-demo-client",
            region="mock",
            status="active",
        ),
        "test": TenantConfig(
            tenant_id="test",
            issuer="http://localhost:8000/mock/test",
            jwks_url="http://localhost:8000/mock/test/.well-known/jwks.json",
            audience="mock-test-client",
            pool_id="mock-pool-test",
            client_id="mock-test-client",
            region="mock",
            status="active",
        ),
    }


class MockFactory(LighthouseFactory):
    """Factory for mock/testing components.

    Creates MockIdentityProvider and MockVerifier instances for testing and
    local development. The mock implementations use in-memory storage and
    don't require AWS credentials or network access.

    The mock provider comes pre-configured with test tenants:
        - "inspectio": Test tenant with sample users
        - "demo": Demo tenant for examples
        - "test": Generic test tenant

    Args:
        None. MockFactory does not accept any configuration arguments.

    Examples:
        Basic usage in tests:
            >>> factory = MockFactory()
            >>> provider = factory.create_identity_provider()
            >>> # Use mock provider without AWS
            >>> pool = await provider.create_pool("test-tenant")

        Token verification only (no IdentityProvider created):
            >>> factory = MockFactory()
            >>> verifier = factory.create_token_verifier()
            >>> # Tenants already pre-loaded in mock
            >>> tenant_id, claims = verifier.verify(mock_token)

        Full test setup:
            >>> factory = MockFactory()
            >>> provider = factory.create_identity_provider()
            >>> verifier = factory.create_token_verifier(token_use="access")
            >>>
            >>> # Create and authenticate
            >>> pool = await provider.create_pool("my-test-pool")
            >>> await provider.invite_user(pool.pool_id, "test@example.com", "admin")
            >>> result = await provider.authenticate("my-test-pool", "test@example.com", "password")
            >>> tenant_id, claims = verifier.verify(result.access_token)

    Note:
        - Mock tokens are base64-encoded JSON, not real JWTs
        - No actual cryptographic validation is performed
        - All data is stored in memory and lost when the process exits
        - Perfect for unit tests and local development
        - Does not require AWS credentials or network access

    See Also:
        - create_factory(): Use create_factory("mock") to create this factory
        - MockIdentityProvider: The provider implementation
        - MockVerifier: The verifier implementation
    """

    def __init__(self) -> None:
        # Shared tenant storage - both provider and verifier use this
        self._tenants: Dict[str, TenantConfig] = _create_default_tenants()
        self._provider: Optional[IdentityProvider] = None

    def create_identity_provider(self) -> IdentityProvider:
        """Create or return cached mock identity provider.

        Creates a MockIdentityProvider with pre-configured test tenants and
        in-memory storage.

        Returns:
            IdentityProvider: A MockIdentityProvider instance with test tenants
                pre-configured.

        Examples:
            >>> factory = MockFactory()
            >>> provider = factory.create_identity_provider()
            >>> # Create test pool
            >>> pool = await provider.create_pool("test-pool")

        Note:
            The provider is cached to maintain state across multiple calls and
            to ensure verifiers use the same tenant state.
        """
        if self._provider is None:
            from lighthouse.identity_providers.mock import MockIdentityProvider

            self._provider = MockIdentityProvider(tenants=self._tenants)
        return self._provider

    def create_token_verifier(self, token_use: str = "access") -> TokenVerifier:
        """Create mock token verifier.

        Creates a MockVerifier that validates mock tokens (base64-encoded JSON)
        using the shared tenant dict for tenant lookup.

        Args:
            token_use: Type of token to verify - "access" or "id".
                For mock tokens, this affects what claims are expected but
                both types use the same validation logic.

        Returns:
            TokenVerifier: A MockVerifier instance that validates mock tokens.

        Examples:
            >>> factory = MockFactory()
            >>> verifier = factory.create_token_verifier()
            >>> # Mock tenants already pre-loaded
            >>> tenant_id, claims = verifier.verify(mock_token)

        Note:
            - Mock verification doesn't perform cryptographic validation
            - Checks token expiration and tenant existence
            - Perfect for testing JWT verification logic without real tokens
        """
        from lighthouse.token_verifiers.mock import MockVerifier

        # Pass shared tenant dict - verifier sees same tenants as provider
        return MockVerifier(self._tenants)
