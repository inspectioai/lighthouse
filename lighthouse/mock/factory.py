"""Factory for mock/testing components."""

from typing import Optional

from lighthouse.core.factory import LighthouseFactory
from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.token_verifier import TokenVerifier


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

        Using pre-configured test tenants:
            >>> factory = MockFactory()
            >>> provider = factory.create_identity_provider()
            >>> config = provider.get_tenant_config("inspectio")
            >>> print(config.issuer)  # Mock issuer for inspectio tenant

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

    def __init__(self):
        self._provider: Optional["MockIdentityProvider"] = None

    def create_identity_provider(self) -> IdentityProvider:
        """Create or return cached mock identity provider.

        Creates a MockIdentityProvider with pre-configured test tenants and
        in-memory storage. The provider instance is cached - subsequent calls
        return the same instance with shared state.

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
            to ensure verifiers use the same provider instance.
        """
        if self._provider is None:
            from lighthouse.mock.identity_provider import MockIdentityProvider

            self._provider = MockIdentityProvider()
        return self._provider

    def create_token_verifier(self, token_use: str = "access") -> TokenVerifier:
        """Create mock token verifier.

        Creates a MockVerifier that validates mock tokens (base64-encoded JSON)
        against the mock provider's tenant configurations.

        Args:
            token_use: Type of token to verify - "access" or "id".
                For mock tokens, this affects what claims are expected but
                both types use the same validation logic.

        Returns:
            TokenVerifier: A MockVerifier instance that validates mock tokens.

        Examples:
            >>> factory = MockFactory()
            >>> provider = factory.create_identity_provider()
            >>> verifier = factory.create_token_verifier()
            >>>
            >>> # Authenticate and verify token
            >>> result = await provider.authenticate("inspectio", "admin", "admin123")
            >>> tenant_id, claims = verifier.verify(result.access_token)
            >>> print(f"Tenant: {tenant_id}, User: {claims.sub}")

        Note:
            - Mock verification doesn't perform cryptographic validation
            - Checks token expiration and tenant existence
            - Perfect for testing JWT verification logic without real tokens
        """
        provider = self.create_identity_provider()
        # MockIdentityProvider already has this method
        return provider.create_verifier(token_use)
