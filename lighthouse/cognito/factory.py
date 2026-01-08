"""Factory for AWS Cognito components."""

from typing import Optional

from lighthouse.core.factory import LighthouseFactory
from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.token_verifier import TokenVerifier


class CognitoFactory(LighthouseFactory):
    """Factory for AWS Cognito components.

    Creates CognitoIdentityProvider and CognitoVerifier instances that are
    properly configured to work together. The factory handles the internal
    wiring between the verifier and provider for tenant resolution.

    Args:
        region: AWS region where Cognito user pools are located.
            Examples: "us-east-1", "eu-west-1", "ap-southeast-1"
            This is required and determines where Cognito API calls are made.

        endpoint_url: Optional custom endpoint URL for testing with LocalStack
            or other AWS-compatible services. If not specified, uses the
            standard AWS Cognito endpoints.
            Example: "http://localhost:4566" for LocalStack

    Attributes:
        region: The AWS region configured for this factory
        endpoint_url: The custom endpoint URL, if configured

    Examples:
        Basic usage in production:
            >>> factory = CognitoFactory(region="us-east-1")
            >>> provider = factory.create_identity_provider()
            >>> await provider.create_pool("my-tenant", config=...)

        Using with LocalStack for local testing:
            >>> factory = CognitoFactory(
            ...     region="us-east-1",
            ...     endpoint_url="http://localhost:4566"
            ... )
            >>> provider = factory.create_identity_provider()

        Creating both provider and verifier:
            >>> factory = CognitoFactory(region="eu-west-1")
            >>> provider = factory.create_identity_provider()
            >>> verifier = factory.create_token_verifier(token_use="id")
            >>> # Verifier automatically uses provider's tenant configs
            >>> tenant_id, claims = verifier.verify(id_token)

    Note:
        - The IdentityProvider instance is cached internally. Multiple calls to
          create_identity_provider() return the same instance.
        - All TokenVerifiers created by this factory share the same provider
          instance for tenant resolution.
        - AWS credentials must be configured via environment variables, AWS
          config files, or IAM roles.

    See Also:
        - create_factory(): Recommended way to create factory instances
        - CognitoIdentityProvider: The provider implementation created
        - CognitoVerifier: The verifier implementation created
    """

    def __init__(self, region: str, endpoint_url: Optional[str] = None):
        self.region = region
        self.endpoint_url = endpoint_url
        self._provider: Optional["CognitoIdentityProvider"] = None

    def create_identity_provider(self) -> IdentityProvider:
        """Create or return cached Cognito identity provider.

        Creates a CognitoIdentityProvider configured with the region and
        endpoint_url specified in the factory constructor. The provider
        instance is cached - subsequent calls return the same instance.

        Returns:
            IdentityProvider: A CognitoIdentityProvider instance configured
                for the specified AWS region.

        Examples:
            >>> factory = CognitoFactory(region="us-east-1")
            >>> provider = factory.create_identity_provider()
            >>> pool = await provider.create_pool("tenant-1")

        Note:
            The provider is cached to ensure that TokenVerifiers created by
            this factory use the same provider instance for tenant resolution.
        """
        if self._provider is None:
            from lighthouse.cognito.identity_provider import CognitoIdentityProvider

            self._provider = CognitoIdentityProvider(
                region=self.region, endpoint_url=self.endpoint_url
            )
        return self._provider

    def create_token_verifier(self, token_use: str = "access") -> TokenVerifier:
        """Create Cognito token verifier.

        Creates a CognitoVerifier that is automatically wired to use the
        IdentityProvider from this factory for tenant resolution. This ensures
        the verifier can look up tenant configurations needed for JWT validation.

        Args:
            token_use: Type of token to verify - "access" or "id".
                See LighthouseFactory.create_token_verifier() for details.

        Returns:
            TokenVerifier: A CognitoVerifier instance configured to verify
                Cognito-issued JWTs and resolve tenants via the factory's provider.

        Examples:
            Verify access tokens:
                >>> factory = CognitoFactory(region="us-east-1")
                >>> verifier = factory.create_token_verifier(token_use="access")
                >>> tenant_id, claims = verifier.verify(access_token)
                >>> print(f"User: {claims.sub}, Tenant: {tenant_id}")

            Verify ID tokens to get custom attributes:
                >>> verifier = factory.create_token_verifier(token_use="id")
                >>> tenant_id, claims = verifier.verify(id_token)
                >>> print(f"Role: {claims.role}, Email: {claims.email}")

        Note:
            - The verifier uses JWKS caching (6 hour TTL by default)
            - Automatically handles key rotation
            - Validates token signature, expiration, issuer, and audience
            - Requires tenant configurations to be loaded in the provider
        """
        from lighthouse.cognito.token_verifier import CognitoVerifier

        # Ensure provider exists for tenant resolution
        provider = self.create_identity_provider()

        # Create verifier with provider's tenant resolution
        return CognitoVerifier(
            tenant_config_resolver=lambda issuer: provider.get_tenant_config_by_issuer_sync(
                issuer
            ),
            token_use=token_use,
        )
