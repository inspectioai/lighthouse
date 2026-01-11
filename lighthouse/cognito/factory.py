"""Factory for AWS Cognito components."""

from typing import Optional

from lighthouse.core.factory import LighthouseFactory
from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.tenant_resolver import TenantConfigResolver
from lighthouse.core.token_verifier import TokenVerifier


class CognitoFactory(LighthouseFactory):
    """Factory for AWS Cognito components.

    Creates CognitoIdentityProvider, CognitoTenantResolver, and CognitoVerifier
    instances that are properly configured to work together.

    The factory now uses TenantConfigResolver as the lightweight interface for
    tenant discovery. Services that only need token verification can use the
    resolver directly without instantiating the full IdentityProvider.

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

        Token verification only (lightweight - no IdentityProvider needed):
            >>> factory = CognitoFactory(region="us-east-1")
            >>> resolver = factory.create_tenant_resolver()
            >>> verifier = factory.create_token_verifier(token_use="access")
            >>> await resolver.discover_tenants()
            >>> tenant_id, claims = verifier.verify(access_token)

        Using with LocalStack for local testing:
            >>> factory = CognitoFactory(
            ...     region="us-east-1",
            ...     endpoint_url="http://localhost:4566"
            ... )
            >>> provider = factory.create_identity_provider()

    Note:
        - TenantConfigResolver is cached and shared between verifier and provider
        - IdentityProvider is only created when explicitly requested
        - AWS credentials must be configured via environment variables, AWS
          config files, or IAM roles.

    See Also:
        - create_factory(): Recommended way to create factory instances
        - CognitoIdentityProvider: The provider implementation
        - CognitoTenantResolver: The resolver implementation
        - CognitoVerifier: The verifier implementation
    """

    def __init__(self, region: str, endpoint_url: Optional[str] = None):
        self.region = region
        self.endpoint_url = endpoint_url
        self._resolver: Optional[TenantConfigResolver] = None
        self._provider: Optional[IdentityProvider] = None

    def create_tenant_resolver(self) -> TenantConfigResolver:
        """Create or return cached Cognito tenant resolver.

        Creates a lightweight CognitoTenantResolver that only handles tenant
        discovery and lookup. This is the minimal component needed for token
        verification - it doesn't include user management or authentication.

        Returns:
            TenantConfigResolver: A CognitoTenantResolver instance configured
                for the specified AWS region.

        Examples:
            >>> factory = CognitoFactory(region="us-east-1")
            >>> resolver = factory.create_tenant_resolver()
            >>> await resolver.discover_tenants()
            >>> config = resolver.get_tenant_config_by_issuer_sync(issuer)

        Note:
            The resolver is cached and shared between verifier and provider.
            This ensures consistent tenant configuration across all components.
        """
        if self._resolver is None:
            from lighthouse.cognito.tenant_resolver import CognitoTenantResolver

            self._resolver = CognitoTenantResolver(
                region=self.region, endpoint_url=self.endpoint_url
            )
        return self._resolver

    def create_identity_provider(self) -> IdentityProvider:
        """Create or return cached Cognito identity provider.

        Creates a CognitoIdentityProvider configured with the region and
        endpoint_url specified in the factory constructor. The provider
        uses the shared TenantConfigResolver for tenant discovery.

        Returns:
            IdentityProvider: A CognitoIdentityProvider instance configured
                for the specified AWS region.

        Examples:
            >>> factory = CognitoFactory(region="us-east-1")
            >>> provider = factory.create_identity_provider()
            >>> pool = await provider.create_pool("tenant-1")

        Note:
            The provider is cached. Multiple calls return the same instance.
            The provider shares the TenantConfigResolver with verifiers.
        """
        if self._provider is None:
            from lighthouse.cognito.identity_provider import CognitoIdentityProvider

            # Create provider with shared resolver
            resolver = self.create_tenant_resolver()
            self._provider = CognitoIdentityProvider(
                region=self.region,
                endpoint_url=self.endpoint_url,
                tenant_resolver=resolver,
            )
        return self._provider

    def create_token_verifier(self, token_use: str = "access") -> TokenVerifier:
        """Create Cognito token verifier.

        Creates a CognitoVerifier that uses the lightweight TenantConfigResolver
        for tenant lookup. This does NOT create or require IdentityProvider.

        Args:
            token_use: Type of token to verify - "access" or "id".
                See LighthouseFactory.create_token_verifier() for details.

        Returns:
            TokenVerifier: A CognitoVerifier instance configured to verify
                Cognito-issued JWTs using the shared TenantConfigResolver.

        Examples:
            Token verification only (no IdentityProvider created):
                >>> factory = CognitoFactory(region="us-east-1")
                >>> resolver = factory.create_tenant_resolver()
                >>> verifier = factory.create_token_verifier(token_use="access")
                >>> await resolver.discover_tenants()
                >>> tenant_id, claims = verifier.verify(access_token)

            Verify ID tokens to get custom attributes:
                >>> verifier = factory.create_token_verifier(token_use="id")
                >>> tenant_id, claims = verifier.verify(id_token)
                >>> print(f"Role: {claims.role}, Email: {claims.email}")

        Note:
            - Uses lightweight TenantConfigResolver, not full IdentityProvider
            - The verifier uses JWKS caching (6 hour TTL by default)
            - Automatically handles key rotation
            - Validates token signature, expiration, issuer, and audience
            - Requires tenant configurations to be loaded via resolver.discover_tenants()
        """
        from lighthouse.cognito.token_verifier import CognitoVerifier

        # Use lightweight resolver instead of full provider
        resolver = self.create_tenant_resolver()

        # Create verifier with resolver's tenant resolution
        return CognitoVerifier(
            tenant_config_resolver=lambda issuer: resolver.get_tenant_config_by_issuer_sync(
                issuer
            ),
            token_use=token_use,
        )
