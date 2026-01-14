"""Abstract factory for creating identity provider components."""

from abc import ABC, abstractmethod

from lighthouse.core.identity_provider import IdentityProvider
from lighthouse.core.token_verifier import TokenVerifier


class LighthouseFactory(ABC):
    """Abstract factory for creating identity provider components.

    This is the base class for all provider-specific factories. Implementations
    provide provider-specific instances that work together correctly. Once
    configured for a provider type (Cognito, Mock, Auth0, etc.), the factory
    can create any needed component for that provider.

    The factory ensures proper coupling between IdentityProvider and TokenVerifier,
    hiding provider-specific wiring details from users. This is particularly
    important because TokenVerifier needs access to tenant configuration from
    IdentityProvider for JWT validation.

    Usage:
        Do not instantiate this class directly. Use create_factory() instead:

        >>> from lighthouse import create_factory
        >>> factory = create_factory("cognito", region="us-east-1")

    See Also:
        - create_factory(): Main entry point for creating factories
        - CognitoFactory: AWS Cognito implementation
        - MockFactory: Mock implementation for testing
    """

    @abstractmethod
    def create_identity_provider(self) -> IdentityProvider:
        """Create an identity provider instance.

        This method creates a provider-specific implementation of the
        IdentityProvider interface. The instance is typically cached
        internally to ensure consistency when creating other components.

        Returns:
            IdentityProvider: A provider-specific implementation that handles
                user pool management, user operations, and authentication flows.

        Examples:
            >>> factory = create_factory("cognito", region="us-east-1")
            >>> provider = factory.create_identity_provider()
            >>> # Now use provider for pool/user operations
            >>> pool = await provider.create_pool("my-app", config=...)
        """
        pass

    @abstractmethod
    def create_token_verifier(self, token_use: str = "access") -> TokenVerifier:
        """Create a token verifier instance.

        This method creates a TokenVerifier that is automatically wired to work
        with the IdentityProvider from this factory. The verifier will use the
        provider's tenant configuration for JWT validation.

        Args:
            token_use: The type of token to verify. Valid values:
                - "access": Verify access tokens (default). Access tokens contain
                    client_id claim and are used for API authorization.
                - "id": Verify ID tokens. ID tokens contain user profile claims
                    like email and custom attributes (e.g., custom:role).

                Choose "access" for API authentication/authorization.
                Choose "id" if you need user attributes or custom claims.

        Returns:
            TokenVerifier: A provider-specific TokenVerifier implementation that
                can verify JWT tokens issued by the identity provider.

        Examples:
            Verify access tokens:
                >>> factory = create_factory("cognito", region="us-east-1")
                >>> verifier = factory.create_token_verifier(token_use="access")
                >>> tenant_id, claims = verifier.verify(access_token)

            Verify ID tokens with custom attributes:
                >>> verifier = factory.create_token_verifier(token_use="id")
                >>> tenant_id, claims = verifier.verify(id_token)
                >>> user_role = claims.role  # custom:role attribute

        Note:
            The verifier requires the IdentityProvider to have tenant configurations
            loaded (via discover_tenants() or get_tenant_config()). This is
            handled automatically by the factory implementation.
        """
        pass


def create_factory(provider_type: str, **kwargs) -> LighthouseFactory:
    """Create a factory for the specified provider type.

    This is the main entry point for users to configure Lighthouse. The factory
    creates provider-specific implementations of IdentityProvider and TokenVerifier
    that work together correctly.

    Args:
        provider_type: The identity provider type to use.
            Valid values: "cognito", "mock"

        **kwargs: Provider-specific configuration arguments.

            For provider_type="cognito":
                region (str, required): AWS region where Cognito resources exist.
                    Example: "us-east-1", "eu-west-1"
                endpoint_url (str, optional): Custom endpoint URL for testing with
                    LocalStack or other AWS-compatible services.
                    Example: "http://localhost:4566"
                tenant_resolver (TenantConfigResolver, optional): Custom tenant resolver
                    implementation. If provided, this resolver will be used instead of
                    creating a CognitoTenantResolver. Use DynamoDBTenantResolver for
                    services that own the DynamoDB table (e.g., Harbor) or
                    HarborTenantResolver for external services (e.g., Faro).

            For provider_type="mock":
                No additional arguments required.

    Returns:
        LighthouseFactory: A configured factory instance that can create
            IdentityProvider and TokenVerifier components.

    Raises:
        ValueError: If provider_type is unknown or required arguments are missing.
        TypeError: If invalid argument types are provided.

    Examples:
        Basic usage with Cognito:
            >>> from lighthouse import create_factory
            >>> factory = create_factory("cognito", region="us-east-1")
            >>> provider = factory.create_identity_provider()
            >>> verifier = factory.create_token_verifier(token_use="access")

        With environment variables:
            >>> import os
            >>> factory = create_factory(
            ...     provider_type=os.getenv("IDENTITY_PROVIDER_TYPE", "cognito"),
            ...     region=os.getenv("AWS_REGION", "us-east-1")
            ... )

        Using mock provider for testing:
            >>> factory = create_factory("mock")
            >>> provider = factory.create_identity_provider()

        With LocalStack for local development:
            >>> factory = create_factory(
            ...     "cognito",
            ...     region="us-east-1",
            ...     endpoint_url="http://localhost:4566"
            ... )

    Note:
        The factory caches the IdentityProvider instance to ensure that
        TokenVerifier components created by the same factory use the same
        provider for tenant resolution.
    """
    if provider_type == "cognito":
        from lighthouse.factories.cognito import CognitoFactory

        # Validate required arguments for Cognito
        if "region" not in kwargs:
            raise ValueError(
                "Missing required argument 'region' for provider_type='cognito'. "
                "Example: create_factory('cognito', region='us-east-1')"
            )
        return CognitoFactory(**kwargs)
    elif provider_type == "mock":
        from lighthouse.factories.mock import MockFactory

        # Mock provider doesn't accept any arguments
        if kwargs:
            raise ValueError(
                f"MockFactory does not accept arguments, but got: {list(kwargs.keys())}. "
                f"Use: create_factory('mock')"
            )
        return MockFactory()
    else:
        raise ValueError(
            f"Unknown provider type: '{provider_type}'. "
            f"Valid types: 'cognito', 'mock'. "
            f"Example: create_factory('cognito', region='us-east-1')"
        )
