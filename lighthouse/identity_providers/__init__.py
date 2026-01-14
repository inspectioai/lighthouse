"""Identity provider implementations for managing user pools and users."""

from lighthouse.identity_providers.cognito import (
    CognitoIdentityProvider,
    ROLE_ATTRIBUTE,
    TENANT_ID_ATTRIBUTE,
    NAME_ATTRIBUTE,
)
from lighthouse.identity_providers.mock import MockIdentityProvider

__all__ = [
    "CognitoIdentityProvider",
    "MockIdentityProvider",
    "ROLE_ATTRIBUTE",
    "TENANT_ID_ATTRIBUTE",
    "NAME_ATTRIBUTE",
]
