"""Tests for IdentityProvider interface compliance."""

import pytest
from abc import ABC
from lighthouse import IdentityProvider, CognitoFactory


def test_identity_provider_is_abstract():
    """Test that IdentityProvider cannot be instantiated."""
    assert issubclass(IdentityProvider, ABC)

    with pytest.raises(TypeError):
        IdentityProvider()  # type: ignore


def test_identity_provider_has_required_methods():
    """Test that IdentityProvider defines all required methods."""
    required_methods = [
        "create_pool",
        "delete_pool",
        "get_pool_info",
        "invite_user",
        "get_user",
        "get_user_by_email",
        "list_users",
        "update_user_role",
        "update_user_display_name",
        "disable_user",
        "enable_user",
        "delete_user",
        "resend_invite",
    ]

    for method in required_methods:
        assert hasattr(IdentityProvider, method), f"IdentityProvider missing method: {method}"


def test_cognito_provider_implements_interface(cognito_factory):
    """Test that CognitoIdentityProvider implements all required methods."""
    required_methods = [
        "create_pool",
        "delete_pool",
        "get_pool_info",
        "invite_user",
        "get_user",
        "get_user_by_email",
        "list_users",
        "update_user_role",
        "update_user_display_name",
        "disable_user",
        "enable_user",
        "delete_user",
        "resend_invite",
    ]

    provider = cognito_factory.create_identity_provider()

    for method in required_methods:
        assert hasattr(provider, method), f"CognitoIdentityProvider missing method: {method}"
        assert callable(getattr(provider, method)), f"CognitoIdentityProvider.{method} is not callable"


def test_cognito_provider_is_identity_provider(cognito_factory):
    """Test that CognitoIdentityProvider is an IdentityProvider."""
    provider = cognito_factory.create_identity_provider()
    assert isinstance(provider, IdentityProvider)
