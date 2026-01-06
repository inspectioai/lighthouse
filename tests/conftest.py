"""Shared pytest fixtures for lighthouse tests."""

import os
import pytest
from moto import mock_aws


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for testing."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_cognito(aws_credentials):
    """Mock Cognito service."""
    with mock_aws():
        yield


@pytest.fixture
def region():
    """AWS region for tests."""
    return "us-east-1"
