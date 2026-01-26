"""AWS Lambda handler for Cognito CustomMessage trigger.

This Lambda function customizes Cognito password reset emails using styled HTML
templates from the lighthouse package.

Environment Variables (Per Pool):
    TENANT_NAME: Display name of the tenant (e.g., "AcmeCorp")
    PANORAMA_URL: Base URL for Panorama (e.g., https://panorama.dev.inspectio.ai)

Deployment:
    1. Package this Lambda with lighthouse as a dependency layer
    2. Deploy one Lambda per tenant (or use pool tags for multi-tenant)
    3. Configure Cognito pool to use this Lambda as CustomMessage trigger

Cognito Event Types Handled:
    - CustomMessage_ForgotPassword: Password reset email (styled)
    - Other types: Pass through unchanged (use Cognito defaults)
"""

import os
from lighthouse.templates import get_password_reset_email_template


def handler(event, context):
    """Handle Cognito CustomMessage trigger events.

    Args:
        event: Cognito trigger event with structure:
            - triggerSource: Event type (e.g., "CustomMessage_ForgotPassword")
            - userPoolId: Cognito pool ID
            - request:
                - userAttributes: User attributes (email, custom:tenant_id, etc.)
                - codeParameter: Verification code placeholder "{####}"
                - usernameParameter: Username placeholder "{username}"
            - response:
                - emailSubject: (set by Lambda)
                - emailMessage: (set by Lambda)
        context: Lambda execution context

    Returns:
        Modified event with customized email subject and message
    """
    trigger_source = event["triggerSource"]

    # Only customize password reset emails
    if trigger_source == "CustomMessage_ForgotPassword":
        # Get configuration from environment variables
        # These should be set when configuring the Lambda trigger in Cognito
        tenant_name = os.getenv("TENANT_NAME", "Inspectio.ai")
        panorama_url = os.getenv("PANORAMA_URL", "https://panorama.app.inspectio.ai")

        # Set customized email subject and message
        event["response"]["emailSubject"] = "Reset Your Password - Inspectio.ai"
        event["response"]["emailMessage"] = get_password_reset_email_template(
            tenant_name=tenant_name,
            panorama_url=panorama_url,
        )

    # For all other trigger types, return event unchanged (Cognito uses defaults)
    return event
