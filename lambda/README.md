# Cognito CustomMessage Lambda Function

AWS Lambda function that customizes Cognito password reset emails with styled HTML templates.

## Purpose

By default, Cognito sends unstyled password reset emails. This Lambda intercepts those emails and replaces them with our branded, styled templates.

## How It Works

1. User requests password reset in Panorama
2. Cognito triggers this Lambda with `CustomMessage_ForgotPassword` event
3. Lambda loads the styled template from `lighthouse/templates/password_reset_email.html`
4. Lambda replaces `{{TENANT_NAME}}` and `{{PANORAMA_URL}}` placeholders
5. Cognito sends the styled email

## Deployment

### Step 1: Package Lambda with Dependencies

```bash
cd lambda
pip install -r requirements.txt -t package/
cp custom_message_handler.py package/
cd package && zip -r ../custom_message_handler.zip . && cd ..
```

### Step 2: Create Lambda Function

```bash
aws lambda create-function \
  --function-name cognito-custom-message-<tenant-name> \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/cognito-lambda-role \
  --handler custom_message_handler.handler \
  --zip-file fileb://custom_message_handler.zip \
  --environment "Variables={TENANT_NAME=AcmeCorp,PANORAMA_URL=https://panorama.dev.inspectio.ai}"
```

### Step 3: Grant Cognito Permission to Invoke Lambda

```bash
aws lambda add-permission \
  --function-name cognito-custom-message-<tenant-name> \
  --statement-id AllowCognitoInvoke \
  --action lambda:InvokeFunction \
  --principal cognito-idp.amazonaws.com \
  --source-arn arn:aws:cognito-idp:REGION:ACCOUNT_ID:userpool/POOL_ID
```

### Step 4: Configure Cognito Pool to Use Lambda

This needs to be done when creating the pool or via update_user_pool:

```python
# In create_pool, add:
"LambdaConfig": {
    "CustomMessage": "arn:aws:lambda:REGION:ACCOUNT_ID:function:cognito-custom-message-<tenant-name>"
}
```

## Configuration

### Per-Tenant Lambda (Recommended)
Deploy one Lambda per tenant with environment variables:
- `TENANT_NAME`: "AcmeCorp"
- `PANORAMA_URL`: "https://panorama.dev.inspectio.ai"

### Single Lambda for All Tenants (Alternative)
Use Cognito pool tags to store tenant_name and panorama_url, and the Lambda reads them at runtime.

## IAM Role

The Lambda execution role needs:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

## Testing

After deployment:
1. Create a test user in the Cognito pool
2. Request password reset via Panorama
3. Check email - should be styled with tenant name and "Reset Password" button
