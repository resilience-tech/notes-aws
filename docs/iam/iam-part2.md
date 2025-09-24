# IAM Part 2 - Advanced Access Management

## Overview
This document covers intermediate IAM concepts essential for certification exams. Focus on cross-account access, federation, STS, and advanced IAM features.

---

## AWS Security Token Service (STS)

### STS Core Concepts
- **Temporary credentials**: Limited-time access keys
- **Session tokens**: Required for temporary credential authentication
- **Assume role**: Primary method for obtaining temporary credentials
- **Federation**: Integrate external identity providers
- **Cross-account access**: Secure access across AWS accounts

### STS API Operations

| Operation | Purpose | Use Case |
|-----------|---------|----------|
| **AssumeRole** | Assume IAM role | Cross-account access, service roles |
| **AssumeRoleWithWebIdentity** | Assume role with web identity | Mobile apps, web applications |
| **AssumeRoleWithSAML** | Assume role with SAML assertion | Enterprise SAML federation |
| **GetFederationToken** | Get federation token | Custom federation scenarios |
| **GetSessionToken** | Get session token | MFA-enabled temporary credentials |

### AssumeRole Example
```python
import boto3

# Create STS client
sts_client = boto3.client('sts')

# Assume role
response = sts_client.assume_role(
    RoleArn='arn:aws:iam::123456789012:role/CrossAccountRole',
    RoleSessionName='MySession',
    ExternalId='unique-external-id',
    DurationSeconds=3600  # 1 hour
)

# Extract temporary credentials
credentials = response['Credentials']
access_key = credentials['AccessKeyId']
secret_key = credentials['SecretAccessKey']
session_token = credentials['SessionToken']

# Use temporary credentials
s3_client = boto3.client(
    's3',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    aws_session_token=session_token
)
```

### Session Duration Limits
```bash
# Default and Maximum Session Durations
Role Session Duration:
- Default: 1 hour
- Maximum: 12 hours (configurable per role)
- Chained roles: 1 hour maximum

Federation Token:
- Default: 12 hours
- Maximum: 36 hours

Session Token (MFA):
- Default: 12 hours
- Maximum: 36 hours
```

---

## Cross-Account Access

### Cross-Account Role Setup

#### Step 1: Create Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::111122223333:user/ExternalUser",
          "arn:aws:iam::111122223333:role/ExternalRole"
        ]
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

#### Step 2: Create Permission Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::shared-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::shared-bucket"
    }
  ]
}
```

#### Step 3: External User Permission
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::444455556666:role/CrossAccountRole"
    }
  ]
}
```

### Cross-Account Resource Sharing
```bash
# Resource-based policies (alternative to role assumption)
S3 Bucket Policy:
- Grant access to external AWS accounts
- No role assumption required
- Direct resource access

Lambda Resource Policy:
- Allow cross-account function invocation
- Event source mappings
- API Gateway integration
```

---

## Identity Federation

### Web Identity Federation

#### OpenID Connect (OIDC) Setup
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "your-app-client-id"
        },
        "StringLike": {
          "accounts.google.com:sub": "user-*"
        }
      }
    }
  ]
}
```

#### Web Identity Federation Flow
```
1. User authenticates with identity provider (Google, Facebook, etc.)
2. Identity provider returns JWT token
3. Application calls AssumeRoleWithWebIdentity with JWT
4. AWS STS validates token and returns temporary credentials
5. Application uses temporary credentials to access AWS resources
```

### SAML Federation

#### SAML Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/CompanySAML"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

#### SAML Attributes Mapping
```xml
<!-- Example SAML Assertion -->
<saml:AttributeStatement>
  <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
    <saml:AttributeValue>arn:aws:iam::123456789012:role/SAMLRole,arn:aws:iam::123456789012:saml-provider/CompanySAML</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
    <saml:AttributeValue>john.doe@company.com</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
    <saml:AttributeValue>3600</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

---

## Permission Boundaries

### Permission Boundary Concepts
- **Maximum permissions**: Define the maximum permissions an entity can have
- **Filter mechanism**: Do not grant permissions by themselves
- **Effective permissions**: Intersection of identity-based policies and boundaries
- **Use cases**: Delegated administration, developer sandboxes

### Permission Boundary Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "ec2:*",
        "lambda:*",
        "iam:GetRole",
        "iam:PassRole"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole"
      ],
      "Resource": "*"
    }
  ]
}
```

### Delegated Administration Pattern
```bash
# Scenario: Allow team leads to manage their team's IAM users
1. Create permission boundary policy
2. Attach boundary to team lead users
3. Grant IAM permissions to team leads
4. Team leads can create users within boundary limits
5. All created users automatically get the same boundary
```

---

## Service-Linked Roles

### Service-Linked Role Characteristics
- **AWS service managed**: Created and managed by AWS services
- **Predefined trust policy**: Service is the trusted principal
- **Predefined permissions**: AWS defines what the service can do
- **Automatic creation**: Created when service requires it
- **Cannot modify**: Trust policy and permissions cannot be changed

### Common Service-Linked Roles
```bash
# Examples of service-linked roles
AWSServiceRoleForElasticLoadBalancing
AWSServiceRoleForRDS
AWSServiceRoleForLambda
AWSServiceRoleForECS
AWSServiceRoleForAutoScaling
AWSServiceRoleForCloudFormation
```

### Service-Linked Role Management
```bash
# Create service-linked role (if supported)
aws iam create-service-linked-role --aws-service-name elasticloadbalancing.amazonaws.com

# List service-linked roles
aws iam list-roles --path-prefix /aws-service-role/

# Delete service-linked role
aws iam delete-service-linked-role --role-name AWSServiceRoleForElasticLoadBalancing
```

---

## IAM Identity Center (SSO)

### Identity Center Features
- **Centralized access management**: Single sign-on to AWS accounts
- **External identity sources**: Active Directory, external SAML providers
- **Permission sets**: Templates for AWS account access
- **Multi-account access**: Manage access across AWS Organizations

### Permission Set Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Environment": ["Development", "Testing"]
        }
      }
    }
  ]
}
```

### Identity Center Integration
```bash
# Integration options
1. AWS Organizations integration
2. Active Directory synchronization
3. External SAML identity providers
4. Built-in identity store
5. API and CLI access through SSO
```

---

## Advanced Policy Features

### Policy Variables
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::company-bucket/${aws:username}/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::company-bucket",
      "Condition": {
        "StringLike": {
          "s3:prefix": "${aws:username}/*"
        }
      }
    }
  ]
}
```

### Common Policy Variables
```bash
# AWS-provided variables
${aws:username}: IAM user name
${aws:userid}: Unique ID of the user
${aws:SourceIp}: Source IP address
${aws:CurrentTime}: Current time
${aws:SecureTransport}: Whether request used SSL
${aws:MultiFactorAuthPresent}: Whether MFA was used
${aws:MultiFactorAuthAge}: Time since MFA authentication

# SAML variables
${saml:sub}: SAML subject
${saml:aud}: SAML audience
${saml:iss}: SAML issuer

# OIDC variables
${oidc:sub}: OIDC subject
${oidc:aud}: OIDC audience
```

### Condition Operators
```json
{
  "Condition": {
    "StringEquals": {
      "s3:x-amz-server-side-encryption": "AES256"
    },
    "StringLike": {
      "s3:prefix": "documents/*"
    },
    "NumericLessThan": {
      "s3:max-keys": "10"
    },
    "DateGreaterThan": {
      "aws:CurrentTime": "2024-01-01T00:00:00Z"
    },
    "IpAddress": {
      "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"]
    },
    "Bool": {
      "aws:SecureTransport": "true"
    }
  }
}
```

---

## Security and Compliance

### IAM Credential Report
```python
import boto3
import csv
import io

def generate_iam_report():
    iam = boto3.client('iam')
    
    # Generate report
    iam.generate_credential_report()
    
    # Wait for completion and get report
    while True:
        try:
            response = iam.get_credential_report()
            break
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(5)
    
    # Parse CSV content
    report_content = response['Content'].decode('utf-8')
    csv_reader = csv.DictReader(io.StringIO(report_content))
    
    # Analyze report
    for row in csv_reader:
        username = row['user']
        password_last_used = row['password_last_used']
        access_key_1_last_used = row['access_key_1_last_used_date']
        
        # Check for inactive users
        if password_last_used == 'N/A' and access_key_1_last_used == 'N/A':
            print(f"Inactive user found: {username}")
```

### Access Analyzer Findings
```bash
# Access Analyzer finding types
External Access:
- S3 buckets accessible from outside account
- IAM roles assumable by external accounts
- KMS keys with external access
- Lambda functions with resource-based policies

Unused Access:
- Unused roles (no activity in 90 days)
- Unused access keys
- Over-privileged policies
```

### CloudTrail IAM Events
```json
{
  "eventTime": "2024-01-15T14:30:45Z",
  "eventName": "AssumeRole",
  "eventSource": "sts.amazonaws.com",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI23HZ27SI6FQMGNQ2",
    "arn": "arn:aws:iam::123456789012:user/Bob",
    "accountId": "123456789012",
    "userName": "Bob"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/S3-Admin-Role",
    "roleSessionName": "Bob-Session"
  },
  "responseElements": {
    "assumedRoleUser": {
      "assumedRoleId": "AROA12345678901234567:Bob-Session",
      "arn": "arn:aws:sts::123456789012:assumed-role/S3-Admin-Role/Bob-Session"
    }
  }
}
```

---

## Exam Tips

### Cross-Account Access Patterns
- **Use roles**: Preferred method for cross-account access
- **External ID**: Use for third-party access scenarios
- **Resource-based policies**: Alternative for some services (S3, Lambda)
- **Temporary credentials**: Always prefer over permanent keys

### Federation Best Practices
- **Web identity**: For mobile and web applications
- **SAML**: For enterprise single sign-on
- **Cognito**: For user management and authentication
- **Identity Center**: For multi-account AWS access

### STS Session Limits
- **Role sessions**: 1-12 hours (default 1 hour)
- **Chained assumptions**: Maximum 1 hour
- **Federation tokens**: 15 minutes to 36 hours
- **Session tokens**: 15 minutes to 36 hours

### Policy Evaluation Order
1. **Explicit deny**: Overrides everything
2. **Permission boundaries**: Limit maximum permissions
3. **Identity-based policies**: Attached to user/group/role
4. **Resource-based policies**: Attached to resources
5. **Service control policies**: Organizational guardrails

---

## Quick Commands

### STS Operations
```bash
# Assume role
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole --role-session-name MySession

# Get caller identity
aws sts get-caller-identity

# Get session token with MFA
aws sts get-session-token --serial-number arn:aws:iam::123456789012:mfa/user --token-code 123456
```

### Federation Setup
```bash
# Create SAML provider
aws iam create-saml-provider --saml-metadata-document file://metadata.xml --name CompanySAML

# Create OIDC provider
aws iam create-open-id-connect-provider --url https://accounts.google.com --thumbprint-list 1234567890abcdef --client-id-list your-client-id

# List identity providers
aws iam list-saml-providers
aws iam list-open-id-connect-providers
```

### Permission Boundaries
```bash
# Set permission boundary
aws iam put-user-permissions-boundary --user-name developer --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary

# Remove permission boundary
aws iam delete-user-permissions-boundary --user-name developer

# List entities with boundary
aws iam list-entities-for-policy --policy-arn arn:aws:iam::123456789012:policy/DeveloperBoundary
```
