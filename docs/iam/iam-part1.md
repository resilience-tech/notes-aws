# IAM Part 1 - Identity Fundamentals

## Overview
This document covers AWS Identity and Access Management (IAM) fundamentals essential for AWS certification exams. Focus on core concepts, users, groups, roles, and basic policy management.

---

## IAM Core Concepts

### Identity and Access Management Components
- **Principal**: Entity that can perform actions (user, role, service)
- **Authentication**: Verifying who you are (username/password, keys)
- **Authorization**: Determining what you can do (policies)
- **Action**: Operation performed on a resource
- **Resource**: AWS service object that actions are performed on
- **Effect**: Allow or Deny result of policy evaluation

### IAM Components Overview

| Component | Purpose | Authentication | Use Case |
|-----------|---------|----------------|----------|
| **Root User** | AWS account owner | Email/password + MFA | Initial setup, billing, account closure |
| **IAM User** | Individual person or application | Username/password or access keys | Long-term credentials for people/apps |
| **IAM Group** | Collection of users | N/A | Organize users with similar permissions |
| **IAM Role** | Temporary credentials | Assume role process | Cross-service access, temporary access |
| **Policy** | Permissions document | N/A | Define what actions are allowed/denied |

---

## IAM Users

### User Characteristics
- **Permanent credentials**: Long-term access keys or passwords
- **Individual identity**: One person or application per user
- **Direct permissions**: Policies attached directly or via groups
- **Maximum users**: 5,000 per AWS account

### User Creation Example
```bash
# Create IAM user
aws iam create-user --user-name developer-john

# Create access keys
aws iam create-access-key --user-name developer-john

# Set password (console access)
aws iam create-login-profile --user-name developer-john --password TempPassword123! --password-reset-required
```

### User Authentication Methods
```bash
# Console Access
- Username and password
- Multi-Factor Authentication (MFA)
- Access through AWS Management Console

# Programmatic Access
- Access Key ID + Secret Access Key
- Used with AWS CLI, SDKs, APIs
- Can have maximum 2 access keys per user

# Temporary Credentials
- AWS STS (Security Token Service)
- Session tokens with expiration
- Additional security token required
```

---

## IAM Groups

### Group Characteristics
- **Collection of users**: Easier permission management
- **No credentials**: Groups don't have their own access keys
- **Policy attachment**: Permissions applied to all group members
- **Nested groups**: Not supported (groups cannot contain other groups)

### Group Management
```bash
# Create group
aws iam create-group --group-name developers

# Add user to group
aws iam add-user-to-group --user-name developer-john --group-name developers

# List group members
aws iam get-group --group-name developers

# Remove user from group
aws iam remove-user-from-group --user-name developer-john --group-name developers
```

### Common Group Patterns
```bash
# Functional Groups
- Developers: Development environment access
- Administrators: Full administrative access
- ReadOnly: Read-only access across services
- Auditors: Monitoring and compliance access

# Project-Based Groups
- Project-Alpha-Developers
- Project-Beta-Testers
- Project-Gamma-Administrators

# Environment-Based Groups
- Development-Environment
- Staging-Environment
- Production-Environment
```

---

## IAM Roles

### Role Characteristics
- **Temporary credentials**: No permanent access keys
- **Assumable**: Can be assumed by users, services, or external entities
- **Cross-account access**: Enable access across AWS accounts
- **Service roles**: Allow AWS services to access other services

### Role Types

| Role Type | Purpose | Trust Policy Principal |
|-----------|---------|----------------------|
| **Service Role** | AWS service assumes role | AWS service (e.g., ec2.amazonaws.com) |
| **Cross-Account Role** | Another AWS account assumes role | AWS account ID |
| **Web Identity Role** | External identity provider | Identity provider (Google, Facebook, etc.) |
| **SAML Role** | SAML identity provider | SAML identity provider |

### Service Role Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Cross-Account Role Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/ExternalUser"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        }
      }
    }
  ]
}
```

### Role Assumption Process
```bash
# Assume role using AWS CLI
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/CrossAccountRole \
  --role-session-name SessionName \
  --external-id unique-external-id

# Response includes temporary credentials
{
  "Credentials": {
    "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
    "SecretAccessKey": "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    "SessionToken": "AQoDYXdzEJr...",
    "Expiration": "2024-01-01T12:00:00Z"
  },
  "AssumedRoleUser": {
    "AssumedRoleId": "AROA3XFRBF535PLBIFUYA:SessionName",
    "Arn": "arn:aws:sts::123456789012:assumed-role/CrossAccountRole/SessionName"
  }
}
```

---

## IAM Policies

### Policy Types

| Policy Type | Scope | Attachment | Use Case |
|-------------|-------|------------|----------|
| **Identity-based** | Identity (user, group, role) | Attached to identity | Standard permissions |
| **Resource-based** | Resource (S3 bucket, Lambda) | Attached to resource | Cross-account access |
| **Permission boundaries** | Identity | Attached as boundary | Maximum permissions |
| **Service control policies** | Organization/OU | AWS Organizations | Organizational guardrails |

### Policy Structure
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
```

### Policy Elements
```bash
# Required Elements
- Version: Policy language version (2012-10-17)
- Statement: Array of permission statements

# Statement Elements
- Sid: Statement identifier (optional)
- Effect: Allow or Deny
- Action: API actions (e.g., s3:GetObject)
- Resource: ARN of resources
- Principal: Who the policy applies to (resource-based only)
- Condition: Circumstances for policy application (optional)
```

### AWS Managed Policies
```bash
# Common AWS Managed Policies
PowerUserAccess: Full access except IAM
ReadOnlyAccess: Read-only access to all services
AdministratorAccess: Full access to all services
Billing: Access to billing information

# Service-Specific Policies
AmazonS3FullAccess: Complete S3 access
AmazonS3ReadOnlyAccess: Read-only S3 access
AmazonEC2FullAccess: Complete EC2 access
AmazonRDSFullAccess: Complete RDS access
```

---

## Policy Evaluation Logic

### Evaluation Process
1. **Default Deny**: All requests are denied by default
2. **Explicit Deny**: Any explicit deny overrides everything
3. **Explicit Allow**: Allow if there's an explicit allow
4. **Final Decision**: Deny if no explicit allow found

### Policy Evaluation Flow
```
Request → Authentication → Authorization → Resource Access
           (Who are you?)  (What can you do?)  (Access granted/denied)
```

### Multiple Policy Evaluation
```bash
# Policy Combination Rules
1. Identity-based policies AND resource-based policies
2. Permission boundaries limit identity-based policies
3. SCPs limit all policies in organization
4. Session policies limit assumed role sessions

# Effective Permissions = 
#   Identity-based ∩ Resource-based ∩ Permission-boundaries ∩ SCPs ∩ Session-policies
```

---

## Security Best Practices

### Root Account Security
```bash
# Root Account Best Practices
1. Enable MFA on root account
2. Create IAM users for daily tasks
3. Don't use root account for regular operations
4. Secure root account access keys (delete if possible)
5. Use root account only for account management tasks
```

### Password Policy
```json
{
  "MinimumPasswordLength": 14,
  "RequireSymbols": true,
  "RequireNumbers": true,
  "RequireUppercaseCharacters": true,
  "RequireLowercaseCharacters": true,
  "AllowUsersToChangePassword": true,
  "MaxPasswordAge": 90,
  "PasswordReusePrevention": 24,
  "HardExpiry": false
}
```

### Multi-Factor Authentication (MFA)
```bash
# MFA Device Types
Virtual MFA: Smartphone apps (Google Authenticator, Authy)
Hardware MFA: Physical tokens (YubiKey)
SMS MFA: Text message (not recommended for root)

# Enable MFA for user
aws iam enable-mfa-device \
  --user-name developer-john \
  --serial-number arn:aws:iam::123456789012:mfa/developer-john \
  --authentication-code-1 123456 \
  --authentication-code-2 789012
```

### Access Key Management
```bash
# Access Key Best Practices
1. Regular rotation (90 days recommended)
2. Delete unused access keys
3. Use IAM roles instead of access keys when possible
4. Monitor access key usage with CloudTrail
5. Use temporary credentials for applications

# Rotate access keys
aws iam create-access-key --user-name developer-john
# Update applications with new keys
aws iam delete-access-key --user-name developer-john --access-key-id AKIAI44QH8DHBEXAMPLE
```

---

## Monitoring and Auditing

### CloudTrail Integration
```bash
# CloudTrail logs IAM events
- User authentication
- Policy changes
- Role assumptions
- Access key usage
- Failed authentication attempts
```

### Access Analyzer
```bash
# IAM Access Analyzer findings
- External access to resources
- Unused roles and policies
- Public and cross-account access
- Policy validation and recommendations
```

### Credential Reports
```bash
# Generate credential report
aws iam generate-credential-report

# Get credential report
aws iam get-credential-report

# Report includes:
- User creation date
- Password last used
- Access key last used
- MFA device status
```

---

## Common Use Cases

### Development Team Setup
```bash
# 1. Create group for developers
aws iam create-group --group-name developers

# 2. Attach policy to group
aws iam attach-group-policy \
  --group-name developers \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# 3. Create users and add to group
aws iam create-user --user-name developer-alice
aws iam add-user-to-group --user-name developer-alice --group-name developers

# 4. Set up console access
aws iam create-login-profile \
  --user-name developer-alice \
  --password TempPassword123! \
  --password-reset-required
```

### EC2 Service Role
```bash
# 1. Create trust policy for EC2
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# 2. Create role
aws iam create-role \
  --role-name EC2-S3-Access-Role \
  --assume-role-policy-document file://trust-policy.json

# 3. Attach policy to role
aws iam attach-role-policy \
  --role-name EC2-S3-Access-Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 4. Create instance profile
aws iam create-instance-profile --instance-profile-name EC2-S3-Access-Profile

# 5. Add role to instance profile
aws iam add-role-to-instance-profile \
  --instance-profile-name EC2-S3-Access-Profile \
  --role-name EC2-S3-Access-Role
```

---

## Exam Tips

### IAM Limits
- **Users per account**: 5,000
- **Groups per account**: 300
- **Roles per account**: 1,000
- **Policies per user**: 10 managed policies
- **Groups per user**: 10
- **Policy size**: 2,048 characters (inline), 6,144 characters (managed)

### Key Exam Points
1. **Global service**: IAM is not region-specific
2. **Root account**: Should not be used for daily tasks
3. **Least privilege**: Grant minimum permissions needed
4. **Explicit deny**: Always overrides allow
5. **Policy evaluation**: Default deny → explicit deny → explicit allow
6. **MFA**: Required for privileged operations
7. **Roles vs Users**: Use roles for applications and services

### Common Scenarios
- **Cross-account access**: Use roles, not shared credentials
- **Application access**: Use roles attached to EC2/Lambda
- **Temporary access**: Use STS assume-role
- **Third-party access**: Use external ID with roles
- **Service integration**: Use service roles

### Troubleshooting Checklist
- ✅ **Authentication**: Valid credentials and MFA if required
- ✅ **Authorization**: Policies allow the requested action
- ✅ **Resource permissions**: Resource-based policies allow access
- ✅ **Condition evaluation**: All policy conditions are met
- ✅ **Permission boundaries**: Not blocking the action
- ✅ **Service availability**: Service is available in the region

---

## Quick Commands

### User Management
```bash
# List users
aws iam list-users

# Get user details
aws iam get-user --user-name developer-john

# List user policies
aws iam list-attached-user-policies --user-name developer-john

# List access keys
aws iam list-access-keys --user-name developer-john
```

### Role Management
```bash
# List roles
aws iam list-roles

# Get role details
aws iam get-role --role-name MyRole

# List role policies
aws iam list-attached-role-policies --role-name MyRole

# Assume role
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole --role-session-name MySession
```

### Policy Management
```bash
# List managed policies
aws iam list-policies --scope Local

# Get policy version
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/MyPolicy --version-id v1

# Simulate policy
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/developer-john \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::my-bucket/my-object
```