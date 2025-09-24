# IAM Advanced Topics

## Overview
This document covers advanced IAM topics and best practices essential for professional-level AWS certifications and enterprise security implementations.

---

## Enterprise IAM Architecture

### Multi-Account Strategy
- **AWS Organizations**: Centralized management of multiple accounts
- **Account separation**: Isolate workloads by environment, business unit, or compliance requirements
- **Cross-account roles**: Secure access between accounts
- **Centralized logging**: CloudTrail and Config across all accounts

### Organization Structure Example
```
Root Organization Unit (OU)
├── Security OU
│   ├── Log Archive Account
│   ├── Audit Account
│   └── Security Tools Account
├── Production OU
│   ├── Prod App Account 1
│   ├── Prod App Account 2
│   └── Shared Services Account
├── Non-Production OU
│   ├── Development Account
│   ├── Testing Account
│   └── Staging Account
└── Sandbox OU
    ├── Developer Sandbox 1
    └── Developer Sandbox 2
```

### Service Control Policies (SCPs)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideEU",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "eu-west-1",
            "eu-west-2",
            "eu-central-1"
          ]
        },
        "ForAllValues:StringNotEquals": {
          "aws:PrincipalServiceName": [
            "cloudfront.amazonaws.com",
            "iam.amazonaws.com",
            "route53.amazonaws.com",
            "support.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "DenyRootUserActions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalType": "Root"
        }
      }
    }
  ]
}
```

---

## Advanced Security Patterns

### Zero Trust Architecture
```bash
# Zero Trust Principles in AWS IAM
1. Never trust, always verify
2. Least privilege access
3. Assume breach mindset
4. Verify explicitly
5. Use risk-based access decisions
```

### Conditional Access Policies
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "NumericLessThan": {
          "aws:MultiFactorAuthAge": "3600"
        },
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24",
            "198.51.100.0/24"
          ]
        },
        "StringEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

### Break Glass Access Pattern
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEmergencyAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "StringEquals": {
          "aws:RequestTag/EmergencyAccess": "true"
        }
      }
    },
    {
      "Sid": "RequireEmergencyTag",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestTag/EmergencyAccess": "true"
        }
      }
    }
  ]
}
```

---

## IAM Policy Optimization

### Policy Analysis Tools
```python
import boto3
import json

def analyze_policy_permissions(policy_arn):
    """Analyze IAM policy for over-privileged permissions"""
    iam = boto3.client('iam')
    
    # Get policy document
    policy = iam.get_policy(PolicyArn=policy_arn)
    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy['Policy']['DefaultVersionId']
    )
    
    document = version['PolicyVersion']['Document']
    
    # Analyze statements
    findings = []
    for statement in document.get('Statement', []):
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Check for overly broad permissions
        for action in actions:
            if action == '*':
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'Wildcard action (*) grants all permissions',
                    'recommendation': 'Specify explicit actions'
                })
            elif action.endswith(':*'):
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': f'Service wildcard {action} grants all service permissions',
                    'recommendation': f'Specify explicit {action.split(":")[0]} actions'
                })
    
    return findings
```

### Least Privilege Policy Generation
```python
def generate_least_privilege_policy(cloudtrail_events):
    """Generate policy based on actual CloudTrail usage"""
    actions_used = set()
    resources_accessed = set()
    
    for event in cloudtrail_events:
        if event.get('errorCode') is None:  # Successful actions only
            action = f"{event['eventSource'].replace('.amazonaws.com', '')}:{event['eventName']}"
            actions_used.add(action)
            
            # Extract resource ARNs
            for resource in event.get('resources', []):
                if resource.get('ARN'):
                    resources_accessed.add(resource['ARN'])
    
    # Generate policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": list(actions_used),
                "Resource": list(resources_accessed) if resources_accessed else "*"
            }
        ]
    }
    
    return policy
```

### Policy Validation and Testing
```bash
# Policy Simulator Commands
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/testuser \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::test-bucket/test-object

# Access Analyzer Policy Validation
aws accessanalyzer validate-policy \
  --policy-document file://policy.json \
  --policy-type IDENTITY_POLICY
```

---

## Automation and Infrastructure as Code

### CloudFormation IAM Templates
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Comprehensive IAM setup for development team'

Parameters:
  TeamName:
    Type: String
    Description: Name of the development team
    Default: 'dev-team'

Resources:
  # Permission Boundary for developers
  DeveloperPermissionBoundary:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: !Sub '${TeamName}-permission-boundary'
      Description: 'Permission boundary for development team'
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 's3:*'
              - 'ec2:*'
              - 'lambda:*'
              - 'dynamodb:*'
              - 'cloudformation:*'
            Resource: '*'
            Condition:
              StringEquals:
                'aws:RequestedRegion': 
                  - 'us-east-1'
                  - 'us-west-2'
          - Effect: Deny
            Action:
              - 'iam:CreateUser'
              - 'iam:DeleteUser'
              - 'iam:CreateRole'
              - 'iam:DeleteRole'
              - 'organizations:*'
            Resource: '*'

  # Developer group
  DeveloperGroup:
    Type: AWS::IAM::Group
    Properties:
      GroupName: !Sub '${TeamName}-developers'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/PowerUserAccess'

  # Cross-account role for CI/CD
  CICDRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${TeamName}-cicd-role'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${CICDAccountId}:root'
            Action: 'sts:AssumeRole'
            Condition:
              StringEquals:
                'sts:ExternalId': !Ref ExternalId
      ManagedPolicyArns:
        - !Ref CICDPolicy

  # Custom policy for CI/CD
  CICDPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: !Sub '${TeamName}-cicd-policy'
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:*'
              - 's3:GetObject'
              - 's3:PutObject'
              - 'ecr:GetAuthorizationToken'
              - 'ecr:BatchCheckLayerAvailability'
              - 'ecr:GetDownloadUrlForLayer'
              - 'ecr:BatchGetImage'
            Resource: '*'

Outputs:
  DeveloperGroupArn:
    Description: 'ARN of the developer group'
    Value: !GetAtt DeveloperGroup.Arn
    Export:
      Name: !Sub '${AWS::StackName}-developer-group-arn'

  CICDRoleArn:
    Description: 'ARN of the CI/CD role'
    Value: !GetAtt CICDRole.Arn
    Export:
      Name: !Sub '${AWS::StackName}-cicd-role-arn'
```

### Terraform IAM Module
```hcl
# main.tf
variable "team_name" {
  description = "Name of the development team"
  type        = string
}

variable "allowed_regions" {
  description = "List of allowed AWS regions"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

# Permission boundary policy
resource "aws_iam_policy" "developer_boundary" {
  name        = "${var.team_name}-permission-boundary"
  description = "Permission boundary for ${var.team_name} developers"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "lambda:*",
          "dynamodb:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
        }
      },
      {
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateRole",
          "iam:DeleteRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# Developer role with permission boundary
resource "aws_iam_role" "developer_role" {
  name                 = "${var.team_name}-developer-role"
  permissions_boundary = aws_iam_policy.developer_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

# Attach policies to role
resource "aws_iam_role_policy_attachment" "developer_poweruser" {
  role       = aws_iam_role.developer_role.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

data "aws_caller_identity" "current" {}

# Output role ARN
output "developer_role_arn" {
  value = aws_iam_role.developer_role.arn
}
```

---

## Compliance and Governance

### SOC 2 Compliance Checklist
```bash
# IAM controls for SOC 2 compliance
✅ Multi-factor authentication enforced
✅ Regular access reviews conducted
✅ Least privilege principle implemented
✅ Segregation of duties maintained
✅ Access logging and monitoring enabled
✅ Password policies enforced
✅ Privileged access management
✅ Regular vulnerability assessments
```

### GDPR Compliance Considerations
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictToEURegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "eu-north-1"
          ]
        }
      }
    },
    {
      "Sid": "RequireEncryption",
      "Effect": "Deny",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::gdpr-compliant-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
```

### Audit Trail Configuration
```python
def setup_comprehensive_auditing():
    """Setup comprehensive IAM auditing"""
    cloudtrail = boto3.client('cloudtrail')
    config = boto3.client('config')
    
    # CloudTrail for IAM events
    cloudtrail.create_trail(
        Name='iam-audit-trail',
        S3BucketName='iam-audit-logs-bucket',
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        EventSelectors=[
            {
                'ReadWriteType': 'All',
                'IncludeManagementEvents': True,
                'DataResources': [
                    {
                        'Type': 'AWS::IAM::*',
                        'Values': ['arn:aws:iam::*']
                    }
                ]
            }
        ]
    )
    
    # Config rules for IAM compliance
    config.put_config_rule(
        ConfigRule={
            'ConfigRuleName': 'iam-user-mfa-enabled',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'IAM_USER_MFA_ENABLED'
            }
        }
    )
    
    config.put_config_rule(
        ConfigRule={
            'ConfigRuleName': 'iam-password-policy',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'IAM_PASSWORD_POLICY'
            }
        }
    )
```

---

## Performance and Scale Optimization

### IAM Quotas and Limits
```bash
# Service Quotas (per account)
Users: 5,000
Groups: 300
Roles: 1,000
Customer managed policies: 1,500
Identity providers: 100
Server certificates: 20

# Policy Quotas
Managed policy size: 6,144 characters
Inline policy size: 2,048 characters
Policies per user: 10 managed + unlimited inline
Policies per group: 10 managed + unlimited inline
Policies per role: 10 managed + unlimited inline
```

### Large-Scale IAM Management
```python
def bulk_user_management():
    """Manage IAM users at scale"""
    iam = boto3.client('iam')
    
    # Batch operations for better performance
    def create_users_batch(user_list):
        for user_batch in chunks(user_list, 10):  # Process in batches
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for user in user_batch:
                    future = executor.submit(create_single_user, user)
                    futures.append(future)
                
                # Wait for completion
                concurrent.futures.wait(futures)
    
    def create_single_user(user_data):
        try:
            iam.create_user(UserName=user_data['username'])
            iam.add_user_to_group(
                UserName=user_data['username'],
                GroupName=user_data['group']
            )
            return True
        except Exception as e:
            print(f"Error creating user {user_data['username']}: {e}")
            return False

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
```

### Caching and Performance
```python
import boto3
from functools import lru_cache
import time

class IAMCache:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.cache_ttl = 300  # 5 minutes
        
    @lru_cache(maxsize=1000)
    def get_user_policies(self, username, timestamp=None):
        """Cached policy retrieval with TTL"""
        try:
            # Get attached managed policies
            managed = self.iam.list_attached_user_policies(UserName=username)
            
            # Get inline policies
            inline = self.iam.list_user_policies(UserName=username)
            
            return {
                'managed': managed['AttachedPolicies'],
                'inline': inline['PolicyNames'],
                'timestamp': time.time()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_cached_user_policies(self, username):
        """Get policies with cache invalidation"""
        current_time = time.time()
        cache_key = int(current_time // self.cache_ttl)
        return self.get_user_policies(username, cache_key)
```

---

## Disaster Recovery and Business Continuity

### IAM Backup Strategy
```python
def backup_iam_configuration():
    """Comprehensive IAM backup"""
    iam = boto3.client('iam')
    backup_data = {}
    
    # Backup users
    users = iam.list_users()['Users']
    backup_data['users'] = []
    
    for user in users:
        user_data = {
            'username': user['UserName'],
            'path': user['Path'],
            'tags': iam.list_user_tags(UserName=user['UserName'])['Tags'],
            'groups': [g['GroupName'] for g in iam.get_groups_for_user(UserName=user['UserName'])['Groups']],
            'attached_policies': iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies'],
            'inline_policies': {}
        }
        
        # Backup inline policies
        inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
        for policy_name in inline_policies:
            policy_doc = iam.get_user_policy(UserName=user['UserName'], PolicyName=policy_name)
            user_data['inline_policies'][policy_name] = policy_doc['PolicyDocument']
        
        backup_data['users'].append(user_data)
    
    # Backup roles
    roles = iam.list_roles()['Roles']
    backup_data['roles'] = []
    
    for role in roles:
        if not role['RoleName'].startswith('AWSServiceRole'):  # Skip service-linked roles
            role_data = {
                'role_name': role['RoleName'],
                'path': role['Path'],
                'assume_role_policy': role['AssumeRolePolicyDocument'],
                'max_session_duration': role.get('MaxSessionDuration', 3600),
                'tags': iam.list_role_tags(RoleName=role['RoleName'])['Tags'],
                'attached_policies': iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies'],
                'inline_policies': {}
            }
            
            # Backup inline policies
            inline_policies = iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
            for policy_name in inline_policies:
                policy_doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)
                role_data['inline_policies'][policy_name] = policy_doc['PolicyDocument']
            
            backup_data['roles'].append(role_data)
    
    return backup_data
```

### Cross-Region IAM Considerations
```bash
# IAM is a global service, but consider:
1. Regional service-linked roles
2. Regional resource-based policies
3. Cross-region access patterns
4. Regional compliance requirements
5. Regional service availability
```

---

## Exam Tips

### Professional Certification Focus Areas
- **AWS Certified Security - Specialty**: Advanced IAM patterns, compliance, monitoring
- **AWS Certified Solutions Architect Professional**: Multi-account architecture, enterprise patterns
- **AWS Certified Advanced Networking**: Cross-account networking, federated access

### Advanced IAM Concepts
- **Permission boundaries**: Maximum permissions, not grants
- **SCPs**: Organizational guardrails, apply to all principals
- **Session policies**: Limit assumed role permissions
- **Principal tags**: Dynamic access control based on tags
- **ABAC**: Attribute-based access control with tags

### Enterprise Best Practices
- **Account strategy**: Separate accounts for different environments/business units
- **Centralized identity**: Use Identity Center for SSO
- **Automated provisioning**: Infrastructure as Code for IAM resources
- **Regular audits**: Access reviews, unused credentials cleanup
- **Monitoring**: CloudTrail, Access Analyzer, Config rules

### Troubleshooting Advanced Issues
- **Policy evaluation**: Use policy simulator
- **Cross-account access**: Check trust policies and external IDs
- **Federation**: Verify SAML/OIDC configuration
- **Performance**: Consider caching and batch operations
- **Quota limits**: Monitor service quotas and request increases

---

## Quick Reference

### IAM Decision Framework
```
Access Request → Authentication → Authorization → Resource Access
                 (MFA, Valid creds) → (Policy evaluation) → (Grant/Deny)
```

### Policy Types Priority
1. **Explicit Deny**: Always wins
2. **Permission Boundaries**: Filter maximum permissions
3. **Service Control Policies**: Organizational constraints
4. **Session Policies**: Limit assumed role sessions
5. **Identity-based**: User/group/role policies
6. **Resource-based**: Attached to resources

### Common Enterprise Patterns
- **Hub-and-spoke**: Central identity account with cross-account roles
- **Federated access**: SAML/OIDC integration with corporate directory
- **Just-in-time access**: Temporary elevated permissions
- **Zero standing privileges**: All access through temporary elevation# Overview

This document covers advanced AWS IAM topics and security best practices.

## Topics

- Policy optimization and troubleshooting
- Federation and identity providers
- Advanced security features
- Compliance and auditing
- Automation and governance

## Notes

Add your notes here...