# Storage Part 1: Fundamentals

## Overview
This document covers the fundamental concepts of AWS storage services, focusing on core storage solutions and their basic usage patterns for AWS certification preparation.

---

## AWS Storage Service Overview

### Core Storage Services
| Service | Type | Use Case | Durability | Availability |
|---------|------|----------|------------|--------------|
| **Amazon S3** | Object Storage | Web storage, backup, data archiving | 99.999999999% (11 9's) | 99.99% |
| **Amazon EBS** | Block Storage | EC2 instance storage | 99.999% to 99.9999% | 99.999% |
| **Amazon EFS** | File Storage | Shared file storage for EC2 | 99.999999999% (11 9's) | 99.99% |
| **Amazon FSx** | File Storage | High-performance workloads | 99.999999999% (11 9's) | 99.99% |

---

**Amazon S3 (Object Storage):**  
Amazon S3 is designed for storing and retrieving any amount of data as objects, making it ideal for use cases such as hosting static website assets (images, HTML files) and providing highly available, durable storage for global access. Its scalability and integration with web protocols make it a popular choice for backup, archiving, and content distribution.

**Amazon EBS (Block Storage):**  
Amazon EBS provides persistent block-level storage volumes for EC2 instances, commonly used to store operating system files and application data. A typical use case is attaching an EBS volume as the root disk of an EC2 instance, ensuring data durability and availability even if the instance is stopped or restarted.

**Amazon EFS (File Storage):**  
Amazon EFS offers a scalable, shared file system accessible by multiple EC2 instances simultaneously. It is well-suited for scenarios like storing user home directories in web applications, enabling concurrent access and seamless scaling for workloads that require POSIX-compliant file storage.

**Amazon FSx (File Storage):**  
Amazon FSx delivers managed file systems optimized for high-performance workloads. For example, FSx for Lustre is used in big data analytics and high-performance computing environments to accelerate data processing, while FSx for Windows File Server supports enterprise applications requiring SMB protocol and Active Directory integration.

### Storage Types Comparison
```bash
Object Storage (S3):
- REST API access
- Internet accessible
- Virtually unlimited capacity
- Best for: Web applications, content distribution, backup

Block Storage (EBS):
- Low-latency access
- Attached to single EC2 instance
- Fixed capacity volumes
- Best for: Database storage, boot volumes, enterprise apps

File Storage (EFS/FSx):
- POSIX-compliant
- Multiple EC2 instance access
- Scalable capacity
- Best for: Content management, web serving, data analytics
```

---

## Amazon S3 Fundamentals

### S3 REST API In-Depth

Amazon S3 provides a RESTful API for programmatic access to buckets and objects. The API uses standard HTTP methods (GET, PUT, POST, DELETE, HEAD) and supports authentication via AWS Signature Version 4.

#### Key Operations
| HTTP Method | Purpose |
|-------------|---------|
| **PUT**     | Upload or create an object |
| **GET**     | Retrieve/download an object |
| **DELETE**  | Delete an object |
| **HEAD**    | Retrieve object metadata |
| **GET**     | List objects in a bucket |
| **PUT**     | Create a bucket |

#### Object Path and Key Prefix

- **Object Path**: In S3, each object is stored in a bucket and identified by a unique key (the full path to the object within the bucket).  
  *Example*:  
  - Bucket: `my-bucket`
  - Key: `images/photo.jpg`
  - S3 URL: `s3://my-bucket/images/photo.jpg`

- **Key Prefix**: A prefix is a string that filters objects within a bucket, similar to a folder path. Listing objects with a prefix returns only those whose keys start with that prefix.  
  *Example*:  
  - Prefix: `images/`
  - Listing with prefix returns:  
    - `images/photo.jpg`
    - `images/logo.png`
    - `images/2024/banner.jpg`

This allows you to organize and retrieve objects efficiently using logical paths.

- Requests must be signed using AWS credentials (access key, secret key).
- Signature is included in the `Authorization` header.
- Example:  
  `Authorization: AWS4-HMAC-SHA256 Credential=AKIA..., SignedHeaders=host;x-amz-date, Signature=...`

#### Example: Upload Object (PUT)

```http
PUT /my-bucket/my-object HTTP/1.1
Host: my-bucket.s3.amazonaws.com
x-amz-date: 20240601T120000Z
Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
Content-Type: text/plain

Hello, S3!
```

#### Example: List Objects (GET)

```http
GET /my-bucket?list-type=2 HTTP/1.1
Host: my-bucket.s3.amazonaws.com
x-amz-date: 20240601T120000Z
Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
```

#### Features

- Supports multipart uploads for large files.
- Enables object versioning, tagging, and metadata management.
- Allows presigned URLs for temporary access.
- Integrates with IAM, bucket policies, and ACLs for access control.

#### References

- [S3 REST API Docs](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)
- [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)

### Core Concepts
```bash
# S3 Hierarchy
Bucket → Object → Version → Metadata

# S3 URL Formats
Virtual-hosted-style: https://bucket-name.s3.region.amazonaws.com/key-name
Path-style: https://s3.region.amazonaws.com/bucket-name/key-name
```

### Bucket Operations
```bash
# Create bucket
aws s3 mb s3://my-unique-bucket-name --region us-east-1

# List buckets
aws s3 ls

# List objects in bucket
aws s3 ls s3://my-bucket-name/

# Bucket configuration
aws s3api get-bucket-location --bucket my-bucket-name
aws s3api get-bucket-versioning --bucket my-bucket-name
```

### Object Operations
```bash
# Upload file
aws s3 cp file.txt s3://my-bucket/file.txt

# Download file
aws s3 cp s3://my-bucket/file.txt ./file.txt

# Sync directory
aws s3 sync ./local-folder s3://my-bucket/folder/

# Copy between buckets
aws s3 cp s3://source-bucket/file.txt s3://dest-bucket/file.txt

# Set object metadata
aws s3 cp file.txt s3://my-bucket/file.txt --metadata key1=value1,key2=value2
```

---

## S3 Storage Classes

### Standard Storage Classes
| Storage Class | Use Case | Retrieval Time | Min Storage Duration | Cost |
|---------------|----------|----------------|---------------------|------|
| **Standard** | Frequently accessed data | Immediate | None | Highest |
| **Standard-IA** | Infrequently accessed | Immediate | 30 days | Medium |
| **One Zone-IA** | Non-critical, infrequent | Immediate | 30 days | Lower |
| **Reduced Redundancy** | Non-critical (deprecated) | Immediate | None | Medium |


![alt text](images/s3-1.svg)

### Archive Storage Classes
| Storage Class | Use Case | Retrieval Time | Min Storage Duration | Cost |
|---------------|----------|----------------|---------------------|------|
| **Glacier Instant** | Archive with instant access | Immediate | 90 days | Low |
| **Glacier Flexible** | Archive data | 1-12 hours | 90 days | Very Low |
| **Glacier Deep Archive** | Long-term archive | 12-48 hours | 180 days | Lowest |

### Storage Class Selection
```python
import boto3

def set_storage_class(bucket, key, storage_class):
    """Set storage class for S3 object"""
    s3 = boto3.client('s3')
    
    # Copy object to itself with new storage class
    copy_source = {'Bucket': bucket, 'Key': key}
    s3.copy_object(
        CopySource=copy_source,
        Bucket=bucket,
        Key=key,
        StorageClass=storage_class,
        MetadataDirective='COPY'
    )

# Usage examples
set_storage_class('my-bucket', 'file.txt', 'STANDARD_IA')
set_storage_class('my-bucket', 'archive.zip', 'GLACIER')
```

### Lifecycle Management
```json
{
  "Rules": [
    {
      "ID": "OptimizeStorageCosts",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "documents/"
      },
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
```

---

## Amazon EBS Fundamentals

### Volume Types
| Volume Type | IOPS | Throughput | Use Case | Price |
|-------------|------|------------|----------|-------|
| **gp3** | 3,000-16,000 | 125-1,000 MB/s | General purpose SSD | Medium |
| **gp2** | 100-16,000 | Up to 250 MB/s | General purpose SSD | Medium |
| **io2** | 100-64,000 | Up to 1,000 MB/s | High IOPS SSD | High |
| **io1** | 100-64,000 | Up to 1,000 MB/s | High IOPS SSD | High |
| **st1** | 40-500 | Up to 500 MB/s | Throughput HDD | Low |
| **sc1** | 12-250 | Up to 250 MB/s | Cold HDD | Lowest |

### EBS Operations
```bash
# Create volume
aws ec2 create-volume \
  --size 100 \
  --volume-type gp3 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=MyVolume}]'

# Attach volume to instance
aws ec2 attach-volume \
  --volume-id vol-1234567890abcdef0 \
  --instance-id i-1234567890abcdef0 \
  --device /dev/sdf

# Create snapshot
aws ec2 create-snapshot \
  --volume-id vol-1234567890abcdef0 \
  --description "My snapshot"

# Restore from snapshot
aws ec2 create-volume \
  --snapshot-id snap-1234567890abcdef0 \
  --availability-zone us-east-1a
```

### EBS Performance Optimization
```python
import boto3

def optimize_ebs_performance():
    """EBS performance optimization guidelines"""
    
    # GP3 volume optimization
    gp3_config = {
        'VolumeType': 'gp3',
        'Size': 100,  # GB
        'Iops': 3000,  # Baseline 3,000 IOPS
        'Throughput': 125  # MB/s
    }
    
    # IO2 for high IOPS requirements
    io2_config = {
        'VolumeType': 'io2',
        'Size': 500,
        'Iops': 10000,  # Up to 64,000 IOPS
        'MultiAttachEnabled': True  # For cluster setups
    }
    
    return {
        'general_purpose': gp3_config,
        'high_performance': io2_config
    }

# Performance monitoring
def monitor_ebs_performance(volume_id):
    """Monitor EBS volume performance"""
    cloudwatch = boto3.client('cloudwatch')
    
    metrics = [
        'VolumeReadOps',
        'VolumeWriteOps',
        'VolumeTotalReadTime',
        'VolumeTotalWriteTime',
        'VolumeQueueLength'
    ]
    
    for metric in metrics:
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EBS',
            MetricName=metric,
            Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
            Period=300,
            Statistics=['Average']
        )
        print(f"{metric}: {response['Datapoints']}")
```

---

## Amazon EFS Fundamentals

### EFS Features
```bash
# EFS Characteristics
- POSIX-compliant NFS
- Petabyte-scale capacity
- Concurrent access from multiple EC2 instances
- Regional service (multi-AZ)
- Performance modes: General Purpose, Max I/O
- Throughput modes: Provisioned, Bursting
```

### EFS Setup
```bash
# Create EFS file system
aws efs create-file-system \
  --creation-token my-efs-token \
  --performance-mode generalPurpose \
  --throughput-mode provisioned \
  --provisioned-throughput-in-mibps 100 \
  --tags Key=Name,Value=MyEFS

# Create mount target
aws efs create-mount-target \
  --file-system-id fs-1234567890abcdef0 \
  --subnet-id subnet-12345678 \
  --security-groups sg-12345678

# Mount on EC2 instance
sudo mount -t efs fs-1234567890abcdef0:/ /mnt/efs
```

### EFS Performance Configuration
```json
{
  "PerformanceMode": "generalPurpose",
  "ThroughputMode": "provisioned",
  "ProvisionedThroughputInMibps": 500,
  "LifecyclePolicies": [
    {
      "TransitionToIA": "AFTER_30_DAYS",
      "TransitionToPrimaryStorageClass": "AFTER_1_ACCESS"
    }
  ]
}
```

---

## Basic Storage Security

### S3 Security Features
```json
{
  "S3SecurityFeatures": {
    "BucketPolicies": "JSON-based access control",
    "ACLs": "Legacy access control (not recommended)",
    "IAMPolicies": "User/role-based permissions",
    "VPCEndpoints": "Private network access",
    "AccessPoints": "Simplified access management",
    "BlockPublicAccess": "Account-level security defaults"
  }
}
```

### S3 Bucket Policy Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadFromSpecificIP",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    },
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### EBS Encryption
```bash
# Create encrypted volume
aws ec2 create-volume \
  --size 100 \
  --volume-type gp3 \
  --availability-zone us-east-1a \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Enable encryption by default
aws ec2 enable-ebs-encryption-by-default

# Check encryption status
aws ec2 get-ebs-encryption-by-default
```

---

## Cost Optimization Basics

### S3 Cost Optimization
```python
def analyze_s3_costs():
    """Basic S3 cost optimization strategies"""
    
    strategies = {
        'lifecycle_policies': {
            'description': 'Automatically transition objects to cheaper storage classes',
            'savings': '50-90%',
            'implementation': 'Configure lifecycle rules'
        },
        'intelligent_tiering': {
            'description': 'Automatically moves data between access tiers',
            'savings': '20-40%',
            'implementation': 'Enable S3 Intelligent-Tiering'
        },
        'request_optimization': {
            'description': 'Optimize request patterns',
            'savings': '10-30%',
            'implementation': 'Use S3 Transfer Acceleration, CloudFront'
        },
        'storage_analysis': {
            'description': 'Monitor access patterns',
            'savings': 'Variable',
            'implementation': 'Enable S3 Storage Class Analysis'
        }
    }
    
    return strategies

# Cost monitoring
def monitor_storage_costs():
    """Monitor storage costs with CloudWatch"""
    
    cloudwatch = boto3.client('cloudwatch')
    
    # S3 storage metrics
    s3_metrics = [
        'BucketSizeBytes',
        'NumberOfObjects'
    ]
    
    # EBS cost metrics
    ebs_metrics = [
        'VolumeReadBytes',
        'VolumeWriteBytes'
    ]
    
    return {
        's3_metrics': s3_metrics,
        'ebs_metrics': ebs_metrics
    }
```

---

## Backup and Disaster Recovery

### S3 Cross-Region Replication
```json
{
  "Role": "arn:aws:iam::123456789012:role/replication-role",
  "Rules": [
    {
      "ID": "ReplicateToSecondaryRegion",
      "Status": "Enabled",
      "Priority": 1,
      "Filter": {
        "Prefix": "critical-data/"
      },
      "Destination": {
        "Bucket": "arn:aws:s3:::backup-bucket-us-west-2",
        "StorageClass": "STANDARD_IA",
        "ReplicationTime": {
          "Status": "Enabled",
          "Time": {
            "Minutes": 15
          }
        },
        "Metrics": {
          "Status": "Enabled",
          "EventThreshold": {
            "Minutes": 15
          }
        }
      }
    }
  ]
}
```

### EBS Backup Strategy
```python
import boto3
from datetime import datetime, timedelta

def automate_ebs_snapshots():
    """Automate EBS snapshot creation"""
    
    ec2 = boto3.client('ec2')
    
    # Create snapshot
    def create_snapshot(volume_id, description):
        response = ec2.create-snapshot(
            VolumeId=volume_id,
            Description=f"{description} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return response['SnapshotId']
    
    # Cleanup old snapshots
    def cleanup_old_snapshots(days_to_keep=7):
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        snapshots = ec2.describe_snapshots(OwnerIds=['self'])
        
        for snapshot in snapshots['Snapshots']:
            start_time = snapshot['StartTime'].replace(tzinfo=None)
            if start_time < cutoff_date:
                try:
                    ec2.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
                    print(f"Deleted snapshot: {snapshot['SnapshotId']}")
                except Exception as e:
                    print(f"Error deleting snapshot {snapshot['SnapshotId']}: {e}")
    
    return {
        'create_snapshot': create_snapshot,
        'cleanup_old_snapshots': cleanup_old_snapshots
    }
```

---

## Monitoring and Troubleshooting

### CloudWatch Metrics
```bash
# S3 Metrics
- BucketSizeBytes
- NumberOfObjects
- AllRequests
- GetRequests
- PutRequests
- DeleteRequests
- HeadRequests
- PostRequests

# EBS Metrics
- VolumeReadOps
- VolumeWriteOps
- VolumeReadBytes
- VolumeWriteBytes
- VolumeTotalReadTime
- VolumeTotalWriteTime
- VolumeIdleTime
- VolumeQueueLength
```

### Common Issues and Solutions
```bash
# S3 Issues
Problem: Slow upload/download speeds
Solution: Use S3 Transfer Acceleration, multipart uploads

Problem: High request costs
Solution: Implement CloudFront, optimize request patterns

Problem: Unexpected charges
Solution: Enable cost monitoring, implement lifecycle policies

# EBS Issues
Problem: Poor I/O performance
Solution: Use GP3/IO2 volumes, enable EBS optimization

Problem: Running out of space
Solution: Extend volume size, implement monitoring

Problem: Backup failures
Solution: Automate snapshots, test restore procedures
```

---

## Best Practices Summary

### S3 Best Practices
```bash
✅ Use appropriate storage classes
✅ Implement lifecycle policies
✅ Enable versioning for critical data
✅ Use multipart uploads for large files
✅ Implement proper access controls
✅ Monitor costs and usage
✅ Enable encryption in transit and at rest
✅ Use CloudFront for content delivery
```

### EBS Best Practices
```bash
✅ Choose appropriate volume types
✅ Enable EBS optimization on instances
✅ Implement regular snapshot schedule
✅ Monitor performance metrics
✅ Use encryption for sensitive data
✅ Plan for capacity growth
✅ Test backup and restore procedures
✅ Optimize IOPS and throughput settings
```

### EFS Best Practices
```bash
✅ Use appropriate performance mode
✅ Configure lifecycle management
✅ Implement proper security groups
✅ Monitor performance and costs
✅ Use regional file systems for HA
✅ Optimize mount configurations
✅ Plan for concurrent access patterns
```

---

## Quick Reference

### Common CLI Commands
```bash
# S3
aws s3 ls                           # List buckets
aws s3 cp file.txt s3://bucket/     # Upload file
aws s3 sync ./dir s3://bucket/dir/  # Sync directory

# EBS
aws ec2 describe-volumes            # List volumes
aws ec2 create-snapshot --volume-id vol-xxx  # Create snapshot
aws ec2 attach-volume --volume-id vol-xxx --instance-id i-xxx --device /dev/sdf

# EFS
aws efs describe-file-systems       # List file systems
aws efs create-mount-target --file-system-id fs-xxx --subnet-id subnet-xxx
```

### Key Storage Patterns
- **Backup**: S3 with lifecycle policies
- **Archive**: S3 Glacier/Deep Archive
- **Content delivery**: S3 + CloudFront
- **Database storage**: EBS GP3/IO2
- **Shared storage**: EFS
- **High-performance computing**: FSx

## Topics

- Introduction to AWS Storage
- Amazon S3 basics
- Storage classes
- Basic operations

## Notes

Add your notes here...

# AWS Storage – Part 1 (Comprehensive Overview)

## 1. Introduction
- AWS provides multiple storage options to meet diverse workload needs — from databases to backups to machine learning.
- Categories: Object, Block, File, Archival, and Hybrid storage.
- Evaluation criteria: Durability (S3: 99.999999999%), Availability (multi-AZ, regional options), Performance (IOPS, throughput), Scalability, Security (encryption, IAM policies), Cost models (pay-as-you-go, tiering).

## 2. Object Storage
### Amazon S3 (Simple Storage Service)
- Stores data as objects (file + metadata + unique ID).
- Virtually unlimited scalability with simple REST API access.
- **Features**: Versioning, lifecycle management, replication, encryption, and event-driven workflows.
- **Storage Classes**: 
  - S3 Standard
  - Intelligent-Tiering
  - Standard-IA / One Zone-IA
  - Glacier tiers (Instant, Flexible, Deep Archive)
- **Use cases**: Data lakes, analytics, ML datasets, backup & restore, static website hosting.

## 3. Block Storage
### Amazon EBS (Elastic Block Store)
- Block-level storage that attaches to EC2 instances like a disk.
- Persistent – survives instance stop/start.
- Snapshots integrated with S3 for backups.
- **Volume types**: gp3, io2/io2 Block Express, st1, sc1.
- **Use cases**: Databases, ERP, transactional workloads.

### Instance Store
- Physically attached NVMe/SATA storage with low latency.
- Ephemeral – data lost when instance stops or fails.
- **Use cases**: Caching, temporary scratch data, HPC workloads.

## 4. File Storage
### Amazon EFS (Elastic File System)
- Managed, scalable NFS file system.
- Supports thousands of clients and multiple AZs.
- **Use cases**: CMS, home directories, big data.

### Amazon FSx (Managed File Systems)
- FSx for Windows File Server → SMB protocol, AD integration.
- FSx for Lustre → HPC, big data, ML workloads.
- FSx for NetApp ONTAP → snapshots, deduplication, enterprise features.
- FSx for OpenZFS → Linux workloads.
- **Use cases**: enterprise storage, HPC, ML.

## 5. Archival Storage (Brief Overview)
- **Amazon S3 Glacier & Deep Archive**: ultra-low-cost, retrieval times vary.
- **Use cases**: Compliance, medical records, digital preservation.

## 6. Hybrid & Edge Storage (Brief Overview)
- **AWS Storage Gateway**: Hybrid storage (file, volume, tape).
- **AWS Snow Family**: Migration devices (Snowcone, Snowball, Snowmobile).
- **AWS DataSync**: Online large-scale data transfer.

## 7. Key Takeaways
- **S3 → Object storage** (scalable, durable).
- **EBS/Instance Store → Block storage** (fast, EC2-focused).
- **EFS/FSx → File storage** (shared, enterprise, HPC).
- **Glacier → Archival storage** (long-term, low cost).
- **Gateway/Snow/DataSync → Hybrid and migration**.

