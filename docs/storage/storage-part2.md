# Storage Part 2

## Overview

This document covers intermediate AWS storage concepts.

## Topics

- Advanced S3 features
- EBS (Elastic Block Store)
- EFS (Elastic File System)
- Storage optimization

## Notes

# Storage Part 2

## Overview

This document covers intermediate AWS storage concepts.

## Topics

- Advanced S3 features
- EBS (Elastic Block Store)
- EFS (Elastic File System)
- Storage optimization

## Notes


# AWS Storage – Part 2 (Deep Specialization)

## 1. Advanced Object Storage (S3 Deep Dive)
- **Durability vs Availability**: durability 11 nines, availability depends on storage class.
- **Security**: SSE-S3, SSE-KMS, SSE-C, client-side encryption. IAM, bucket policies, ACLs.
- **Performance**: Multipart upload, Transfer Acceleration.
- **Cost**: Lifecycle rules, Intelligent-Tiering, Glacier transitions.
- **Use Cases**: Data lakes, event pipelines, ML datasets.

## 2. S3 Security – Bucket Policy vs IAM Policy
### IAM Policy
- Attached to IAM users, groups, or roles.
- Defines what a principal (who) can do in AWS.
- Example: "User Alice can s3:GetObject in bucket X."
- Best for internal access control.

### Bucket Policy
- Attached directly to a bucket.
- Defines what actions are allowed on the bucket and by whom.
- Example: "Account B can s3:PutObject in bucket Y."
- Best for cross-account/public access.

### Key Differences
| Feature | IAM Policy | Bucket Policy |
|---------|------------|---------------|
| Scope | Attached to users/roles | Attached to S3 buckets |
| Control | Defines what the user can do | Defines what the bucket allows |
| Typical Use | Internal access control | Cross-account or public access |
| Evaluation | Combined with bucket policy | Combined with IAM policy |

👉 **Best practice**: Use IAM policies for internal access, and bucket policies for cross-account/public access.

## 3. Advanced Block Storage (EBS Deep Dive)
- gp3 baseline 3,000 IOPS, io2 Block Express up to 256K IOPS.
- Snapshots: incremental, shareable across accounts/regions.
- Best Practices: encryption, RAID, CloudWatch monitoring.

## 4. Advanced File Storage (EFS & FSx Deep Dive)
- **EFS**: General Purpose vs Max I/O, Bursting vs Provisioned throughput, Standard vs EFS-IA.
- **FSx for Windows File Server**: SMB, AD.
- **FSx for Lustre**: HPC workloads.
- **FSx for NetApp ONTAP**: enterprise features.
- **FSx for OpenZFS**: Linux workloads.

## 5. Archival & Backup
- **Glacier tiers**: instant, expedited, standard, bulk retrievals.
- **AWS Backup**: centralized backup management for multiple services.

## 6. Hybrid & Migration
- **Storage Gateway** (File, Volume, Tape).
- **Snow Family** (Snowcone, Snowball, Snowmobile).
- **DataSync**: high-speed online sync.
- **Transfer Family**: managed FTP/SFTP to S3/EFS.

## 7. Specialized Workloads
- **HPC** → FSx Lustre, Instance Store.
- **AI/ML** → S3 + FSx Lustre.
- **Analytics** → S3 + Athena + Redshift Spectrum.
- **Compliance** → Glacier Vault Lock, encryption, WORM.

## 8. Cost Optimization
- Match storage class to pattern (S3 IA, Glacier).
- Intelligent-Tiering for unpredictable workloads.
- EBS snapshots → Glacier.
- Lifecycle policies for S3/EFS.
- Monitor with Cost Explorer/CloudWatch.

## 9. Exam & Interview Quick Wins
- **S3 vs EBS vs EFS**: object vs block vs file.
- **FSx**: pick service by protocol/workload.
- **Glacier**: archival only.
- **Gateway vs DataSync**: hybrid vs migration.
- **Bucket Policy vs IAM Policy**: bucket defines allowed actions, IAM defines user permissions.

## Key Takeaways
- **Part 1**: What to use.
- **Part 2**: How to use it best (secure, optimize, specialize).
