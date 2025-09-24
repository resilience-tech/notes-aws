# Compute Part 1 - EC2 Fundamentals

## Overview
This document covers AWS compute fundamentals essential for AWS certification exams. Focus on EC2 core concepts, instance types, storage, and basic operations.

---

## Amazon EC2 (Elastic Compute Cloud)

### Core Concepts
- **Instance**: Virtual server in the cloud
- **AMI**: Amazon Machine Image (template for instances)
- **Instance Type**: Hardware configuration (CPU, memory, network)
- **Key Pair**: SSH keys for secure instance access
- **Security Groups**: Virtual firewall for instances
- **User Data**: Bootstrap scripts for instance initialization

### Instance Types

| Family | Purpose | Examples | Use Cases |
|--------|---------|----------|-----------|
| **General Purpose** | Balanced CPU, memory, networking | t3, t4g, m5, m6i | Web servers, small DBs, development |
| **Compute Optimized** | High-performance processors | c5, c6i, c7g | CPU-intensive apps, gaming, HPC |
| **Memory Optimized** | Fast performance for memory workloads | r5, r6i, x1e, z1d | In-memory DBs, real-time analytics |
| **Storage Optimized** | High sequential read/write | i3, i4i, d2, h1 | Distributed file systems, data warehouses |
| **Accelerated Computing** | Hardware accelerators (GPU, FPGA) | p3, p4, g4, f1 | Machine learning, video processing |

### Instance Naming Convention
```
c5n.xlarge
│ │  └── Size (nano, micro, small, medium, large, xlarge, 2xlarge, etc.)
│ └── Generation (newer = better performance/price)
└── Family (c = compute optimized)

Additional suffixes:
- n = Enhanced networking
- d = NVMe SSD storage
- a = AMD processors
- g = Graviton (ARM) processors
```

### Instance Sizes and vCPUs
| Size | vCPUs | Memory | Network Performance |
|------|-------|--------|-------------------|
| nano | 1 | 0.5 GiB | Up to 25 Gbps |
| micro | 1 | 1 GiB | Up to 25 Gbps |
| small | 1 | 2 GiB | Up to 25 Gbps |
| medium | 1 | 4 GiB | Up to 25 Gbps |
| large | 2 | 8 GiB | Up to 25 Gbps |
| xlarge | 4 | 16 GiB | Up to 25 Gbps |
| 2xlarge | 8 | 32 GiB | Up to 25 Gbps |

---

## Instance Storage

### EBS (Elastic Block Store)
- **Persistent storage**: Data survives instance termination
- **Network attached**: Separate from instance hardware
- **Snapshots**: Point-in-time backups to S3
- **Encryption**: At-rest and in-transit encryption available

#### EBS Volume Types

| Volume Type | Performance | Use Case | Max IOPS | Max Throughput |
|-------------|-------------|----------|----------|----------------|
| **gp3** | General purpose SSD | Balanced price/performance | 16,000 | 1,000 MiB/s |
| **gp2** | General purpose SSD | Legacy, burstable | 16,000 | 250 MiB/s |
| **io2** | Provisioned IOPS SSD | High IOPS, low latency | 64,000 | 1,000 MiB/s |
| **io1** | Provisioned IOPS SSD | Legacy IOPS | 64,000 | 1,000 MiB/s |
| **st1** | Throughput optimized HDD | Big data, data warehouses | 500 | 500 MiB/s |
| **sc1** | Cold HDD | Infrequent access | 250 | 250 MiB/s |

### Instance Store
- **Ephemeral storage**: Data lost on instance stop/termination
- **Physical storage**: Directly attached to instance host
- **High performance**: Very low latency, high IOPS
- **No snapshots**: Cannot create backups

```bash
# Instance store characteristics
- Free with instance
- Cannot be detached/reattached
- Data persists through reboot only
- Ideal for: temporary files, cache, buffers
```

---

## Amazon Machine Images (AMIs)

### AMI Types
- **AWS provided**: Amazon Linux, Ubuntu, Windows
- **Marketplace**: Third-party commercial AMIs
- **Community**: Public AMIs from other users
- **Custom**: Your own created AMIs

### AMI Components
```bash
# AMI includes:
- Root volume template (EBS snapshot or instance store)
- Launch permissions (public, specific accounts)
- Block device mapping (additional volumes)
- Instance metadata
```

### Creating Custom AMIs
```bash
# Create AMI from running instance
aws ec2 create-image --instance-id i-1234567890abcdef0 --name "My Custom AMI" --description "Web server with app installed"

# Copy AMI to another region
aws ec2 copy-image --source-region us-east-1 --source-image-id ami-12345678 --name "Copied AMI"
```

---

## Instance Lifecycle

### Instance States
```
pending → running → stopping → stopped → terminating → terminated
          ↓
        rebooting → running
```

### Launch Process
1. **Choose AMI**: Select operating system and software
2. **Choose instance type**: Select hardware configuration
3. **Configure instance**: Network, IAM role, user data
4. **Add storage**: EBS volumes and instance store
5. **Add tags**: Metadata for organization
6. **Configure security group**: Firewall rules
7. **Review and launch**: Select key pair

### User Data Script Example
```bash
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo "<h1>Hello from EC2!</h1>" > /var/www/html/index.html
```

---

## Security

### Key Pairs
- **Public key**: Stored on instance in ~/.ssh/authorized_keys
- **Private key**: Downloaded once, used for SSH access
- **Region specific**: Must import or create in each region

```bash
# Connect to instance
ssh -i my-key.pem ec2-user@public-ip-address

# For Ubuntu instances
ssh -i my-key.pem ubuntu@public-ip-address
```

### Security Groups
```bash
# Example security group rules
Type        Protocol  Port Range  Source
SSH         TCP       22         My IP (203.0.113.25/32)
HTTP        TCP       80         Anywhere (0.0.0.0/0)
HTTPS       TCP       443        Anywhere (0.0.0.0/0)
Custom TCP  TCP       8080       sg-12345678 (another security group)
```

### IAM Roles for EC2
```bash
# Attach IAM role to instance
aws ec2 associate-iam-instance-profile --instance-id i-1234567890abcdef0 --iam-instance-profile Name=MyRole

# Instance can then access AWS services without storing credentials
aws s3 ls s3://my-bucket/  # No need for access keys
```

---

## Networking

### IP Addresses
- **Private IP**: Always assigned, used within VPC
- **Public IP**: Dynamic, changes on stop/start
- **Elastic IP**: Static public IP, persists until released

### Placement Groups
- **Cluster**: Low latency within single AZ
- **Partition**: Large distributed workloads across multiple AZs
- **Spread**: Small number of critical instances on distinct hardware

### Enhanced Networking
- **SR-IOV**: Single Root I/O Virtualization
- **Higher bandwidth**: Up to 100 Gbps
- **Lower latency**: Reduced CPU utilization
- **No additional charge**: Available on supported instances

---

## Monitoring and Management

### CloudWatch Metrics
```bash
# Basic monitoring (5-minute intervals) - Free
- CPU Utilization
- Network In/Out
- Disk Read/Write Operations
- Status Check Failed

# Detailed monitoring (1-minute intervals) - Additional cost
- Same metrics with higher frequency
```

### Status Checks
- **System status check**: AWS infrastructure
- **Instance status check**: Instance software/network
- **Actions**: Reboot or terminate on failure

### Instance Metadata
```bash
# Access from within instance
curl http://169.254.169.254/latest/meta-data/

# Common metadata endpoints
/instance-id
/instance-type  
/local-ipv4
/public-ipv4
/security-groups
/iam/security-credentials/role-name
```

---

## Cost Optimization

### Purchasing Options

| Option | Commitment | Savings | Use Case |
|--------|------------|---------|----------|
| **On-Demand** | None | 0% | Unpredictable workloads |
| **Reserved** | 1-3 years | Up to 75% | Steady state workloads |
| **Spot** | None | Up to 90% | Fault-tolerant workloads |
| **Dedicated Host** | 1-3 years | Varies | Licensing requirements |

### Reserved Instance Types
```bash
# Standard RI
- No flexibility in instance attributes
- Highest discount (up to 75%)

# Convertible RI  
- Change instance family, OS, tenancy
- Lower discount (up to 54%)

# Scheduled RI
- Recurring schedule (daily, weekly, monthly)
- Specific time windows
```

### Spot Instances
```bash
# Spot instance characteristics
- Up to 90% discount vs On-Demand
- Can be interrupted with 2-minute notice
- Good for: batch jobs, data analysis, CI/CD
- Spot Fleet: Manage multiple spot instances
```

---

## Exam Tips

### Instance Limits
- **Running instances**: 20 per region (soft limit)
- **EBS volumes**: 5,000 per region
- **Snapshots**: 10,000 per region
- **Elastic IPs**: 5 per region

### Best Practices
1. **Right-size instances**: Start small, monitor, adjust
2. **Use appropriate storage**: gp3 for most workloads
3. **Implement monitoring**: CloudWatch alarms
4. **Security groups**: Least privilege principle
5. **Regular snapshots**: Backup critical data
6. **Use IAM roles**: Avoid hardcoded credentials

### Common Scenarios
- **Web servers**: t3.medium with gp3 storage and ALB
- **Databases**: r5 instances with io2 volumes
- **Batch processing**: Spot instances with auto scaling
- **Development**: t3.micro with burstable performance

### Troubleshooting Checklist
- ✅ **Instance state**: Check if running
- ✅ **Status checks**: System and instance status
- ✅ **Security groups**: Verify port access
- ✅ **Key pairs**: Correct private key for SSH
- ✅ **Network**: VPC, subnet, route table configuration
- ✅ **User data**: Check cloud-init logs

---

## Quick Commands

### AWS CLI Examples
```bash
# Launch instance
aws ec2 run-instances --image-id ami-12345678 --count 1 --instance-type t3.micro --key-name my-key --security-group-ids sg-12345678

# Describe instances
aws ec2 describe-instances --instance-ids i-1234567890abcdef0

# Start/stop instances
aws ec2 start-instances --instance-ids i-1234567890abcdef0
aws ec2 stop-instances --instance-ids i-1234567890abcdef0

# Create AMI
aws ec2 create-image --instance-id i-1234567890abcdef0 --name "My AMI"

# Create snapshot
aws ec2 create-snapshot --volume-id vol-1234567890abcdef0 --description "My snapshot"
```

### Instance Management
```bash
# Connect via SSH
ssh -i my-key.pem ec2-user@public-ip

# Copy files to instance
scp -i my-key.pem file.txt ec2-user@public-ip:~/

# Check instance metadata
curl http://169.254.169.254/latest/meta-data/instance-id

# View user data script
curl http://169.254.169.254/latest/user-data
```
