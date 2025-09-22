# Network Part 1 - VPC Fundamentals

## Overview
This document covers AWS networking fundamentals essential for AWS certification exams. Focus on VPC core concepts, subnets, routing, and security components.

---

## Amazon VPC (Virtual Private Cloud)

### Core Concepts
- **VPC**: Isolated virtual network in AWS cloud
- **CIDR Block**: IP address range for VPC (e.g., 10.0.0.0/16)
- **Subnets**: Subdivisions of VPC in specific Availability Zones
- **Route Tables**: Control traffic routing within VPC
- **Internet Gateway**: Connects VPC to internet
- **NAT Gateway/Instance**: Outbound internet access for private subnets

### VPC Components

| Component | Purpose | Key Facts |
|-----------|---------|-----------|
| **Internet Gateway (IGW)** | Internet access for public subnets | One per VPC, horizontally scaled |
| **NAT Gateway** | Outbound internet for private subnets | AZ-specific, managed service |
| **NAT Instance** | Manual NAT solution | EC2-based, requires management |
| **VPC Peering** | Connect VPCs privately | Non-transitive, same/cross region |
| **Transit Gateway** | Hub for multiple VPC connections | Simplifies complex topologies |
| **VPN Gateway** | On-premises VPN connectivity | IPSec VPN tunnels |

### Subnets

#### Public vs Private Subnets
```
Public Subnet:
- Has route to Internet Gateway (0.0.0.0/0 → IGW)
- Resources get public IP addresses
- Used for: Web servers, load balancers, bastion hosts

Private Subnet:
- No direct route to Internet Gateway
- Outbound internet via NAT Gateway/Instance
- Used for: Databases, application servers, backend services
```

#### Subnet Sizing
```bash
# Example VPC: 10.0.0.0/16 (65,536 IPs)
VPC CIDR: 10.0.0.0/16

# Subnet examples:
Public Subnet A:  10.0.1.0/24  (256 IPs - 5 reserved = 251 usable)
Private Subnet A: 10.0.2.0/24  (256 IPs - 5 reserved = 251 usable)
Public Subnet B:  10.0.3.0/24  (256 IPs - 5 reserved = 251 usable)
Private Subnet B: 10.0.4.0/24  (256 IPs - 5 reserved = 251 usable)
```

#### Reserved IP Addresses (per subnet)
- **Network address**: 10.0.1.0
- **VPC router**: 10.0.1.1
- **DNS server**: 10.0.1.2
- **Future use**: 10.0.1.3
- **Broadcast**: 10.0.1.255

---

## Security Groups vs NACLs

### Security Groups (Instance Level)
- **Stateful**: Return traffic automatically allowed
- **Allow rules only**: Cannot explicitly deny
- **All rules evaluated**: Permissive approach
- **Default**: Deny all inbound, allow all outbound

```bash
# Example Security Group rules
Inbound:
- HTTP (80) from 0.0.0.0/0
- HTTPS (443) from 0.0.0.0/0  
- SSH (22) from 10.0.0.0/16

Outbound:
- All traffic (0-65535) to 0.0.0.0/0
```

### Network ACLs (Subnet Level)
- **Stateless**: Must allow both inbound and outbound
- **Allow and deny rules**: Explicit deny possible
- **Rules processed in order**: Lower number = higher priority
- **Default**: Allow all inbound and outbound

```bash
# Example NACL rules
Rule # | Type | Protocol | Port Range | Source | Allow/Deny
100    | HTTP | TCP      | 80         | 0.0.0.0/0 | ALLOW
200    | HTTPS| TCP      | 443        | 0.0.0.0/0 | ALLOW
300    | SSH  | TCP      | 22         | 10.0.0.0/16 | ALLOW
*      | ALL  | ALL      | ALL        | 0.0.0.0/0 | DENY
```

---

## Routing

### Route Tables
- **Main Route Table**: Default for all subnets
- **Custom Route Tables**: Associate with specific subnets
- **Local Route**: Automatic within VPC CIDR
- **Priority**: Most specific route wins

#### Example Route Table (Public Subnet)
```
Destination    Target
10.0.0.0/16   Local
0.0.0.0/0     igw-xxxxxxxx
```

#### Example Route Table (Private Subnet)
```
Destination    Target
10.0.0.0/16   Local  
0.0.0.0/0     nat-xxxxxxxx
```

---

## DNS and DHCP

### DNS Resolution
- **enableDnsHostnames**: Assign public DNS hostnames
- **enableDnsSupport**: Enable DNS resolution
- **Amazon-provided DNS**: Located at VPC CIDR + 2

### DHCP Options Sets
```bash
# Default DHCP options
domain-name = region.compute.internal (us-east-1: ec2.internal)
domain-name-servers = AmazonProvidedDNS
```

---

## Common Architecture Patterns

### Multi-AZ Web Application
```
VPC: 10.0.0.0/16
├── Public Subnet A (10.0.1.0/24) - AZ-1a
│   ├── Application Load Balancer
│   └── NAT Gateway A
├── Private Subnet A (10.0.2.0/24) - AZ-1a  
│   ├── Web Server A
│   └── App Server A
├── Public Subnet B (10.0.3.0/24) - AZ-1b
│   └── NAT Gateway B  
├── Private Subnet B (10.0.4.0/24) - AZ-1b
│   ├── Web Server B
│   └── App Server B
└── Database Subnet Group
    ├── DB Subnet A (10.0.5.0/24) - AZ-1a
    └── DB Subnet B (10.0.6.0/24) - AZ-1b
```

---

## Exam Tips

### VPC Limits (per region)
- **VPCs**: 5 (default), can request increase
- **Subnets**: 200 per VPC
- **Route Tables**: 200 per VPC
- **Security Groups**: 2,500 per VPC
- **Rules per Security Group**: 60 inbound, 60 outbound

### Best Practices
1. **Plan CIDR carefully**: Avoid overlapping with on-premises
2. **Use multiple AZs**: For high availability
3. **Separate tiers**: Public, private, database subnets
4. **Least privilege**: Restrictive security groups
5. **Monitor**: VPC Flow Logs for traffic analysis

### Common Scenarios
- **Public web app**: ALB in public, instances in private
- **Database access**: Private subnets, database security groups
- **Hybrid connectivity**: VPN Gateway or Direct Connect
- **Multi-region**: VPC Peering or Transit Gateway

### Troubleshooting Checklist
- ✅ **Route tables**: Correct routes to IGW/NAT
- ✅ **Security groups**: Allow required ports
- ✅ **NACLs**: Allow both inbound and outbound
- ✅ **Public IPs**: Assigned to public subnet instances
- ✅ **DNS settings**: Enabled for hostname resolution

---

## Quick Commands

### AWS CLI Examples
```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16

# Create subnet
aws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a

# Create and attach Internet Gateway
aws ec2 create-internet-gateway
aws ec2 attach-internet-gateway --vpc-id vpc-xxx --internet-gateway-id igw-xxx

# Create route table and add route
aws ec2 create-route-table --vpc-id vpc-xxx
aws ec2 create-route --route-table-id rtb-xxx --destination-cidr-block 0.0.0.0/0 --gateway-id igw-xxx
```