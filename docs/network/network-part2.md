# Network Part 2 - Advanced Connectivity

## Overview
This document covers intermediate AWS networking concepts essential for certification exams. Focus on connectivity services, load balancing, and advanced VPC features.

---

## Load Balancing

### Application Load Balancer (ALB)
- **Layer 7**: HTTP/HTTPS traffic
- **Path-based routing**: Route based on URL path
- **Host-based routing**: Route based on hostname
- **Target types**: Instances, IPs, Lambda functions

```bash
# ALB Routing Examples
/api/* → API servers target group
/images/* → Image servers target group
admin.example.com → Admin target group
```

#### ALB Features
- **SSL termination**: Handle SSL/TLS encryption
- **Sticky sessions**: Route user to same target
- **Health checks**: Monitor target health
- **WebSocket support**: Real-time applications

### Network Load Balancer (NLB)
- **Layer 4**: TCP/UDP traffic
- **Ultra-high performance**: Millions of requests/second
- **Static IP**: Elastic IP per AZ
- **Preserve source IP**: Client IP visible to targets

### Gateway Load Balancer (GWLB)
- **Layer 3**: Network layer (IP packets)
- **Third-party appliances**: Firewalls, IDS/IPS
- **Transparent**: Invisible to source/destination

### Classic Load Balancer (CLB)
- **Legacy**: Use ALB/NLB for new deployments
- **Layer 4 & 7**: Basic load balancing
- **Limited features**: Compared to modern LBs

---

## VPC Connectivity

### VPC Peering
- **Private connectivity**: Between VPCs
- **Non-transitive**: No routing through intermediate VPC
- **Same/Cross region**: Regional or global
- **Same/Cross account**: Within or between AWS accounts

```
VPC A (10.0.0.0/16) ←→ VPC B (10.1.0.0/16)
VPC A (10.0.0.0/16) ←→ VPC C (10.2.0.0/16)
VPC B cannot reach VPC C through VPC A
```

#### VPC Peering Limitations
- **No overlapping CIDR**: IP ranges cannot conflict
- **No transitive routing**: Hub-and-spoke requires multiple peerings
- **DNS resolution**: Must enable for cross-VPC DNS

### Transit Gateway
- **Hub-and-spoke**: Central router for multiple VPCs
- **Transitive routing**: VPCs can reach each other through TGW
- **Cross-region**: Connect TGWs in different regions
- **Route tables**: Control connectivity between attachments

```
        Transit Gateway
             |
    ┌────────┼────────┐
    │        │        │
  VPC A    VPC B    VPC C
    │        │        │
 On-Prem   VPN    Direct Connect
```

#### Transit Gateway Benefits
- **Scalability**: Support thousands of VPCs
- **Centralized management**: Single point of control
- **Monitoring**: CloudWatch metrics and VPC Flow Logs
- **Bandwidth**: Up to 50 Gbps per attachment

---

## Internet Connectivity

### Internet Gateway (IGW)
- **VPC component**: One per VPC
- **Horizontally scaled**: Redundant and highly available
- **No bandwidth constraints**: Scales automatically
- **Public subnet requirement**: For direct internet access

### NAT Gateway
- **Managed service**: AWS-operated NAT
- **AZ-specific**: Deploy in each AZ for HA
- **Bandwidth**: Up to 45 Gbps
- **No security groups**: Use NACLs for traffic control

```bash
# High Availability NAT Setup
Public Subnet A (AZ-1a) → NAT Gateway A
Public Subnet B (AZ-1b) → NAT Gateway B

Private Subnet A → Route to NAT Gateway A
Private Subnet B → Route to NAT Gateway B
```

### NAT Instance
- **EC2-based**: Customer-managed
- **Security groups**: Can apply SG rules
- **Source/destination check**: Must disable
- **Cost**: Potentially lower for small workloads

---

## Hybrid Connectivity

### AWS Site-to-Site VPN
- **IPSec tunnels**: Encrypted connection to on-premises
- **Virtual Private Gateway**: VPC-side VPN endpoint
- **Customer Gateway**: On-premises VPN device
- **BGP support**: Dynamic routing protocol

```
On-Premises ←→ Customer Gateway ←→ VPN Tunnel ←→ Virtual Private Gateway ←→ VPC
```

#### VPN Components
- **Virtual Private Gateway (VGW)**: Attach to VPC
- **Customer Gateway (CGW)**: Logical representation of on-prem device
- **VPN Connection**: Two IPSec tunnels for redundancy

### AWS Direct Connect
- **Dedicated connection**: Physical link to AWS
- **Consistent performance**: Predictable bandwidth
- **Lower costs**: For high data transfer volumes
- **Private connectivity**: Bypass internet

#### Direct Connect Features
- **Virtual Interfaces (VIFs)**:
  - Private VIF: Access VPC resources
  - Public VIF: Access AWS public services
  - Transit VIF: Connect to Transit Gateway
- **LAG (Link Aggregation)**: Combine multiple connections
- **BGP routing**: Dynamic route advertisement

---

## DNS and Route 53

### Route 53 Resolver
- **Hybrid DNS**: Connect on-premises and AWS DNS
- **Conditional forwarding**: Route queries based on domain
- **Inbound endpoint**: On-premises queries AWS resources
- **Outbound endpoint**: AWS queries on-premises resources

### Private Hosted Zones
- **Internal DNS**: Resolve private domain names
- **VPC association**: Specify which VPCs can resolve
- **Split-horizon DNS**: Different answers for internal/external

---

## Security Services

### AWS WAF (Web Application Firewall)
- **Layer 7 protection**: HTTP/HTTPS traffic filtering
- **Integration**: ALB, CloudFront, API Gateway
- **Rules**: Block/allow based on conditions
- **Rate limiting**: Prevent DDoS attacks

### AWS Shield
- **DDoS protection**: Standard (free) and Advanced (paid)
- **Always-on**: Automatic protection for all AWS resources
- **Advanced features**: 24/7 DRT support, cost protection

### Network Firewall
- **Stateful inspection**: Deep packet inspection
- **IDS/IPS capabilities**: Intrusion detection/prevention
- **Domain filtering**: Block malicious domains
- **Suricata rules**: Open-source rule format

---

## Monitoring and Troubleshooting

### VPC Flow Logs
- **Traffic capture**: Source, destination, ports, protocol
- **Levels**: VPC, subnet, or ENI level
- **Destinations**: CloudWatch Logs, S3, Kinesis
- **Analysis**: Identify traffic patterns and security issues

```bash
# Flow Log Fields
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
```

### CloudWatch Metrics
- **Load Balancer**: Request count, latency, error rates
- **NAT Gateway**: Bytes processed, active connections
- **VPN**: Tunnel state, packet count

---

## Exam Tips

### Common Connectivity Patterns
- **Multi-VPC**: Use Transit Gateway for hub-and-spoke
- **Hybrid cloud**: Direct Connect for consistent performance
- **High availability**: Multiple AZs, multiple connections
- **Cost optimization**: NAT Gateway vs NAT Instance

### Troubleshooting Steps
1. **Check route tables**: Verify correct routes exist
2. **Security groups**: Ensure required ports are open
3. **NACLs**: Verify subnet-level rules
4. **DNS resolution**: Check enableDnsHostnames/Support
5. **Flow logs**: Analyze traffic patterns

### Performance Considerations
- **Placement groups**: Cluster for low latency
- **Enhanced networking**: SR-IOV for high performance
- **Bandwidth**: Consider instance type network performance
- **Multi-path**: Use multiple connections for bandwidth

---

## Quick Reference

### Load Balancer Comparison
| Feature | ALB | NLB | GWLB |
|---------|-----|-----|------|
| Layer | 7 (HTTP/HTTPS) | 4 (TCP/UDP) | 3 (IP) |
| Static IP | No | Yes | Yes |
| SSL Termination | Yes | Yes | No |
| WebSocket | Yes | Yes | No |
| Path Routing | Yes | No | No |

### Connectivity Options
- **Same region VPCs**: VPC Peering or Transit Gateway
- **Cross-region VPCs**: VPC Peering or Transit Gateway
- **On-premises**: VPN or Direct Connect
- **Internet access**: Internet Gateway (public) or NAT (private)