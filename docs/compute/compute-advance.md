# Compute Advanced Topics

## Overview
This document covers advanced AWS compute topics and optimization strategies essential for professional-level AWS certifications and complex production workloads.

---

## High Performance Computing (HPC)

### HPC Instance Types
- **C5n**: Compute optimized with 100 Gbps networking
- **M5n/M5dn**: General purpose with enhanced networking
- **R5n**: Memory optimized with enhanced networking
- **P4**: GPU instances for ML and HPC workloads
- **Inf1**: Machine learning inference optimization

### HPC Networking
```bash
# Enhanced Networking Features
- SR-IOV: Single Root I/O Virtualization
- EFA: Elastic Fabric Adapter for HPC
- Placement Groups: Cluster placement for low latency
- Jumbo Frames: 9000 MTU for high throughput
```

#### Elastic Fabric Adapter (EFA)
```bash
# EFA Benefits
- Bypass kernel for user-space networking
- Support for MPI (Message Passing Interface)
- Low latency: Sub-microsecond latencies
- High bandwidth: Up to 100 Gbps

# Supported Instance Types
- C5n.18xlarge, C5n.metal
- M5dn.24xlarge, M5n.24xlarge
- R5dn.24xlarge, R5n.24xlarge
- P3dn.24xlarge, P4d.24xlarge
```

### HPC Storage Patterns
```bash
# Lustre File System (FSx for Lustre)
- High-performance parallel file system
- Optimized for HPC workloads
- Integration with S3 for data repository
- Scratch and persistent deployment types

# EBS Optimized Instances
- Dedicated bandwidth to EBS
- Up to 80,000 IOPS per instance
- gp3 volumes with baseline performance
- io2 Block Express for highest performance
```

---

## Spot Instances Advanced

### Spot Instance Fundamentals
- **90% cost savings**: Compared to On-Demand pricing
- **2-minute warning**: Before interruption
- **Spot price**: Fluctuates based on supply/demand
- **Interruption handling**: Graceful shutdown required

### Spot Fleet Configuration
```json
{
  "SpotFleetRequestConfig": {
    "IamFleetRole": "arn:aws:iam::123456789012:role/aws-ec2-spot-fleet-role",
    "AllocationStrategy": "diversified",
    "TargetCapacity": 10,
    "SpotPrice": "0.05",
    "LaunchSpecifications": [
      {
        "ImageId": "ami-12345678",
        "InstanceType": "m5.large",
        "KeyName": "my-key",
        "SecurityGroups": [{"GroupId": "sg-12345678"}],
        "SubnetId": "subnet-12345678"
      },
      {
        "ImageId": "ami-12345678", 
        "InstanceType": "m5.xlarge",
        "KeyName": "my-key",
        "SecurityGroups": [{"GroupId": "sg-12345678"}],
        "SubnetId": "subnet-87654321"
      }
    ]
  }
}
```

### Spot Instance Best Practices
```bash
# Application Design
- Stateless applications
- Checkpointing for long-running jobs
- Graceful shutdown handling
- Data persistence to durable storage

# Fleet Management
- Diversify across instance types and AZs
- Use multiple small instances vs few large ones
- Set maximum price to avoid unexpected costs
- Monitor spot price history
```

### Spot Instance Interruption Handling
```python
import boto3
import requests

def check_spot_interruption():
    """Check if spot instance is marked for termination"""
    try:
        response = requests.get(
            'http://169.254.169.254/latest/meta-data/spot/instance-action',
            timeout=2
        )
        if response.status_code == 200:
            return True  # Instance will be terminated
    except:
        pass
    return False  # Instance is safe

def graceful_shutdown():
    """Handle graceful shutdown of application"""
    if check_spot_interruption():
        # Save state, cleanup resources
        print("Spot instance interruption detected. Shutting down gracefully...")
        # Your shutdown logic here
```

---

## Container Optimization

### ECS Performance Optimization

#### Task Definition Optimization
```json
{
  "family": "optimized-web-app",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "app",
      "image": "my-app:latest",
      "cpu": 512,
      "memory": 1024,
      "memoryReservation": 512,
      "essential": true,
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/optimized-app",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### ECS Service Auto Scaling
```bash
# Target Tracking Scaling
Target: CPU Utilization 70%
Scale-out cooldown: 300 seconds
Scale-in cooldown: 300 seconds

# Step Scaling Policy
Metric: Memory Utilization
Thresholds:
- >80%: Add 2 tasks
- >90%: Add 4 tasks
- <40%: Remove 1 task
```

### Kubernetes (EKS) Optimization

#### Horizontal Pod Autoscaler (HPA)
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Vertical Pod Autoscaler (VPA)
```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: web-app-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: app
      maxAllowed:
        cpu: 1
        memory: 2Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

#### Cluster Autoscaler
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-autoscaler-status
  namespace: kube-system
data:
  nodes.max: "50"
  scale-down-delay-after-add: "10m"
  scale-down-unneeded-time: "10m"
  skip-nodes-with-local-storage: "false"
  skip-nodes-with-system-pods: "false"
```

---

## Serverless Computing Advanced

### Lambda Performance Optimization

#### Memory and CPU Allocation
```python
import time
import boto3

def lambda_handler(event, context):
    # Monitor execution metrics
    start_time = time.time()
    
    # Your application logic here
    result = process_data(event['data'])
    
    # Calculate and log performance metrics
    execution_time = time.time() - start_time
    memory_used = context.memory_limit_in_mb
    
    print(f"Execution time: {execution_time:.2f}s")
    print(f"Memory allocated: {memory_used}MB")
    
    return result
```

#### Provisioned Concurrency
```bash
# Configure provisioned concurrency
aws lambda put-provisioned-concurrency-config \
  --function-name my-function \
  --qualifier $LATEST \
  --provisioned-concurrency-target 100

# Benefits:
- Eliminates cold starts
- Consistent low latency
- Predictable performance
- Additional cost for provisioned capacity
```

#### Lambda Layers Optimization
```python
# Layer structure for reusable components
/opt/
├── python/
│   └── lib/
│       └── python3.9/
│           └── site-packages/
│               ├── requests/
│               ├── boto3/
│               └── custom_utils/
└── bin/
    └── custom_binary

# Layer usage in function
import sys
sys.path.append('/opt/python/lib/python3.9/site-packages')
import custom_utils
```

### Step Functions for Orchestration
```json
{
  "Comment": "A distributed data processing workflow",
  "StartAt": "ProcessData",
  "States": {
    "ProcessData": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "ProcessBatch1",
          "States": {
            "ProcessBatch1": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:us-east-1:123456789012:function:ProcessBatch",
              "Parameters": {
                "batch": "1"
              },
              "End": true
            }
          }
        },
        {
          "StartAt": "ProcessBatch2", 
          "States": {
            "ProcessBatch2": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:us-east-1:123456789012:function:ProcessBatch",
              "Parameters": {
                "batch": "2"
              },
              "End": true
            }
          }
        }
      ],
      "Next": "AggregateResults"
    },
    "AggregateResults": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:AggregateResults",
      "End": true
    }
  }
}
```

---

## Performance Monitoring and Optimization

### CloudWatch Enhanced Monitoring
```bash
# Custom Metrics for Applications
aws cloudwatch put-metric-data \
  --namespace "MyApp/Performance" \
  --metric-data MetricName=ResponseTime,Value=150,Unit=Milliseconds,Dimensions=[{Name=Environment,Value=Production}]

# X-Ray Tracing for Distributed Applications
- Trace requests across services
- Identify performance bottlenecks
- Analyze service dependencies
- Debug and optimize applications
```

### Application Performance Patterns
```python
# Circuit Breaker Pattern for Resilience
import time
from enum import Enum

class CircuitState(Enum):
    CLOSED = 1
    OPEN = 2
    HALF_OPEN = 3

class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    def call(self, func, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.timeout:
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise e
    
    def on_success(self):
        self.failure_count = 0
        self.state = CircuitState.CLOSED
    
    def on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
```

---

## Cost Optimization Advanced

### Reserved Instance Strategy
```bash
# RI Portfolio Optimization
Standard RIs:
- 1-year term: ~40% savings
- 3-year term: ~60% savings
- No flexibility in instance attributes

Convertible RIs:
- 1-year term: ~30% savings  
- 3-year term: ~54% savings
- Can change instance family, OS, tenancy

Scheduled RIs:
- For predictable recurring workloads
- Specific time windows (daily, weekly, monthly)
- Lower commitment, moderate savings
```

### Savings Plans Strategy
```bash
# Compute Savings Plans
- Flexible across instance families and regions
- Apply to EC2, Lambda, Fargate
- 1-year: ~50% savings
- 3-year: ~66% savings

# EC2 Instance Savings Plans
- Specific to instance family in region
- Higher discount rates
- Less flexibility than Compute Savings Plans
```

### Right-Sizing Recommendations
```python
# Automated right-sizing analysis
import boto3

def analyze_instance_utilization():
    cloudwatch = boto3.client('cloudwatch')
    ec2 = boto3.client('ec2')
    
    instances = ec2.describe_instances()
    recommendations = []
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            
            # Get CPU utilization metrics
            cpu_metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=datetime.utcnow() - timedelta(days=14),
                EndTime=datetime.utcnow(),
                Period=3600,
                Statistics=['Average']
            )
            
            avg_cpu = sum([m['Average'] for m in cpu_metrics['Datapoints']]) / len(cpu_metrics['Datapoints'])
            
            if avg_cpu < 10:
                recommendations.append({
                    'instance_id': instance_id,
                    'current_type': instance_type,
                    'recommendation': 'Downsize or use Spot instances',
                    'avg_cpu': avg_cpu
                })
    
    return recommendations
```

---

## Disaster Recovery and High Availability

### Multi-Region Compute Architecture
```bash
# Active-Active Setup
Region 1 (Primary):
- Auto Scaling Group: min=2, desired=4, max=10
- Application Load Balancer
- RDS Multi-AZ primary

Region 2 (Secondary):
- Auto Scaling Group: min=1, desired=2, max=10
- Application Load Balancer  
- RDS read replica (can be promoted)

# Route 53 Health Checks
- Monitor primary region endpoint
- Automatic failover to secondary region
- Latency-based or weighted routing
```

### Container Disaster Recovery
```yaml
# EKS Multi-Region Setup
apiVersion: v1
kind: Service
metadata:
  name: app-service
  annotations:
    external-dns.alpha.kubernetes.io/hostname: app.example.com
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"
spec:
  type: LoadBalancer
  selector:
    app: web-app
  ports:
  - port: 80
    targetPort: 8080

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
      - name: app
        image: my-app:v1.2.3
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

## Automation and Infrastructure as Code

### Advanced CloudFormation Templates
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Auto Scaling Web Application with ALB'

Parameters:
  InstanceType:
    Type: String
    Default: t3.micro
    AllowedValues: [t3.micro, t3.small, t3.medium]
    Description: EC2 instance type

  MinSize:
    Type: Number
    Default: 1
    MinValue: 1
    MaxValue: 10

  MaxSize:
    Type: Number
    Default: 5
    MinValue: 1
    MaxValue: 20

Resources:
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub '${AWS::StackName}-launch-template'
      LaunchTemplateData:
        ImageId: !Ref LatestAmiId
        InstanceType: !Ref InstanceType
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
        IamInstanceProfile:
          Arn: !GetAtt InstanceProfile.Arn
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash
            yum update -y
            yum install -y httpd
            systemctl start httpd
            systemctl enable httpd

  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: !Sub '${AWS::StackName}-asg'
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      MinSize: !Ref MinSize
      MaxSize: !Ref MaxSize
      DesiredCapacity: !Ref MinSize
      VPCZoneIdentifier:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2
      TargetGroupARNs:
        - !Ref TargetGroup
      HealthCheckType: ELB
      HealthCheckGracePeriod: 300

  ScaleUpPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      AdjustmentType: ChangeInCapacity
      AutoScalingGroupName: !Ref AutoScalingGroup
      Cooldown: 300
      ScalingAdjustment: 1

  ScaleDownPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      AdjustmentType: ChangeInCapacity
      AutoScalingGroupName: !Ref AutoScalingGroup
      Cooldown: 300
      ScalingAdjustment: -1

Outputs:
  LoadBalancerURL:
    Description: URL of the load balancer
    Value: !Sub 'http://${ApplicationLoadBalancer.DNSName}'
    Export:
      Name: !Sub '${AWS::StackName}-ALB-URL'
```

---

## Exam Tips

### Professional Certification Topics
- **AWS Certified Solutions Architect Professional**: Multi-region architectures, cost optimization
- **AWS Certified DevOps Engineer Professional**: CI/CD, infrastructure automation
- **AWS Certified Advanced Networking**: EFA, placement groups, performance optimization

### Performance Optimization Checklist
- ✅ **Right-size instances**: Monitor and adjust based on utilization
- ✅ **Use appropriate storage**: Match storage type to workload requirements
- ✅ **Enable enhanced networking**: For high-performance workloads
- ✅ **Implement caching**: ElastiCache, CloudFront, application-level caching
- ✅ **Optimize container images**: Minimal base images, multi-stage builds
- ✅ **Monitor and alert**: CloudWatch, X-Ray, custom metrics

### Cost Optimization Strategies
- **Compute**: Reserved Instances, Savings Plans, Spot Instances
- **Containers**: Fargate Spot, right-sized tasks, efficient images
- **Serverless**: Right-sized memory, provisioned concurrency optimization
- **Storage**: Lifecycle policies, appropriate storage classes
- **Network**: Data transfer optimization, CloudFront usage

---

## Quick Reference

### Instance Performance Comparison
| Workload Type | Recommended Instance | Key Features |
|---------------|---------------------|--------------|
| **Web servers** | t3, t4g | Burstable performance |
| **Databases** | r5, r6i | Memory optimized |
| **Analytics** | c5, c6i | Compute optimized |
| **HPC** | c5n, m5n | Enhanced networking |
| **ML training** | p3, p4 | GPU accelerated |
| **ML inference** | inf1, g4 | Inference optimized |

### Container Service Selection
- **ECS Fargate**: Serverless containers, minimal management
- **ECS EC2**: More control, potentially lower cost
- **EKS**: Kubernetes native, portable workloads
- **Lambda**: Event-driven, sub-second billing
- **Batch**: Large-scale batch processing