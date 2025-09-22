# Compute Part 2 - Serverless & Containers

## Overview
This document covers intermediate AWS compute concepts essential for certification exams. Focus on Lambda, container services, Auto Scaling, and orchestration.

---

## AWS Lambda

### Core Concepts
- **Serverless compute**: Run code without managing servers
- **Event-driven**: Triggered by events from AWS services
- **Pay per request**: Billed for execution time and memory
- **Automatic scaling**: Handles concurrent executions
- **Stateless functions**: Each invocation is independent

### Lambda Runtime Support
```bash
# Supported Runtimes (as of 2025)
- Python 3.8, 3.9, 3.10, 3.11, 3.12
- Node.js 18.x, 20.x
- Java 8, 11, 17, 21
- .NET 6, 8
- Go 1.x
- Ruby 3.2
- Custom Runtime (using Lambda Runtime API)
```

### Lambda Limits

| Resource | Limit | Notes |
|----------|-------|-------|
| **Memory** | 128 MB - 10,240 MB | In 1 MB increments |
| **Timeout** | 15 minutes | Maximum execution time |
| **Temp storage (/tmp)** | 512 MB - 10,240 MB | Ephemeral storage |
| **Environment variables** | 4 KB | Total size limit |
| **Deployment package** | 50 MB (zipped), 250 MB (unzipped) | Function code |
| **Concurrent executions** | 1,000 (default) | Per region, can request increase |

### Lambda Pricing Model
```bash
# Pricing components
Request charges: $0.20 per 1M requests
Duration charges: $0.0000166667 per GB-second

# Example calculation
Function: 512 MB memory, 100ms execution
Monthly executions: 1,000,000
Cost = (1M requests × $0.20/1M) + (1M × 0.5 GB × 0.1s × $0.0000166667/GB-s)
     = $0.20 + $0.83 = $1.03/month
```

### Event Sources
- **Synchronous**: API Gateway, Application Load Balancer, CloudFront
- **Asynchronous**: S3, SNS, CloudWatch Events, SES
- **Stream-based**: Kinesis Data Streams, DynamoDB Streams, SQS

### Lambda Function Example
```python
import json
import boto3

def lambda_handler(event, context):
    # Extract data from event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Process the event
    s3 = boto3.client('s3')
    response = s3.get_object(Bucket=bucket, Key=key)
    
    # Return response
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Processed {key} from {bucket}',
            'size': response['ContentLength']
        })
    }
```

---

## Container Services

### Amazon ECS (Elastic Container Service)

#### Core Concepts
- **Task Definition**: Blueprint for containers
- **Service**: Maintains desired number of tasks
- **Cluster**: Logical grouping of compute resources
- **Task**: Running instance of task definition

#### Launch Types
```bash
# EC2 Launch Type
- You manage EC2 instances
- More control over infrastructure
- Lower cost for predictable workloads

# Fargate Launch Type  
- AWS manages infrastructure
- Serverless containers
- Pay for vCPU and memory resources
```

#### Task Definition Example
```json
{
  "family": "web-app",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "web-container",
      "image": "nginx:latest",
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "essential": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/web-app",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Amazon EKS (Elastic Kubernetes Service)

#### Core Concepts
- **Managed Kubernetes**: AWS-managed control plane
- **Worker nodes**: EC2 instances or Fargate
- **Pods**: Smallest deployable units
- **Services**: Stable network endpoints for pods

#### Node Group Types
```bash
# Managed Node Groups
- AWS manages EC2 instances
- Automatic updates and patching
- Integrated with Auto Scaling

# Self-Managed Node Groups
- You manage EC2 instances
- More customization options
- Manual updates required

# Fargate
- Serverless pod execution
- No node management
- Pay per pod resource usage
```

#### EKS Cluster Components
```yaml
# Example Pod definition
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
  - name: web-container
    image: nginx:1.21
    ports:
    - containerPort: 80
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "200m"
```

---

## Auto Scaling

### EC2 Auto Scaling

#### Components
- **Launch Template/Configuration**: Instance specifications
- **Auto Scaling Group**: Manages instance fleet
- **Scaling Policies**: Rules for scaling actions
- **CloudWatch Alarms**: Triggers for scaling

#### Scaling Types
```bash
# Manual Scaling
- Set desired capacity manually
- Immediate effect
- Used for known capacity changes

# Scheduled Scaling
- Scale at specific times
- Recurring schedules supported
- Good for predictable patterns

# Dynamic Scaling
- Target Tracking: Maintain metric target
- Step Scaling: Scale based on metric thresholds  
- Simple Scaling: Legacy, single scaling action
```

#### Launch Template Example
```json
{
  "LaunchTemplateName": "web-server-template",
  "LaunchTemplateData": {
    "ImageId": "ami-12345678",
    "InstanceType": "t3.micro",
    "KeyName": "my-key",
    "SecurityGroupIds": ["sg-12345678"],
    "IamInstanceProfile": {
      "Name": "EC2InstanceProfile"
    },
    "UserData": "IyEvYmluL2Jhc2gKeXVtIHVwZGF0ZSAteQ=="
  }
}
```

### Application Auto Scaling
- **ECS Services**: Scale container tasks
- **DynamoDB**: Scale read/write capacity
- **Aurora**: Scale read replicas
- **Lambda**: Manage concurrent executions

---

## Elastic Load Balancing Integration

### Auto Scaling with Load Balancers
```bash
# Integration benefits
- Health checks from load balancer
- Automatic registration/deregistration
- Even distribution of traffic
- Blue/green deployments
```

### Target Group Health Checks
```bash
# Health check configuration
Protocol: HTTP/HTTPS
Port: 80 or 443
Path: /health
Healthy threshold: 2-10 consecutive successes
Unhealthy threshold: 2-10 consecutive failures
Timeout: 2-120 seconds
Interval: 5-300 seconds
```

---

## Container Orchestration Patterns

### Service Discovery
```bash
# ECS Service Discovery
- AWS Cloud Map integration
- DNS-based service discovery
- Automatic registration/deregistration

# EKS Service Discovery  
- Kubernetes DNS (CoreDNS)
- Service mesh (Istio, App Mesh)
- External DNS integration
```

### Blue/Green Deployments
```bash
# ECS Blue/Green with CodeDeploy
1. Create new task definition
2. Deploy to new target group (Green)
3. Test green environment
4. Switch traffic from Blue to Green
5. Terminate blue environment

# EKS Blue/Green
1. Deploy new version to separate namespace
2. Update service selector
3. Monitor and validate
4. Clean up old version
```

### Rolling Updates
```bash
# ECS Rolling Updates
- Update service with new task definition
- Replace tasks gradually
- Maintain service availability
- Configurable deployment parameters

# EKS Rolling Updates
- Kubernetes native rolling updates
- Deployment strategies: RollingUpdate, Recreate
- Readiness and liveness probes
```

---

## Monitoring and Logging

### CloudWatch Integration
```bash
# Lambda Metrics
- Invocations, Duration, Errors
- Throttles, Concurrent Executions
- Dead Letter Queue errors

# ECS Metrics
- CPU and Memory Utilization
- Task and Service counts
- Load balancer request metrics

# EKS Metrics
- Cluster and node metrics
- Pod resource utilization
- Custom application metrics
```

### Logging Strategies
```bash
# Lambda Logging
- CloudWatch Logs (automatic)
- Structured logging with JSON
- Log retention configuration

# Container Logging
- awslogs driver for CloudWatch
- Fluent Bit for log forwarding
- Centralized logging with ELK stack
```

---

## Security Best Practices

### Lambda Security
```bash
# IAM Execution Role
- Least privilege permissions
- Resource-specific policies
- VPC configuration for private resources

# Environment Variables
- Encrypt sensitive data with KMS
- Use AWS Systems Manager Parameter Store
- Avoid hardcoded secrets
```

### Container Security
```bash
# Image Security
- Scan images for vulnerabilities
- Use minimal base images
- Sign images for integrity

# Runtime Security
- Read-only root filesystem
- Non-root user execution
- Resource limits and quotas
```

---

## Cost Optimization

### Lambda Cost Optimization
```bash
# Memory allocation
- Right-size memory for performance
- Monitor duration and adjust
- Use Provisioned Concurrency wisely

# Architecture patterns
- Avoid cold starts with warm-up
- Use step functions for workflows
- Batch processing for efficiency
```

### Container Cost Optimization
```bash
# ECS Optimization
- Use Spot instances for fault-tolerant workloads
- Right-size task definitions
- Optimize container images

# EKS Optimization
- Use Spot nodes for cost savings
- Implement cluster autoscaler
- Right-size pods and requests/limits
```

---

## Exam Tips

### Lambda Exam Points
- **15-minute timeout**: Maximum execution time
- **Concurrent executions**: Default 1,000 per region
- **Cold starts**: First invocation latency
- **VPC configuration**: Adds ENI creation overhead
- **Dead letter queues**: Handle failed executions

### Container Service Comparison
| Feature | ECS | EKS | Fargate |
|---------|-----|-----|---------|
| **Learning curve** | Low | High | Low |
| **Kubernetes native** | No | Yes | Partial |
| **Vendor lock-in** | High | Low | High |
| **Management overhead** | Low | Medium | Minimal |
| **Cost** | Low | Medium | Higher |

### Auto Scaling Best Practices
1. **Use target tracking**: Simplest scaling policy
2. **Set appropriate cooldowns**: Prevent rapid scaling
3. **Monitor scaling metrics**: Ensure policies work correctly
4. **Test scaling policies**: Validate behavior under load
5. **Use multiple metrics**: Combine CPU, memory, custom metrics

---

## Quick Commands

### Lambda CLI Examples
```bash
# Create function
aws lambda create-function --function-name my-function --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-role --handler index.handler --zip-file fileb://function.zip

# Invoke function
aws lambda invoke --function-name my-function --payload '{"key1":"value1"}' response.json

# Update function code
aws lambda update-function-code --function-name my-function --zip-file fileb://updated-function.zip

# Set environment variables
aws lambda update-function-configuration --function-name my-function --environment Variables='{VAR1=value1,VAR2=value2}'
```

### ECS CLI Examples
```bash
# Create cluster
aws ecs create-cluster --cluster-name my-cluster

# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service
aws ecs create-service --cluster my-cluster --service-name my-service --task-definition my-task:1 --desired-count 2

# Update service
aws ecs update-service --cluster my-cluster --service my-service --desired-count 3
```

### Auto Scaling CLI Examples
```bash
# Create launch template
aws ec2 create-launch-template --launch-template-name my-template --launch-template-data file://template.json

# Create Auto Scaling group
aws autoscaling create-auto-scaling-group --auto-scaling-group-name my-asg --launch-template LaunchTemplateName=my-template,Version=1 --min-size 1 --max-size 5 --desired-capacity 2 --vpc-zone-identifier "subnet-12345,subnet-67890"

# Create scaling policy
aws autoscaling put-scaling-policy --auto-scaling-group-name my-asg --policy-name scale-out --scaling-adjustment 1 --adjustment-type ChangeInCapacity
```