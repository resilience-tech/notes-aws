# IAM Internals and Architecture

## Overview
This document provides deep technical insights into AWS IAM's internal architecture, policy evaluation engine, and troubleshooting methodologies essential for expert-level understanding.

---

## IAM Architecture Deep Dive

### Core Components Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    AWS IAM Service                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Identity  │  │    Policy   │  │     Access Token    │  │
│  │ Management  │  │  Evaluation │  │     Management      │  │
│  │   Engine    │  │   Engine    │  │      (STS)          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Principal  │  │   Resource  │  │      Audit &        │  │
│  │   Store     │  │    Store    │  │     Logging         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │               Global Distribution Layer                 │ │
│  │    (Multi-Region Replication & Consistency)            │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Identity Management Engine Internals
```python
class IAMIdentityEngine:
    """Simplified representation of IAM Identity Engine"""
    
    def __init__(self):
        self.principal_store = PrincipalStore()
        self.credential_validator = CredentialValidator()
        self.mfa_engine = MFAEngine()
        
    def authenticate_principal(self, credentials):
        """Multi-step authentication process"""
        # Step 1: Validate credential format and basic checks
        if not self.credential_validator.validate_format(credentials):
            return AuthResult(success=False, reason="Invalid credential format")
        
        # Step 2: Principal existence check
        principal = self.principal_store.lookup(credentials.principal_id)
        if not principal:
            return AuthResult(success=False, reason="Principal not found")
        
        # Step 3: Credential verification
        if not self.credential_validator.verify(credentials, principal):
            return AuthResult(success=False, reason="Invalid credentials")
        
        # Step 4: MFA verification (if required)
        if principal.requires_mfa():
            mfa_result = self.mfa_engine.verify(credentials.mfa_token, principal)
            if not mfa_result.success:
                return AuthResult(success=False, reason="MFA verification failed")
        
        # Step 5: Account status checks
        if principal.is_disabled():
            return AuthResult(success=False, reason="Principal disabled")
        
        return AuthResult(
            success=True,
            principal=principal,
            authentication_time=datetime.utcnow()
        )
```

### Policy Evaluation Engine Deep Dive
```python
class PolicyEvaluationEngine:
    """Comprehensive policy evaluation logic"""
    
    def __init__(self):
        self.policy_cache = PolicyCache()
        self.condition_engine = ConditionEngine()
        
    def evaluate_request(self, principal, action, resource, context):
        """Complete request evaluation flow"""
        
        # Collect all applicable policies
        policies = self._collect_policies(principal, resource)
        
        # Evaluate in priority order
        result = EvaluationResult()
        
        # 1. Explicit DENY always wins
        for policy in policies.explicit_deny:
            if self._evaluate_policy(policy, action, resource, context):
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Explicit deny in policy",
                    policy_id=policy.id
                )
        
        # 2. Check permission boundaries
        if policies.permission_boundaries:
            boundary_allows = any(
                self._evaluate_policy(pb, action, resource, context)
                for pb in policies.permission_boundaries
            )
            if not boundary_allows:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Permission boundary restriction"
                )
        
        # 3. Check Service Control Policies (SCPs)
        if policies.service_control_policies:
            scp_allows = all(
                not self._policy_denies(scp, action, resource, context)
                for scp in policies.service_control_policies
            )
            if not scp_allows:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Service Control Policy restriction"
                )
        
        # 4. Check for explicit ALLOW
        for policy in policies.allow_policies:
            if self._evaluate_policy(policy, action, resource, context):
                return EvaluationResult(
                    decision=Decision.ALLOW,
                    reason="Explicit allow in policy",
                    policy_id=policy.id
                )
        
        # 5. Default DENY (implicit)
        return EvaluationResult(
            decision=Decision.DENY,
            reason="No explicit allow found (default deny)"
        )
    
    def _evaluate_policy(self, policy, action, resource, context):
        """Evaluate single policy document"""
        for statement in policy.statements:
            if self._statement_matches(statement, action, resource, context):
                return statement.effect == "Allow"
        return False
    
    def _statement_matches(self, statement, action, resource, context):
        """Check if statement matches current request"""
        # Action matching
        if not self._action_matches(statement.actions, action):
            return False
        
        # Resource matching
        if not self._resource_matches(statement.resources, resource):
            return False
        
        # Condition evaluation
        if statement.conditions:
            if not self.condition_engine.evaluate(statement.conditions, context):
                return False
        
        return True
```

---

## Policy Evaluation Deep Dive

### Condition Engine Architecture
```python
class ConditionEngine:
    """Advanced condition evaluation engine"""
    
    OPERATORS = {
        'StringEquals': lambda actual, expected: actual == expected,
        'StringNotEquals': lambda actual, expected: actual != expected,
        'StringLike': lambda actual, expected: fnmatch.fnmatch(actual, expected),
        'StringNotLike': lambda actual, expected: not fnmatch.fnmatch(actual, expected),
        'NumericEquals': lambda actual, expected: float(actual) == float(expected),
        'NumericNotEquals': lambda actual, expected: float(actual) != float(expected),
        'NumericLessThan': lambda actual, expected: float(actual) < float(expected),
        'NumericLessThanEquals': lambda actual, expected: float(actual) <= float(expected),
        'NumericGreaterThan': lambda actual, expected: float(actual) > float(expected),
        'NumericGreaterThanEquals': lambda actual, expected: float(actual) >= float(expected),
        'DateEquals': lambda actual, expected: datetime.fromisoformat(actual) == datetime.fromisoformat(expected),
        'DateNotEquals': lambda actual, expected: datetime.fromisoformat(actual) != datetime.fromisoformat(expected),
        'DateLessThan': lambda actual, expected: datetime.fromisoformat(actual) < datetime.fromisoformat(expected),
        'DateLessThanEquals': lambda actual, expected: datetime.fromisoformat(actual) <= datetime.fromisoformat(expected),
        'DateGreaterThan': lambda actual, expected: datetime.fromisoformat(actual) > datetime.fromisoformat(expected),
        'DateGreaterThanEquals': lambda actual, expected: datetime.fromisoformat(actual) >= datetime.fromisoformat(expected),
        'Bool': lambda actual, expected: str(actual).lower() == str(expected).lower(),
        'BinaryEquals': lambda actual, expected: base64.b64decode(actual) == base64.b64decode(expected),
        'IpAddress': lambda actual, expected: ipaddress.ip_address(actual) in ipaddress.ip_network(expected),
        'NotIpAddress': lambda actual, expected: ipaddress.ip_address(actual) not in ipaddress.ip_network(expected),
        'ArnEquals': lambda actual, expected: actual == expected,
        'ArnLike': lambda actual, expected: fnmatch.fnmatch(actual, expected),
        'ArnNotEquals': lambda actual, expected: actual != expected,
        'ArnNotLike': lambda actual, expected: not fnmatch.fnmatch(actual, expected)
    }
    
    def evaluate(self, conditions, context):
        """Evaluate all conditions using AND logic"""
        for condition_operator, condition_block in conditions.items():
            if not self._evaluate_condition_block(condition_operator, condition_block, context):
                return False
        return True
    
    def _evaluate_condition_block(self, operator, condition_block, context):
        """Evaluate single condition block"""
        # Handle set operations
        if operator.startswith('ForAllValues:'):
            return self._evaluate_for_all_values(operator[13:], condition_block, context)
        elif operator.startswith('ForAnyValue:'):
            return self._evaluate_for_any_value(operator[12:], condition_block, context)
        else:
            return self._evaluate_simple_condition(operator, condition_block, context)
    
    def _evaluate_simple_condition(self, operator, condition_block, context):
        """Evaluate simple condition"""
        operator_func = self.OPERATORS.get(operator)
        if not operator_func:
            raise ValueError(f"Unknown condition operator: {operator}")
        
        for context_key, expected_values in condition_block.items():
            actual_value = context.get(context_key)
            if actual_value is None:
                return False
            
            # Handle list of expected values (OR logic)
            if isinstance(expected_values, list):
                if not any(operator_func(actual_value, exp) for exp in expected_values):
                    return False
            else:
                if not operator_func(actual_value, expected_values):
                    return False
        
        return True
```

### Resource Matching Engine
```python
class ResourceMatcher:
    """Advanced resource matching with wildcards and variables"""
    
    def __init__(self):
        self.variable_resolver = VariableResolver()
    
    def matches(self, policy_resource, actual_resource, context):
        """Check if policy resource pattern matches actual resource"""
        
        # Resolve variables in policy resource
        resolved_resource = self.variable_resolver.resolve(policy_resource, context)
        
        # Handle wildcards
        if '*' in resolved_resource:
            return self._wildcard_match(resolved_resource, actual_resource)
        
        # Exact match
        return resolved_resource == actual_resource
    
    def _wildcard_match(self, pattern, resource):
        """Wildcard matching for resource patterns"""
        # Convert IAM wildcard pattern to regex
        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
        return re.match(f'^{regex_pattern}$', resource) is not None

class VariableResolver:
    """Resolve policy variables like ${aws:username}"""
    
    def resolve(self, resource_pattern, context):
        """Resolve all variables in resource pattern"""
        resolved = resource_pattern
        
        # Built-in variables
        variables = {
            '${aws:username}': context.get('aws:username', ''),
            '${aws:userid}': context.get('aws:userid', ''),
            '${aws:arn}': context.get('aws:arn', ''),
            '${aws:requestid}': context.get('aws:requestid', ''),
            '${aws:SourceIp}': context.get('aws:SourceIp', ''),
            '${aws:CurrentTime}': context.get('aws:CurrentTime', ''),
            '${aws:SecureTransport}': context.get('aws:SecureTransport', ''),
            '${aws:MultiFactorAuthPresent}': context.get('aws:MultiFactorAuthPresent', ''),
            '${aws:MultiFactorAuthAge}': context.get('aws:MultiFactorAuthAge', ''),
            '${aws:RequestedRegion}': context.get('aws:RequestedRegion', ''),
            '${aws:PrincipalType}': context.get('aws:PrincipalType', ''),
            '${aws:PrincipalArn}': context.get('aws:PrincipalArn', ''),
            '${aws:PrincipalServiceName}': context.get('aws:PrincipalServiceName', ''),
        }
        
        # Add custom tags
        for key, value in context.items():
            if key.startswith('aws:PrincipalTag/'):
                tag_name = key.replace('aws:PrincipalTag/', '')
                variables[f'${{aws:PrincipalTag/{tag_name}}}'] = value
            elif key.startswith('aws:RequestTag/'):
                tag_name = key.replace('aws:RequestTag/', '')
                variables[f'${{aws:RequestTag/{tag_name}}}'] = value
        
        # Replace variables
        for var, value in variables.items():
            resolved = resolved.replace(var, str(value))
        
        return resolved
```

---

## STS Token Management Internals

### Token Lifecycle Management
```python
class STSTokenManager:
    """Internal STS token lifecycle management"""
    
    def __init__(self):
        self.token_store = TokenStore()
        self.encryption_service = EncryptionService()
        
    def issue_token(self, principal, role_arn=None, session_duration=3600):
        """Issue new STS token with comprehensive metadata"""
        
        # Generate unique token ID
        token_id = self._generate_token_id()
        
        # Create token metadata
        token_metadata = TokenMetadata(
            token_id=token_id,
            principal_arn=principal.arn,
            role_arn=role_arn,
            issue_time=datetime.utcnow(),
            expiry_time=datetime.utcnow() + timedelta(seconds=session_duration),
            issuer='sts.amazonaws.com',
            session_name=f"session-{int(time.time())}",
            mfa_authenticated=principal.mfa_verified,
            source_identity=principal.source_identity
        )
        
        # Generate token payload
        token_payload = {
            'iss': 'sts.amazonaws.com',
            'sub': principal.arn,
            'aud': 'aws',
            'exp': int(token_metadata.expiry_time.timestamp()),
            'iat': int(token_metadata.issue_time.timestamp()),
            'jti': token_id,
            'role_arn': role_arn,
            'session_name': token_metadata.session_name,
            'mfa': token_metadata.mfa_authenticated
        }
        
        # Encrypt and sign token
        encrypted_token = self.encryption_service.encrypt_and_sign(token_payload)
        
        # Store token metadata for tracking
        self.token_store.store(token_id, token_metadata)
        
        return STSToken(
            access_key_id=f"ASIA{self._generate_key_suffix()}",
            secret_access_key=self._generate_secret_key(),
            session_token=encrypted_token,
            expiration=token_metadata.expiry_time
        )
    
    def validate_token(self, session_token):
        """Validate and decrypt STS token"""
        try:
            # Decrypt and verify signature
            token_payload = self.encryption_service.decrypt_and_verify(session_token)
            
            # Check expiration
            if datetime.utcnow().timestamp() > token_payload['exp']:
                return ValidationResult(valid=False, reason="Token expired")
            
            # Check token existence in store
            token_metadata = self.token_store.get(token_payload['jti'])
            if not token_metadata:
                return ValidationResult(valid=False, reason="Token not found")
            
            # Check if token was revoked
            if token_metadata.revoked:
                return ValidationResult(valid=False, reason="Token revoked")
            
            return ValidationResult(
                valid=True,
                principal_arn=token_payload['sub'],
                role_arn=token_payload.get('role_arn'),
                session_name=token_payload['session_name'],
                mfa_authenticated=token_payload['mfa']
            )
            
        except Exception as e:
            return ValidationResult(valid=False, reason=f"Token validation error: {e}")
    
    def revoke_token(self, token_id):
        """Revoke specific token"""
        token_metadata = self.token_store.get(token_id)
        if token_metadata:
            token_metadata.revoked = True
            token_metadata.revoked_time = datetime.utcnow()
            self.token_store.update(token_id, token_metadata)
            return True
        return False
```

### Cross-Account Role Assumption Deep Dive
```python
class CrossAccountRoleManager:
    """Internal cross-account role assumption logic"""
    
    def assume_role(self, principal, target_role_arn, external_id=None, session_name=None):
        """Complete cross-account role assumption flow"""
        
        # Parse target role ARN
        role_components = self._parse_role_arn(target_role_arn)
        target_account = role_components['account']
        role_name = role_components['role_name']
        
        # Get role definition from target account
        target_role = self._get_role_definition(target_account, role_name)
        if not target_role:
            raise RoleNotFoundError(f"Role {target_role_arn} not found")
        
        # Evaluate trust policy
        trust_evaluation = self._evaluate_trust_policy(
            target_role.trust_policy,
            principal,
            external_id
        )
        
        if not trust_evaluation.allowed:
            raise AssumeRoleError(f"Trust policy evaluation failed: {trust_evaluation.reason}")
        
        # Create new principal context for assumed role
        assumed_principal = AssumedRolePrincipal(
            original_principal=principal,
            assumed_role_arn=target_role_arn,
            session_name=session_name or f"AssumeRoleSession-{int(time.time())}",
            max_session_duration=target_role.max_session_duration
        )
        
        # Issue STS token for assumed role
        return self.sts_manager.issue_token(
            assumed_principal,
            role_arn=target_role_arn,
            session_duration=min(3600, target_role.max_session_duration)
        )
    
    def _evaluate_trust_policy(self, trust_policy, principal, external_id):
        """Evaluate role trust policy"""
        for statement in trust_policy['Statement']:
            if statement['Effect'] == 'Allow':
                # Check principal matching
                if not self._principal_matches(statement['Principal'], principal):
                    continue
                
                # Check conditions
                if 'Condition' in statement:
                    context = self._build_trust_context(principal, external_id)
                    if not self.condition_engine.evaluate(statement['Condition'], context):
                        continue
                
                # Trust policy allows assumption
                return TrustEvaluationResult(allowed=True)
        
        return TrustEvaluationResult(
            allowed=False,
            reason="No matching allow statement in trust policy"
        )
```

---

## Performance and Scaling Internals

### Policy Caching Architecture
```python
class PolicyCacheManager:
    """Advanced policy caching with invalidation"""
    
    def __init__(self):
        self.cache = {}
        self.cache_stats = CacheStats()
        self.invalidation_manager = InvalidationManager()
        
    def get_effective_policies(self, principal_arn, cache_key=None):
        """Get effective policies with intelligent caching"""
        
        if cache_key is None:
            cache_key = self._generate_cache_key(principal_arn)
        
        # Check cache first
        cached_result = self.cache.get(cache_key)
        if cached_result and not self._is_expired(cached_result):
            self.cache_stats.record_hit()
            return cached_result['policies']
        
        # Cache miss - compute policies
        self.cache_stats.record_miss()
        policies = self._compute_effective_policies(principal_arn)
        
        # Store in cache with TTL
        self.cache[cache_key] = {
            'policies': policies,
            'timestamp': time.time(),
            'ttl': 300  # 5 minutes
        }
        
        return policies
    
    def invalidate_principal(self, principal_arn):
        """Invalidate cache for specific principal"""
        keys_to_remove = []
        for cache_key in self.cache:
            if principal_arn in cache_key:
                keys_to_remove.append(cache_key)
        
        for key in keys_to_remove:
            del self.cache[key]
        
        self.cache_stats.record_invalidation(len(keys_to_remove))
    
    def _generate_cache_key(self, principal_arn):
        """Generate deterministic cache key"""
        # Include principal ARN and current policy version hashes
        policy_versions = self._get_policy_version_hashes(principal_arn)
        key_components = [principal_arn] + sorted(policy_versions)
        return hashlib.sha256('|'.join(key_components).encode()).hexdigest()

class RequestThrottlingManager:
    """Internal request throttling and rate limiting"""
    
    def __init__(self):
        self.rate_limiters = {}
        self.burst_capacity = 1000
        self.sustained_rate = 100  # requests per second
        
    def check_rate_limit(self, principal_arn, request_type):
        """Check if request should be throttled"""
        
        limiter_key = f"{principal_arn}:{request_type}"
        
        if limiter_key not in self.rate_limiters:
            self.rate_limiters[limiter_key] = TokenBucketRateLimiter(
                capacity=self.burst_capacity,
                refill_rate=self.sustained_rate
            )
        
        limiter = self.rate_limiters[limiter_key]
        
        if limiter.consume():
            return RateLimitResult(allowed=True)
        else:
            return RateLimitResult(
                allowed=False,
                retry_after=limiter.time_until_refill(),
                reason="Rate limit exceeded"
            )

class TokenBucketRateLimiter:
    """Token bucket rate limiting implementation"""
    
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
    
    def consume(self, tokens=1):
        """Attempt to consume tokens from bucket"""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        tokens_to_add = (now - self.last_refill) * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now
    
    def time_until_refill(self):
        """Calculate time until next token is available"""
        if self.tokens > 0:
            return 0
        return (1 - self.tokens) / self.refill_rate
```

---

## Monitoring and Observability Internals

### Internal Metrics Collection
```python
class IAMMetricsCollector:
    """Comprehensive IAM metrics collection"""
    
    def __init__(self):
        self.metrics_buffer = []
        self.collectors = {
            'authentication': AuthenticationMetrics(),
            'authorization': AuthorizationMetrics(),
            'policy_evaluation': PolicyEvaluationMetrics(),
            'token_management': TokenMetrics(),
            'performance': PerformanceMetrics()
        }
    
    def collect_authentication_metrics(self, auth_event):
        """Collect authentication-related metrics"""
        metrics = {
            'timestamp': auth_event.timestamp,
            'principal_type': auth_event.principal_type,
            'authentication_method': auth_event.auth_method,
            'mfa_used': auth_event.mfa_verified,
            'source_ip': auth_event.source_ip,
            'user_agent': auth_event.user_agent,
            'success': auth_event.success,
            'failure_reason': auth_event.failure_reason,
            'duration_ms': auth_event.duration_ms
        }
        
        self.collectors['authentication'].record(metrics)
    
    def collect_authorization_metrics(self, authz_event):
        """Collect authorization decision metrics"""
        metrics = {
            'timestamp': authz_event.timestamp,
            'principal_arn': authz_event.principal_arn,
            'action': authz_event.action,
            'resource': authz_event.resource,
            'decision': authz_event.decision,
            'policy_used': authz_event.policy_id,
            'evaluation_time_ms': authz_event.evaluation_time_ms,
            'policies_evaluated': authz_event.policies_count,
            'conditions_evaluated': authz_event.conditions_count
        }
        
        self.collectors['authorization'].record(metrics)
    
    def generate_health_report(self):
        """Generate comprehensive health report"""
        return {
            'authentication': {
                'success_rate': self.collectors['authentication'].success_rate(),
                'avg_duration': self.collectors['authentication'].avg_duration(),
                'mfa_adoption': self.collectors['authentication'].mfa_adoption_rate(),
                'failed_attempts': self.collectors['authentication'].failed_attempts_count()
            },
            'authorization': {
                'avg_evaluation_time': self.collectors['authorization'].avg_evaluation_time(),
                'deny_rate': self.collectors['authorization'].deny_rate(),
                'policy_cache_hit_rate': self.collectors['policy_evaluation'].cache_hit_rate(),
                'complex_evaluations': self.collectors['policy_evaluation'].complex_evaluation_count()
            },
            'performance': {
                'p95_response_time': self.collectors['performance'].p95_response_time(),
                'p99_response_time': self.collectors['performance'].p99_response_time(),
                'throughput_rps': self.collectors['performance'].requests_per_second(),
                'error_rate': self.collectors['performance'].error_rate()
            },
            'tokens': {
                'active_tokens': self.collectors['token_management'].active_token_count(),
                'token_generation_rate': self.collectors['token_management'].generation_rate(),
                'expired_tokens_cleaned': self.collectors['token_management'].cleanup_count(),
                'invalid_token_attempts': self.collectors['token_management'].invalid_attempts()
            }
        }
```

### Advanced Debugging Tools
```python
class IAMDebugger:
    """Advanced IAM debugging and troubleshooting tools"""
    
    def __init__(self):
        self.trace_collector = TraceCollector()
        self.policy_analyzer = PolicyAnalyzer()
        
    def trace_authorization_flow(self, principal_arn, action, resource, context):
        """Detailed authorization flow tracing"""
        
        trace_id = self._generate_trace_id()
        trace = AuthorizationTrace(trace_id)
        
        try:
            # Step 1: Principal resolution
            trace.add_step("principal_resolution", "START")
            principal = self._resolve_principal(principal_arn)
            trace.add_step("principal_resolution", "SUCCESS", {
                'principal_type': principal.type,
                'active': principal.active,
                'mfa_devices': len(principal.mfa_devices)
            })
            
            # Step 2: Policy collection
            trace.add_step("policy_collection", "START")
            policies = self._collect_all_policies(principal, resource)
            trace.add_step("policy_collection", "SUCCESS", {
                'identity_policies': len(policies.identity_based),
                'resource_policies': len(policies.resource_based),
                'permission_boundaries': len(policies.permission_boundaries),
                'scps': len(policies.service_control_policies)
            })
            
            # Step 3: Policy evaluation
            trace.add_step("policy_evaluation", "START")
            for policy_type, policy_list in policies.items():
                for policy in policy_list:
                    policy_result = self._evaluate_single_policy(policy, action, resource, context)
                    trace.add_policy_evaluation(policy_type, policy.id, policy_result)
            
            # Step 4: Final decision
            final_decision = self._make_final_decision(trace.policy_evaluations)
            trace.add_step("final_decision", "SUCCESS", {
                'decision': final_decision.decision,
                'reason': final_decision.reason,
                'applicable_policies': final_decision.applicable_policies
            })
            
            return trace
            
        except Exception as e:
            trace.add_step("error", "FAILURE", {
                'error': str(e),
                'error_type': type(e).__name__
            })
            return trace
    
    def analyze_policy_conflicts(self, principal_arn):
        """Analyze potential policy conflicts"""
        
        policies = self._collect_all_policies_for_principal(principal_arn)
        conflicts = []
        
        # Check for explicit allow/deny conflicts
        for i, policy1 in enumerate(policies):
            for j, policy2 in enumerate(policies[i+1:], i+1):
                conflict = self._check_policy_conflict(policy1, policy2)
                if conflict:
                    conflicts.append(conflict)
        
        # Check for permission boundary violations
        boundary_violations = self._check_boundary_violations(policies)
        conflicts.extend(boundary_violations)
        
        return PolicyConflictReport(
            principal_arn=principal_arn,
            conflicts=conflicts,
            recommendations=self._generate_conflict_recommendations(conflicts)
        )
    
    def simulate_policy_change(self, policy_arn, new_policy_document):
        """Simulate impact of policy changes"""
        
        # Get current policy
        current_policy = self._get_policy(policy_arn)
        
        # Analyze current permissions
        current_permissions = self.policy_analyzer.extract_permissions(current_policy)
        
        # Analyze new permissions
        new_permissions = self.policy_analyzer.extract_permissions(new_policy_document)
        
        # Calculate diff
        added_permissions = new_permissions - current_permissions
        removed_permissions = current_permissions - new_permissions
        
        # Find affected principals
        affected_principals = self._find_principals_using_policy(policy_arn)
        
        return PolicyChangeSimulation(
            policy_arn=policy_arn,
            added_permissions=list(added_permissions),
            removed_permissions=list(removed_permissions),
            affected_principals=affected_principals,
            risk_assessment=self._assess_change_risk(added_permissions, removed_permissions),
            rollback_plan=self._generate_rollback_plan(policy_arn, current_policy)
        )
```

---

## Troubleshooting Methodology

### Common IAM Issues and Root Causes
```python
class IAMTroubleshooter:
    """Systematic IAM troubleshooting"""
    
    COMMON_ISSUES = {
        'access_denied': {
            'checks': [
                'verify_principal_exists',
                'check_policy_attachments',
                'evaluate_permission_boundaries',
                'check_service_control_policies',
                'verify_resource_policies',
                'check_condition_evaluation',
                'verify_mfa_requirements'
            ]
        },
        'assume_role_failed': {
            'checks': [
                'verify_role_exists',
                'check_trust_policy',
                'verify_external_id',
                'check_mfa_requirements',
                'verify_source_ip_restrictions',
                'check_session_duration',
                'verify_role_path'
            ]
        },
        'token_expired': {
            'checks': [
                'check_token_expiration',
                'verify_token_format',
                'check_system_clock_skew',
                'verify_token_source',
                'check_revocation_status'
            ]
        }
    }
    
    def diagnose_issue(self, issue_type, context):
        """Systematic issue diagnosis"""
        
        if issue_type not in self.COMMON_ISSUES:
            return DiagnosisResult(
                success=False,
                message=f"Unknown issue type: {issue_type}"
            )
        
        checks = self.COMMON_ISSUES[issue_type]['checks']
        results = []
        
        for check_name in checks:
            check_method = getattr(self, check_name)
            result = check_method(context)
            results.append(result)
            
            if result.blocking:
                # Found root cause
                return DiagnosisResult(
                    success=True,
                    root_cause=result,
                    all_checks=results,
                    recommendations=self._generate_recommendations(result)
                )
        
        return DiagnosisResult(
            success=False,
            message="No definitive root cause found",
            all_checks=results,
            recommendations=self._generate_general_recommendations(results)
        )
    
    def verify_principal_exists(self, context):
        """Check if principal exists and is active"""
        try:
            principal = self.iam_client.get_user(UserName=context['username'])
            return CheckResult(
                check_name="principal_exists",
                passed=True,
                details=f"Principal {context['username']} exists and is active"
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return CheckResult(
                    check_name="principal_exists",
                    passed=False,
                    blocking=True,
                    details=f"Principal {context['username']} does not exist",
                    recommendation="Create the user or check the username spelling"
                )
            raise
    
    def check_policy_attachments(self, context):
        """Verify policy attachments"""
        try:
            attached_policies = self.iam_client.list_attached_user_policies(
                UserName=context['username']
            )
            
            if not attached_policies['AttachedPolicies']:
                return CheckResult(
                    check_name="policy_attachments",
                    passed=False,
                    blocking=True,
                    details=f"No policies attached to {context['username']}",
                    recommendation="Attach appropriate policies to grant permissions"
                )
            
            return CheckResult(
                check_name="policy_attachments",
                passed=True,
                details=f"Found {len(attached_policies['AttachedPolicies'])} attached policies"
            )
            
        except Exception as e:
            return CheckResult(
                check_name="policy_attachments",
                passed=False,
                details=f"Error checking policy attachments: {e}"
            )
```

### Performance Debugging Tools
```python
class PerformanceProfiler:
    """IAM performance profiling and optimization"""
    
    def profile_policy_evaluation(self, principal_arn, sample_requests):
        """Profile policy evaluation performance"""
        
        results = []
        total_time = 0
        
        for request in sample_requests:
            start_time = time.perf_counter()
            
            # Collect policies
            policy_collection_start = time.perf_counter()
            policies = self._collect_policies(principal_arn, request['resource'])
            policy_collection_time = time.perf_counter() - policy_collection_start
            
            # Evaluate policies
            evaluation_start = time.perf_counter()
            decision = self._evaluate_policies(policies, request['action'], request['resource'], request['context'])
            evaluation_time = time.perf_counter() - evaluation_start
            
            total_request_time = time.perf_counter() - start_time
            total_time += total_request_time
            
            results.append({
                'action': request['action'],
                'resource': request['resource'],
                'decision': decision.decision,
                'times': {
                    'policy_collection_ms': policy_collection_time * 1000,
                    'policy_evaluation_ms': evaluation_time * 1000,
                    'total_request_ms': total_request_time * 1000
                },
                'policy_stats': {
                    'policies_evaluated': len(policies),
                    'conditions_evaluated': decision.conditions_evaluated,
                    'cache_hits': decision.cache_hits,
                    'cache_misses': decision.cache_misses
                }
            })
        
        return PerformanceProfile(
            principal_arn=principal_arn,
            total_requests=len(sample_requests),
            total_time_ms=total_time * 1000,
            avg_request_time_ms=(total_time / len(sample_requests)) * 1000,
            results=results,
            bottlenecks=self._identify_bottlenecks(results),
            recommendations=self._generate_performance_recommendations(results)
        )
    
    def _identify_bottlenecks(self, results):
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        # Check for slow policy collection
        avg_collection_time = sum(r['times']['policy_collection_ms'] for r in results) / len(results)
        if avg_collection_time > 50:  # 50ms threshold
            bottlenecks.append({
                'type': 'slow_policy_collection',
                'severity': 'high' if avg_collection_time > 100 else 'medium',
                'details': f'Average policy collection time: {avg_collection_time:.1f}ms',
                'recommendation': 'Consider policy optimization or caching improvements'
            })
        
        # Check for complex evaluations
        complex_evaluations = [r for r in results if r['policy_stats']['conditions_evaluated'] > 10]
        if len(complex_evaluations) > len(results) * 0.3:  # 30% threshold
            bottlenecks.append({
                'type': 'complex_policy_evaluations',
                'severity': 'medium',
                'details': f'{len(complex_evaluations)} requests had complex evaluations',
                'recommendation': 'Simplify policy conditions or restructure policies'
            })
        
        # Check cache efficiency
        total_cache_requests = sum(r['policy_stats']['cache_hits'] + r['policy_stats']['cache_misses'] for r in results)
        cache_hit_rate = sum(r['policy_stats']['cache_hits'] for r in results) / total_cache_requests if total_cache_requests > 0 else 0
        
        if cache_hit_rate < 0.7:  # 70% threshold
            bottlenecks.append({
                'type': 'low_cache_hit_rate',
                'severity': 'medium',
                'details': f'Cache hit rate: {cache_hit_rate:.1%}',
                'recommendation': 'Review cache configuration and policy structure'
            })
        
        return bottlenecks
```

---

## Security Deep Dive

### Cryptographic Implementation Details
```python
class IAMCryptographicManager:
    """IAM cryptographic operations and key management"""
    
    def __init__(self):
        self.key_manager = AWSKeyManager()
        self.encryption_algorithms = {
            'token_encryption': 'AES-256-GCM',
            'policy_signing': 'RSA-PSS-SHA256',
            'credential_hashing': 'PBKDF2-SHA256'
        }
    
    def encrypt_session_token(self, token_payload):
        """Encrypt STS session token with AES-256-GCM"""
        
        # Generate random nonce
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Get current encryption key
        encryption_key = self.key_manager.get_current_token_key()
        
        # Encrypt payload
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, auth_tag = cipher.encrypt_and_digest(
            json.dumps(token_payload).encode('utf-8')
        )
        
        # Combine components
        encrypted_token = base64.b64encode(
            nonce + auth_tag + ciphertext
        ).decode('ascii')
        
        return encrypted_token
    
    def decrypt_session_token(self, encrypted_token):
        """Decrypt and verify STS session token"""
        
        try:
            # Decode base64
            token_data = base64.b64decode(encrypted_token)
            
            # Extract components
            nonce = token_data[:12]
            auth_tag = token_data[12:28]
            ciphertext = token_data[28:]
            
            # Try current key first, then previous keys for rotation
            for key_version in self.key_manager.get_decryption_keys():
                try:
                    cipher = AES.new(key_version.key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
                    
                    return json.loads(plaintext.decode('utf-8'))
                    
                except ValueError:
                    continue  # Try next key version
            
            raise TokenDecryptionError("Unable to decrypt token with any available key")
            
        except Exception as e:
            raise TokenDecryptionError(f"Token decryption failed: {e}")
    
    def sign_policy_document(self, policy_document):
        """Sign policy document for integrity verification"""
        
        # Normalize policy for consistent signing
        normalized_policy = self._normalize_policy(policy_document)
        
        # Create signature payload
        payload = {
            'policy': normalized_policy,
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0'
        }
        
        # Sign with RSA-PSS
        signing_key = self.key_manager.get_policy_signing_key()
        signature = signing_key.sign(
            json.dumps(payload, sort_keys=True).encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'policy': policy_document,
            'signature': base64.b64encode(signature).decode('ascii'),
            'signed_payload': payload
        }
```

---

## Quick Reference for Experts

### IAM Request Flow (Simplified)
```
1. Authentication: Credential validation + MFA
2. Authorization: Policy collection + evaluation
3. Token issuance: STS token generation (if applicable)
4. Request processing: Service-specific authorization
5. Audit logging: CloudTrail event generation
```

### Policy Evaluation Order
```
1. Explicit DENY (any policy) → DENY
2. Permission Boundaries → Filter maximum permissions
3. Service Control Policies → Apply organizational constraints
4. Session Policies → Limit assumed role permissions
5. Explicit ALLOW (identity/resource policies) → ALLOW
6. Default → DENY
```

### Critical Performance Factors
- **Policy complexity**: Minimize conditions and wildcards
- **Cache efficiency**: Structure policies for effective caching
- **Principal count**: Limit attached policies per principal
- **Evaluation depth**: Avoid deeply nested condition logic
- **Token lifetime**: Balance security vs. performance

### Expert Troubleshooting Checklist
```bash
# Quick diagnostics
1. Check principal existence and status
2. Verify policy attachments and syntax
3. Test permission boundaries and SCPs
4. Validate trust policies for roles
5. Examine condition evaluation context
6. Review CloudTrail for detailed errors
7. Use policy simulator for testing
8. Check service-specific authorizations
```

This comprehensive internals documentation provides the deep technical understanding needed for expert-level IAM troubleshooting, optimization, and architecture decisions.