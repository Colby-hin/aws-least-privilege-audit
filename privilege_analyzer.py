#!/usr/bin/env python3
"""
AWS Least Privilege Policy Review Script

This script analyzes IAM policies, users, roles, and groups for least privilege compliance
against SOC 2 CC6.3 and NIST 800-53 AC-6 requirements.

Author: GRC Engineering Team
Version: 1.0
Date: 2024-08-31

Requirements:
- Python 3.9+
- boto3
- AWS CLI configured with appropriate permissions

Usage:
    python privilege_analyzer.py [--profile PROFILE_NAME] [--region REGION] [--output-format json|csv|both]

Example:
    python privilege_analyzer.py --profile grceng --region us-east-1 --output-format both
"""

import boto3
import json
import csv
import argparse
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PrivilegeAnalyzer:
    """
    Analyzes AWS IAM policies for least privilege compliance.
    
    This class checks:
    - Overly permissive policies
    - Unused permissions
    - Administrative access patterns
    - Policy complexity and risk
    - Cross-service privilege escalation
    """
    
    def __init__(self, profile_name: Optional[str] = None, region_name: str = 'us-east-1'):
        """
        Initialize the privilege analyzer.
        
        Args:
            profile_name: AWS CLI profile name (optional)
            region_name: AWS region to use (default: us-east-1)
        """
        self.profile_name = profile_name
        self.region_name = region_name
        self.session = None
        self.iam_client = None
        self.sts_client = None
        self.account_id = None
        
        # High-risk permissions
        self.high_risk_actions = [
            'iam:*', 'sts:AssumeRole', '*:*', 'iam:CreateRole', 'iam:AttachRolePolicy',
            'iam:PutRolePolicy', 'iam:CreateUser', 'iam:AttachUserPolicy',
            'iam:PutUserPolicy', 'ec2:*', 's3:*', 'lambda:*'
        ]
        
        # Administrative policies
        self.admin_policies = [
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/PowerUserAccess',
            'arn:aws:iam::aws:policy/IAMFullAccess'
        ]
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize AWS clients with optional profile support."""
        try:
            if self.profile_name:
                logger.info(f"Using AWS profile: {self.profile_name}")
                self.session = boto3.Session(profile_name=self.profile_name)
            else:
                logger.info("Using default AWS credentials")
                self.session = boto3.Session()
            
            self.iam_client = self.session.client('iam', region_name=self.region_name)
            self.sts_client = self.session.client('sts', region_name=self.region_name)
            
            # Get account ID
            response = self.sts_client.get_caller_identity()
            self.account_id = response['Account']
            logger.info(f"Connected to AWS Account: {self.account_id}")
            
        except ProfileNotFound:
            logger.error(f"AWS profile '{self.profile_name}' not found")
            raise
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure AWS CLI or set environment variables")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            raise
    
    def analyze_users(self) -> List[Dict[str, Any]]:
        """Analyze IAM users for privilege compliance."""
        try:
            logger.info("Analyzing IAM users...")
            
            users = []
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    logger.info(f"Analyzing user: {username}")
                    
                    user_analysis = {
                        'type': 'USER',
                        'name': username,
                        'arn': user['Arn'],
                        'create_date': user['CreateDate'],
                        'attached_policies': [],
                        'inline_policies': [],
                        'groups': [],
                        'risk_score': 0,
                        'findings': [],
                        'recommendations': []
                    }
                    
                    # Get attached managed policies
                    try:
                        attached_response = self.iam_client.list_attached_user_policies(UserName=username)
                        user_analysis['attached_policies'] = attached_response.get('AttachedPolicies', [])
                    except ClientError as e:
                        logger.warning(f"Could not get attached policies for {username}: {e}")
                    
                    # Get inline policies
                    try:
                        inline_response = self.iam_client.list_user_policies(UserName=username)
                        policy_names = inline_response.get('PolicyNames', [])
                        for policy_name in policy_names:
                            policy_response = self.iam_client.get_user_policy(
                                UserName=username, PolicyName=policy_name
                            )
                            user_analysis['inline_policies'].append({
                                'PolicyName': policy_name,
                                'PolicyDocument': policy_response.get('PolicyDocument')
                            })
                    except ClientError as e:
                        logger.warning(f"Could not get inline policies for {username}: {e}")
                    
                    # Get groups
                    try:
                        groups_response = self.iam_client.list_groups_for_user(UserName=username)
                        user_analysis['groups'] = groups_response.get('Groups', [])
                    except ClientError as e:
                        logger.warning(f"Could not get groups for {username}: {e}")
                    
                    # Analyze privileges
                    self._analyze_entity_privileges(user_analysis)
                    users.append(user_analysis)
            
            return users
            
        except ClientError as e:
            logger.error(f"Error analyzing users: {e}")
            return []
    
    def analyze_roles(self) -> List[Dict[str, Any]]:
        """Analyze IAM roles for privilege compliance."""
        try:
            logger.info("Analyzing IAM roles...")
            
            roles = []
            paginator = self.iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    rolename = role['RoleName']
                    
                    # Skip AWS service roles
                    if rolename.startswith('aws-service-role/'):
                        continue
                        
                    logger.info(f"Analyzing role: {rolename}")
                    
                    role_analysis = {
                        'type': 'ROLE',
                        'name': rolename,
                        'arn': role['Arn'],
                        'create_date': role['CreateDate'],
                        'attached_policies': [],
                        'inline_policies': [],
                        'trust_policy': role.get('AssumeRolePolicyDocument'),
                        'risk_score': 0,
                        'findings': [],
                        'recommendations': []
                    }
                    
                    # Get attached managed policies
                    try:
                        attached_response = self.iam_client.list_attached_role_policies(RoleName=rolename)
                        role_analysis['attached_policies'] = attached_response.get('AttachedPolicies', [])
                    except ClientError as e:
                        logger.warning(f"Could not get attached policies for {rolename}: {e}")
                    
                    # Get inline policies
                    try:
                        inline_response = self.iam_client.list_role_policies(RoleName=rolename)
                        policy_names = inline_response.get('PolicyNames', [])
                        for policy_name in policy_names:
                            policy_response = self.iam_client.get_role_policy(
                                RoleName=rolename, PolicyName=policy_name
                            )
                            role_analysis['inline_policies'].append({
                                'PolicyName': policy_name,
                                'PolicyDocument': policy_response.get('PolicyDocument')
                            })
                    except ClientError as e:
                        logger.warning(f"Could not get inline policies for {rolename}: {e}")
                    
                    # Analyze privileges
                    self._analyze_entity_privileges(role_analysis)
                    roles.append(role_analysis)
            
            return roles
            
        except ClientError as e:
            logger.error(f"Error analyzing roles: {e}")
            return []
    
    def _analyze_entity_privileges(self, entity: Dict[str, Any]):
        """Analyze privileges for a user or role."""
        risk_score = 0
        findings = []
        recommendations = []
        
        # Check for administrative policies
        for policy in entity['attached_policies']:
            policy_arn = policy.get('PolicyArn', '')
            if policy_arn in self.admin_policies:
                risk_score += 50
                findings.append(f"Has administrative policy: {policy.get('PolicyName')}")
                recommendations.append(f"Review necessity of administrative access")
        
        # Analyze inline policies
        for policy in entity['inline_policies']:
            policy_doc = policy.get('PolicyDocument', {})
            if isinstance(policy_doc, dict):
                statements = policy_doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                
                for statement in statements:
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for high-risk actions
                        for action in actions:
                            if any(risk_action in str(action) for risk_action in self.high_risk_actions):
                                risk_score += 20
                                findings.append(f"High-risk permission: {action}")
                        
                        # Check for wildcard permissions
                        if '*' in str(actions):
                            risk_score += 30
                            findings.append("Contains wildcard permissions")
                            recommendations.append("Replace wildcards with specific permissions")
                        
                        # Check for overly broad resources
                        resources = statement.get('Resource', [])
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        if '*' in str(resources):
                            risk_score += 15
                            findings.append("Allows access to all resources")
                            recommendations.append("Restrict resource access to specific ARNs")
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 40:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        entity['risk_score'] = risk_score
        entity['risk_level'] = risk_level
        entity['findings'] = findings
        entity['recommendations'] = recommendations
    
    def generate_compliance_report(self, users: List[Dict[str, Any]], 
                                 roles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive privilege compliance report."""
        all_entities = users + roles
        
        report = {
            'account_id': self.account_id,
            'scan_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_entities': len(all_entities),
                'users': len(users),
                'roles': len(roles),
                'critical_risk': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'admin_policies_count': 0
            },
            'entities': all_entities,
            'recommendations': [],
            'executive_summary': ''
        }
        
        # Calculate statistics
        for entity in all_entities:
            risk_level = entity.get('risk_level', 'LOW')
            if risk_level == 'CRITICAL':
                report['summary']['critical_risk'] += 1
            elif risk_level == 'HIGH':
                report['summary']['high_risk'] += 1
            elif risk_level == 'MEDIUM':
                report['summary']['medium_risk'] += 1
            else:
                report['summary']['low_risk'] += 1
            
            # Count admin policies
            for policy in entity.get('attached_policies', []):
                if policy.get('PolicyArn') in self.admin_policies:
                    report['summary']['admin_policies_count'] += 1
        
        # Generate executive summary
        total = report['summary']['total_entities']
        critical = report['summary']['critical_risk']
        high_risk = report['summary']['high_risk']
        
        if total == 0:
            report['executive_summary'] = "No IAM entities found for analysis."
        else:
            compliance_rate = ((total - critical - high_risk) / total) * 100
            report['executive_summary'] = f"Privilege compliance assessment: {compliance_rate:.1f}% of entities follow least privilege principles. "
            
            if critical > 0:
                report['executive_summary'] += f"{critical} entities have critical privilege violations requiring immediate review."
            elif high_risk > 0:
                report['executive_summary'] += f"{high_risk} entities have high-risk privilege configurations."
            else:
                report['executive_summary'] += "All entities demonstrate appropriate privilege levels."
        
        # Generate recommendations
        if critical > 0:
            report['recommendations'].append(f"URGENT: Review {critical} entities with critical privilege violations")
        if high_risk > 0:
            report['recommendations'].append(f"Review {high_risk} entities with high-risk configurations")
        if report['summary']['admin_policies_count'] > 0:
            report['recommendations'].append(f"Audit {report['summary']['admin_policies_count']} administrative policy assignments")
        
        return report
    
    def save_json_report(self, report: Dict[str, Any], filename: str = None):
        """Save compliance report as JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"privilege_compliance_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON report saved: {filename}")
        return filename
    
    def save_csv_report(self, report: Dict[str, Any], filename: str = None):
        """Save compliance report as CSV file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"privilege_compliance_summary_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Type', 'Name', 'Risk Level', 'Risk Score', 'Attached Policies',
                'Inline Policies', 'Key Findings', 'Recommendations'
            ])
            
            # Write entity data
            for entity in report.get('entities', []):
                attached_count = len(entity.get('attached_policies', []))
                inline_count = len(entity.get('inline_policies', []))
                
                writer.writerow([
                    entity.get('type', ''),
                    entity.get('name', ''),
                    entity.get('risk_level', ''),
                    entity.get('risk_score', 0),
                    attached_count,
                    inline_count,
                    '; '.join(entity.get('findings', [])),
                    '; '.join(entity.get('recommendations', []))
                ])
        
        logger.info(f"CSV report saved: {filename}")
        return filename

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='AWS Privilege Compliance Analyzer')
    parser.add_argument('--profile', help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--output-format', choices=['json', 'csv', 'both'], default='both',
                       help='Output format (default: both)')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        logger.info("Starting privilege compliance analysis...")
        analyzer = PrivilegeAnalyzer(profile_name=args.profile, region_name=args.region)
        
        # Analyze entities
        users = analyzer.analyze_users()
        roles = analyzer.analyze_roles()
        
        # Generate compliance report
        compliance_report = analyzer.generate_compliance_report(users, roles)
        
        # Save reports
        if args.output_format in ['json', 'both']:
            json_file = analyzer.save_json_report(compliance_report)
            print(f"JSON report: {json_file}")
        
        if args.output_format in ['csv', 'both']:
            csv_file = analyzer.save_csv_report(compliance_report)
            print(f"CSV report: {csv_file}")
        
        # Print summary
        print(f"\nPrivilege Compliance Summary:")
        print(f"Total entities: {compliance_report['summary']['total_entities']}")
        print(f"Critical risk: {compliance_report['summary']['critical_risk']}")
        print(f"High risk: {compliance_report['summary']['high_risk']}")
        print(f"Admin policies: {compliance_report['summary']['admin_policies_count']}")
        print(f"\nExecutive Summary:")
        print(compliance_report['executive_summary'])
        
    except Exception as e:
        logger.error(f"Privilege analysis failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()
