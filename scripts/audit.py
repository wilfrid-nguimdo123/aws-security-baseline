import boto3
import json
from datetime import datetime

# AWS clients
s3_client      = boto3.client('s3')
iam_client     = boto3.client('iam')
ec2_client     = boto3.client('ec2', region_name='eu-west-3')

# Audit results storage
findings = []

def add_finding(severity, service, resource, message):
    """Add a security finding to the report."""
    findings.append({
        "severity": severity,   # CRITICAL / HIGH / MEDIUM / LOW
        "service":  service,    # S3 / IAM / EC2
        "resource": resource,   # Resource name or ID
        "message":  message,    # Description of the issue
        "timestamp": datetime.now().isoformat()
    })
    print(f"[{severity}] {service} — {resource}: {message}")
    
    
def audit_s3():
    """Check S3 buckets for public access and encryption."""
    print("\n[*] Auditing S3 buckets...")
    
    try:
        buckets = s3_client.list_buckets()['Buckets']
        
        if not buckets:
            print("    No S3 buckets found.")
            return
            
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            # Check public access
            try:
                public_access = s3_client.get_bucket_policy_status(
                    Bucket=bucket_name
                )
                if public_access['PolicyStatus']['IsPublic']:
                    add_finding(
                        "CRITICAL", "S3", bucket_name,
                        "Bucket is publicly accessible via bucket policy"
                    )
            except s3_client.exceptions.from_code('NoSuchBucketPolicy'):
                pass  # No policy = not public via policy
                
            # Check encryption
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except Exception:
                add_finding(
                    "HIGH", "S3", bucket_name,
                    "Bucket encryption is not enabled"
                )
                
    except Exception as e:
        print(f"    Error auditing S3: {e}")
        
        
def audit_iam():
    """Check IAM users for MFA and access key rotation."""
    print("\n[*] Auditing IAM users...")
    
    try:
        users = iam_client.list_users()['Users']
        
        if not users:
            print("    No IAM users found.")
            return
            
        for user in users:
            username = user['UserName']
            
            # Check MFA
            mfa_devices = iam_client.list_mfa_devices(
                UserName=username
            )['MFADevices']
            
            if not mfa_devices:
                add_finding(
                    "HIGH", "IAM", username,
                    "MFA is not enabled — account vulnerable to brute force"
                )
            
            # Check access keys rotation
            access_keys = iam_client.list_access_keys(
                UserName=username
            )['AccessKeyMetadata']
            
            for key in access_keys:
                key_age = (datetime.now() - 
                          key['CreateDate'].replace(tzinfo=None)).days
                
                if key_age > 90:
                    add_finding(
                        "MEDIUM", "IAM", username,
                        f"Access key not rotated in {key_age} days (recommended: 90 days max)"
                    )
                    
    except Exception as e:
        print(f"    Error auditing IAM: {e}")
        
def audit_security_groups():
    """Check security groups for dangerous open ports."""
    print("\n[*] Auditing Security Groups...")
    
    # Ports dangereux à ne jamais ouvrir à 0.0.0.0/0
    dangerous_ports = {
        22:   "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis"
    }
    
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        
        for sg in sgs:
            sg_id   = sg['GroupId']
            sg_name = sg['GroupName']
            
            for rule in sg['IpPermissions']:
                from_port = rule.get('FromPort', 0)
                to_port   = rule.get('ToPort', 0)
                
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    
                    # Port ouvert à tout internet
                    if cidr == '0.0.0.0/0':
                        for port, service in dangerous_ports.items():
                            if from_port <= port <= to_port:
                                add_finding(
                                    "CRITICAL", "EC2", f"{sg_name} ({sg_id})",
                                    f"Port {port} ({service}) open to 0.0.0.0/0 — critical exposure"
                                )
                                
    except Exception as e:
        print(f"    Error auditing Security Groups: {e}")
        
def generate_report():
    """Generate JSON security report."""
    report = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "critical": len([f for f in findings if f['severity'] == 'CRITICAL']),
        "high":     len([f for f in findings if f['severity'] == 'HIGH']),
        "medium":   len([f for f in findings if f['severity'] == 'MEDIUM']),
        "low":      len([f for f in findings if f['severity'] == 'LOW']),
        "findings": findings
    }
    
    # Save report to file
    report_name = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_name, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"\n{'='*50}")
    print(f"AUDIT COMPLETE")
    print(f"{'='*50}")
    print(f"Total findings : {report['total_findings']}")
    print(f"Critical       : {report['critical']}")
    print(f"High           : {report['high']}")
    print(f"Medium         : {report['medium']}")
    print(f"Low            : {report['low']}")
    print(f"Report saved   : {report_name}")
    print(f"{'='*50}")

# Entry point — run all audits
if __name__ == "__main__":
    try:
        print("="*50)
        print("AWS SECURITY AUDIT")
        print("="*50)
        
        audit_s3()
        audit_iam()
        audit_security_groups()
        generate_report()
    except Exception as e:
        print(f"ERREUR : {e}")