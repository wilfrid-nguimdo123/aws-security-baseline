# AWS Security Baseline

> "Security is not a product, but a process." — Bruce Schneier

# Why this project ?

Cloud misconfigurations are responsible for over 80% of data breaches today. 
A single public S3 bucket, an IAM user without MFA, or a wide-open security 
group can expose an entire organization to attackers in minutes.

This project was born from a simple question : **what does a secure AWS 
infrastructure look like from day one ?**

The answer is this tool — an automated pipeline that deploys a hardened AWS 
environment with Terraform, then immediately audits it with a Python scanner 
to detect any security drift before it becomes a vulnerability.

# What it does

Instead of manually clicking through the AWS console and hoping nothing is 
misconfigured, this project lets you :

- **Deploy** a production-grade secure infrastructure in a single command
- **Audit** your entire AWS account automatically and detect real vulnerabilities
- **Report** every finding with severity levels, affected resources and timestamps
- **Destroy** everything cleanly when done — no orphaned resources, no surprise bills

# Architecture
```
Internet
    ↓
Internet Gateway
    ↓
VPC (10.0.0.0/16)
├── Public Subnet  10.0.1.0/24  → EC2 (SSH restricted, HTTPS only)
└── Private Subnet 10.0.2.0/24  → Isolated resources
```

Every resource is tagged, every volume is encrypted, every port is justified.
Nothing is open by default — everything requires an explicit reason to exist.

# Security philosophy

This project applies three core principles :

**Least privilege** — IAM roles grant only what is strictly necessary.
No wildcard permissions, no admin access for service accounts.

**Defense in depth** — Security is layered. The VPC isolates the network,
the security group filters traffic, the encrypted volume protects data at rest.
A breach at one layer does not compromise the others.

**Auditability** — Every security finding is timestamped and logged.
The audit script runs against real AWS APIs — not simulations.

# Tech Stack

![Terraform](https://img.shields.io/badge/Terraform-1.x-7B42BC?logo=terraform)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python)
![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?logo=amazonaws)
![boto3](https://img.shields.io/badge/boto3-1.42-FF9900)

# Project Structure
```
aws-security-baseline/
├── terraform/
│   ├── main.tf          # VPC, EC2, Security Groups, IAM
│   ├── variables.tf     # Configurable parameters
│   └── outputs.tf       # Infrastructure outputs
├── scripts/
│   └── audit.py         # Automated security scanner
├── docs/
│   └── architecture.md  # Architecture documentation
└── README.md
```

# Quick Start

# 1. Deploy Infrastructure
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

# 2. Run Security Audit
```bash
pip install boto3
python scripts/audit.py
```

# 3. Review Report
```json
{
    "total_findings": 1,
    "critical": 0,
    "high": 1,
    "findings": [
        {
            "severity": "HIGH",
            "service": "IAM",
            "resource": "user_test",
            "message": "MFA is not enabled — account vulnerable to brute force"
        }
    ]
}
```

# 4. Destroy Infrastructure
```bash
terraform destroy
```

# Security Checks

| Check | Service | Severity |
|-------|---------|----------|
| Public S3 bucket detection | S3 | CRITICAL |
| Bucket encryption verification | S3 | HIGH |
| MFA enforcement on IAM users | IAM | HIGH |
| Access key rotation (90 days) | IAM | MEDIUM |
| Dangerous ports open to 0.0.0.0/0 | EC2 | CRITICAL |

# Author

Wilfrid NGUIMDO : Cybersecurity & Cloud Engineer  
[LinkedIn](https://linkedin.com/in/wilfridnguimdo-780283336) 
