# AWS Least Privilege Compliance Checker
 
An automated review of AWS Identity and Access Management permissions, built to identify administrative access, wildcard permissions, broad resource access, and other configurations that conflict with least privilege principles.
 
I created a controlled AWS test environment with several IAM identities, each representing a different privilege scenario, then ran a Python and Boto3 analyzer against the account. The analyzer assigned a risk score to each IAM user and role and generated findings, recommendations, a JSON report, and a CSV summary.
 
This project was completed as part of a GRC Engineering Club lab. The original instructional materials and source code are not included in this repository — what you'll find here is my implementation, testing process, results, and lessons learned.
 
---
 
## Objectives
 
- Create an IAM identity with read access for privilege reviews
- Create test identities with different permission levels
- Detect administrative access and wildcard permissions
- Calculate a risk score for each IAM user and role
- Generate audit evidence in JSON and CSV formats
- Connect the results to least privilege control requirements
## Technologies Used
 
- Amazon Web Services
- AWS Identity and Access Management
- Python 3
- Boto3
- AWS Command Line Interface
- jq
 
---
 
## Control Mapping
 
This project supports evidence collection for the following controls:
 
| Control | Requirement |
|---|---|
| SOC 2 CC6.3 | Logical access controls should prevent unauthorized access to systems and data. |
| NIST SP 800-53 AC-6 | Organizations should apply the principle of least privilege. |
| NIST SP 800-53 AC-6(1) | Access to security functions should be limited to authorized users. |
| NIST SP 800-53 AC-6(2) | Users performing nonsecurity functions should operate without unnecessary security privileges. |
 
The analyzer supports control reviews. It does not, by itself, prove that an organization is fully compliant.
 
---
 
## AWS Test Environment
 
All work was performed in a dedicated AWS test account. The test identities described below were created solely for this lab and were deleted after the assessment was complete.
 
### Audit Identity
 
I created a customer managed IAM policy named `GRCLabPrivilegeAudit` that granted read access to the IAM and STS operations needed by the analyzer. These permissions allowed the tool to list users, roles, attached policies, inline policies, and caller identity information.

<img width="1908" height="986" alt="image2" src="https://github.com/user-attachments/assets/f0249c6a-99e3-4658-97e9-724365f95f40" />
 
I then created an IAM user named `grc-lab-auditor`, attached the `GRCLabPrivilegeAudit` policy, and disabled console access. This identity represented a least privilege audit account with read access to only the IAM information the analyzer required.


<!-- SCREENSHOT 2: Drag the AWS screenshot showing grc-lab-auditor with GRCLabPrivilegeAudit below this line -->

<img width="1903" height="926" alt="image8" src="https://github.com/user-attachments/assets/a68beb6c-7979-4747-8983-56da65ffb83e" />


### Scoped Access Test
 
I created an IAM user named `test-scoped` with an inline policy that allowed `s3:GetObject` against a specific bucket path. This scenario represented a limited, job-specific permission set and provided a comparison point against the administrative and wildcard test identities.

### Administrative Access Test
 
I created an IAM user named `test-overprivileged` and attached the AWS managed `AdministratorAccess` policy directly to the user. This scenario represented excessive administrative access that should require review, justification, and remediation.

<!-- SCREENSHOT 3: Drag the AWS screenshot showing test-overprivileged with AdministratorAccess below this line -->

<img width="1815" height="839" alt="image12" src="https://github.com/user-attachments/assets/3c552d87-fa6e-471a-85a9-c7510054bfdf" />


### Wildcard Permission Test
 
I created an IAM role named `test-wildcard-role` with an inline policy granting unrestricted access:
 
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```
 
This configuration intentionally granted full access so I could confirm that the analyzer detected both wildcard actions and unrestricted resource access.

<img width="1697" height="619" alt="AWS inline wildcard policy assigned to test-wildcard-role" src="https://github.com/user-attachments/assets/cb806335-a184-4285-83be-54487f1cbf16" />

---

## Running the Analyzer
 
I activated the Python virtual environment and ran the analyzer against my configured AWS CLI profile:
 
```bash
source privilege-lab-env/bin/activate
python privilege_analyzer.py --profile grceng --output-format both
```
 
The analyzer connected to the AWS account, reviewed the available IAM users and roles, and generated a detailed JSON report alongside a CSV summary. AWS account identifiers were redacted from all output.

<img width="992" height="470" alt="Terminal output showing the analyzer execution and executive summary" src="https://github.com/user-attachments/assets/33dc9d8a-7088-4bb5-9c34-e7f39bd945bd" />

---

## Scan Results
<img width="1533" height="118" alt="AM privilege analysis results showing entity risk scores, findings, and remediation recommendations" src="https://github.com/user-attachments/assets/201f146f-4f11-4cb6-b84d-d5c5e46453e8" />

The scan identified two high risk identities. The `test-overprivileged` user received a risk score of 50 because the AWS managed `AdministratorAccess` policy was attached directly to the user, and the `test-wildcard-role` role received a risk score of 45 because its inline policy allowed wildcard actions against all AWS resources. The remaining identities scored zero, as the analyzer did not identify administrative policies or risky inline permissions on them.
 
### Validating a False Positive
 
The `test-scoped` user received a risk score of 15. Its policy was limited to objects inside a single S3 bucket, but the analyzer read the trailing object wildcard as broad resource access and flagged it accordingly.
 
This finding was incorrect, and confirming it required inspecting the full resource ARN rather than trusting the analyzer's output. It exposed a real limitation in the current resource parsing logic — one that would have produced a misleading finding had this assessment gone to an auditor unvalidated.

---

## Generated Evidence

The analyzer produced two timestamped evidence files after the completed scan.

<img width="782" height="94" alt="image" src="https://github.com/user-attachments/assets/8eaea138-9992-4263-bd7a-8a0690d032b5" />


### JSON Report

The JSON report contained detailed information for every analyzed identity.

It included the identity type, name, ARN, attached policies, inline policies, risk score, risk level, findings, and recommendations.

```text
privilege_compliance_report_20260728_205148_redacted.json
```
### CSV Summary

The CSV summary presented the findings in a compact format for review.

It included each identity, its risk level, risk score, policy counts, findings, and recommended remediation.

```text
privilege_compliance_summary_20260728_205148.csv
```
---

## Recommended Remediation
 
**Remove unnecessary administrative access.** The `AdministratorAccess` policy should be removed from `test-overprivileged` and replaced with a policy granting only the permissions required for the user's assigned responsibilities. Administrative access should require documented approval and periodic review.
 
**Replace wildcard permissions.** The `"Action": "*"` permission assigned to `test-wildcard-role` should be replaced with an explicit list of approved AWS actions, and `"Resource": "*"` should be replaced with specific resource ARNs wherever the AWS service supports resource-level restrictions.
 
**Improve resource pattern analysis.** The analyzer should distinguish between a global wildcard and a wildcard inside a scoped resource ARN. `"Resource": "*"` represents unrestricted resource access, while `arn:aws:s3:::example-bucket/*` represents objects inside one specific S3 bucket. These patterns should not produce the same finding.

---

## What I Learned

This project showed me that least privilege reviews require more than checking for the `AdministratorAccess` policy.

Risk can also come from wildcard actions, broad resource permissions, inline policies, managed policies, and role trust relationships.

I learned how to use Python and Boto3 to collect IAM configuration data and turn it into repeatable compliance evidence.

I also learned that automated findings still require technical validation. The scoped S3 policy demonstrated how simple wildcard detection can produce a misleading result when the full resource ARN is not considered.

The most useful output was not only the risk score. The findings and remediation guidance made the assessment easier to explain to both technical teams and auditors.

---

## Conclusion

The analyzer successfully connected to AWS, reviewed six IAM entities, calculated risk scores, and generated JSON and CSV evidence.

It identified one user with administrative access and one role with unrestricted wildcard permissions.

The assessment also revealed a limitation in the resource parsing logic when evaluating an S3 object ARN.

This project demonstrated how Python and Boto3 can support repeatable IAM access reviews. It also reinforced the importance of validating automated findings before using them for compliance decisions.

---

## Attribution

This project was completed as part of a GRC Engineering Club lab.

The original instructional materials and source code are not included in this repository. This repository documents my implementation, testing process, findings, evidence, and lessons learned.

AWS account identifiers were redacted from all public screenshots and evidence files.
