# AWS Least Privilege Compliance Checker

## Project Overview

This project documents an automated review of AWS Identity and Access Management permissions.

The goal was to identify administrative access, wildcard permissions, broad resource access, and other configurations that conflict with least privilege principles.

I created a controlled AWS test environment with several IAM identities. Each identity represented a different privilege scenario. I then ran a Python and Boto3 analyzer against the account.

The analyzer assigned a risk score to each IAM user and role. It also generated findings, recommendations, a JSON report, and a CSV summary.

This project was completed as part of a GRC Engineering Club lab. The original instructional materials and source code are not included in this repository. This repository documents my implementation, testing process, results, and lessons learned.

## Project Objectives

1. Create an IAM identity with read access for privilege reviews.

2. Create test identities with different permission levels.

3. Detect administrative access and wildcard permissions.

4. Calculate a risk score for each IAM user and role.

5. Generate audit evidence in JSON and CSV formats.

6. Connect the results to least privilege control requirements.

## Technologies Used

1. Amazon Web Services

2. AWS Identity and Access Management

3. Python 3

4. Boto3

5. AWS Command Line Interface

6. Kali Linux

7. JSON

8. CSV

9. jq

## Control Mapping

This project supports evidence collection for the following controls.

1. **SOC 2 CC6.3**

   Logical access controls should prevent unauthorized access to systems and data.

2. **NIST SP 800-53 AC-6**

   Organizations should apply the principle of least privilege.

3. **NIST SP 800-53 AC-6(1)**

   Access to security functions should be limited to authorized users.

4. **NIST SP 800-53 AC-6(2)**

   Users performing nonsecurity functions should operate without unnecessary security privileges.

The analyzer supports control reviews. It does not prove that an organization is fully compliant by itself.

## AWS Test Environment

I created several IAM identities to test different permission conditions.

### Audit Identity

I created a customer managed IAM policy named `GRCLabPrivilegeAudit`.

The policy granted read access to the IAM and STS operations needed by the analyzer. These permissions allowed the tool to list users, roles, attached policies, inline policies, and caller identity information.


<img width="1908" height="986" alt="image2" src="https://github.com/user-attachments/assets/f0249c6a-99e3-4658-97e9-724365f95f40" />




I created an IAM user named `grc-lab-auditor` and attached the `GRCLabPrivilegeAudit` policy.

Console access was disabled for this user. The identity represented a least privilege audit account with read access to the IAM information required by the analyzer.

<!-- SCREENSHOT 2: Drag the AWS screenshot showing grc-lab-auditor with GRCLabPrivilegeAudit below this line -->

<img width="1903" height="926" alt="image8" src="https://github.com/user-attachments/assets/a68beb6c-7979-4747-8983-56da65ffb83e" />



### Scoped Access Test

I created an IAM user named `test-scoped`.

The user received an inline policy that allowed `s3:GetObject` against a specific bucket path.

This scenario represented a limited, job-specific permission set. It provided a comparison point against the administrative and wildcard test identities.

### Administrative Access Test

I created an IAM user named `test-overprivileged`.

The AWS managed `AdministratorAccess` policy was attached directly to this user.

This scenario represented excessive administrative access that should require review, justification, and remediation.

<!-- SCREENSHOT 3: Drag the AWS screenshot showing test-overprivileged with AdministratorAccess below this line -->

<img width="1815" height="839" alt="image12" src="https://github.com/user-attachments/assets/3c552d87-fa6e-471a-85a9-c7510054bfdf" />


### Wildcard Permission Test

I created an IAM role named `test-wildcard-role`.

The role received an inline policy with the following permissions.

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```
This configuration intentionally granted unrestricted access so I could confirm that the analyzer detected wildcard actions and unrestricted resource access.

<img width="1697" height="619" alt="AWS inline wildcard policy assigned to test-wildcard-role" src="https://github.com/user-attachments/assets/cb806335-a184-4285-83be-54487f1cbf16" />

---

## Running the Analyzer

I activated the Python virtual environment and ran the analyzer with my configured AWS CLI profile.

```bash
source privilege-lab-env/bin/activate
python privilege_analyzer.py --profile grceng --output-format both
```

The analyzer connected to the AWS account and reviewed the available IAM users and roles.

The analyzer generated a detailed JSON report and a CSV summary. AWS account identifiers were redacted.

<img width="992" height="470" alt="Terminal output showing the analyzer execution and executive summary" src="https://github.com/user-attachments/assets/33dc9d8a-7088-4bb5-9c34-e7f39bd945bd" />


## Scan Results
<img width="1533" height="118" alt="AM privilege analysis results showing entity risk scores, findings, and remediation recommendations" src="https://github.com/user-attachments/assets/201f146f-4f11-4cb6-b84d-d5c5e46453e8" />

The scan identified two high risk identities.

The `test-overprivileged` user received a risk score of 50 because the AWS managed `AdministratorAccess` policy was attached directly to the user.

The `test-wildcard-role` role received a risk score of 45 because its inline policy allowed wildcard actions against all AWS resources.

The `test-scoped` user received a risk score of 15. Its policy was limited to objects inside one S3 bucket, but the analyzer interpreted the object wildcard as broad resource access. This exposed a limitation in the current resource parsing logic.

The remaining identities received scores of zero because the analyzer did not identify administrative policies or risky inline permissions.

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
## Recommended Remediation
### Remove Unnecessary Administrative Access

The `AdministratorAccess` policy should be removed from `test-overprivileged`.

It should be replaced with a policy that grants only the permissions required for the user’s assigned responsibilities.

Administrative access should require documented approval and periodic review.

### Replace Wildcard Permissions

The `"Action": "*"` permission assigned to `test-wildcard-role` should be replaced with an explicit list of approved AWS actions.

The `"Resource": "*"` permission should be replaced with specific resource ARNs whenever the AWS service supports resource-level restrictions.

### Improve Resource Pattern Analysis

The analyzer should distinguish between a global wildcard and a wildcard inside a scoped resource ARN.

`"Resource": "*"` represents unrestricted resource access.

`arn:aws:s3:::example-bucket/*` represents objects inside one specific S3 bucket.

These patterns should not receive the same finding.

## Current Limitations

The current version has several limitations.

1. The analyzer reports IAM users and roles as its primary entities.

2. IAM group policies are not analyzed as separate report entries.

3. Attached managed policy documents are not fully inspected for every possible permission.

4. The analyzer recognizes a limited set of administrative policies through known policy ARNs.

5. A wildcard inside a scoped resource ARN can be incorrectly treated as unrestricted resource access.

6. The analyzer identifies permissions that require review. It does not prove that access is approved, justified, monitored, or actively used.

7. The tool does not perform complete privilege escalation path analysis.

8. The tool does not analyze CloudTrail activity or unused permissions.

## What I Learned

This project showed me that least privilege reviews require more than checking for the `AdministratorAccess` policy.

Risk can also come from wildcard actions, broad resource permissions, inline policies, managed policies, and role trust relationships.

I learned how to use Python and Boto3 to collect IAM configuration data and turn it into repeatable compliance evidence.

I also learned that automated findings still require technical validation. The scoped S3 policy demonstrated how simple wildcard detection can produce a misleading result when the full resource ARN is not considered.

The most useful output was not only the risk score. The findings and remediation guidance made the assessment easier to explain to both technical teams and auditors.

## Conclusion

The analyzer successfully connected to AWS, reviewed six IAM entities, calculated risk scores, and generated JSON and CSV evidence.

It identified one user with administrative access and one role with unrestricted wildcard permissions.

The assessment also revealed a limitation in the resource parsing logic when evaluating an S3 object ARN.

This project demonstrated how Python and Boto3 can support repeatable IAM access reviews. It also reinforced the importance of validating automated findings before using them for compliance decisions.

## Attribution

This project was completed as part of a GRC Engineering Club lab.

The original instructional materials and source code are not included in this repository. This repository documents my implementation, testing process, findings, evidence, and lessons learned.

AWS account identifiers were redacted from all public screenshots and evidence files.
