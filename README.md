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

