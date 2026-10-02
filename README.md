# terraform-cloud-security

Inspect Terraform plan JSON for selected AWS configuration risks before deployment.

## Run

Requires Python 3.10+ on Windows, Linux or macOS. No dependencies.

```bash
python scanner.py sample.json
python scanner.py sample.json --output report.json --fail-on-high
python -m unittest -v
```

Exit codes: 0 = completed, 1 = high findings with --fail-on-high, 2 = invalid input or I/O failure.

## Scope

Input: terraform show -json output for a saved plan. Checks RDS public accessibility/encryption, EBS encryption and CloudTrail multi-region settings, including nested modules. Unknown values are reported separately. Only these AWS resource types are covered.

Reports include severity, resource, check, detail and remediation. No cloud credentials are needed; these tools inspect local JSON only. A clean report means none of the implemented checks matched, not that the cloud account is secure. Treat inventory and Terraform plans as sensitive; do not commit real account data. Sample data is fictional.

## Publish

```powershell
git init
git add .
git commit -m "Initial cloud security scanner"
gh repo create terraform-cloud-security --public --source . --remote origin --push
```

