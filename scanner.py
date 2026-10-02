"""Inspect Terraform plan JSON for selected AWS configuration risks before deployment."""
def resources(module):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from resources(child)

def audit(data):
    findings = []
    planned = data.get("planned_values", {}).get("root_module", {})
    unknowns = {r.get("address"): r.get("change", {}).get("after_unknown", {}) for r in data.get("resource_changes", [])}
    for resource in resources(planned):
        if resource.get("mode", "managed") != "managed":
            continue
        kind, values = resource.get("type"), resource.get("values") or {}
        checks = {"aws_db_instance": [("publicly_accessible", False, "RDS_PUBLIC"), ("storage_encrypted", True, "RDS_ENCRYPTION")],
                  "aws_ebs_volume": [("encrypted", True, "EBS_ENCRYPTION")],
                  "aws_cloudtrail": [("is_multi_region_trail", True, "TRAIL_MULTI_REGION")]}
        for field, safe, check in checks.get(kind, []):
            value = values.get(field)
            unknown = unknowns.get(resource["address"], {}).get(field)
            if unknown or value is None:
                severity, detail = "UNKNOWN", f"{field} is absent or unknown until apply."
            elif value == safe:
                continue
            else:
                severity, detail = "HIGH", f"{field} is set to {value!r}."
            findings.append({"resource": resource["address"], "severity": severity, "check": check, "detail": detail, "remediation": f"Review and set {field} to {safe!r} when appropriate."})
    return findings

import argparse
import json
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input JSON file")
    parser.add_argument("--output", type=Path, help="Write JSON report")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 when HIGH findings exist")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Input must be a JSON object")
        findings = audit(data)
        report = {"findings": findings, "finding_count": len(findings), "scope": "Only documented checks and supplied input are evaluated."}
        text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(f["severity"] == "HIGH" for f in findings))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"Invalid input or report error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

