# src/app/utils/reporting_utils.py

from typing import List, Dict, Any

from app.agents.schemas import VulnerabilityFinding

def create_sarif_report(findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
    """
    Creates a SARIF 2.1.0 compliant report from a list of vulnerability findings.

    Args:
        findings: A list of Pydantic VulnerabilityFinding objects.

    Returns:
        A dictionary representing the SARIF report.
    """
    results = []
    rules = {}

    for finding in findings:
        rule_id = finding.cwe if finding.cwe else "CWE-Unknown"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"Vulnerability/{rule_id}",
                "shortDescription": {"text": f"Vulnerability Type: {rule_id}"},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.split('-')[-1]}.html"
            }

        result = {
            "ruleId": rule_id,
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number},
                    }
                }
            ],
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "remediation": finding.remediation,
                "references": finding.references,
                "tags": ["security", finding.severity]
            },
        }
        results.append(result)

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secure Coding Platform SARIF Report",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }