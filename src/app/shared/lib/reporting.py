# src/app/shared/lib/reporting.py

import io
from typing import List, Dict, Any
from xhtml2pdf import pisa

from app.core.schemas import VulnerabilityFinding, ImpactReport
from app.api.v1.models import SummaryReportResponse

def generate_pdf_from_html(html_content: str) -> bytes:
    """
    Converts an HTML string into a PDF byte stream.
    """
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        src=io.StringIO(html_content),  # a readable source
        dest=pdf_buffer,                # a writeable dest
        encoding='utf-8'
    )
    if pisa_status.err: # type: ignore
        raise IOError(f"PDF generation failed: {pisa_status.err}") # type: ignore
    
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()

def create_executive_summary_html(impact_report: ImpactReport, summary_report: SummaryReportResponse) -> str:
    """
    Generates an HTML string for the executive summary PDF report.
    """
    # Basic CSS for styling the PDF
    html_style = """
    <style>
        @page { size: a4 portrait; margin: 1.5cm; }
        body { font-family: 'Helvetica', 'Arial', sans-serif; font-size: 11pt; color: #333; }
        h1 { font-size: 24pt; color: #1a237e; text-align: center; margin-bottom: 5px; }
        h2 { font-size: 16pt; color: #3949ab; border-bottom: 2px solid #ccc; padding-bottom: 5px; margin-top: 25px; }
        p { line-height: 1.4; }
        .subtitle { text-align: center; color: #555; font-size: 10pt; margin-bottom: 30px; }
        .summary-card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; background-color: #f9f9f9;}
        .summary-card-title { font-size: 12pt; font-weight: bold; color: #333; margin-top:0; }
        .findings-list { list-style-type: square; padding-left: 20px; }
        .findings-list li { margin-bottom: 8px; }
        .tag { display: inline-block; padding: 4px 8px; border-radius: 4px; color: #fff; font-size: 9pt; margin-right: 5px; }
        .tag-blue { background-color: #3498db; }
        .tag-orange { background-color: #f39c12; }
    </style>
    """

    # HTML Body
    html_body = f"""
    <h1>Executive Security Summary</h1>
    <p class="subtitle">
        <strong>Project:</strong> {summary_report.project_name} | <strong>Scan ID:</strong> {summary_report.submission_id}
    </p>

    <div class="summary-card">
        <p class="summary-card-title">Executive Overview</p>
        <p>{impact_report.executive_summary}</p>
    </div>

    <h2>Vulnerability Analysis</h2>
    <p>{impact_report.vulnerability_overview}</p>

    <h2>High-Risk Findings</h2>
    <ul class="findings-list">
        {''.join(f'<li>{item}</li>' for item in impact_report.high_risk_findings_summary)}
    </ul>

    <h2>Remediation Strategy</h2>
    <p>{impact_report.remediation_strategy}</p>
    <p><strong>Estimated Effort:</strong> <span class="tag tag-orange">{impact_report.estimated_remediation_effort}</span></p>

    <h2>Architectural Changes</h2>
    <ul class="findings-list">
         {''.join(f'<li>{item}</li>' for item in impact_report.required_architectural_changes) if impact_report.required_architectural_changes else '<li>None</li>'}
    </ul>

    <h2>Vulnerability Categories Found</h2>
    <p>
        {''.join(f'<span class="tag tag-blue">{cat}</span>' for cat in impact_report.vulnerability_categories)}
    </p>
    """

    return f"<html><head>{html_style}</head><body>{html_body}</body></html>"


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
