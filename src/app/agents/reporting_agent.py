import logging
import datetime
from typing import TypedDict, List, Optional, Dict, Any

from langgraph.graph import StateGraph, END
# No LLM calls are typically made by the ReportingAgent itself; it processes existing data.

logger = logging.getLogger(__name__)


# --- State Definition for ReportingAgent ---
class ReportingAgentState(TypedDict):
    submission_id: int
    collated_findings: List[Dict[str, Any]]  # Output from assemble_and_collate_node
    # For context, like original code for snippets or file paths
    files_data: List[
        Dict[str, Any]
    ]  # Each: {"filename": str, "content": str, "detected_language": str}
    primary_language: Optional[str]
    # Suggested fixes (filename -> fixed_code_string) from assemble_and_collate_node
    final_fixed_code_map: Optional[Dict[str, str]]

    # Outputs produced by this agent
    json_report_data: Optional[Dict[str, Any]]
    sarif_report_data: Optional[Dict[str, Any]]  # SARIF is JSON structure
    text_summary_data: Optional[str]  # A simple text summary

    # This will be the final output packaged for the database
    # It can contain the structured json_report_data and references or summaries of others.
    final_structured_report: Optional[Dict[str, Any]]
    error_message: Optional[str]


# --- Node Functions ---


def generate_json_report_node(state: ReportingAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    collated_findings = state.get("collated_findings", [])
    files_data = state.get("files_data", [])
    final_fixed_code_map = state.get("final_fixed_code_map", {})
    logger.info(
        f"ReportingAgent Node: generate_json_report_node for Submission ID: {submission_id}"
    )

    original_code_map = {f["filename"]: f["content"] for f in files_data}

    # Basic summary
    num_findings = 0
    num_errors = 0
    critical_issues_count = 0
    high_issues_count = 0
    medium_issues_count = 0
    low_issues_count = 0

    for finding_item in collated_findings:
        if finding_item.get("is_error"):
            num_errors += 1
        else:
            num_findings += 1
            severity = (
                finding_item.get("details", {}).get("severity", "Unknown").lower()
            )
            if severity == "critical":  # Assuming critical might be used
                critical_issues_count += 1
            elif severity == "high":
                high_issues_count += 1
            elif severity == "medium":
                medium_issues_count += 1
            elif severity == "low":
                low_issues_count += 1

    report_summary = (
        f"Analysis for submission {submission_id} completed. "
        f"Found {num_findings} potential vulnerabilities/issues and {num_errors} processing errors. "
        f"Severity Summary: Critical-{critical_issues_count}, High-{high_issues_count}, "
        f"Medium-{medium_issues_count}, Low-{low_issues_count}."
    )

    json_report = {
        "report_schema_version": "1.0.0",
        "submission_id": submission_id,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": report_summary,
        "statistics": {
            "total_findings_issues": len(collated_findings),
            "vulnerability_findings": num_findings,
            "processing_errors": num_errors,
            "severity_counts": {
                "critical": critical_issues_count,
                "high": high_issues_count,
                "medium": medium_issues_count,
                "low": low_issues_count,
            },
        },
        "detailed_findings": collated_findings,  # Contains all details, source, context
        "original_code_snippets": original_code_map,  # May need to be selective for large projects
        "suggested_fixes": final_fixed_code_map,
    }
    logger.debug(f"JSON report generated for Submission ID: {submission_id}")
    return {"json_report_data": json_report}


async def generate_basic_sarif_report_node(
    state: ReportingAgentState,
) -> Dict[str, Any]:  # Made async
    submission_id = state["submission_id"]
    collated_findings = state.get("collated_findings", [])
    # files_data is available in 'state' if needed for more complex URI generation, but not directly used in this basic version.
    primary_language_from_state = state.get("primary_language", "unknown")
    logger.info(
        f"ReportingAgent Node: generate_basic_sarif_report_node for Submission ID: {submission_id}"
    )

    rules = []
    results = []

    rule_id_map = {}
    rule_idx_counter = 0

    for idx, item in enumerate(collated_findings):
        if item.get("is_error"):
            continue

        details = item.get("details", {})
        description = details.get("description", "Unknown issue")
        recommendation = details.get("recommendation", "No specific recommendation.")
        severity = details.get("severity", "Medium").lower()
        asvs_id = details.get("asvs_id", "")

        cwe_ids_from_finding = []
        # Assuming 'cwe_mapping' is a list of dicts like [{"description": "...", "cwe_id": "CWE-XXX"}]
        # This comes from the map_to_standards_node of specialized agents.
        raw_cwe_info = details.get("cwe_mapping")
        if isinstance(raw_cwe_info, list):
            for cwe_entry in raw_cwe_info:
                if isinstance(cwe_entry, dict) and cwe_entry.get("cwe_id"):
                    cwe_ids_from_finding.append(str(cwe_entry.get("cwe_id")))

        rule_key = f"{asvs_id}_{description[:50]}"  # Create a more stable rule key
        if not asvs_id:  # Fallback if asvs_id is missing
            rule_key = description[:50]

        if rule_key not in rule_id_map:
            rule_id_map[rule_key] = (
                f"SCP-{rule_idx_counter:03d}"  # Use a simpler prefix
            )
            rules.append(
                {
                    "id": rule_id_map[rule_key],
                    "shortDescription": {"text": description[:120]},
                    "fullDescription": {"text": description},
                    "helpUri": f"https://example.com/docs/rules/{rule_id_map[rule_key]}",  # Placeholder
                    "help": {
                        "text": recommendation,
                        "markdown": f"**Recommendation:**\n{recommendation}",
                    },
                    "defaultConfiguration": {
                        "level": "warning"
                        if severity in ["medium", "low", "informational", "info"]
                        else "error"
                    },
                    "properties": {
                        "tags": ["security", primary_language_from_state, asvs_id]
                        if asvs_id
                        else ["security", primary_language_from_state],
                        "precision": "medium",
                        "asvs_id": asvs_id,
                        "cwe": cwe_ids_from_finding,  # List of CWE IDs (e.g., ["CWE-79", "CWE-89"])
                    },
                }
            )
            rule_idx_counter += 1

        file_path_str = item.get("filename", "unknown_file")
        # For SARIF, URIs are often relative to a checkout root, or fully qualified.
        # Using filename directly for now.
        file_uri = file_path_str

        line_start = details.get("line_start")
        line_end = details.get("line_end", line_start)
        try:
            line_start = int(line_start) if line_start is not None else 1
            line_end = int(line_end) if line_end is not None else line_start
        except (ValueError, TypeError):
            line_start = 1
            line_end = 1

        result_item = {
            "ruleId": rule_id_map[rule_key],
            "level": "warning"
            if severity in ["medium", "low", "informational", "info"]
            else "error",
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri},
                        "region": {
                            "startLine": line_start,
                            "endLine": line_end,
                        },
                    }
                }
            ],
        }
        results.append(result_item)

    sarif_log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureCodePlatform Agent Analysis",
                        "version": "0.2.0",
                        "informationUri": "https://example.com/your-project-docs",  # Replace with actual URI
                        "language": primary_language_from_state
                        if primary_language_from_state != "unknown"
                        else "en-US",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.datetime.now(
                            datetime.timezone.utc
                        ).isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }
    logger.debug(
        f"Enhanced Basic SARIF report generated for Submission ID: {submission_id}"
    )
    return {"sarif_report_data": sarif_log, "error_message": state.get("error_message")}


def generate_text_summary_node(state: ReportingAgentState) -> Dict[str, Any]:
    submission_id = state["submission_id"]
    collated_findings = state.get("collated_findings", [])
    logger.info(
        f"ReportingAgent Node: generate_text_summary_node for Submission ID: {submission_id}"
    )

    if not collated_findings:
        return {"text_summary_data": "No findings or errors to summarize."}

    summary_lines = [f"Text Summary for Submission ID: {submission_id}\n" + "=" * 40]

    for i, finding_item in enumerate(collated_findings):
        source = finding_item.get("source", "Unknown Source")
        filename = finding_item.get("filename", "N/A")
        details = finding_item.get("details", {})

        summary_lines.append(f"\nFinding {i + 1}:")
        summary_lines.append(f"  Source: {source}")
        summary_lines.append(f"  File: {filename}")

        if finding_item.get("is_error"):
            summary_lines.append(
                f"  Error: {details.get('error_message', 'Unknown error')}"
            )
        else:
            description = details.get("description", "N/A")
            severity = details.get("severity", "N/A")
            line_start = details.get("line_start", "N/A")
            recommendation = details.get("recommendation", "N/A")
            asvs_id = details.get("asvs_id", "N/A")

            summary_lines.append(f"  Description: {description}")
            summary_lines.append(f"  Severity: {severity}")
            summary_lines.append(f"  Line: {line_start}")
            summary_lines.append(f"  ASVS ID: {asvs_id}")
            summary_lines.append(f"  Recommendation: {recommendation}")

        trigger_context = finding_item.get("trigger_context")
        if trigger_context and isinstance(trigger_context, dict):
            summary_lines.append(
                f"  Trigger Context: "
                f"Area: {trigger_context.get('triggering_area', 'N/A')}, "
                f"Likelihood: {trigger_context.get('likelihood_from_context_analysis', 'N/A')}"
            )

    text_summary = "\n".join(summary_lines)
    logger.debug(f"Text summary generated for Submission ID: {submission_id}")
    return {"text_summary_data": text_summary}


def compile_final_report_node(state: ReportingAgentState) -> Dict[str, Any]:
    """
    Compiles all generated report data into a single dictionary
    that will be stored in the database.
    """
    submission_id = state["submission_id"]
    logger.info(
        f"ReportingAgent Node: compile_final_report_node for Submission ID: {submission_id}"
    )

    # The main JSON report already contains most of the necessary information.
    # We will use it as the base and can add references or summaries of other formats if needed.
    # For now, the json_report_data will be the primary structured report.
    # SARIF and Text can be stored separately if the DB schema allows, or embedded/referenced.
    # The `AnalysisResult.report_content` in DB is JSON, so `json_report_data` fits well.
    # We can add SARIF and Text into this main JSON blob.

    final_structured_report = state.get("json_report_data", {})

    # Embed or reference other formats
    if state.get("sarif_report_data"):
        final_structured_report["sarif_report"] = state.get("sarif_report_data")
    if state.get("text_summary_data"):
        final_structured_report["text_summary"] = state.get("text_summary_data")

    if not final_structured_report:
        return {"error_message": "No report data was generated."}

    return {
        "final_structured_report": final_structured_report,
        "error_message": state.get("error_message"),
    }


# --- Graph Construction ---
def build_reporting_agent_graph() -> Any:
    """Builds and returns the compiled LangGraph for the ReportingAgent."""
    graph = StateGraph(ReportingAgentState)

    graph.add_node("generate_json_report", generate_json_report_node)
    graph.add_node("generate_basic_sarif_report", generate_basic_sarif_report_node)
    graph.add_node("generate_text_summary", generate_text_summary_node)
    graph.add_node("compile_final_report", compile_final_report_node)

    # Define the workflow: Generate all reports in parallel (conceptually) then compile.
    # For LangGraph, we can run them sequentially or use a parallel construct if needed.
    # For simplicity, running sequentially here.
    graph.set_entry_point("generate_json_report")
    graph.add_edge("generate_json_report", "generate_basic_sarif_report")
    graph.add_edge("generate_basic_sarif_report", "generate_text_summary")
    graph.add_edge("generate_text_summary", "compile_final_report")
    graph.add_edge("compile_final_report", END)

    compiled_graph = graph.compile()
    logger.info("ReportingAgent graph compiled successfully.")
    return compiled_graph
