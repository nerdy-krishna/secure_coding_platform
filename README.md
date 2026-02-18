# AI-Powered Secure Coding & Compliance Automation Platform

This is an open-source, AI-powered tool designed to help developers and security teams audit code for vulnerabilities and apply intelligent remediations automatically. The platform's "Audit-First, Remediate-Intelligently" approach ensures full control and visibility throughout the security analysis process.

## Key Features

* **Comprehensive Code Auditing**: Submit your code by uploading files, providing a Git repository URL, or uploading a project archive (`.zip`, `.tar.gz`). The system performs a deep analysis to identify security vulnerabilities.
* **Intelligent, AI-Powered Remediation**: Go beyond just finding issues. Select vulnerabilities and let the platform's multi-agent system generate precise code fixes.
* **Transparent Cost Estimation**: The platform provides a detailed cost estimate for the full, in-depth vulnerability scan, allowing for approval of the major analysis cost upfront. A small, initial analysis is performed using an AI model to understand the code structure and determine which security specialists are needed. The main, intensive scan only proceeds after your explicit approval of the provided estimate.
* **Selective Scanning**: Use the interactive file tree to include or exclude specific files and folders from the analysis, saving time and reducing costs by focusing only on relevant code.
* **Downloadable Fixes**: Once remediation is complete, download the entire fixed codebase as a convenient zip archive.
* **In-Depth Reporting**:
    * **Executive Summary**: Get a high-level, downloadable PDF summary of the security posture, perfect for stakeholders.
    * **Detailed Findings**: Explore each vulnerability with details on CWE, severity, and remediation advice.
    * **Risk Score**: Understand the project's security risk at a glance with a calculated risk score.
* **Multi-Provider LLM Support**: Choose from a range of Large Language Model providers, including OpenAI, Google, and Anthropic, for analysis needs.
* **Proactive Security Advisor**: Engage with a built-in chat to get proactive guidance and ask security-related questions about the project.
* **Test-Validated Remediation (Coming Soon)**: The remediation process will soon integrate with existing test suites to ensure that automated fixes do not break the application's functionality.

## How It Works: A Simplified Workflow

1.  **Submit**: Upload your code and select the files you want to scan.
2.  **Estimate**: The platform analyzes the code to provide a cost estimate for the audit.
3.  **Approve**: Review the cost and approve the scan to proceed.
4.  **Analyze**: AI agents perform a parallel audit to identify vulnerabilities.
5.  **Review**: Examine the detailed findings and the executive summary report.
6.  **Remediate**: Select vulnerabilities for automatic fixing.
7.  **Download**: Download the patched codebase.

## Installation

### Automatic Setup (Recommended)
We provide automated scripts to set up the environment, build containers, and initialize the database.

**macOS / Linux:**
```bash
git clone https://github.com/nerdy-krishna/secure_coding_platform.git
cd secure_coding_platform
chmod +x setup.sh
./setup.sh
```

**Windows:**
Double-click `setup.bat` or run it from the command line.

### Manual Setup
For detailed manual installation instructions, please refer to the [Installation Guide](docs/docs/getting-started/installation.md).

## Getting Started

1.  **Register**: Create an account on the platform.
2.  **Configure LLMs**: Navigate to **Admin > LLM Settings** to add your LLM provider configurations. This step requires superuser privileges and must be completed before running a scan. You will need to provide your API key, select the model, and set the token costs.
3.  **Submit Code**: Once the LLMs are configured, go to the "Submit Code" page.
4.  **Analyze**: Choose your submission method, select from the configured AI models, and start the analysis.
5.  **Approve & Review**: Follow the on-screen prompts to approve the cost and review your report.