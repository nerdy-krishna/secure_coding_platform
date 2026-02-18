# Grafana & Loki: Layman's Guide to Logging

This guide is designed to help you use the **Grafana** dashboard and **Loki** (the logging system) without needing to be an expert. It will show you exactly how to find what's broken or what the system is doing.

## 1. Quick Access
- **URL:** [http://localhost:3000](http://localhost:3000)
- **Login:** `admin` / `admin` (skip password change if prompted)
- **Go to Logs:** Click the **Compass Icon (Explore)** in the left sidebar.

## 2. The Simple 3-Step Process

Every time you want to find something, follow these 3 steps:

1.  **Select Datasource:** Ensure the dropdown at the top-left says **Loki**.
2.  **Paste Query:** Copy one of the queries below into the "Log browser" box (make sure "Code" button is selected).
3.  **Run Query:** Click the blue **"Run query"** button at the top right.

> **💡 Pro Tip:** Don't forget to check the **Time Range** picker (next to the Run button). If you ran a scan 2 hours ago, set it to "Last 3 hours".

---

## 3. How to Find Specific Information

### 🔍 Finding LLM Prompts (What did we verify?)
To see exactly what text was sent to the AI model during a scan:
1.  Copy this query:
    ```logql
    {service_name="worker"} |= "Final prompt_text"
    ```
2.  Click **Run query**.
3.  Look for lines starting with `DEBUG: [AgentName]`. Click on a log line to expand it and read the full prompt.

### ❌ finding Errors (Why did it fail?)
To filter for error messages across the entire system:
1.  Copy this query:
    ```logql
    {level="ERROR"}
    ```
2.  Click **Run query**.
    *   This shows errors from both the **App** (API) and **Worker** (Scanning).

To filter for errors *only* in the backend worker (where scans happen):
    ```logql
    {service_name="worker", level="ERROR"}
    ```

### 🆔 Tracking a Specific Scan
If you have a Scan ID (e.g., from the URL or database), use it to find *everything* related to that scan:
1.  Copy this query (replace `YOUR-SCAN-ID` with the actual ID):
    ```logql
    {service_name="worker"} |= "YOUR-SCAN-ID"
    ```
2.  This will show the entire timeline: scan start, file analysis, agent actions, and completion.

### 🧩 Analyzing Specific Agent Behavior
To see what a specific agent (e.g., `ClientSideAgent`) is doing:
1.  Copy this query:
    ```logql
    {service_name="worker"} |= "ClientSideAgent"
    ```
2.  This filters logs to only show lines containing that agent's name.

---

## 4. Cheat Sheet: Copy & Paste Queries

| **I want to find...** | **Query to Paste** |
| :--- | :--- |
| **All App Logs (API)** | `{service_name="app"}` |
| **All Worker Logs (Scans)** | `{service_name="worker"}` |
| **Detailed Errors** | `{level="ERROR"}` |
| **LLM Prompts** | `{service_name="worker"} |= "Final prompt_text"` |
| **LLM Responses** | `{service_name="worker"} |= "parsed_output"` |
| **Specific Text** | `{service_name="worker"} |= "search term here"` |

---

## 5. Understanding the Log "Labels"
When you expand a log line, you'll see "Labels". These are key details about the log:
*   **`service_name`**: Who created the log? (e.g., `worker` = scanner, `app` = backend API)
*   **`level`**: How important is it? (`INFO` = normal, `ERROR` = something broke, `WARNING` = potentially bad)
*   **`logger_name`**: Which part of the code created it? (e.g., `app.infrastructure.agents`)

## 6. Common Issues & Fixes
*   **"No Data"**:
    *   Check your **Time Range** (top right). Is it set to "Last 5 minutes" but the scan happened 10 minutes ago?
    *   Did the service actually run? Check if the docker container is up: `docker ps`.
*   **Logs look cut off**:
    *   Click on the log line to expand it. The summary view truncates long messages.
*   **Timestamps look wrong**:
    *   Logs use UTC (Universal Time). Check if there's a timezone difference with your local time.
