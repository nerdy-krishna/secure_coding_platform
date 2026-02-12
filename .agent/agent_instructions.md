# Agent Operational Guidelines

This document serves as the primary instruction set for the Antigravity agent when working on the Secure Coding Platform.

## 1. Project Structure Maintenance
- **Requirement:** The project structure file (`.agent/PROJECT_STRUCTURE.md`) must be kept up-to-date.
- **Action:** Whenever new files are created, deleted, or significantly refactored, update the directory tree and file dictionary to reflect the current state of the codebase.

## 2. Missing Code Recovery
- **Requirement:** Use the provided recovery files as the source of truth for missing code.
- **Action:** If a file or code block is missing in the local repository, refer to `.agent/backend.txt` or `.agent/frontend.txt` to retrieve the original implementation.

## 3. Version Control
- **Requirement:** All changes must be committed to GitHub.
- **Action:** After completing a task or a logical unit of work, stage and commit the changes with a clear, descriptive commit message. Ensure these changes are pushed to the remote repository.