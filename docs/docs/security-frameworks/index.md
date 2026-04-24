---
sidebar_position: 1
title: Security Frameworks Overview
---

# Security Frameworks

SCCAP ships with three default OWASP frameworks and supports any
number of custom frameworks added by admins. Every scan is tagged
with one or more frameworks at submission time; the tag controls
both RAG retrieval for the Advisor and how the Compliance page
rolls up findings.

- [**Supported Frameworks**](./supported-frameworks.md) — the 3
  defaults + how admins add custom ones.
- [Multi-Framework Scanning (user guide)](../user-guide/code-analysis/multi-framework-scanning.md) — picking frameworks at submit time.
- [Updating Framework Knowledge (developer guide)](../development/updating-framework-knowledge.md)
  — CSV / Git-URL ingestion walkthrough.
