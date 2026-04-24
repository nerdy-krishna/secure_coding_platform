# SCCAP MCP server

FastMCP server mounted at `/mcp` on the main FastAPI app. Same JWT
auth as the REST API — an agentic client (Claude Code, Cursor, etc.)
sends `Authorization: Bearer <SCCAP_JWT>` and gets access to the same
user surface the UI has.

## Tools

| Name | Purpose |
|---|---|
| `sccap_submit_scan` | Start a scan from inline files **or** a public git URL. Returns `scan_id`. |
| `sccap_get_scan_status` | Current scan state + cost_details. |
| `sccap_get_scan_result` | Full findings + SARIF for a completed scan. |
| `sccap_approve_scan` | Release a `PENDING_COST_APPROVAL` scan — drives the LangGraph `Command(resume=...)` path. |
| `sccap_apply_fixes` | Apply AI-suggested fixes from a SUGGEST-mode scan; `finding_ids` optional subset. |
| `sccap_ask_advisor` | One-shot advisor Q&A with RAG context. Not session-persisted. |

Admin surfaces (user management, framework ingestion) stay REST-only —
they're human workflows, not agentic.

## Claude Code client config

Add to your MCP settings (Claude Code → Settings → MCP → Edit config):

```jsonc
{
  "mcpServers": {
    "sccap": {
      "transport": "http",
      "url": "http://localhost:8000/mcp/",
      "headers": {
        "Authorization": "Bearer <paste-your-sccap-jwt-here>"
      }
    }
  }
}
```

To get a JWT:

```bash
curl -sX POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=<email>&password=<password>" \
  | jq -r .access_token
```

## Rate limiting

MCP calls share the per-user bucket with UI calls. There's no separate
quota; invoking tools from Claude Code consumes the same allowance as
clicking through the UI.

## Protocol

Streamable HTTP (MCP 2024-11-05 spec). Not stdio; not SSE. This means
the same endpoint handles `initialize`, `tools/list`, `tools/call`, etc.
in one HTTP path.

## Adding a tool

1. Add a Pydantic input schema in `src/app/api/mcp/server.py`.
2. Decorate an `async def` with `@mcp.tool`.
3. Resolve the current user via `_current_user(session)` and check
   authz before dispatching to a service method.
4. Return a plain dict (FastMCP serialises it). Raise `ValueError` /
   `PermissionError` for user-visible errors.

No restart is needed under `--reload`; the next `tools/list` call
picks up the new tool automatically.
