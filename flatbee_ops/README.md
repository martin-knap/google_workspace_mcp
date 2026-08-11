# Flatbee Ops MCP

Curated company-level tool surface built into Workspace MCP. It keeps Google
OAuth and Drive ACL enforcement in the existing Workspace runtime and composes:

- Twenty for current exact structured state;
- Workspace semantic search and the PDF/AnyDoc document reader for evidence;
- Graphiti for relationships and temporal context;
- a durable SQLite workflow registry.

The initial workflow DSL is deliberately read-only. Definitions may contain
only `semantic_search`, `document_read`, `twenty_query`, and `graph_search`
steps. Creating or updating a workflow uses an actor-bound, expiring immutable
plan and exact plan-ID confirmation. Arbitrary MCP tool execution is not part of
the DSL.

Runtime settings:

- `FLATBEE_OPS_ALLOWED_EMAILS`: exact comma-separated allowlist;
- `FLATBEE_OPS_DB`: persistent SQLite path;
- `TWENTY_BASE_URL` and `TWENTY_API_KEY`: Twenty read client;
- `GRAPHITI_MCP_URL` and `GRAPHITI_MCP_SERVICE_TOKEN`: internal read-only
  Graphiti MCP hop.

Load only this curated service with:

```bash
workspace-mcp --transport streamable-http --tools flatbee_ops --tool-tier core
```

