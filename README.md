# Hook Server Examples

Example webhook servers implementing the CATE (Contextual Access for Tool Execution) hook system. These servers handle access control, pre-execution validation, and post-execution filtering for tool calls.

## Examples

### Advanced Server (Full-Featured with Web UI)

A comprehensive server combining all features with a browser-based dashboard for configuration.

- **[examples/contextual_access/advanced_server/](examples/contextual_access/advanced_server/)** - Access rules, PII redaction, A/B testing, and a web UI

### Focused Examples (Single-Purpose, No UI)

Minimal servers demonstrating individual hook capabilities:

| Example | Description | Hook Points Used |
| ------- | ----------- | ---------------- |
| **[user_blocking](examples/contextual_access/user_blocking/)** | Block specific users from tools | Access, Pre |
| **[content_filter](examples/contextual_access/content_filter/)** | Filter/block based on content | Access, Pre, Post |
| **[pii_redactor](examples/contextual_access/pii_redactor/)** | Detect and redact PII in outputs | Post |
| **[ab_testing](examples/contextual_access/ab_testing/)** | A/B and canary test tool versions | Pre |
| **[basic_rules](examples/contextual_access/basic_rules/)** | Configurable rules for all hooks | Access, Pre, Post |

## Quick Start

```bash
# Run the advanced server with the web dashboard
go run ./examples/contextual_access/advanced_server -config ./examples/contextual_access/advanced_server/example-config.yaml

# Or run a focused example
go run ./examples/contextual_access/pii_redactor -types "email,ssn,credit_card"
go run ./examples/contextual_access/user_blocking -block "user1,user2"
go run ./examples/contextual_access/content_filter -config ./examples/contextual_access/content_filter/example-config.yaml
go run ./examples/contextual_access/ab_testing -config ./examples/contextual_access/ab_testing/example-config.yaml
```

## Hook Points

These servers implement webhook endpoints that integrate with an engine's hook system:

| Endpoint | Purpose |
| -------- | ------- |
| `GET /health` | Health check |
| `POST /access` | Control which tools users can see |
| `POST /pre` | Validate/modify tool inputs before execution |
| `POST /post` | Validate/modify tool outputs after execution |

Post-hook requests from remote MCP servers also carry `content`, the content blocks the server returned alongside `output`. The examples that redact or filter `output` apply the same change to `content` and return it as `override.content`. MCP gateways render only text blocks, so pii_redactor and content_filter handle just those; advanced_server handles every block.

## Architecture

```
Engine Request Flow
────────────────────────────────────────────────►

     ↓                    ↓                    ↓
┌─────────┐         ┌─────────┐         ┌─────────┐
│ ACCESS   │         │   PRE   │         │  POST   │
│ Hook     │         │  Hook   │         │  Hook   │
└────┬────┘         └────┬────┘         └────┬────┘
     │                    │                    │
     ▼                    ▼                    ▼
 Can user see       Can user run         Filter/modify
 this tool?         this tool?           the output?
```

## Project Structure

```
├── examples/
│   └── contextual_access/
│       ├── advanced_server/    # Full-featured server with web UI
│       ├── basic_rules/        # Configurable rules (original example)
│       ├── user_blocking/      # Block specific users
│       ├── content_filter/     # Content-based filtering
│       ├── pii_redactor/       # PII detection and redaction
│       └── ab_testing/         # A/B and canary testing
├── pkg/
│   └── server/             # Generated types from OpenAPI schema
├── go.mod
└── go.sum
```
