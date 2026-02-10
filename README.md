# CATE Webhook Hook Server Examples

Example webhook servers for the CATE (Contextual Access for Tool Execution) hook system. These servers implement the webhook protocol for the three hook points: `tool.access`, `tool.pre`, and `tool.post`.

## Examples

### Full Server (with Web UI)

A comprehensive hook server with a web dashboard for configuration. Includes all features: rules, PII redaction, A/B testing, and tool catalog integration.

```bash
go run ./examples/full_server
# Open http://localhost:8888/ for the dashboard
```

[Full documentation](examples/full_server/README.md)

### Basic Rules

A configurable test server with YAML-based rule configuration and hot-reload.

```bash
go run ./examples/basic_rules -config ./examples/basic_rules/example-config.yaml
```

[Full documentation](examples/basic_rules/README.md)

### Content Filter

Demonstrates blocking users, filtering toolkits, and rejecting requests based on content matching.

```bash
go run ./examples/content_filter
```

[Full documentation](examples/content_filter/README.md)

### PII Redactor

Demonstrates detecting and redacting personally identifiable information (emails, IPs, SSNs, phone numbers, credit cards, dates of birth) from tool outputs.

```bash
go run ./examples/pii_redactor
```

[Full documentation](examples/pii_redactor/README.md)

### A/B Testing

Demonstrates routing tool executions to different server variants for A/B testing and canary deployments.

```bash
go run ./examples/ab_testing
```

[Full documentation](examples/ab_testing/README.md)

## Hook Points

All examples implement the three CATE webhook hook points:

| Hook Point    | Endpoint | Purpose                                    |
| ------------- | -------- | ------------------------------------------ |
| `tool.access` | `/access`| Control which tools a user can see         |
| `tool.pre`    | `/pre`   | Validate/modify requests before execution  |
| `tool.post`   | `/post`  | Filter/modify responses after execution    |

Plus a health check at `/health`.

## Response Codes

| Code                  | Meaning                   |
| --------------------- | ------------------------- |
| `OK`                  | Allow / proceed           |
| `CHECK_FAILED`        | Block / deny              |
| `RATE_LIMIT_EXCEEDED` | Rate limit exceeded       |

## Schema

The webhook request/response types are generated from the [CATE webhook schema](https://github.com/ArcadeAI/schemas/blob/main/logical_extensions/http/1.0/schema.yaml) using oapi-codegen. See `pkg/server/` for the generated types.
