# Full Hook Server

A comprehensive CATE webhook hook server with a web UI for configuration. It implements all webhook endpoints (`/health`, `/access`, `/pre`, `/post`) with:

- **Rule-based access control** - Block users, filter toolkits/tools, pattern matching
- **Pre-execution hooks** - Block or modify requests before tool execution
- **Post-execution hooks** - Block or modify responses after tool execution
- **PII redaction** - Detect and redact personally identifiable information
- **A/B testing** - Route tool executions to different variants with traffic splitting
- **Tool catalog integration** - Fetch tools from an external API for experimentation
- **Web UI** - Configure everything through a modern dashboard

## Quick Start

```bash
# Run with defaults (port 8888, no auth)
go run ./examples/full_server

# Run with a specific config file
go run ./examples/full_server -config ./examples/full_server/default-config.yaml

# Run with authentication
go run ./examples/full_server -token "my-secret-token"

# Run with TLS
go run ./examples/full_server -tls -cert server.crt -key server.key
```

Then open http://localhost:8888/ in your browser to access the dashboard.

## Command Line Flags

| Flag       | Default        | Description                                          |
| ---------- | -------------- | ---------------------------------------------------- |
| `-port`    | `8888`         | Port to listen on                                    |
| `-token`   | `""`           | Bearer token for authentication (empty = no auth)    |
| `-verbose` | `true`         | Log all requests to stdout                           |
| `-config`  | `config.yaml`  | Path to YAML configuration file                      |
| `-tls`     | `false`        | Enable TLS/HTTPS                                     |
| `-cert`    | `""`           | Path to server certificate (PEM)                     |
| `-key`     | `""`           | Path to server private key (PEM)                     |
| `-ca`      | `""`           | Path to CA certificate for mTLS                      |

## Features

### 1. Access Control (tool.access hook)

Control which tools users can see based on user ID, toolkit name, or tool name.

- **Default action**: Allow or deny all unmatched requests
- **Pattern matching**: Exact, glob (`Admin*`), or regex (`~^test-.*`)
- **First-match wins**: Rules are evaluated in order

### 2. Pre-Execution Rules (tool.pre hook)

Validate and modify requests before tool execution:

- **Block** requests based on user, toolkit, tool, or input content
- **Rate limit** specific tools
- **Override** inputs, secrets, headers, or server routing
- **Content matching**: Check if inputs contain specific values

### 3. Post-Execution Rules (tool.post hook)

Filter and transform responses after tool execution:

- **Block** responses based on success/failure or output content
- **Override** output values (e.g., replace sensitive data)

### 4. PII Redaction

Automatically detect and handle personally identifiable information:

- **Supported types**: Email, IP address, SSN, phone number, credit card, date of birth
- **Modes**: Redact (replace with placeholders) or Block (reject response)
- **Custom patterns**: Add your own regex patterns for domain-specific PII
- **Test tool**: Try redaction before enabling in the dashboard

### 5. A/B Testing

Route tool executions to different server variants:

- **Traffic splitting**: Percentage-based distribution between variants
- **Sticky assignment**: Same user always gets the same variant (hash-based)
- **User targeting**: Include/exclude users by pattern
- **Canary deploys**: Start with small percentage, gradually increase

### 6. Tool Catalog Integration

Fetch tools from an external API:

- **Periodic fetching**: Configurable interval
- **Tool browsing**: View fetched tools in the dashboard
- **A/B test setup**: Use fetched tools to create experiments

## Endpoints

### Webhook Endpoints (CATE Protocol)

| Method | Path      | Description           |
| ------ | --------- | --------------------- |
| GET    | `/health` | Health check          |
| POST   | `/access` | Access control hook   |
| POST   | `/pre`    | Pre-execution hook    |
| POST   | `/post`   | Post-execution hook   |

### API Endpoints

| Method | Path                 | Description                    |
| ------ | -------------------- | ------------------------------ |
| GET    | `/api/config`        | Get full configuration         |
| PUT    | `/api/config`        | Update configuration           |
| GET    | `/api/logs`          | Get request logs               |
| DELETE | `/api/logs`          | Clear request logs             |
| GET    | `/api/status`        | Server status                  |
| POST   | `/api/pii/test`      | Test PII redaction             |
| POST   | `/api/arcade/fetch`  | Trigger tool catalog fetch     |
| GET    | `/api/arcade/tools`  | Get cached tools               |
| GET    | `/api/ab/assignments`| Get A/B variant assignments    |
| DELETE | `/api/ab/assignments`| Clear variant assignments      |

### Web UI

| Path       | Description          |
| ---------- | -------------------- |
| `/`        | Dashboard            |

## Configuration File

The server uses a YAML configuration file (default: `config.yaml`). See `default-config.yaml` for a fully documented example.

The config file supports hot-reload - changes are picked up automatically.

## Integration

Configure a webhook plugin to point to this server:

```yaml
plugins:
  - type: webhook
    name: full-hook-server
    config:
      endpoints:
        health: http://localhost:8888/health
        access: http://localhost:8888/access
        pre: http://localhost:8888/pre
        post: http://localhost:8888/post
      auth:
        type: bearer
        token: my-secret-token
      timeout: 5s
```
