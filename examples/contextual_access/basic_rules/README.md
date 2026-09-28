# Webhook Test Server

A configurable test server for validating the CATE webhook hook system. It implements all webhook endpoints (`/health`, `/access`, `/pre`, `/post`) with configurable behavior, request logging, and rule-based blocking/modification.

## Quick Start

```bash
# Run with defaults (port 8888, no auth, allow all)
go run ./examples/contextual_access/basic_rules

# Run with authentication
go run ./examples/contextual_access/basic_rules -token "my-secret-token"

# Run with configuration file (enables blocking/modification rules)
go run ./examples/contextual_access/basic_rules -config ./examples/contextual_access/basic_rules/example-config.yaml
```

## Command Line Flags

| Flag       | Default | Description                                          |
| ---------- | ------- | ---------------------------------------------------- |
| `-port`    | `8888`  | Port to listen on                                    |
| `-token`   | `""`    | Bearer token for authentication (empty = no auth)    |
| `-verbose` | `true`  | Log all requests to stdout                           |
| `-config`  | `""`    | Path to YAML configuration file (enables hot-reload) |

## Configuration File

The server can be configured via a YAML file that supports:

- **Access control**: Allow/deny tools based on user, toolkit, or tool name
- **Pre-execution hooks**: Block execution or modify inputs, secrets, headers, server routing
- **Post-execution hooks**: Block responses or modify outputs. An output override also clears the server's `content` blocks (sent by remote MCP servers), so clients get the new output instead of the original text.
- **Pattern matching**: Exact match, glob patterns (`*`), or regex (`~pattern`)

### Example Configuration

```yaml
# Health endpoint
health:
  status: healthy # healthy, degraded, unhealthy

# Access control - determines which tools a user can see
access:
  default_action: allow # allow or deny
  rules:
    - user_id: "blocked-user"
      action: deny
      reason: "User is suspended"

    - toolkit: "DangerousToolkit"
      action: deny

    - user_id: "~^admin-.*" # Regex: users starting with "admin-"
      toolkit: "Admin*" # Glob: toolkits starting with "Admin"
      action: allow

# Pre-execution hook - runs before tool execution
pre:
  default_action: proceed # proceed, block, or rate_limit
  rules:
    # Block based on input content
    - toolkit: "Email"
      tool: "sendEmail"
      input_match: "to contains @blocked.com"
      action: block
      error_message: "Blocked domain"

    # Modify inputs
    - toolkit: "FileSystem"
      action: proceed
      override:
        inputs:
          path: "/sandbox/"
        headers:
          X-Sandbox: "true"

    # Inject secrets
    - toolkit: "Database"
      action: proceed
      override:
        secrets:
          DB_PASSWORD: "test-password"

    # Reroute to different server
    - user_id: "test-user"
      action: proceed
      override:
        server:
          name: "test-worker"
          uri: "http://localhost:9999"
          type: "arcade"

# Post-execution hook - runs after tool execution
post:
  default_action: proceed
  rules:
    # Block failed executions
    - success: false
      action: block
      error_message: "Execution failed"

    # Redact output
    - toolkit: "Database"
      action: proceed
      override:
        output:
          data: "[REDACTED]"
```

### Pattern Matching

| Pattern | Example     | Description                             |
| ------- | ----------- | --------------------------------------- |
| Exact   | `user-123`  | Matches exactly "user-123"              |
| Glob    | `Admin*`    | Matches "Admin", "AdminTools", etc.     |
| Regex   | `~^test-.*` | Matches "test-user", "test-admin", etc. |
| Empty   | `""`        | Matches anything (wildcard)             |

### Input/Output Matching

For `input_match` and `output_match` fields:

```yaml
# Check if key exists
input_match: "api_key"

# Check exact value
input_match: "mode=production"

# Check if value contains substring
input_match: "email contains @example.com"
```

## Hot-Reload

When using a config file, the server watches for changes and automatically reloads. You can also update configuration via the API.

## Endpoints

### Webhook Endpoints

| Method | Path      | Description           |
| ------ | --------- | --------------------- |
| GET    | `/health` | Health check endpoint |
| POST   | `/access` | Access control hook   |
| POST   | `/pre`    | Pre-execution hook    |
| POST   | `/post`   | Post-execution hook   |

### Admin Endpoints

| Method | Path       | Description                 |
| ------ | ---------- | --------------------------- |
| GET    | `/_status` | Server status               |
| GET    | `/_logs`   | View all logged requests    |
| DELETE | `/_logs`   | Clear request logs          |
| GET    | `/_config` | View current configuration  |
| PUT    | `/_config` | Update configuration (JSON) |

## Testing Examples

### Block a User via API

```bash
curl -X PUT http://localhost:8888/_config \
  -H "Content-Type: application/json" \
  -d '{
    "access": {
      "default_action": "allow",
      "rules": [
        {"user_id": "bad-user", "action": "deny", "reason": "Blocked"}
      ]
    }
  }'
```

### Block a Tool Execution

```bash
curl -X PUT http://localhost:8888/_config \
  -H "Content-Type: application/json" \
  -d '{
    "pre": {
      "default_action": "proceed",
      "rules": [
        {
          "toolkit": "Email",
          "tool": "sendEmail",
          "action": "block",
          "error_message": "Email sending is disabled"
        }
      ]
    }
  }'
```

### Modify Tool Inputs

```bash
curl -X PUT http://localhost:8888/_config \
  -H "Content-Type: application/json" \
  -d '{
    "pre": {
      "default_action": "proceed",
      "rules": [
        {
          "toolkit": "FileSystem",
          "action": "proceed",
          "override": {
            "inputs": {"path": "/safe/directory/"}
          }
        }
      ]
    }
  }'
```

### Redact Output

```bash
curl -X PUT http://localhost:8888/_config \
  -H "Content-Type: application/json" \
  -d '{
    "post": {
      "default_action": "proceed",
      "rules": [
        {
          "toolkit": "Database",
          "action": "proceed",
          "override": {
            "output": {"data": "[REDACTED]", "count": 0}
          }
        }
      ]
    }
  }'
```

## Integration with Arcade Engine

Configure a webhook plugin in your Engine to point to this test server:

```yaml
plugins:
  - type: webhook
    name: test-hook
    binding_type: org
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

## Response Codes

| Code                  | Meaning                              |
| --------------------- | ------------------------------------ |
| `OK`                  | Proceed with execution               |
| `CHECK_FAILED`        | Block execution (action: block/deny) |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit (action: rate_limit)  |
