# Advanced Hook Server

A comprehensive hook server with a web dashboard for managing access rules, PII redaction, and A/B testing. All three hook points (access, pre-execution, post-execution) are fully supported with configurable behavior stored in a YAML file.

## Features

### 1. Basic Rules (Access, Pre, Post)
- **Access control**: Block users, toolkits, or specific tools from being visible
- **Pre-execution rules**: Block or modify tool requests before execution
- **Post-execution rules**: Block or modify tool responses after execution. A rule that overrides the output also clears the server's `content` blocks, so clients get the new output instead of the original text.
- **Pattern matching**: Exact, glob (`*`), and regex (`~pattern`) patterns
- **Input/output matching**: Filter based on request content

### 2. PII Redaction
- Automatically detect and handle PII in tool responses
- Supported PII types: email addresses, IPv4 addresses, SSNs, phone numbers, credit cards, dates of birth
- Custom regex patterns for organization-specific PII
- Choose to **redact** (replace with placeholders) or **block** (reject the response entirely)

### 3. A/B & Canary Testing
- Route tool calls to different versions or servers
- Consistent user assignment via deterministic hashing
- Configure traffic splits (e.g., 90/10 canary, 50/50 A/B)
- Fetch available tools from an external tool registry API
- Real-time statistics dashboard

### 4. Web Dashboard
- Configure all features through a browser-based UI
- Real-time request log viewer
- PII detection tester
- A/B experiment statistics
- Raw configuration editor

## Quick Start

```bash
# Run with defaults (port 8888, no auth)
go run ./examples/contextual_access/advanced_server

# Run with a configuration file
go run ./examples/contextual_access/advanced_server -config ./examples/contextual_access/advanced_server/example-config.yaml

# Run with authentication
go run ./examples/contextual_access/advanced_server -token "my-secret-token"

# Run with TLS
go run ./examples/contextual_access/advanced_server -tls -cert server.crt -key server.key
```

Then open `http://localhost:8888/` in your browser to access the dashboard.

## Command Line Flags

| Flag       | Default            | Description                                          |
| ---------- | ------------------ | ---------------------------------------------------- |
| `-port`    | `8888`             | Port to listen on                                    |
| `-token`   | `""`               | Bearer token for authentication (empty = no auth)    |
| `-verbose` | `true`             | Log all requests to stdout                           |
| `-config`  | `""`               | Path to YAML configuration file (enables hot-reload) |
| `-tls`     | `false`            | Enable TLS/HTTPS                                     |
| `-cert`    | `""`               | Path to server certificate file (PEM)                |
| `-key`     | `""`               | Path to server private key file (PEM)                |
| `-ca`      | `""`               | Path to CA certificate (enables mTLS)                |

## Configuration File

The server stores its configuration in a YAML file (default: `hook-config.yaml`). Configuration can be modified through:

1. **The web dashboard** at `/`
2. **The API** at `/api/config`
3. **Editing the YAML file** directly (auto-reloads)

See [example-config.yaml](example-config.yaml) for a full example with all options.

## Endpoints

### Webhook Endpoints

| Method | Path      | Description           |
| ------ | --------- | --------------------- |
| GET    | `/health` | Health check endpoint |
| POST   | `/access` | Access control hook   |
| POST   | `/pre`    | Pre-execution hook    |
| POST   | `/post`   | Post-execution hook   |

### Dashboard

| Method | Path | Description    |
| ------ | ---- | -------------- |
| GET    | `/`  | Web dashboard  |

### API Endpoints

| Method     | Path                  | Description                         |
| ---------- | --------------------- | ----------------------------------- |
| GET/PUT    | `/api/config`         | Get/update configuration            |
| POST       | `/api/config/save`    | Save configuration to file          |
| GET/DELETE | `/api/logs`           | View/clear request logs             |
| GET        | `/api/status`         | Server status                       |
| POST       | `/api/registry/fetch` | Fetch tools from external registry  |
| GET        | `/api/ab/stats`       | A/B testing statistics              |
| DELETE     | `/api/ab/stats`       | Reset A/B statistics                |
| POST       | `/api/pii/test`       | Test PII detection on sample text   |

## PII Redaction Details

The PII redactor scans all string values in tool response outputs, and the string fields of any `content` blocks (sent by remote MCP servers), returning the redacted blocks as `override.content`. Base64 payloads (`data`, `blob`) are left as-is. When PII is detected:

- **Redact mode**: Replaces PII with labeled placeholders (e.g., `[EMAIL REDACTED]`)
- **Block mode**: Returns an error response instead of the tool output

### Supported PII Types

| Type         | Pattern Example         | Redacted As              |
| ------------ | ----------------------- | ------------------------ |
| Email        | `user@example.com`      | `[EMAIL REDACTED]`      |
| IPv4         | `192.168.1.1`           | `[IP REDACTED]`         |
| SSN          | `123-45-6789`           | `[SSN REDACTED]`        |
| Phone        | `(555) 123-4567`        | `[PHONE REDACTED]`      |
| Credit Card  | `4111-1111-1111-1111`   | `[CREDIT CARD REDACTED]` |
| Date of Birth| `01/15/1990`            | `[DOB REDACTED]`        |

Custom patterns can be added via the `pii.custom` configuration.

## A/B Testing Details

A/B testing works by intercepting tool calls in the pre-execution hook:

1. When a tool call matches an active experiment, a variant is selected
2. Variant selection uses consistent hashing (SHA-256 of user_id + experiment_name)
3. This ensures the same user always gets the same variant
4. If the variant specifies an alternate server, the request is routed there
5. Statistics track how many requests each variant receives

### Experiment Modes

- **A/B**: Equal or weighted split between two variants for comparison
- **Canary**: Small percentage of traffic routed to new version for validation

### Tool Registry Integration

The server can fetch available tools from an external tool registry API (e.g., [Arcade](https://docs.arcade.dev/en/references/api)):

1. Configure the registry URL and API key in the A/B Testing settings
2. Click "Fetch Available Tools" to discover tools and their versions
3. Use the discovered tools to set up experiments

## Integration

Configure a webhook plugin to point to this server:

```yaml
plugins:
  - type: webhook
    name: advanced-hook
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
