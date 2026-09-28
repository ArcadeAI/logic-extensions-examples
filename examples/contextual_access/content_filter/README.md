# Content Filter Example

A minimal hook server that demonstrates how to **filter tool calls and responses based on their content**.

## What It Shows

- **Access hook**: Block entire toolkits from being visible
- **Pre-execution hook**: Block tool execution when inputs contain prohibited content (keywords or regex patterns)
- **Post-execution hook**: Block or replace prohibited content in tool outputs and content text blocks

## Quick Start

```bash
# Run with a config file
go run ./examples/contextual_access/content_filter -config ./examples/contextual_access/content_filter/example-config.yaml
```

## Config File Format

```yaml
# Simple keyword blocking (case-insensitive, checked in both inputs and outputs)
blocked_keywords:
  - "confidential"
  - "internal-only"
  - "secret-project"

# Block entire toolkits
blocked_toolkits:
  - "DangerousToolkit"
  - "Internal*"

# Regex patterns for blocking inputs before execution
blocked_input_patterns:
  - name: "external-email"
    pattern: "@(?!mycompany\\.com)\\w+\\.\\w+"
    action: block
    message: "External email addresses are not allowed"

  - name: "sql-injection"
    pattern: "(?i)(DROP|DELETE|TRUNCATE)\\s+TABLE"
    action: block
    message: "Potentially dangerous SQL detected"

# Regex patterns for filtering outputs after execution
blocked_output_patterns:
  - name: "internal-urls"
    pattern: "https?://internal\\.[\\w.]+"
    action: replace
    replacement: "[INTERNAL URL REMOVED]"

  - name: "api-keys"
    pattern: "(?i)(api[_-]?key|token)[\"']?\\s*[:=]\\s*[\"']?[\\w-]{20,}"
    action: block
    message: "Output contains what appears to be an API key"
```

## How It Works

Rules match each value on its own, so a keyword or pattern doesn't match across two separate fields.

### Input Filtering (Pre-Hook)
1. Each tool input value is checked on its own
2. Blocked keywords are checked (case-insensitive substring match)
3. Blocked input patterns are checked (regex match)
4. If any match is found, the tool execution is blocked with an error message

### Output Filtering (Post-Hook)
1. Each tool output value, and each value in `content` text blocks (sent by remote MCP servers), is checked on its own
2. Blocked keywords are checked
3. Blocked output patterns are checked:
   - `action: "block"` - Reject the entire response
   - `action: "replace"` - Replace matching content with the replacement string, in both the output and `content` text blocks (returned as `override.content`). Other block types pass through unchanged.

## Testing

```bash
# Start the server with example rules
go run ./examples/contextual_access/content_filter -config ./examples/contextual_access/content_filter/example-config.yaml &

# Test pre-hook - should be blocked (contains blocked keyword)
curl -X POST http://localhost:8888/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "test-1",
    "tool": {"name": "Search", "toolkit": "Web", "version": "1.0.0"},
    "context": {"user_id": "user1"},
    "inputs": {"query": "find confidential documents"}
  }'

# Test post-hook - content replacement
curl -X POST http://localhost:8888/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "test-2",
    "tool": {"name": "Search", "toolkit": "Web", "version": "1.0.0"},
    "context": {"user_id": "user1"},
    "server": {"name": "s1", "uri": "http://localhost", "type": "arcade"},
    "inputs": {"query": "test"},
    "output": {"result": "Visit https://internal.company.com/secret for details"},
    "success": true
  }'
```
