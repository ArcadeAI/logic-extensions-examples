# Content Filter Example

A minimal CATE webhook server that demonstrates how to block users, filter tools, and reject requests based on content matching.

## What It Shows

- **Access hook**: Block specific users or toolkits from being discovered
- **Pre-execution hook**: Block requests based on input content (e.g., blocked email domains)
- **Post-execution hook**: Block responses containing prohibited content

## Quick Start

```bash
go run ./examples/content_filter -port 8888
```

## How It Works

### Access Hook (User & Toolkit Blocking)

The access hook runs when a user requests their available tools. It:

1. Checks if the user is in the blocked users list
2. Filters out blocked toolkits from the response

```bash
# This user will see no tools (blocked)
curl -X POST http://localhost:8888/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "suspended-user",
    "toolkits": {
      "Email": {"tools": {"sendEmail": [{"version": "1.0"}]}}
    }
  }'

# This toolkit will be filtered out
curl -X POST http://localhost:8888/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "normal-user",
    "toolkits": {
      "SafeToolkit": {"tools": {"doStuff": [{"version": "1.0"}]}},
      "DangerousToolkit": {"tools": {"doHarm": [{"version": "1.0"}]}}
    }
  }'
```

### Pre-Execution Hook (Input Content Filtering)

The pre hook runs before tool execution. It checks inputs against content rules:

```bash
# This will be blocked (email to @blocked.com)
curl -X POST http://localhost:8888/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-1",
    "tool": {"name": "sendEmail", "toolkit": "Email", "version": "1.0"},
    "inputs": {"to": "someone@blocked.com", "body": "Hello"},
    "context": {"user_id": "user-1"}
  }'

# This will be blocked (password field exists)
curl -X POST http://localhost:8888/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-2",
    "tool": {"name": "login", "toolkit": "Auth", "version": "1.0"},
    "inputs": {"username": "admin", "password": "secret123"},
    "context": {"user_id": "user-1"}
  }'
```

### Post-Execution Hook (Output Content Filtering)

The post hook runs after tool execution. It checks outputs for prohibited content:

```bash
# This will be blocked (output contains CONFIDENTIAL)
curl -X POST http://localhost:8888/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-3",
    "tool": {"name": "query", "toolkit": "Database", "version": "1.0"},
    "output": {"data": "CONFIDENTIAL: internal report..."},
    "server": {"name": "db", "uri": "http://db:8080", "type": "arcade"},
    "context": {"user_id": "user-1"}
  }'
```

## Response Codes

| Code           | Meaning                      |
| -------------- | ---------------------------- |
| `OK`           | Request allowed to proceed   |
| `CHECK_FAILED` | Request blocked by a rule    |
