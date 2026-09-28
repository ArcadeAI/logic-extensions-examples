# User Blocking Example

A minimal hook server that demonstrates how to **block specific users** from accessing and executing tools.

## What It Shows

- **Access hook**: Blocked users won't see any tools in the tool list
- **Pre-execution hook**: Blocked users can't execute tools (defense in depth)
- **Post-execution hook**: Pass-through (no modification needed)

## Quick Start

```bash
# Block users via command line
go run ./examples/contextual_access/user_blocking -block "user1,user2,user3"

# Block users via config file
go run ./examples/contextual_access/user_blocking -config ./examples/contextual_access/user_blocking/example-config.yaml
```

## Config File Format

```yaml
blocked_users:
  - user_id: "bad-user"
    reason: "Account suspended"
  - user_id: "former-employee"
    reason: "No longer with organization"
```

## How It Works

1. The **access hook** receives a list of all available tools and the requesting user
2. If the user is in the blocked list, ALL tools are added to the deny list
3. The **pre-execution hook** provides a second check - if a blocked user somehow gets past access control, execution is still denied
4. The **post-execution hook** is a pass-through since no output filtering is needed

## Testing

```bash
# Start the server
go run ./examples/contextual_access/user_blocking -block "blocked-user" &

# Test access hook - user is blocked
curl -X POST http://localhost:8888/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "blocked-user",
    "toolkits": {
      "Email": {"tools": {"SendEmail": [{"version": "1.0.0"}]}}
    }
  }'

# Test access hook - user is allowed
curl -X POST http://localhost:8888/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "good-user",
    "toolkits": {
      "Email": {"tools": {"SendEmail": [{"version": "1.0.0"}]}}
    }
  }'
```
