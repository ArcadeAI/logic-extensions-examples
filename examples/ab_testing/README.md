# A/B Testing Example

A minimal CATE webhook server that demonstrates how to perform A/B testing and canary deployments by routing tool executions to different server variants.

## What It Shows

- **Pre-execution hook**: Override server routing to direct requests to different tool versions
- **Deterministic assignment**: Hash-based variant selection ensures consistent routing
- **Sticky sessions**: Same user always gets the same variant
- **Traffic splitting**: Configurable weight distribution between variants

## Quick Start

```bash
go run ./examples/ab_testing -port 8890
```

## How It Works

The server intercepts tool execution requests at the **pre-hook** and:

1. Checks if there's an active experiment for the requested tool
2. Computes a deterministic hash of the user ID + experiment name
3. Uses the hash to assign a variant based on configured weights
4. Overrides the `server` field in the response to route to the variant's server

### Experiment Configuration

Two example experiments are pre-configured:

**A/B Test** - `search-v2-rollout`:
- Matches: `Search.WebSearch`
- Control (80%): Routes to `http://search-v1:8080`
- Treatment (20%): Routes to `http://search-v2:8080`

**Canary Deploy** - `email-canary`:
- Matches: `Email.*` (all email tools)
- Stable (95%): Routes to `http://email-stable:8080`
- Canary (5%): Routes to `http://email-canary:8080`

## Testing

### A/B Test Routing

```bash
# User "alice" will be assigned to one variant (deterministic)
curl -X POST http://localhost:8890/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-1",
    "tool": {"name": "WebSearch", "toolkit": "Search", "version": "1.0"},
    "inputs": {"query": "test search"},
    "context": {"user_id": "alice"}
  }'

# Same user always gets the same variant
curl -X POST http://localhost:8890/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-2",
    "tool": {"name": "WebSearch", "toolkit": "Search", "version": "1.0"},
    "inputs": {"query": "another search"},
    "context": {"user_id": "alice"}
  }'

# Different user may get a different variant
curl -X POST http://localhost:8890/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-3",
    "tool": {"name": "WebSearch", "toolkit": "Search", "version": "1.0"},
    "inputs": {"query": "test search"},
    "context": {"user_id": "bob"}
  }'
```

Expected response (server override):
```json
{
  "code": "OK",
  "override": {
    "server": {
      "name": "search-v2",
      "uri": "http://search-v2:8080",
      "type": "arcade"
    }
  }
}
```

### Canary Deploy

```bash
# Email tool - most users routed to stable
curl -X POST http://localhost:8890/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-4",
    "tool": {"name": "sendEmail", "toolkit": "Email", "version": "1.0"},
    "inputs": {"to": "user@example.com", "body": "Hello"},
    "context": {"user_id": "user-123"}
  }'
```

### Non-Experiment Tool

Tools without experiments pass through unchanged:

```bash
curl -X POST http://localhost:8890/pre \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-5",
    "tool": {"name": "calculate", "toolkit": "Math", "version": "1.0"},
    "inputs": {"expression": "2+2"},
    "context": {"user_id": "user-1"}
  }'
```

Expected response (no override):
```json
{
  "code": "OK"
}
```

### View Assignments

```bash
curl http://localhost:8890/_assignments
```

## Key Concepts

### Deterministic Assignment

The variant assignment uses SHA-256 hashing of `experiment_name:user_id` to produce a deterministic bucket (0-99). This means:

- No external database needed for assignment tracking
- Same user always gets the same variant
- Distribution approximates the configured weights over many users

### Canary Deployment Pattern

To do a canary deployment:

1. Start with a 99/1 or 95/5 split (stable/canary)
2. Monitor error rates for the canary variant
3. Gradually increase canary weight: 5% -> 10% -> 25% -> 50% -> 100%
4. If issues arise, set canary weight to 0% to roll back

### Server Routing Override

The A/B testing works by overriding the `server` field in the pre-hook response. The engine then routes the tool execution to the specified server instead of the default one.
