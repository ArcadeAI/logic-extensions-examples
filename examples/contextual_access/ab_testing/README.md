# A/B Testing Example

A minimal hook server that demonstrates how to **A/B test and canary-deploy tool versions** by routing tool calls to different servers.

## What It Shows

- **Pre-execution hook**: Route tool calls to different servers/versions based on experiment config
- **Consistent hashing**: Same user always gets the same variant (sticky assignment)
- **Weighted traffic splitting**: Control what percentage of traffic goes to each variant
- **Tool registry integration**: Fetch available tools from an external API (e.g., [Arcade](https://docs.arcade.dev/en/references/api))
- **Statistics tracking**: Monitor how many requests each variant receives

## Quick Start

```bash
# Run with experiment config
go run ./examples/contextual_access/ab_testing -config ./examples/contextual_access/ab_testing/example-config.yaml
```

## Config File Format

```yaml
# Optional: external tool registry for discovering tools
registry_url: "https://api.example.com"
registry_key: "your-api-key"

experiments:
  # Canary deployment: 10% traffic to new version
  - name: "search-v2-canary"
    enabled: true
    toolkit: "Search"
    tool: "WebSearch"
    mode: canary
    variants:
      - name: "stable"
        weight: 90
        version: "1.0.0"
      - name: "canary"
        weight: 10
        version: "2.0.0"
        server_name: "search-v2"
        server_uri: "http://search-v2.internal:8080"
        server_type: "arcade"

  # 50/50 A/B test
  - name: "email-provider-compare"
    enabled: true
    toolkit: "Email"
    tool: "*"
    mode: ab
    variants:
      - name: "provider-a"
        weight: 50
      - name: "provider-b"
        weight: 50
        server_name: "email-alt"
        server_uri: "http://email-alt.internal:8080"
        server_type: "arcade"
```

## How It Works

### Variant Selection
1. When a tool call matches an active experiment (by toolkit and tool patterns), a variant is selected
2. Selection uses consistent hashing: `SHA256(user_id + ":" + experiment_name)`
3. The hash is mapped to a variant based on configured weights
4. The same user always gets the same variant for a given experiment

### Server Routing
- If the selected variant has a `server_uri`, the pre-hook overrides the server routing
- This allows routing to different backend servers, different tool versions, etc.
- If no server override is specified, the tool executes normally (useful for tracking only)

### Statistics
- GET `/stats` returns per-experiment, per-variant request counts
- This shows the actual traffic distribution across variants

## Testing

```bash
# Start with example config
go run ./examples/contextual_access/ab_testing -config ./examples/contextual_access/ab_testing/example-config.yaml &

# Send pre-hook requests for different users
for i in $(seq 1 20); do
  curl -s -X POST http://localhost:8888/pre \
    -H "Content-Type: application/json" \
    -d "{
      \"execution_id\": \"exec-$i\",
      \"tool\": {\"name\": \"WebSearch\", \"toolkit\": \"Search\", \"version\": \"1.0.0\"},
      \"context\": {\"user_id\": \"user-$i\"},
      \"inputs\": {\"query\": \"test\"}
    }" | python3 -m json.tool
  echo
done

# Check statistics
curl -s http://localhost:8888/stats | python3 -m json.tool
```

## Tool Registry Integration

The server can fetch available tools from an external tool registry API:

```bash
# Configure registry URL in config, then fetch
curl -s -X POST http://localhost:8888/registry/fetch | python3 -m json.tool
```

This is useful for discovering what tools and versions are available before setting up experiments.
