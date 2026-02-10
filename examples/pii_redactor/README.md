# PII Redactor Example

A minimal CATE webhook server that demonstrates how to detect and redact personally identifiable information (PII) from tool outputs using the post-execution hook.

## What It Shows

- **Post-execution hook**: Scan tool output for PII patterns and either redact or block
- **Output modification**: Replace sensitive data with redaction markers using the `override` mechanism
- **Two modes**: Redact (replace PII) or Block (reject the entire response)

## Quick Start

```bash
# Redact mode (default) - replace PII with markers
go run ./examples/pii_redactor -port 8889

# Block mode - reject responses containing PII
go run ./examples/pii_redactor -port 8889 -mode block
```

## Supported PII Types

| Type           | Example              | Replacement        |
| -------------- | -------------------- | ------------------ |
| Email          | john@example.com     | [EMAIL_REDACTED]   |
| IP Address     | 192.168.1.1          | [IP_REDACTED]      |
| SSN            | 123-45-6789          | [SSN_REDACTED]     |
| Phone Number   | (555) 123-4567       | [PHONE_REDACTED]   |
| Credit Card    | 4111-1111-1111-1111  | [CC_REDACTED]      |
| Date of Birth  | 01/15/1990           | [DOB_REDACTED]     |

## Testing

### Redact Mode

The post-hook replaces PII with markers and returns the modified output:

```bash
curl -X POST http://localhost:8889/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-1",
    "tool": {"name": "search", "toolkit": "Contacts", "version": "1.0"},
    "output": {
      "name": "John Doe",
      "email": "john@example.com",
      "phone": "(555) 123-4567",
      "ip": "Connected from 192.168.1.100",
      "ssn": "SSN: 123-45-6789",
      "notes": "Born on 01/15/1990, card ending 4111-1111-1111-1111"
    },
    "server": {"name": "contacts", "uri": "http://contacts:8080", "type": "arcade"},
    "context": {"user_id": "user-1"}
  }'
```

Expected response (redact mode):
```json
{
  "code": "OK",
  "override": {
    "output": {
      "name": "John Doe",
      "email": "[EMAIL_REDACTED]",
      "phone": "[PHONE_REDACTED]",
      "ip": "Connected from [IP_REDACTED]",
      "ssn": "SSN: [SSN_REDACTED]",
      "notes": "Born on [DOB_REDACTED], card ending [CC_REDACTED]"
    }
  }
}
```

### Block Mode

When PII is found, the entire response is blocked:

```bash
# Start in block mode
go run ./examples/pii_redactor -port 8889 -mode block

# This response will be blocked because it contains an email
curl -X POST http://localhost:8889/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-2",
    "tool": {"name": "lookup", "toolkit": "HR", "version": "1.0"},
    "output": {"result": "Contact: admin@company.com"},
    "server": {"name": "hr", "uri": "http://hr:8080", "type": "arcade"},
    "context": {"user_id": "user-1"}
  }'
```

Expected response (block mode):
```json
{
  "code": "CHECK_FAILED",
  "error_message": "Response blocked: contains personally identifiable information"
}
```

### No PII (Pass Through)

When no PII is detected, the response passes through unchanged:

```bash
curl -X POST http://localhost:8889/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-3",
    "tool": {"name": "calculate", "toolkit": "Math", "version": "1.0"},
    "output": {"result": 42, "formula": "6 * 7"},
    "server": {"name": "math", "uri": "http://math:8080", "type": "arcade"},
    "context": {"user_id": "user-1"}
  }'
```

Expected response:
```json
{
  "code": "OK"
}
```

## How It Works

1. Tool executes and produces output
2. Engine sends the output to this post-hook server
3. Server scans all string values (recursively) for PII patterns
4. In **redact** mode: PII is replaced with `[TYPE_REDACTED]` markers using the `override.output` field
5. In **block** mode: If PII is found, returns `CHECK_FAILED` to reject the response entirely
6. If no PII is found, returns `OK` to pass through unchanged
