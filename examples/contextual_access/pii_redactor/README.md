# PII Redactor Example

A minimal hook server that demonstrates how to **detect and redact personally identifiable information (PII)** from tool outputs.

## What It Shows

- **Post-execution hook**: Scans all string values in tool outputs and content text blocks for PII patterns
- **Redact mode**: Replaces detected PII with labeled placeholders
- **Block mode**: Rejects the entire response if PII is detected
- Recursive scanning of nested objects and arrays

## Quick Start

```bash
# Redact all PII types (default)
go run ./examples/contextual_access/pii_redactor

# Only detect specific PII types
go run ./examples/contextual_access/pii_redactor -types "email,ssn,credit_card"

# Block responses instead of redacting
go run ./examples/contextual_access/pii_redactor -action block
```

## Supported PII Types

| Type           | Flag             | Example                  | Redacted As              |
| -------------- | ---------------- | ------------------------ | ------------------------ |
| Email          | `email`          | `user@example.com`       | `[EMAIL REDACTED]`       |
| IPv4 Address   | `ipv4`           | `192.168.1.1`            | `[IP REDACTED]`          |
| SSN            | `ssn`            | `123-45-6789`            | `[SSN REDACTED]`         |
| Phone Number   | `phone`          | `(555) 123-4567`         | `[PHONE REDACTED]`       |
| Credit Card    | `credit_card`    | `4111-1111-1111-1111`    | `[CREDIT CARD REDACTED]` |
| Date of Birth  | `date_of_birth`  | `01/15/1990`             | `[DOB REDACTED]`         |

## How It Works

1. The **access** and **pre-execution** hooks are pass-throughs (PII redaction only applies to outputs)
2. The **post-execution hook** receives the tool's output
3. All string values in the output are recursively scanned for PII patterns, and so are `content` text blocks (sent by remote MCP servers). The redacted blocks are returned as `override.content`; other block types pass through unchanged.
4. Based on the configured action:
   - **Redact**: Each PII match is replaced with a type-specific placeholder
   - **Block**: The entire response is rejected with an error listing the PII types found

## Testing

```bash
# Start the server
go run ./examples/contextual_access/pii_redactor &

# Test with PII in output - will be redacted
curl -X POST http://localhost:8888/post \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "test-1",
    "tool": {"name": "Lookup", "toolkit": "Database", "version": "1.0.0"},
    "context": {"user_id": "user1"},
    "server": {"name": "s1", "uri": "http://localhost", "type": "arcade"},
    "inputs": {"query": "get user info"},
    "output": {
      "name": "Jane Smith",
      "email": "jane@example.com",
      "phone": "(555) 123-4567",
      "ssn": "123-45-6789",
      "ip": "Client connected from 10.0.1.42"
    },
    "success": true
  }'

# Expected output: all PII fields are redacted
# {
#   "code": "OK",
#   "override": {
#     "output": {
#       "name": "Jane Smith",
#       "email": "[EMAIL REDACTED]",
#       "phone": "[PHONE REDACTED]",
#       "ssn": "[SSN REDACTED]",
#       "ip": "Client connected from [IP REDACTED]"
#     }
#   }
# }
```
