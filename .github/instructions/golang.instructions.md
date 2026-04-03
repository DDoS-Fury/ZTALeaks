---
description: "Use when: writing, editing, or reviewing Go files in the services/ directory."
applyTo: "**/*.go"
---
# Golang Development Guidelines for ZTALeaks

When working with Go code in this repository (e.g., `security-orchestrator`, `business-logic`, `seeder`), strictly follow these guidelines:

## Error Handling
- **Context Wrapping**: All returned errors must include context wrapping using `fmt.Errorf("failed to [action]: %w", err)` to preserve the original error trace.
- **Logging**: Log errors with the request context, ensuring `X-Request-ID` is extracted and included in the log output for Splunk traceability.

## Data Models
- **Struct Tags**: All struct models interacting with MongoDB or Envoy MUST have proper explicit `json` and `bson` tags. 
- **OmitEmpty**: Use `omitempty` for optional fields to avoid polluting the database or API responses.

## Concurrency & Context
- Always pass `context.Context` as the first argument to functions that involve I/O, database calls, or network requests (e.g., querying the Security or Business DB).