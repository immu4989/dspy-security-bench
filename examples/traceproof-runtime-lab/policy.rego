package traceproof

import rego.v1

default allow := false

allow if {
  input.principal == "synthetic-reviewer"
  input.agent == "records-assistant"
  input.resource == "https://mcp.example.test/records"
  input.scopes == ["records:read"]
}

decision := {
  "allow": true,
  "reason": "bounded synthetic records lookup",
} if {
  allow
}

decision := {
  "allow": false,
  "reason": "request is outside the frozen lab grant",
} if {
  not allow
}
