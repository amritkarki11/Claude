# Pentest Agent — Project Rules

## Mission
Local-first, from-scratch hybrid AI agent that automates ~65% of VAPT breadth.
Accuracy over coverage. Verified findings only.

## Hard rules
- Every outbound request MUST pass agent.scope.check(). Fail closed.
- No finding is reported until a deterministic verifier confirms it.
- Redact PII/creds/tokens before any non-local model call.
- Authorized scope only — allowlist in config.yaml.

## Conventions
- Python 3.11+, async where I/O-bound (httpx).
- One module per task; write a test; commit before moving on.
- Reuse building-block libs (httpx, parsers). Build detection LOGIC from scratch, not plumbing.
- All vuln knowledge lives as recipes (yaml) in agent/recipes/ following the schema.

## Recipe schema
id, applies_to, tech_signals, preconditions, detect[], signal, verify, severity, remediation, source

## Current phase
Phase 1 — HTTP engine + auth (next). Phases 0 done once env is set up.
