# AI Pentest Agent — Build Plan

Local-first, zero recurring cost, built from scratch. Hybrid brain (local grunt +
free-API reasoning). Benchmarked against your own confirmed findings.
**Goal:** automate ~65% of repetitive VAPT breadth; you keep creative depth.

---

## Guardrails (never skip)
- **Authorized targets only.** Every outbound request passes `scope.check()`. Fail closed.
- **Verifier is non-negotiable.** Nothing reaches you as a "finding" until code has re-tested it.
- **Redaction before any cloud call.** PII/creds/tokens/hostnames stripped on-box first.
- **Ground truth = your findings.** Each phase is benchmarked against a confirmed bug
  (start with the Unicommerce OTP IDOR).

## Claude Code working rules
- One module per task. **Test + commit after each** — never one-shot the whole agent.
- Keep `CLAUDE.md` current (rules, schema, conventions) so every task has context.
- After each module: run its test, run the benchmark, commit, then move on.
- When a phase says "Done when", don't advance until that's true.

## Repo structure (target)
```
pentest-agent/
├── CLAUDE.md                # project rules for Claude Code (see Appendix A)
├── config.yaml              # scope + model routing (already scaffolded)
├── requirements.txt
├── run.py                   # CLI entrypoint
├── agent/
│   ├── scope.py             # [scaffolded] hard allowlist
│   ├── router.py            # [scaffolded] local/fast/frontier router
│   ├── redact.py            # [scaffolded] privacy gate
│   ├── http.py              # async HTTP engine + auth
│   ├── recon/               # crawler, JS extractor, param discovery, fingerprint
│   ├── recipes/             # vuln recipes (yaml) — the "skills"
│   ├── scanners/            # detect() modules, one per vuln class
│   ├── verify/              # verify() modules, deterministic confirmation
│   ├── kb/                  # embedder, vector store, retriever, ingestion
│   ├── orchestrator.py      # the agent loop
│   └── report.py            # verified findings -> your template
├── benchmarks/              # confirmed findings as test cases
└── outputs/                 # reports, logs (gitignored)
```

---

## Phase 0 — Environment (30–60 min)
- **0.1** Install Python 3.11+, create venv, `git init`.
- **0.2** Create repo structure above; add `.gitignore` (venv, outputs/, *.env, creds).
- **0.3** Drop in the 4 scaffolded files (config.yaml, scope.py, router.py, redact.py).
- **0.4** Get free reasoning keys: Groq (console.groq.com) + optionally Google AI Studio.
  Put in a local `.env` (never commit).
- **0.5** (Optional, weak HW) Install Ollama, `ollama pull qwen3:4b` for local triage/redaction.
- **0.6** Write `CLAUDE.md` (Appendix A). Verify `python run.py --check` reaches at least one tier.
- **Done when:** `--check` shows one reasoning tier responding; repo committed.

## Phase 1 — Core spine: HTTP engine + auth
- **1.1** `http.py`: async client (httpx), configurable timeout/retries/headers.
- **1.2** **Every** request routes through `scope.check(url)` — no exceptions.
- **1.3** Auth layer: JWT, cookie (JSESSIONID), Bearer, custom header; a `Session` object holds creds.
- **1.4** Structured request/response logging (method, url, status, len, timing) to JSONL.
- **1.5** Proxy toggle (route via Burp `127.0.0.1:8080` for debugging).
- **1.6** Unit test: authed GET to a scoped endpoint returns 200 + logs correctly.
- **→ Claude Code task:** *"Build agent/http.py per Phase 1. Async httpx wrapper, scope-gated,
  multi-auth Session, JSONL logging, proxy toggle. Write a unit test. Don't touch other modules."*
- **Done when:** test passes; an out-of-scope URL raises ScopeError; committed.

## Phase 2 — Recon
- **2.1** Crawler: collect URLs + forms from a seed, same-origin only, depth-limited.
- **2.2** JS/SPA extractor: pull endpoints + params from JS bundles (regex + AST-lite).
- **2.3** Param discovery: query/body/header params per endpoint.
- **2.4** Fingerprinting: server, framework, auth type, CDN/origin.
- **2.5** Output a normalized `inventory.json` (endpoints, methods, params, auth needs).
- **2.6** **Benchmark:** run the JS extractor on the Unicommerce `uniweb.min.js` → expect ~600 endpoints.
- **→ Claude Code task:** one sub-module at a time (2.1, then 2.2…), test each, commit each.
- **Done when:** inventory.json is produced for a scoped target; JS benchmark hits the expected count.

## Phase 3 — Model router + redaction (mostly scaffolded)
- **3.1** Confirm `router.py` routes jobs to configured tiers.
- **3.2** Add a second redaction pass using the local model for context PII regex misses.
- **3.3** Wire free-tier providers (Groq/Gemini) + keep `$100 Claude` as `frontier` escalation.
- **3.4** Prompt templates per job: `triage`, `hypothesis`, `exploit_chain`, `report`.
- **3.5** Budget tracker: count frontier tokens, stop at the config cap.
- **Done when:** each job type returns sane output on a sample; redaction verified on a creds-laden blob.

## Phase 4 — Recipe engine + Knowledge Base (the "skills")
- **4.1** Finalize recipe schema (yaml): id, applies_to, tech_signals, preconditions, detect,
  signal, verify, severity, remediation, source.
- **4.2** Recipe loader + validator (reject malformed recipes).
- **4.3** Local embedder (nomic-embed-text or bge-small) + vector store (Chroma or FAISS).
- **4.4** Retriever: given target signals → top-k relevant recipes.
- **4.5** Convert your **first** confirmed finding (Unicommerce OTP IDOR) into a recipe by hand.
- **4.6** Ingestion pipeline skeleton (add sources incrementally, official feeds first):
  Nuclei templates (git) → NVD CVE API → CISA KEV → disclosed writeups → PayloadsAllTheThings/WSTG/MASTG.
  Each source: fetch → clean → normalize to schema → dedupe → embed → store.
- **4.7** Dedupe + quality filter (drop low-signal/duplicate entries).
- **→ Claude Code task:** build 4.1–4.4 first; prove retrieval on 1 hand-written recipe before any ingestion.
- **Done when:** retriever returns your IDOR recipe when queried with matching signals.

## Phase 5 — First scanner + verifier end-to-end (PROVE THE LOOP)
- **5.1** `Scanner` base class: `detect(target, recipe) -> [candidates]`.
- **5.2** Implement the IDOR scanner from the recipe (replay with victim identifiers).
- **5.3** `Verifier` base class: `verify(candidate) -> CONFIRMED | FALSE | NEEDS_HUMAN`.
- **5.4** Implement IDOR verifier: deterministic re-test asserting the recipe `signal`.
- **5.5** **Benchmark:** run against Unicommerce `/data/myaccount/sendOTP` → must re-find the IDOR.
- **5.6** Record result: found? false positives? This is your first accuracy number.
- **Done when:** the agent independently rediscovers the known IDOR and the verifier confirms it.

## Phase 6 — Orchestrator
- **6.1** State model: target, inventory, candidate queue, confirmed findings, human queue.
- **6.2** The loop: `recon → retrieve recipes → run scanners → verify → route confirmed to human queue`.
- **6.3** Human review queue: confirmed findings written to a file for your judgment.
- **6.4** Run the full loop on one scoped target end-to-end.
- **Done when:** one command takes a target → produces a human queue of verified candidates.

## Phase 7 — Reporter
- **7.1** Report template in your house format (title, severity, impact, steps/PoC, remediation).
- **7.2** `report` job drafts the writeup from a verified finding (model + redaction).
- **7.3** Export to markdown + pdf/docx.
- **7.4** Generate the report for the IDOR finding; you edit, not write from scratch.
- **Done when:** a verified finding becomes a near-final report you only tweak.

## Phase 8 — Expand coverage
- **8.1** Add scanners + recipes per class: SQLi (incl. 2nd-order), XXE, SSRF, XSS, access control, auth.
- **8.2** Convert remaining Unicommerce + PureID findings → recipes **and** benchmarks.
- **8.3** Mobile track: Flutter/Frida recipes (root/emulator/RASP bypass) as a separate module set.
- **8.4** Scale ingestion: full CVE feeds, more disclosed writeups, nuclei template sync.
- **8.5** Benchmark suite: run against ALL confirmed findings → precision/recall scorecard.
- **Done when:** scorecard shows the agent re-finds most of your known bugs with low false positives.

## Phase 9 — Hardening & usability
- **9.1** CLI polish: resume/checkpoint, per-phase run flags.
- **9.2** Rate limiting + stealth options (low-noise mode, like the drips-cea requirement).
- **9.3** Scope safety audit: fuzz the scope guard, confirm nothing leaks.
- **9.4** Headless run mode for repeatable benchmark runs.
- **Done when:** you can point it at a new authorized target and trust the output.

---

## Appendix A — CLAUDE.md starter (put at repo root)
```markdown
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
<update this each session so tasks stay scoped>
```

## Appendix B — Build order at a glance
0 Env → 1 HTTP spine → 2 Recon → 3 Router → 4 Recipes+KB → 5 First scanner+verifier
→ 6 Orchestrator → 7 Reporter → 8 Expand → 9 Harden

Always benchmark each phase against a confirmed finding before advancing.
