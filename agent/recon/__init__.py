"""Recon subsystem — discovers endpoints, params, and tech signals from targets.

Modules:
  - nmap_scanner: Port scanning + service version detection + exploit lookup
  - crawler: Spider HTML pages for links/forms (Phase 2.1)
  - js_extractor: Extract API endpoints from JavaScript bundles (Phase 2.2)
  - param_discovery: Infer parameter names/types (Phase 2.3)
  - fingerprint: Tech-stack fingerprinting (Phase 2.4)
  - inventory: Normalized recon inventory builder (Phase 2.5)
  - auth_bypass: Login bypass discovery via SQLi (Phase 2.6)
"""
