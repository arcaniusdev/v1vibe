# Architectural Decisions

## Malware Scanning Instruction Design (SERVER_INSTRUCTIONS)

### Problem
AI assistants were not consistently scanning all files during security reviews:
- Vague instructions like "Find ALL files" and "scan every file" led to shortcuts
- Assistants would scan 5-10 files instead of all project files
- Abstract imperatives ("do not skip") were ineffective

### Solution
Prescriptive, checkpoint-driven instructions with validation checkpoints:

1. **Exact discovery command:** Provide copy-paste `find` command instead of vague instruction
2. **Validation checkpoint:** "If <10 files scanned, you MISSED files" - forces self-check
3. **Mandatory reporting:** "Report 'Scanned X files' BEFORE proceeding" - prevents silent progression
4. **Performance justification:** Explains gRPC scanner is fast (~1s/file) so no reason to skip

### Implementation

- `SERVER_INSTRUCTIONS`: Step 1 broken into discovery and scan substeps
- `security_review` MCP prompt: Multi-step workflow with concrete bash commands
- `scan_malware` MCP prompt: Validation checkpoints and count reporting

### Design Principles for AI Assistant Instructions

- ✅ Concrete commands > abstract imperatives ("run this" vs "find all files")
- ✅ Measurable checkpoints > trust-based progression ("report count" vs "move on")
- ✅ Self-validation triggers > external validation ("if <10 files, redo" vs human review)
- ✅ Performance justification > assumed understanding ("1s/file" vs "this is fast")

### Rationale

- AI assistants respond better to procedural checklists than imperative statements
- Validation checkpoints create accountability without human oversight
- Concrete commands reduce cognitive load and interpretation variance
- Pattern applies to all MCP prompt design, not just malware scanning

### Testing
All 275 tests pass, validates instructions don't break tool functionality

## Threat Intelligence Implementation

### API Choice
Uses `/v3.0/threatintel/feedIndicators` (Vision One global feed)

### Rationale
Provides comprehensive historical data with stable REST API, supports local caching for instant lookups

## Threat Feed Scope

### Full Historical Fetch
Downloads all available threat data from Vision One inception (2018-present) on first run

### Rationale
- API supports unlimited time ranges
- Fetching all historical data (266K indicators, ~95MB) provides maximum threat coverage with minimal overhead
- Time range tested: 20+ years accepted by API; actual data spans March 2018 to present (~8.1 years)

### Rejected Alternatives
- 1-year window only (original implementation, missed 195K+ historical threats)
- 5-year window (conservative, still misses ~3 years of data)
- On-demand API calls (too slow, quota concerns)

## Cache Strategy

- **Disk-persistent JSON:** `~/.v1vibe/threat_feed_cache.json` (~95MB)
- **Atomic writes:** Temp file + rename to prevent corruption
- **Delta updates:** Hourly refresh fetches only new indicators since `last_updated_at` (typically <1,000 indicators)
- **Session cache:** Loaded once into `AppContext._threat_feed_cache`, reused for all searches
- **Performance:** First run ~60s, subsequent lookups <0.1s, hourly refreshes <5s

## Artifact Scanner (TMAS) Limitations and Mitigations

### Known Limitations

1. **Malware scanning:** TMAS only supports malware scanning on container images, not directory artifacts
   - **Mitigation:** Use `scan_file` tool for file-by-file malware scanning (works on all file types)

2. **Secret scanning symlink sensitivity:** TMAS secret scanner aggressively follows symlinks, causing failures on project roots with `.venv` (symlinks to `/opt/homebrew` on macOS)
   - **Mitigation 1:** Scan source code subdirectories only (e.g., `src/`, `app/`, `lib/`)
   - **Mitigation 2:** Run vulnerability and secret scans separately (vulnerability scanning works on full projects)
   - **Mitigation 3:** Filtered directory copying excludes .venv, node_modules, .git, etc.
   - **Note:** Filtered copying helps but TMAS secret scanner can still encounter symlinks in edge cases

### Implemented Workarounds

- **Automatic exclusions:** `.venv`, `venv`, `node_modules`, `.git`, `__pycache__`, `.pytest_cache`, `dist`, `build`, `.tox`, `.mypy_cache`, `.ruff_cache`
- **Filtered directory copying:** `_create_filtered_copy()` creates clean copy without symlinks before mounting to Docker or running TMAS
- **Enhanced error messages:** Failed scans return actionable `suggestions` array with specific workarounds
- **EXCLUDED_DIRS constant:** User-editable list of directories to skip (artifact_scanner.py:38)

### Decision Rationale

- TMAS limitations are upstream (Trend Micro's tool), not v1vibe bugs
- Providing clear error messages and workarounds is better than silently failing
- Vulnerability scanning (most common use case) works perfectly on full projects
- Secret scanning on `src/` directories provides 95%+ coverage for source code secrets
