# Stage 9 portable Windows validation handoff

> Execute inline with TDD; no product-code edits and no claims of native Windows execution.

**Goal:** Let the operator run the existing six Windows DPAPI/locking checks without installing Python.
**Architecture:** A separate ZIP contains the unchanged profile.4 runtime/payload, unchanged native-check script, an isolated supervisor and an ASCII CMD launcher. Results are sanitized JSON/TXT, using synthetic profiles only. No GUI or device operation is started.
**Spec:** WINDOWS_VALIDATION_CHECKLIST.md; user asks to proceed; actual Windows/equipment validation remains operator-owned.

## Constraints / rulings
- Progress stays 80%; this is stage 9 preparation, not its completion.
- Preserve all product files, Windows EXE, dependencies, protection/command/retry policies.
- Reuse 1,835 extracted files including licensing notices; no downloads at execution, no policy bypass, no administrator request.
- Do not read the live profile. The six checks use TemporaryDirectory and explicit ProfileStore paths.
- Native script unchanged. A separate subprocess supervisor verifies payload hashes and captures only allowlisted status/error categories, not tracebacks or local paths.
- Native pass is possible only on Windows with the packaged interpreter and all six expected checks passing. Other platforms, timeouts, missing/tampered payloads, skipped/missing checks must not pass.
- Whole stage 9 also requires manual EXE/UI/reboot/account checks even after six automatic checks pass.

## Tasks
- [x] Pin source tree, verify unchanged EXE payload; run baseline.
- [x] RED tests for integrity/path checks, sanitized results, incomplete/error/unsupported results.
- [x] Implement the standalone runner/launcher; GREEN; test process execution/error/timeout boundaries locally without faking Windows success.
- [x] Package unchanged runtime + six native checks; compare hashes; full regression and direct review.
- [ ] Add usage/progress record; update feature branch only, with expected head; no merge/Release/CI.
