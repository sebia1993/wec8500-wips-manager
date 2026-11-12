# profile.2 interruption and lifecycle assurance

> **For agentic workers:** Use superpowers:executing-plans and systematic-debugging. Only reproduced product defects authorize implementation changes.

**Goal:** Check remaining persistence/interruption and profile-worker lifecycle boundaries without changing user features.
**Architecture:** Exercise existing ProfileStore, ProfileApp and Runner against temporary files, process boundaries and loopback peers. No production refactoring unless a regression demonstrates a real fault.
**Tech Stack:** Python stdlib, unittest, Tk/Xvfb. Synthetic protector is not native DPAPI.
**Spec:** PROFILE_STABILITY.md and user's continuing stabilization request.

## Global Constraints
- Keep main/stabilization branches, device commands, retry/status policy and secret/report policy unchanged.
- Do not change Windows runtime or claim native Windows/real equipment validation.
- Retain profile.2 EXE when product source does not change.

## Review Focus
- Process death must release the cooperative lock and not publish incomplete saved settings.
- File flush/sync errors must preserve previous bytes and remove incomplete staging files.
- Secret blocks for different kinds must not be interchangeable.
- Changes while preparing credentials must prevent new device connections, not destroy prior results.
- Closing/cancelling during profile work must preserve committed data or visible errors as appropriate.

### Task 1 — Persistence interruption
- [x] Add tests/test_profile_assurance.py: real child-process kill during lock/atomic replace; fsync failure; swapped secret tokens.
- [x] Run on unmodified profile.2. Preserve failures as RED evidence, investigate before editing. Passing tests are additional coverage, not fixes.

### Task 2 — Profile lifecycle
- [x] Add real-Tk/loopback tests for external rotation/deletion during credential preparation, close refusal and delete failure on requested close.
- [x] Assert no wrong-target connection, no leaked worker, stable prior results and sanitized failures.
- [x] Perform targeted mutation checks on temporary source copies to ensure tests detect removed guards. Never ship mutants.

### Task 3 — Completion
- [x] Run complete suite twice in one process and record errors/skips/remaining threads.
- [x] Re-read diff, check existing application files and original EXE payload hashes.
- [x] Update feature/windows-protected-profile only with compare-and-swap head check; no merge/Release.
- [x] Provide accurate results and bounded validation limitations; do not create a new EXE for tests-only changes.
