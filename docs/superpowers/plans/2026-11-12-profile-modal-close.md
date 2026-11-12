# Profile close-dialog race stabilization

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development.

**Goal:** Preserve the existing promise that a profile-prepared device job does not start after the operator requests closure, including while the close dialog runs its nested event loop.
**Architecture:** Keep profile-worker completion queued until the close decision is resolved. A main-thread-only dialog guard will cover the nested loop, distinct from the accepted close flag. No changes to device commands, retries, saved credentials or persistence.
**Tech Stack:** Python stdlib, Tk/Xvfb, unittest, loopback TCP.
**Spec:** PROFILE_STABILITY.md (close semantics) and the user's request to continue stabilization.

## Global Constraints
- Existing controller credential exclusion, DPAPI backend, profile schema and device policy unchanged.
- No main/stabilization merge or Release. Update feature branch only after validation.
- No Windows/real-device validation claims. Only package static checks here.

## Review Focus
- Native Tk close dialog may process timer events while waiting for a response.
- Accept: no connection during the dialog or after acceptance.
- Decline: preparation proceeds once, but never before the decision.
- Save/delete failure finishing during the dialog remains visible, not silently discarded on close.
- Repeated close events cannot open nested decisions or release the job early.

### Task 1: Reproduce before modification
- [x] Create tests/test_profile_modal_close.py: real Tk askyesno with timer-driven button invocation, gated secret decryption and a real loopback controller.
- [x] Verify at least the acceptance and decline tests fail on profile.2 because the controller receives a connection while the dialog is open.

### Task 2: Minimal lifecycle fix
- [x] Add a main-thread close-dialog guard in profile_ui.py; defer profile completion consumption until the answer is recorded; release guard in finally.
- [x] Keep all existing normal run, failure, close and retry behavior otherwise unchanged.
- [x] Add and execute save success/failure, duplicate close, and dialog callback cleanup boundary checks.

### Task 3: Delivery
- [x] Run complete suite twice and verify no skipped tests or remaining workers. Review the focused diff.
- [x] Repack prior SFX/runtime as profile.3, extract and compare all payload files; source/evidence ZIPs and hash manifest.
- [x] Commit/push with expected-head guard and verify untouched main/stabilization branches.
