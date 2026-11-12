# Profile load commit safety plan

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development.

**Goal:** Check that a partial GUI application of a loaded profile cannot combine old credentials/targets with a newly loaded endpoint.
**Architecture:** Preserve existing profile schema, encryption, device workflows and persistence; only change profile application ordering if a real-Tk regression reproduces unsafe mixed state.
**Tech Stack:** Python stdlib, Tk/Xvfb, unittest, local TCP.
**Spec:** PROFILE_FEATURE.md (controller credentials blank on load, manual fallback), PROFILE_STABILITY.md, user's continuing stabilization request.

## Global Constraints
- No new user features or device commands, no retry/result policy changes.
- Only feature/windows-protected-profile may be updated; no main merge or Release.
- Native Windows/DPAPI/equipment remain operator validation.

## Review Focus
- A widget update can fail after some public fields change; stale secrets/targets must not remain executable.
- Failed loading must not destroy stored profile bytes or prior result/uncertain-write evidence.
- A successful retry must apply a coherent profile and still require controller credentials.
- Normal save/load/no-profile/manual paths must retain existing contracts.

### Task 1: Reproduce
- [x] Add tests/test_profile_load_commit.py exercising real ProfileApp and store; inject a single TclError at a widget boundary, not a replacement completion handler.
- [x] Show failure on the unchanged baseline; record state and real loopback connection effects.

### Task 2: Minimal fix if reproduced
- [x] Clear connection credentials and saved-secret eligibility before applying a new profile's public fields.
- [x] Publish the loaded profile only after the required form updates succeed; retain exact persistence bytes and previous run evidence.
- [x] Exercise early/late faults and successful retry, no new UI or persistence policy.

### Task 3: Delivery
- [x] Run full suite twice, inspect failures/skips/workers, review diff.
- [x] If product changes, create profile.4 from existing runtime/SFX; re-extract and compare. Otherwise retain profile.3.
- [x] Push with expected remote head, verify tree and untouched branches; include actual evidence/limitations.
