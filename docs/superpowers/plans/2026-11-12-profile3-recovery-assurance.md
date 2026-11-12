# profile.3 manual recovery assurance

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. These are additional assurance tests; product changes require a reproduced defect first.

**Goal:** Check that profile failures do not prevent deliberate manual operation or silently revive saved credentials.
**Architecture:** Exercise unchanged ProfileApp, ProfileStore, Runner and loopback transport using temporary profile files and synthetic secrets. Preserve profile.3 if no product failure is reproduced.
**Tech Stack:** Python unittest, Tk/Xvfb, local TCP; injected protector is not native Windows DPAPI.
**Spec:** PROFILE_FEATURE.md (manual input fallback and explicit storage), PROFILE_STABILITY.md (data preservation), PROFILE_MODAL_STABILITY.md (profile.3 baseline), user's continuation request.

## Global Constraints
- No new user features, device commands, authentication policy or runtime changes.
- No main/stabilization branch changes, merge or Release; feature branch only.
- No native Windows or equipment validation claims.
- Do not rebuild/renumber the EXE for tests-only work.

## Review Focus
- Corrupt/unreadable profile must not retain a usable cached secret.
- Manual password entry must recover from decryption failure without overwriting stored ciphertext.
- Query-only execution must remain independent of an unusable saved target key.
- Deselecting saved secrets must survive a new app instance.
- Failed deletion and omitted AP targets must not cause automatic operations or lose data.

### Task 1: Boundary tests
- [x] Add tests/test_profile_manual_recovery.py with real Tk/store/Runner/loopback fixtures.
- [x] Cover corrupt startup, denied reload, failed decryption/manual retry, unusable target key, deselection/reopen, corrupt delete/resave, failed delete/retry, missing targets.
- [x] Run against unmodified profile.3; investigate failures before touching product code. Passing cases are coverage, not bug fixes.

### Task 2: Verification and delivery
- [x] Re-run entire suite twice with zero errors/skips/remaining workers.
- [x] Negative control on disposable source copy to prove selected new assertions detect removed protections.
- [x] Direct code review, unchanged tree/blob comparison and existing EXE payload checks.
- Publish to the existing feature branch with an expected-head guard and verify the remote tree; no new EXE is needed for this tests-only change.
