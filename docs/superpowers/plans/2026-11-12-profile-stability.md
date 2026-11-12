# Protected Profile Stability Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans; all work in isolated worktree.

**Goal:** Prevent stale profile writes/uses and keep Tk responsive during profile I/O/DPAPI.
**Architecture:** SHA-256 snapshot revision with a short OS lock around comparison/commit; UI captures plain data then performs profile jobs off the Tk thread. Existing device Runner unchanged.
**Tech Stack:** Python stdlib, Tk, Windows msvcrt byte lock (POSIX flock for tests), existing DPAPI.
**Spec:** Approved audit: WEC8500_profile.1_안정성_추가점검.md, priorities 1–3; user approved implementation.

## Global Constraints
- Never store WEC8500 ID/password; no plaintext fallback or new external packages.
- Existing device commands, retry/status policy and report formats unchanged.
- No main merge or Release. Update feature/windows-protected-profile only after verification.
- Native Windows DPAPI/locking/EXE and real equipment remain operator validation.
- No automatic backup, new password for resume, or ACL rewriting in this scope.

## Review Focus
- Two windows read one revision then both save: at most one commits, other cannot revert credentials.
- External deletion/rotation during decryption: no stale prepared credentials accepted.
- Encryption/write/deletion errors: old bytes survive, no plaintext/log leakage.
- Async completion/close/start failure: no duplicate jobs, Tk from workers, or late device start.
- Resume uses original snapshot/evidence: explicit notice, no silent credential changes.

### Task 1: Persistence consistency
Files: profile_errors.py, profile_lock.py, profile_store.py, tests/test_profile_consistency.py.
Interfaces: Profile.revision; ProfileStore.observed_revision; assert_current(revision); save/delete(expected_revision=...).
- [x] Write stale-write/delete/new-create and stale-secret tests; demonstrate RED.
- [x] Add short nonblocking OS lock, safe error codes, snapshot revisions; compare/commit in one lock. Crypto outside lock with recheck.
- [x] Add real process races, lock release, corrupted revision and failure preservation checks; GREEN.
- [x] Commit local implementation.

### Task 2: Responsive profile operations
Files: profile_ui.py, profile_tasks.py, tests/test_profile_async.py; adapt old GUI assertions to async boundaries.
- [x] RED: delayed save/decrypt/load/delete must return to event loop; old-window new-job cannot start.
- [x] Capture main-thread form data; one worker job + separate completion queue; success/failure/close handling only on main thread.
- [x] Keep original resume snapshot and show explicit authentication/target notice; never force-kill native call.
- [x] GREEN: slow worker ticks, disabled edits, startup errors, close discards prepared device job, failures preserve state.

### Task 3: Verification and delivery
- [x] Full regression twice in one process; inspect errors/skips/threads; normal device behavior unchanged.
- [x] Direct diff/security review; Windows-native test script for new lock/conflict behavior (not executed here).
- [x] Repack original runtime/SFX; extract/compare all payload files; source and evidence ZIPs/hashes.
- [x] Update feature branch with expected head lease; verify unchanged main/stabilization refs.
