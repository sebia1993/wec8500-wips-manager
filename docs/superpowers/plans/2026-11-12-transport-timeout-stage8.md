# Stage 8: AP_LOGIN_TIMEOUT investigation and final development gate

> For agentic workers: use superpowers:executing-plans and systematic-debugging.

**Goal:** Reproduce and explain intermittent in-memory transport-test login failures without weakening product timeouts or device safety.
**Architecture:** Verify the pinned 2fcb28e tree, inspect retained first-failure evidence, distinguish real elapsed time and synthetic protocol time, then change only the faulty boundary demonstrated by tests.
**Tech Stack:** Python stdlib unittest, Tk/Xvfb, synthetic peer and existing loopback TCP integration.
**Spec:** User-approved 10-stage checklist: start 70%; stage 8 adds 10% only after the investigation and final development checks close. Windows/equipment stages 9–10 are excluded.

## Constraints
- No new application functions, timeout/retry/status changes, main merge or Release.
- Keep all failed-run evidence; historical scheduling causes cannot be asserted without trace evidence.
- Work in local isolated worktree; update only feature/windows-protected-profile with expected head.
- Existing profile.4 EXE remains unchanged if only tests/docs change.

## Review focus
- Host scheduling pauses must not masquerade as absent replies from an in-memory peer.
- Real configured response expiry and cancellation must still be tested and enforced.
- Clock mocks must not modify Python time globally or leak into integration/GUI tests.
- Two subcases may share a config; state and mock cleanup must remain isolated.
- Keep real socket integration tests and no skipped tests in Linux validation.

## Tasks
- [x] Reconstruct snapshot from attached source and prior evidence patch; verify tree identity.
- [x] Run baseline whole suite; trace targeted AP login waits and retained errors.
- [x] Reproduce causal mechanism with controlled conditions and record alternative hypotheses.
- [x] Write regressions first; make minimum test/implementation fix supported by reproduction.
- [x] Run focused repetitions, full suite twice, negative controls and application hash comparison.
- [ ] Publish evidence, progress register and Windows handoff checklist; verify GitHub branch update.

## Rulings and outcome

- Reproduced host-time dependency is a unit-fixture problem; keep product code unchanged. Historical per-failure scheduler details are not recoverable from the old log and are not claimed.
- No subagent reviewer available; the focused diff and safety/timeout negative controls were reviewed directly.
- 40 transport tests x100 and 407 full tests x2 pass without failures/errors/skips/remaining workers.
- Progress gate 8 is closed on the reproduced mechanism remediation and final local checks; Windows/device gates 9–10 remain open.
- GitHub publication verification is recorded in the delivered evidence bundle, not assumed before the ref update.
