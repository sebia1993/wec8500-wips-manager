# profile.4 save-dialog consent assurance

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. Product changes require a reproduced defect; passing existing behavior is assurance, not a bug fix.

**Goal:** Verify that real save-dialog choices, cancellation and invalid-input recovery match the explicit secret-storage contract.
**Architecture:** Invoke existing Tk buttons/checkbuttons and run the real ProfileApp, ProfileStore and Runner. Use only synthetic credentials, temporary files and a loopback controller. Keep profile.4 unless a product defect is reproduced.
**Tech Stack:** Python unittest, Tk/Xvfb, standard-library sockets. TokenProtector is an external-protection test double, not Windows DPAPI validation.
**Spec:** docs/superpowers/specs/2026-11-12-windows-profile-design.md; PROFILE_FEATURE.md; user's continuation request.

## Global Constraints
- No new features, command/retry/result policy changes, or plaintext credential persistence.
- Keep main and the stabilization branch unchanged; update only feature/windows-protected-profile with expected-head verification.
- No release, runtime upgrade, or new EXE for test-only work.
- Actual Windows and equipment validation remain with the operator.

## Review Focus
- First save without checking secret options must not persist typed passwords or keys.
- Cancel/button, Escape and window-close paths must preserve the prior profile.
- Checkbox selections must control persistence, not only UI appearance.
- Invalid public input must keep the dialog editable and leave disk untouched.
- Another window's update while the dialog is open must not be silently overwritten.
- Persist/reopen/inspect must use only the selected AP secret and require fresh WEC credentials.

### Task 1 — Save-dialog behavior
- [x] Add tests/test_profile_save_dialog.py using actual Tk button invocation, not calls directly to the persistence handler.
- [x] Cover the six review-focus behaviors, asserting disk bytes, recoverable values and wire commands.
- [x] Run on the unchanged product. Investigate any failures before modifying code.
- [x] Run disposable negative-control mutations for missing consent and save-on-cancel; never ship mutants.

### Task 2 — Final verification and delivery
- [x] Run the complete suite twice in one process, checking failures/skips and remaining threads.
- [x] Inspect the focused diff and existing source hashes. Re-extract the original EXE and compare its payload manifest.
- Publish the verified changes to the existing feature branch with an expected-head guard and verify the tree; preserve initial failed-run evidence.
