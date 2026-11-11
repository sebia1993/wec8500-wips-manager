# Windows Protected Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Restore one approved profile with optional DPAPI secrets; never persist WEC credentials.
**Architecture:** Isolated ProfileStore + current-user DPAPI backend + ProfileApp subclass of unchanged GUI. Existing Runner/transport/report policies untouched.
**Tech Stack:** Python 3.11+, Tkinter, ctypes/Win32, unittest; no new runtime package.
**Spec:** docs/superpowers/specs/2026-11-12-windows-profile-design.md

## Global Constraints
- Explicit secret-storage choices; never serialize controller_user/controller_password.
- No plaintext fallback, automatic network actions, policy changes or main/stabilization branch updates.
- Native Windows and equipment validation remain operator tasks, not claimed as completed.

## Review Focus
- Different controller/AP identity must invalidate stored secrets: store and GUI tests.
- Empty entries are not placeholders; manual override and deselection must work: GUI tests.
- Encryption/write/corruption failures preserve prior file and allow manual operation: store tests.
- Demo actions cannot expose/decrypt/overwrite real secrets: GUI tests.
- Query-only execution must not decrypt saved target key: mode tests.

### Task 1 — store and DPAPI
- [x] Add tests/test_profile_store.py for explicit selection, allowed fields, bindings, malformed inputs, atomic failure, delete and unsupported platform. Run RED.
- [x] Implement wec_wips/dpapi.py and wec_wips/profile_store.py. Interfaces protect/unprotect(bytes,entropy), ProfileStore.load/save/delete/secret. Run GREEN.
- [x] Add Win32 contract tests and operator-only native Windows check; commit.

### Task 2 — GUI integration
- [x] Add tests/test_profile_ui.py with real Tk and injected non-production protector. Run RED.
- [x] Implement wec_wips/profile_ui.py ProfileApp(root,store=...) and main(demo_fill=False). Modify app.py import only. Run GREEN + existing regression; commit.

### Task 3 — delivery
- [x] Re-read diff, run complete suite twice and collect logs. Check unchanged production modules.
- [x] Repack original runtime/SFX with new app code, extract and compare; no native Windows claim.
- [x] Add usage/security/validation docs; source/EXE/evidence ZIP and hash manifest.
- [x] Push new feature branch off bb9d09b, verify tree and unchanged existing branches.
