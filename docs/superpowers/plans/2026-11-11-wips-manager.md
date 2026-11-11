# WEC8500 WIPS Manager Implementation Plan

> **For agentic workers:** execute independent modules against the shared interfaces below; verify integration before delivery.

**Goal:** Windows 11 Python GUI for sequential AP WIPS configuration changes through WEC8500 Telnet.

**Architecture:** core validation/parser/runner with replaceable Telnet/AP SSH transport and demo transport; GUI uses a queue and worker thread. One controller session with strict exit/prompt verification between APs prevents context leakage.

**Tech Stack:** Python 3.11+, Tkinter, socket/select, unittest.

**Spec:** ../specs/2026-11-11-wips-design.md

## Global Constraints
- No real connection or credentials during development.
- All credentials runtime only, never in exports or raw logs.
- No mode changes, reboot, guessed save or mutation retries.
- Configuration match does not establish WIPS connectivity.

## Review Focus
- Nested SSH returns to controller after failure: no AP configuration sent there.
- After every AP, exit must return to the exact captured controller prompt before the next ssh; failure halts the batch.
- Partial response, timeout or stop after write: result must be unknown.
- Unknown/duplicate/malformed IP fields must not cause a success or mutation.
- Existing and new shared keys and passwords must not leak to CSV/log/error UI.
- GUI worker must use queue for all Tk operations and stop must unblock dialogs/waits.

### Task 1: Core, runner and tests
Files: wec_wips/core.py, tests/test_core.py.
Interfaces: RunConfig, Summary, Result, parse_summary, export_results, Runner.
- [x] Write input/parser/runner safety tests and run to establish missing implementation.
- [x] Implement strict validation, exact verification, result allowlist and cancellation semantics.
- [x] Run `python -m unittest discover -s tests -v`.

### Task 2: Controller/AP transport and tests
Files: wec_wips/transport.py, tests/test_transport.py.
Interfaces: Session(config, stop, confirm).connect(ap_ip), execute(command), leave_ap(), controller_ready property, close().
- [x] Test fake-channel fragmented password/prompt, controller fallback and host-key handling.
- [x] Implement Telnet controller login and bounded interactive prompt waits.
- [x] Run transport tests and combined suite.

### Task 3: GUI, Windows launch and delivery
Files: wec_wips/gui.py, app.py, requirements.txt, install.cmd, start.cmd, README.md.
Interfaces: Runner emits log {message}, progress {index,total,ap_ip}, result {result:Result}, done {cancelled}; inspect/apply modes. GUI calls export_results(path, results).
- [x] Implement form, AP paste/CSV, queue worker, trust confirmation, demo, stop and CSV export.
- [x] Verify GUI demo, cancelled/failed paths and CSV output.
- [x] Review source independently, fix substantive defects, run complete suite, package validated source ZIP and persist deliverable.

### v1.1 explicit user workflow update
- [x] Single controller connection; AP default root:50022.
- [x] Conditional automatic yes on new AP SSH question; password only after request; reject changed host keys.
- [x] Exit and exact controller prompt verification between APs; show return status.
- [x] Add shared-session unit and real loopback SSH two-AP/exit-failure tests.

### v1.2 controller transport correction
- [x] WEC8500 uses Telnet port 23, AP still uses CLI SSH root:50022.
- [x] Implement fragmented Telnet IAC/options and controller username/password prompt handling.
- [x] Remove Paramiko and third-party runtime dependencies; install/start usable offline.
- [x] Verify real loopback Telnet→nested AP SSH two-target sequence and failure isolation.

### v1.3 read-only target IP verification
- [x] Add verify_ip mode with required target IP and no WIPS key requirement.
- [x] Run only summary and exit; show IP match/mismatch and retain target in CSV.
- [x] Continue on mismatch; retain existing failure/session stop behavior.
- [x] Verify core, GUI and loopback Telnet with no config transmission, then build EXE/ZIP.
