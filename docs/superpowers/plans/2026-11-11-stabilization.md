# v1.5.1 behavior-preserving stabilization

## Approved scope
User approved implementation after review; Windows and equipment validation belongs to user.
Keep UI, commands, modes, defaults, retries, status policy, hostname priority, shared-key reporting and formats unchanged. No dependency/runtime upgrade. Work on a separate branch; do not merge or publish Release.

## Tasks
1. Pin upstream 35ef7b4978a18bf5b684b63981dfdf3e462ffdd5; verify source hashes and full-suite baseline.
2. RED/GREEN: prevent missing-key removal in conflicting AP inventory; preserve conflict exclusion.
3. RED/GREEN: preserve fragmented UTF-8 per controller connection; reset on close/reconnect, fail closed on pending incomplete unsolicited data.
4. Diagnose full-suite delay using stack dumps; change only reproduced root cause.
5. Test cancellation/cleanup, large GUI queues and export failures; only fix reproduced faults.
6. Correct documentation; maintain all application policies including partial-recovery classification.
7. Full regression, behavior parity and package static validation; produce source/Windows/evidence ZIPs and push isolated branch.

## Verification
Each production fix requires a failing regression first. Run all tests together without skips, then repeat. Synthetic data/loopback only. No real equipment, no native Windows execution. Compare unchanged files, command traces and package hashes.
