# Known Bugs

## [Severity: High] Silent failure when antivirus signature age is unparseable
- **File:** winrecon/checks.py:610-651
- **Issue:** When `sig_age_str` can't be converted to int, `sig_age` is set to -1; neither the `> 7` nor the `>= 0` branch fires, so no finding is emitted and the unparseable state is hidden.
- **Repro:** Run on a host where `Get-MpComputerStatus` returns a non-numeric `SigAge` ("Unknown", empty, error text).
- **Fix:** Add an `else` branch that emits a WARNING finding for `sig_age < 0`.

## [Severity: Medium] RTP check unreachable when AV is disabled
- **File:** winrecon/checks.py:616-635
- **Issue:** The `if av_enabled / elif not rtp` structure skips the RTP check whenever AV is disabled, so both issues can't be reported together.
- **Repro:** System with disabled Defender but a separately broken RTP setting — only the AV finding appears.
- **Fix:** Replace the `elif` with an independent `if not rtp:` so both states are reported.

## [Severity: Medium] CLI mutates module global DEFAULT_TIMEOUT
- **File:** winrecon/cli.py:190
- **Issue:** Assigning to `_core_mod.DEFAULT_TIMEOUT` from the CLI breaks idempotency and leaks state into any later importer of the module.
- **Repro:** Import and call `winrecon.core` functions after `cli.main()` ran with a custom timeout — the override persists.
- **Fix:** Thread the timeout through `run_command()` call sites instead of patching the module global.

## [Severity: Low] "Reports saved" logged even when HTML report write fails
- **File:** winrecon/cli.py:221-228
- **Issue:** Success message is emitted unconditionally; if JSON succeeds but HTML write throws, the log misreports success.
- **Repro:** Point output to a directory that rejects `.html` writes — JSON is saved, success message prints, HTML is missing.
- **Fix:** Wrap each write in try/except and only log once both reports land on disk.
