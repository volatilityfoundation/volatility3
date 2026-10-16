# ApiHooks Gap Ledger

These report-backed observations are intentionally excluded from the counted
560-case suite because the current plugin does not detect them directly:

- `SetWindowsHookEx` / GUI hook-chain style interception
- VEH and hardware-breakpoint based API interception
- IRP / driver-object major-function hooks

They remain tracked here so future detector work can turn them into first-class
coverage without overloading the current plugin test suite with expected misses.
