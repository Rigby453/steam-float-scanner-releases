# Steam Float Scanner releases

Current immutable Windows release: **1.2.3**. [Installer](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.2.3), [exact source](https://github.com/parserst/steam-float-scanner/tree/v1.2.3), [qualification and CI limits](https://github.com/parserst/steam-float-scanner/blob/625c94ae2b42b9e398de9b7963a08b37c5700b21/docs/reports/2026-11/analytics-runtime-fixes-2026-11-01.md).

Compact retained analytics metadata/exact revisions, page-only reconstruction, acknowledged parallel read accounting and bounded analytics30s/45s local timeouts. Scope after exclusions is separate from the raw Steam catalogue; new/current freshness is one minute and historical runs retain their policies.

Source 04b9e22f7a06d903cc1ffa396c64e536ab9bcf6e. Installer121851722bytes; SHA256 6ff9148769f55422a007995c3fff1389db02f10d73e7e1462174a2d65f526a6a. Native218/45/eight smoke groups and financial14profiles/56roles/56alterations PASS. Actual packaged renderer/preload/SQLite scope20613→16867 and freshness1minute persist across full restart. Installed1.2.2 button fully downloaded/verified1.2.3 in a separate empty test profile; no owner installation.

Original Ed25519 key and policy2026110103 preserve previous approvals and23Nov2026 expiry. No new paid/live purchase claim. Seven assets/hash/sourceZIP checks PASS. CI41341561165: tests (ubuntu-24.04):success; package (windows-latest):success; package (ubuntu-24.04):success; tests (windows-latest):failure. Two unchanged Windows root tests failed (asynchronous event-order and log-directory recovery race); complete ledger/limits in the report. Authenticode absent. No new owner Steam run or purchase; no universal300ms/full-market-hour guarantee.
