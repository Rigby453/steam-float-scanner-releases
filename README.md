# Steam Float Scanner releases

Current immutable Windows release: **1.2.4**. [Installer](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.2.4), [exact source](https://github.com/parserst/steam-float-scanner/tree/v1.2.4), [single report, all checks and CI limits](https://github.com/parserst/steam-float-scanner/blob/a7501f747abe6192ecbfe068817ab3d636ad3e27/docs/reports/2026-11/analytics-requests-timeouts-2026-11-01.md).

Fixes the1.2.0 interval identity-query whole-run scan, lets durable catalogue items start before a slow later page, removes unrelated HTML endpoint waits from JSON analytics and restores explicit Continue after storage timeout. Four existing-index searches retain every conflicting identity check; no schema migration, data deletion or automatic unknown-write replay.

Retained20-lookup SELECT batches:5.65–8.34s before /7.8–15.2ms after, identical rows. This excludes checkpoint writes/fsync and is not a full new live Steam crawl. Existing30s/45s analytics deadlines and financial rules remain unchanged.

Source ef48377bfb42180e49274661f97dd2a13889022b; source SHA256 14696bfef37c40d182812d8569e785a2851ae5efb85c230d2593967d2f7184ff. Installer121851504bytes, SHA256 ccd1c6bd3341f29448443f60e0de212d3ded0ad7b2e420f3456ea1accdd22982. Native218payload/45build/eight smoke groups, financial14profiles/56roles/56altered-reference checks PASS. Actual installed1.2.3 GUI button fully downloaded and verified1.2.4 in an isolated empty profile; no owner installation. Seven assets and sourceZIP verified.

Original key, policy2026110104, previous approvals and23Nov2026 expiry retained. Implementation214fb83113f74aa079c088704cb88a6079bdda2479484f9befcc6f5e17d2bc0e reviewed and admitted by the production gate; no new paid/live purchase claim. CI41347320465: package (windows-latest):success; tests (ubuntu-24.04):success; package (ubuntu-24.04):failure; tests (windows-latest):success. Linux package failed its unchanged backup-maintenance smoke waiting15s for a child; internal cause UNKNOWN and subsequent Linux package/sandbox acceptance is not claimed. Both full source suites and Windows package passed. Authenticode absent.
