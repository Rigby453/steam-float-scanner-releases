# Steam Float Scanner releases

Current immutable Windows release: **1.1.2**. [Installer](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.1.2), [exact source](https://github.com/parserst/steam-float-scanner/tree/v1.1.2), [verification](https://github.com/parserst/steam-float-scanner/blob/main/docs/reports/2026-10/1.1.2.md).

Commit `71b99455216b5b717f3f0a7eb2aa3d49d927c085`. EXE SHA-256: `75d559780a5afc7cf69f68801b393d930f94ea89ad519957c7f56f6d0f62da8a`.

Standalone Recent matches selected saved skin rules and checks exact Float, seed and price through a shared scanner proxy pool. Country/bulk proxy controls remain available when Steam analytics cannot load. Existing unified scanner functionality is retained. Recent is a small window and is not complete market coverage.

8890 local tests PASS / 10 skipped; strict types, browser fixtures, native packaging and complete public updater verification PASS. [Protected original-key signing](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/40132115932) succeeded. Source CI availability is recorded separately. The reviewed signed purchase policy supports this chain and equivalent versions without paid compatibility tests; unchanged exact purchase/receipt safeguards remain.

No server installation, profile start or real purchases were performed during this release. Previous releases and compatibility metadata remain available. Linux historical artifacts are preserved; this release qualifies Windows x64.
