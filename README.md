# Steam Float Scanner releases

Current Windows release: **1.1.1**, published and immutable.
[Installer and seven assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.1.1).
[Exact source tag](https://github.com/parserst/steam-float-scanner/tree/v1.1.1):
`ffee149548335ef59f8da9aa493975accb40132d`.

EXE: **116995340 bytes**, SHA-256
`eb49f249bfffdfd78bc5dd953375f9096876e65927033492edfe46af80413c91`.
The existing Ed25519 update trust key is unchanged.

The unified scanner includes CPU/RAM load profiles, native charm search and
exact AUTO_BUY, explicitly enabled common-list/applied-sticker purchases,
bounded Recent RU/US discovery and valid-row processing in partial replies.
Existing exact listing/asset/account/price rules, Guard, Stop, durable reserves,
ambiguous-send holds and receipt reconciliation remain. NODE remains the default
transport; GO is an explicit read-only experiment. New channels do not establish
complete market coverage or a universal live speed improvement.

- Local Windows integration suites: **8882 PASS, 10 skipped** before the isolated compatibility correction; **108 focused checks and strict types PASS** after it. Native packaging passed all eight smokes, 42 first-party build files and 213 payload files. The actual packaged financial harness passed 14 profiles, 56 role checks and 56 tamper checks, including pending-receipt and late-Stop blocks, with zero external requests or purchases.
- [Protected signing/publication40126108139](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/40126108139): SUCCESS, original key, all seven public assets verified, immutable latest1.1.1.
- [Independent public updater acceptance](https://github.com/parserst/steam-float-scanner/blob/main/docs/verification/unified-20261024/public-update-1.1.1.json): actual production service/transport verified the signature, downloaded the complete EXE and checked its SHA-256. Version parameters0.2.159/1.0.1/1.0.9 offer1.1.1;1.1.1 returns UP_TO_DATE. This verifies the current service, not the old installed binaries or a newly exercised GUI button.
- Source GitHub CI40125682175 did not start because of account billing/spending limits. Local qualification and protected release signing are separate successful evidence; the unavailable source CI is not described as a test pass.
- The source ZIP matches all2072 native build inputs: exact tagged source plus nine generated public cabinet files. [Source/package/release report](https://github.com/parserst/steam-float-scanner/blob/main/docs/reports/2026-10/1.1.1.md).

The mutable `purchase-compatibility-v1` channel now also serves signed
`protocol.json`, revision **2026102401**, valid through
**2026-11-23T19:34:02.707Z**. The current client automatically reuses approval
when its exact reviewed financial chain is unchanged across app-version or
unrelated scanner/UI edits. Changed chains, bad signatures, expiry and rollback
remain blocked. The public production gate passed current/equivalent-version
admission and changed-chain refusal with **zero Steam requests and purchases**.
Paid compatibility tests are not required for an unchanged chain. Historical
Steam UI compatibility metadata remains separate and is preserved.

Seattle readonly verification found installed1.0.1 and available1.1.1 with the
same public installer hash. No server installation, owner-profile start, login
or real purchase was performed. Historical GUI findings and new charm/common-list
live purchase acceptance are not closed by source or package tests.

[Signing instructions](SIGNING.md),
[public updater acceptance scope](PUBLIC_UPDATER_ACCEPTANCE.md),
[source acceptance and archive register](https://github.com/parserst/steam-float-scanner/blob/main/docs/reports/2026-10/1.1.1.md).
Protected Environment Secrets remain restricted to main. Signing keys, owner
profiles, sessions, cookies and proxy credentials never belong in Git.

Earlier immutable releases and source tags remain historical, including
[1.0.1](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.0.1),
[1.0.0](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.0.0)
and [0.2.150](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.150).
An old installed159 client retains its old300s progressing-download timeout;
one manual transition may be necessary on a slow connection.
