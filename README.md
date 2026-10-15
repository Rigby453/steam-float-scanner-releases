# Steam Float Scanner releases

Current Windows release: **1.0.1**, published and immutable.
[Installer and seven assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.0.1).
[Exact source tag](https://github.com/parserst/steam-float-scanner/tree/v1.0.1):
`8afd1b0c4c88f4cf1046647283ce63110fe3a1af`.

EXE: **116516861 bytes**, SHA-256
`b73703b6f2afb06c01494b3a7a920646e4ce9298420aced83237c4fccbef805c`.
The existing Ed25519 update trust key is unchanged.

This consolidates qualified Reader/parser/Seen, exact-purchase/receipt,
DIRECT/proxy and SFS account improvements. Same-device recovery authenticates
the retained personal code for the same owner and preserves backup encryption.
The OWNER build keeps undeployed payment and browser-control services disabled.
The public updater now bounds headers, body inactivity and total transfer
separately instead of aborting a progressing download after300 seconds.
An old installed159 client retains its old timeout: one manual transition
using this installer may be necessary on a slow connection.

- [Native Windows qualification](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/38789078465): **7752 PASS, one platform skip**; types, build, payload and Reader smokes passed. Exact native files were independently hash-checked. A separate local native financial check passed14 profiles,56 role and56 tamper checks; the CI financial output/wait gap was corrected for future runs.
- [Protected signing/publication](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/38792582499): original key, seven verified assets, immutable latest1.0.1.
- [Unprivileged public updater acceptance](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/38792811462): actual1.0.1 production service/transport downloaded all116516861 bytes anonymously, checked the signature and independent SHA-256, and repeated local verification. Version parameters152/159 offer1.0.1;1.0.1 reports UP_TO_DATE. This executes1.0.1 source, not the old installed152/159 binaries.
- The actual native1.0.1 Settings update button passed against the public channel in a fresh stopped profile. Isolated EngineRuntime AUTO_BUY ARM/START, one synthetic exact purchase, receipt, FULL storage and Stop passed. Owner installation, owner login, live purchases and live speed acceptance were not performed.

The separate `purchase-compatibility-v1` prerelease channel contains signed
revision**2026101503**:13 preserved legacy deployments plus three reviewed
exact111-module snapshots, no automatic graph policies, original expiry
**2026-11-04T20:12:56.038Z**. Fresh native production verification passed.
Unknown deployments continue to block. The protected1503 job published the
asset but failed its final anonymous readback window; subsequent independent
public signature/payload readback and the native production gate passed.
Future readback polling was extended without repeating publication mutations;
91 mock tests and independent review passed. That future polling window has
not been exercised in another protected signing run.

[Signing instructions](SIGNING.md),
[public updater acceptance scope](PUBLIC_UPDATER_ACCEPTANCE.md),
[private source acceptance and archive register](https://github.com/parserst/steam-float-scanner/blob/main/docs/reports/2026-10/1.0.1.md).
Existing protected Environment Secrets remain restricted to main. Signing keys,
owner profiles, sessions, cookies and proxy credentials never belong in Git.

Earlier immutable releases and source tags remain historical, including
[1.0.0](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v1.0.0),
[0.2.152](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.152)
and [0.2.150](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.150).
Historical GUI price/proxy-order/layout findings are not closed by package
smokes; their prior acceptance limits remain in source reports and Git history.
