# Steam Float Scanner Windows releases

Current release: **0.2.145**.
[Installer and verified assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.145).

Adds bounded core statistics, read-only reports, authoritative Seen snapshots
and reduced snapshot-validation cost. Includes the owner's public compatibility
metadata and Start-safe proxy cleanup corrections, all reading/purchase/Guard/
maintenance work from144 and the143 startup fix. Previous release bytes and
source tags are preserved.

EXE: `Steam-Float-Scanner-Setup-0.2.145.exe`, **112975717 bytes**. SHA-256:
`c417110a5f8fc837499230e75f5a91cb7d653f915c9c728aafd50760c92c6650`.

Source: [v0.2.145](https://github.com/parserst/steam-float-scanner/tree/v0.2.145).
[Release acceptance](https://github.com/parserst/steam-float-scanner/blob/main/docs/RELEASE_0_2_145.md)
separates source, native offline, package, signature, updater, download and live
proof. Source components accept4906 tests/383 files; six packaged smokes,
197-file NSIS payload, three isolated native cases, the existing Ed25519 trust
key and all seven anonymous full downloads pass. The production public updater
144→145 downloads identical bytes and145 reports UP_TO_DATE.

The recent-observation cache has constant-time overflow eviction after its
20,000-key bound; report reads cannot enter the financial writer's queue.
Current Seen membership stays at20,000 entries independently of financial
claims/history. Local actual-SQLite component CPU comparisons improve, while
complete read and fake-purchase tails vary. A stable full-engine gain, live
Steam purchase latency and an installed overnight scan are not established.
Earlier injected-client/mock-persistence measurements retain their limits.

- Render20/100, AUTO/RU/EN, exact purchase identity/money/session, durable send
  fences, Stop and receipt verification remain enforced.
- Guard overlaps one optional exact observation with an already sent BUY;
  ACCEPT requires the exact current token and durable fence.
- Future updater cleanup requires initialized new-version storage; current/
  pending installers and reports remain. Build checks remove only their own
  temporary extraction after durable reports.
- Older completed database snapshots become verified streaming archives,
  keeping the latest five and current recovery raw. Errors retain originals;
  archives are never auto-deleted. The bundled restore command writes a new file.

The source Git remains private; exact source ZIP and Windows assets are public
under the owner's choice. Publication does not install, change an owner profile,
clean existing owner files, send real BUY/ACCEPT or deploy a server. No separate
server repository was identified. Historical
[0.2.144](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.144),
[0.2.143](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.143)
and earlier releases remain immutable. Installed142 and later use this public
signed channel; older141 needs a manual first transition because its protected
updater Edge was not deployed.

## Automated signing

[Cloud signing and publication instructions](SIGNING.md). The trusted existing
key is held in protected GitHub Environment Secrets; never add it to Git or chat.
