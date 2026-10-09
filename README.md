# Steam Float Scanner releases

Current release: **0.2.150**.
[Installer and all eleven verified assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.150).

Windows EXE: 112112013 bytes, SHA256
`3f9a0788303640c2570436fdcaf8094172a83df67f0de5fbea384399af7e6561`.
Linux DEB: 106331284 bytes, SHA256
`7ad4b888c9911d28267ebc98f91061b07a7b2d330baaddb52876d53ab80385c6`.

[Exact source tag](https://github.com/parserst/steam-float-scanner/tree/v0.2.150)
identifies build commit `1d85315cc096b9aa343764d27d9f0adb58a2f2c3`.
Native Windows/Ubuntu CI passed source suites and package verification.
[Signing and publication](https://github.com/Rigby453/steam-float-scanner-releases/actions/runs/37916817523)
verified all eleven public assets before latest promotion. The existing Ed25519
trust key is retained; the new release is immutable. Independent Windows/Linux
checks composing the actual150 production transport and service report
149→AVAILABLE150 and150→UP_TO_DATE. The earlier149 check omitted the transport
wrapper and missed its GitHub redirect rejection. Installed149 needs one manual
upgrade to150. This release also extends bounded database preparation time and
stops repeated startup timeouts; command and financial deadlines are unchanged.

[Automated signing instructions](SIGNING.md) let an authorized Cloud dispatcher
publish through GitHub Actions without receiving the signing key. The old
encrypted PEM and passphrase are Environment Secrets restricted to main;
trusted signer bytes are pinned by the workflow. Secret values are never in Git.
A Cloud caller still needs repository access and Actions dispatch permission.

GUI baseline price/proxy-order/layout failures remain unresolved; package
proof does not establish a clean full GUI suite. Owner-profile installation,
live AUTO_BUY/Steam and Seattle deployment are separate checks. In particular,
150 does not repair the newly confirmed Steam PURCHASE_CONTRACT_ROUTE_CHANGED;
that needs separately reviewed and signed compatibility metadata.

## Previous release history

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
