# Steam Float Scanner — official private releases

Current release: **0.2.141**. [Installer and seven verified assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.141).

Variable manual proxy groups, recent endpoint-specific reliability, passive timing, automatic local run reports, device-local plans, bounded full-graph compatibility and protected updater implementation. All seven release assets were fully downloaded with owner authentication and SHA-256 matched.

Exact source: [v0.2.141](https://github.com/parserst/steam-float-scanner/tree/v0.2.141). Source archive, signed manifest, installer/blockmap/latest.yml, build-verification and release-source provenance accompany the release. Later main documentation may advance; historical releases and tags are retained.

**First upgrade from installed136/139 is manual.** Stop and drain the app, take a consistent profile/SQLite backup, exit fully, then run the authorized installer. This publication does not install on either device or start scanning/purchasing.

The repository stays private. Protected in-app updates require deployment of the SFS authenticated release backend and a dedicated server-only read credential. That deployment is pending administrator access; no shared GitHub token is shipped in the app. Current protected-channel live check/download is unverified. The offline authenticated handler/download/signature/hash/drain/install-callback contract passed.

Unknown Steam dependency graphs remain fail-closed until a complete reviewed signed policy exists. Live successful purchase and combined-device account ownership SQL deployment are not established by local tests. See source [release acceptance](https://github.com/parserst/steam-float-scanner/blob/main/docs/RELEASE_0_2_141.md) and [protected release deployment guide](https://github.com/parserst/steam-float-scanner/blob/v0.2.141/docs/protected-releases.md).
