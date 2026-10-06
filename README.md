# Steam Float Scanner — official releases

Current release: **0.2.142**. [Installer and seven verified assets](https://github.com/Rigby453/steam-float-scanner-releases/releases/tag/v0.2.142).

This correction fixes STORAGE_FAILURE when proxy preflight returns PROXY_PAYMENT_REQUIRED or PROXY_PROVIDER_DENIED. Additive migration037 preserves the existing runtime fields and extends the SQLite outcome constraint. Refused routes stay disabled across save/reopen; a newer verified success can restore them. Existing exact purchase, money, Stop, Guard and receipt safeguards are retained.

Price review now compares market/proposed prices beside the skin, allows result rejection and optional local proposal-only startup checking. Ownership failures offer SFS account navigation; explicit Start recalculation preserves all route/purchase safeguards. Buyer/session SQL has been deployed and passed synthetic transactional rollback tests; no real purchase is claimed.

The owner explicitly chose to keep this release repository public on2026-10-06. The source Git repository remains private; the exact release source archive is public with its other assets. Exact source: [v0.2.142](https://github.com/parserst/steam-float-scanner/tree/v0.2.142). The release includes installer/blockmap/latest.yml, the existing-key signed manifest, build verification, source provenance and the exact source archive. Historical release bytes and tags are retained.

On the affected Seattle server, the owner installed0.2.141; this task does not install0.2.142 or start any market operation. Stop/drain, take a consistent profile backup, exit fully and install the verified correction manually. The0.2.141 protected in-app updater still requires its configured authenticated backend, whose Edge deployment remains pending; buyer/session SQL is deployed and rollback-smoked. In0.2.142 the update button uses the pinned public signed GitHub channel without SFS login/backend dependency, retaining signature/hash and explicit-install/Stop/drain checks. No GitHub credential is shipped in the application.

See [release acceptance](https://github.com/parserst/steam-float-scanner/blob/main/docs/RELEASE_0_2_142.md). Source tests and a migrated consistent copy do not prove a successful live purchase or fix the proxy provider's payment/quota refusal.
