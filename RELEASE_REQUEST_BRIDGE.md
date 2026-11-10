# Reviewed source request to the existing protected release signer

This is a local candidate for the public release repository. It adds a bounded
Windows 1.2.14 request path using existing repository write access. It does not
change the signing key, Environment, financial admission, or existing signer.
Do not publish the request until root has accepted the final Analytics/price
fixes, source commit, privacy review, reconstruction test and local checks.

## Public files

Publish these reviewed files to `Rigby453/steam-float-scanner-releases` together:

| Local candidate | Public repository path |
| --- | --- |
| `release-request.mjs` | `tools/release-request.mjs` |
| `release-request.test.mjs` | `tools/release-request.test.mjs` |
| `build-release-request.yml` | `.github/workflows/build-release-request.yml` |
| `RELEASE_REQUEST_BRIDGE.md` | `RELEASE_REQUEST_BRIDGE.md` |

Keep the original `tools/sign-release.mjs` unchanged, SHA-256
`12088d415fc8553ee0a7491d1457813c2c42204121ca1f20b5a9d866b532c38a`.
The workflow contains three identical pins for the new helper. Recompute and
review every pin whenever its bytes change. New helper tests run without the
write token; only the final trusted staging command receives it.

In a subsequent deliberate atomic commit, add both:

- `release-requests/1.2.14.pack.b64`: canonical single-line base64, optionally one
  final LF, of the genuine supplemental Git pack; never an invented commit.
- `release-requests/1.2.14.json`: the reviewed request below. Only a change to
  this exact request on public `main` triggers the new workflow.

## Request schema

The following is a schema example, not a valid release request; replace every
placeholder with verified actual bytes/identities. Arbitrary URLs, scripts,
version overrides, key names, token fields or financial approvals are rejected.

```json
{
  "schemaVersion": 1,
  "version": "1.2.14",
  "sourceCommit": "<actual immutable 40-hex private-source commit>",
  "sourceTree": "<that actual commit's 40-hex tree>",
  "sourceSha256": "<sourceState SHA256 of all actual build inputs>",
  "baseZip": { "sha256": "<verified public 1.2.13 source ZIP SHA256>", "bytes": 0 },
  "supplement": {
    "path": "release-requests/1.2.14.pack.b64",
    "sha256": "<decoded binary pack SHA256>",
    "bytes": 0
  },
  "omittedPaths": [],
  "releaseNotes": "<reviewed nonempty release notes>"
}
```

The base URL is fixed in the helper to the existing public v1.2.13 source ZIP.
Its maximum is 128 MiB; the decoded supplemental pack maximum is 16 MiB.
The pack must contain the actual final commit/tree objects and every needed
blob/tree absent from the public ZIP. Missing historical parents are allowed
only by the declared actual HEAD shallow boundary. Root must prepare/review
the objects and public source contents; a Git object hash is not a secrets scan.

Prefer `omittedPaths: []`. Only explicit non-build `docs/` files and old
`release/build-records/<version>.json` may be omitted, maximum 256. No build,
test, migration, tools, cloud, lockfile or configuration input can be omitted.
Omitted private files are absent, not filled with placeholders. Their real
tree/blob identities are retained in the actual tree; the source ZIP declares
the sparse scope in `SOURCE_MATERIALIZATION.json` and release-source metadata.
Such an archive is the exact available build/test source, not a complete copy
of historical repository documents.

## Execution and trust boundaries

1. The read-only Windows job checks the helper/signer pins, validates the
   bounded request/base ZIP/base64 pack, seeds raw Git objects (including ignored
   files, with no line filters), reconstructs the actual shallow HEAD/tree and
   verifies each present blob OID. No synthetic source commit is created.
2. It restores locked dependencies and checksum-verified Electron, runs full
   source types/build and root/engine/desktop suites, then native packaging and
   the actual Electron packaged financial 14/56/56 acceptance. It requires the
   current original-key financial admission before making a release bundle.
   It has no signing Environment, signing secret or write-token environment.
3. A fresh Ubuntu staging job downloads only the current run's artifact. It
   verifies exact file inventory/hashes, source/request/run/native identities,
   feed, source ZIP inventory and strict zero-write financial proof. The current
   public original-key policy must admit the actual win32/x64 implementation.
   Unknown/expired/near-expiry financial bytes stop here. No policy is signed,
   extended, duplicated or automatically approved.
4. Staging alone has repository-scoped ephemeral `contents: write` and
   `actions: write`, no signing Environment/key. It rejects any existing
   `v1.2.14` release (including an incomplete draft), creates a new stable draft,
   uploads the exact six Windows inputs, and dispatches the **unchanged**
   `sign-release.yml` on main using the exact draft/source-record identities.
5. The existing signer receives a real `workflow_dispatch`; its event/ref/
   workflow-file checks are not spoofed. Its independent verify stage, original
   main-only `release-signing` Environment and pinned builtin-only key-bearing
   script remain intact. It rechecks admission and assets, signs, verifies
   public bytes and immutability, then promotes latest. Dispatch is not success.

Keep public main at the reviewed request commit until staging and signing have
started/completed. Staging checks main before draft creation and dispatch and
fails if it moved. No stage executes code from the source ZIP or built artifact
with the write token; no source/dependency code ever executes with the key.
The native proof still has the existing trusted-build boundary; this is not an
independent attestation against arbitrary malicious reviewed source code.

GitHub explicitly permits a workflow's `GITHUB_TOKEN` to create a real
`workflow_dispatch` run, unlike ordinary token-generated pushes:
[GitHub triggering documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
This uses the already authorized repository integration and repository-scoped
runner token. It does not require credential extraction, a new login, PAT,
signing key, Environment relaxation or removal of protected checks.

## Checks and remaining acceptance

Run the pure validator tests with:

```text
node --test work/release-automation/release-request.test.mjs
```

In the public repository use `node --test tools/release-request.test.mjs`.
These tests validate request/context/base64/ZIP traversal and CRC controls,
financial proof shape and compatibility with the unchanged signer inventory.
They do not prove an actual complete-source reconstruction or remote CI.

Root's next isolated materialization check must use the actual 73 MB public
source ZIP plus its genuine reconstructed source pack, verify exact commit,
tree, complete present blob hashes, clean index and sourceState SHA, and check
that no original source/profile is touched. The helper currently downloads
the fixed base URL; a test may inject an in-memory response from the already
hash-verified local ZIP. Do not change production URLs or hashes for the test.

The actual historical 1.2.13 financial proof matches all 14/56/56 zero-write
fields and native source identity. Its old build-verification JSON lacks the
new `purchaseImplementation` field. Do not manufacture that field: the new
1.2.14 package verifier must emit and verify it from the actual ASAR.

Failures preserve the draft/artifacts for inspection and do not overwrite,
delete, automatically resume, change latest or rebuild an immutable version.
If staging fails after creating a draft, root must inspect the precise state
and deliberately plan recovery with the exact retained bytes. A new login,
old workflow rerun with substituted inputs, unknown admission or secret read
is not a recovery shortcut.

No remote files, release, workflow run, installation or purchase were created
while preparing this local candidate. Actual publication/installation acceptance
and source/public readback remain root's work after final source review.
