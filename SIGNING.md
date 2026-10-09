# Scanner release signing in GitHub Actions

This implementation belongs in `Rigby453/steam-float-scanner-releases`.
Cloud prepares verified unsigned artifacts and dispatches the existing workflow.
GitHub Actions signs them with the same key already trusted by installed
Scanner versions, verifies downloads, and publishes without the laptop.
The private key is never supplied to the Cloud chat or checked into Git.

## One-time owner-controlled setup

1. Review and commit `.github/workflows/sign-release.yml`,
   `tools/sign-release.mjs`, and `tools/sign-release.test.mjs` on release-repo
   `main`. The workflow must contain the exact script SHA256 in both steps;
   no placeholder may remain. The full checkout action SHA is pinned.
2. Create the `release-signing` GitHub environment and set its deployment
   branch rule to the literal branch `main`, with no tag rule. Restrict who
   may modify workflow files; do not give Cloud's dispatcher Workflows write.
3. In that environment, store `SFS_UPDATE_PRIVATE_KEY_PEM` (the existing
   encrypted PKCS8 PEM) and `SFS_UPDATE_KEY_PASSPHRASE` (its passphrase).
   Export the existing DPAPI-protected passphrase only in a local in-memory
   operation and pipe each value into `gh secret set --env release-signing`.
   Do not put secret values in argv, console output, files, `.env`, or a PR.
   Do not rotate the key: old installed versions already trust its public key.
4. Enable release immutability for future releases in the release repository.
   It protects a release's assets/tag only after publication; old nonimmutable
   releases are not rewritten. The signer publishes nonlatest first and
   refuses latest promotion unless the returned release is immutable.
5. Give Cloud a separately scoped GitHub dispatch/upload credential for this
   repository: Contents write to create a draft/upload assets and Actions
   write to dispatch the existing workflow. No Secrets, Administration, or
   Workflows write is needed. A GitHub App or suitably scoped existing
   integration avoids a broad cross-repository PAT. Provision through its
   normal secret settings, not a chat message. The signer itself uses only
   its repository-scoped, short-lived `GITHUB_TOKEN`.

No required reviewer or waiting period is imposed by this workflow. An owner
may optionally configure an environment reviewer if manual release approval
is desired. Branch restriction and the code hash pin remain necessary in
either mode. Uploading both secrets puts signing capability in the approved
GitHub runner; encryption of the PEM does not isolate it from a job that is
given both values. Repository administrators and workflow maintainers remain
trusted. This design reduces exposure; it does not promise impossibility of
a leak from a compromised GitHub account or runner.

The script hash pin is security-critical: even without Workflows write,
Contents write can edit an external `.mjs` file on `main`. The unchanged
workflow refuses to execute modified signer bytes. Updating signer code
therefore also requires an authorized workflow-file change updating the pin.
The signer is standalone and imports only Node builtins.

## Preparing a release

Produce native Windows package proof, and Linux proof when releasing the deb.
Review the source CI run and exact source commit using source-repo access.
Create a *new stable draft* `v<version>` in the release repository. Its body
must be the reviewed release notes; existing published versions are rejected.

For a Windows and Linux release, attach these nine unsigned assets:

- `Steam-Float-Scanner-Setup-<version>.exe`
- `Steam-Float-Scanner-Setup-<version>.exe.blockmap`
- `latest.yml`
- `build-verification.json`
- `Steam-Float-Scanner-<version>-amd64.deb`
- `latest-linux.yml`
- `linux-build-verification.json`
- `steam-float-scanner-source-<version>.zip`
- `release-source.json`

Do not attach signed manifests before dispatch. For a Windows-only release,
omit the three Linux inputs. The fixed signer accepts no arbitrary asset names,
source scripts, executable helpers, download URLs, or platform targets.

`release-source.json` preserves the existing provenance fields and requires:

```json
{
  "version": "0.2.150",
  "sourceCommit": "<40 lowercase hex characters>",
  "sourceSha256": "<native proof source hash: 64 lowercase hex>",
  "sourceZip": { "name": "steam-float-scanner-source-0.2.150.zip", "sha256": "<64 lowercase hex>", "bytes": 123 },
  "ciRunId": "<reviewed source workflow run ID>",
  "releaseNotesSha256": "<SHA256 of UTF8 draft body after trim>",
  "assets": [
    { "name": "<one unsigned asset other than release-source.json>", "sha256": "<64 lowercase hex>", "bytes": 123 }
  ]
}
```

The `assets` array has exactly eight entries for Windows+Linux or five for
Windows only. Every entry has exactly `name`, `sha256`, and `bytes`; inventory
the exact uploaded bytes. `release-source.json` cannot hash itself. Its SHA256
is provided separately as dispatch input. Additional existing provenance
fields such as artifact IDs may remain in that JSON; none is executed.

From an authenticated Cloud terminal, dispatch on `main` with:

```bash
gh workflow run sign-release.yml --repo Rigby453/steam-float-scanner-releases --ref main \
  -f release_id=RELEASE_ID -f version=VERSION \
  -f source_commit=SOURCE_COMMIT -f source_record_sha256=SOURCE_RECORD_SHA256
```

These values are identifiers and hashes, never signing secrets. Record the
created run ID, wait for completion, inspect the receipt, then independently
verify that the public latest feed names the intended version. Dispatch
acceptance is not job completion.

## What the workflow verifies

The first job has no signing secrets. It checks workflow identity, new stable
version, exact draft ID/tag, complete asset inventory, bounded downloads and
hashes, native proof source/version/installer consistency, source ZIP identity,
draft-note hash, and the fixed one-installer update-feed format.

The signing job rechecks the same data. It decrypts the key in memory, confirms
that its public key equals the installed application's existing anchor, signs
the canonical payload with Ed25519, and verifies each signature. Only the
known signer step receives the key variables. No npm install, archive
extraction, source checkout, downloaded executable, or artifact script runs
with the key. It adds `manifest.json` and, when applicable,
`manifest-linux-x64-deb.json` without overwriting anything.

All inputs and signed assets are read back before publication. The workflow
publishes without changing latest, requires immutability, anonymously
downloads every public asset and hashes it, then promotes and verifies latest.
Authenticated GitHub API requests never forward their bearer token to CDN
redirects. Logs contain bounded error codes and public identifiers/hashes;
OpenSSL errors, response bodies, signed download URLs and key text are omitted.

Source CI trust is explicit: `GITHUB_TOKEN` belongs only to the release repo
and cannot authenticate a private source-repo CI lookup. A PASS JSON uploaded
by the dispatcher is evidence of its claim, not cryptographic proof that CI
ran. The dispatcher must review source CI before dispatching. Dispatch access
therefore grants release authority. Independent CI authorization would need
a separately approved source read-only GitHub App or a verified build
attestation; neither is falsely implied here.

## Failure and verification scope

The workflow never clobbers or deletes assets. A partial upload leaves the
draft for inspection. A failure after publication leaves the version
nonlatest when possible; inspect exact stage and remote state before a retry.
A rerun against a published version intentionally fails; do not rebuild the
same version or remove immutability to force a rerun.

Local tests use generated disposable keys only. They cover wrong key and
passphrase, signature tampering, unsafe workflow inputs, asset/proof mismatch,
feed modification, redirect token stripping and bounded downloads. Native
149 proof/feed compatibility was checked from local frozen artifacts.
Full publication is proven only by an actual successful GitHub run and public
readback. This pipeline signs update metadata; it does not provide Windows
Authenticode, perform the owner's GUI test, or install anything on Seattle.

## Official references checked 2026-10-09

- [Actions secrets and stdin provisioning](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).
- [Manual/API workflow dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
- [Environment secret and branch restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
- [Repository-scoped GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token).
- [Release asset REST API](https://docs.github.com/en/rest/releases/assets) and [release publication API](https://docs.github.com/en/rest/releases/releases).
- [Immutable release protection and draft-first publication](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
- [GitHub CLI encrypts secrets locally before upload](https://cli.github.com/manual/gh_secret_set).
