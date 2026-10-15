# Real public updater acceptance candidate

Copy the three helper files into release-repository `tools/`, and the YAML into
`.github/workflows/public-updater-acceptance.yml` only after root review. This
subtask did not modify release-control, commit, push, dispatch or publish.

Pinned target:1.0.1, release414157889, source
`8afd1b0c4c88f4cf1046647283ce63110fe3a1af`, public source ZIP SHA256
`84c7131c7853ea4e7b6405b29f8caa92d62a6494631763920f09d686dc2bd3a8`.
The job refuses an unpublished/nonimmutable/prerelease target and requires the
reviewed native proof to name that exact version, commit and installer SHA.
Dispatch only after native CI38789078465 PASS and immutable publication.

Required dispatch inputs:

- `native_proof_sha256`: exact SHA256 of the public native build-verification.json.
- `installer_sha256`: exact SHA256 of its native Windows1.0.1 installer.
- `installer_bytes`: exact byte count of that same artifact from native inventory.

The job has only contents:read, no signing environment, secrets or credential
inputs. It performs no checkout. Three public helpers are fetched from the exact
workflow commit and SHA256-checked before execution. Setup Node and artifact
upload actions use full SHA pins. Source and dependency execution receive no
GITHUB_TOKEN/GH_TOKEN/npm credential; package lifecycle scripts and Electron
download are disabled. No source build, broad test suite, binary execution or
financial/account call occurs.

Preparation uses only Node builtins to anonymously fetch the exact public proof
and ZIP. Native proof is bound to the dispatch SHA; ZIP is bound to its hardcoded
reviewed SHA before extraction. The Python standard-library extractor rechecks
that SHA before ZIP parsing and rejects path traversal, links/special files,
duplicates, encryption and excessive expansion. The actual local pinned ZIP
passed check-only validation:3361 members,68977115 uncompressed bytes, version1.0.1.

After `npm ci --ignore-scripts`, Node24 and the source's actual TSX loader import
`createProductionUpdateService` and `createReleaseTransport` directly from that
verified archive. The real production transport uses a real anonymous fetch;
private fallback always throws OWNER_ACCESS_FORBIDDEN. No network mocks are used.

Checks:

- Source client1.0.1 with currentVersion parameter0.2.159: AVAILABLE1.0.1.
- The same source client with parameter0.2.152: AVAILABLE1.0.1.
- The same source client with parameter1.0.1: UP_TO_DATE.
- Full real installer download through the first client; exact size and streamed
  independent SHA256 must match reviewed native inputs and the signed manifest.
- Repeat actual `verifyDownloadedFile`, then a fresh UP_TO_DATE check.

The159/152 values are comparison parameters. This job does not run those installed
binaries or repair their old five-minute downloader. It does not prove Electron
GUI/button behavior, owner installation, laptop route speed or AUTO_BUY. The
evidence labels sourceClientVersion1.0.1 and these limitations explicitly.

The full job is capped at15minutes and the live-check helper adds an8minute
network budget. A budget exhaustion is UNKNOWN/failed, never PASS. Only small
sanitized JSON files are uploaded; no installer, source archive, signed CDN URL,
raw native proof or local profile is included.

Local validation completed: both Node files parse; the requested TSX import form
loads the actual production factory/transport; pinned source ZIP hash/structure
check passes without extraction or execution. No full public acceptance was run
before publication. Root must inspect the resulting GitHub run and evidence.

Action pins verified against the official
[setup-node commit](https://github.com/actions/setup-node/commit/49933ea5288caeca8642d1e84afbd3f7d6820020)
and [upload-artifact commit](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02).
