# Exact-byte continuation of the retained 1.2.14 candidate

Local candidate only. No remote publication, dispatch or build is performed by
preparing these files. The existing original-key signer and release-request
helper remain unchanged. No keys, approval rules or policy expiry are changed.

Run 42822864217 passed full source/root/engine/desktop checks and native package
verification, then failed bundling because `financial-acceptance.json` did not
exist. Its PowerShell GUI-subsystem Electron invocation was not awaited. The old
step's green status is NOT financial proof. The retained ZIP has exactly five
files: original EXE, blockmap, update feed, native build proof and readiness.
Root separately verified the exact retained bytes, all 221 extracted payload
hashes, and the awaited actual financial acceptance locally. This continuation
repeats those controls in CI without changing the installer.

Publish the following code first, WITHOUT its trigger file, then read back all
Git blobs. Mapping:

* `continue-release-request.mjs` -> `tools/continue-release-request.mjs`
* `continue-release-request.test.mjs` -> `tools/continue-release-request.test.mjs`
* `build-release-request.continuation.yml` -> `.github/workflows/build-release-request.yml`
* This document -> `docs/RELEASE_REQUEST_CONTINUATION.md` (optional)

The workflow candidate REPLACES that filename, retaining its real push/main
identity required by the unchanged staging helper. It triggers only on
`release-continuations/1.2.14.json`; the original release-request path no longer
triggers native packaging. Do not publish it under a different workflow filename
and do not override GitHub context variables. Existing release-request workflow
assertions describe the old build mode; use the new continuation tests for this
explicit replacement. The pure original helper/signing behavior is unchanged.

After code readback/review, root may deliberately publish a JSON object EXACTLY
equal to the exported `PIN` from the new helper at
`release-continuations/1.2.14.json` to trigger. Do not change original request or
pack files. The original request SHA256 is pinned, as are source commit/tree/SHA,
the failed run/workflow commit, artifact ID/name/size/SHA and all five file hashes.
Do not rerun the old workflow: that would attempt an immutable native rebuild.

The Windows job has only contents/actions READ permissions. Its token is passed
only to artifact download. Source execution explicitly rejects a token. It
checks original run steps, downloads and hashes the precise original artifact
into a fresh private directory, verifies its exact five files, then copies them
without overwrite alongside the three genuine tracked historical build records.
It extracts original EXE payload using the locked vendor checksum-verified 7za,
requires the exact 221-file set and all native-proof hashes, prepares only the
normal deterministic cabinet web/legal provenance inputs (not desktop/engine
compilation or NSIS packaging), then requires the original sourceState SHA and
actual packaged financial identity. Node `execFileSync` waits for the retained
Electron's true exit; a new financial proof must exist and pass 14/56/56, zero
network/writes/purchases, Stop and native schema assertions. Original payload
and five retained assets are rehashed afterward. New source ZIP is generated
from the unchanged actual source Git tree by the original helper.

The normal strict bundle is bound to the NEW truthful continuation CI run and
workflow commit. The native build proof and original installer remain unchanged;
the old run is evidenced by the fixed continuation request and CI checks. Stage
downloads only this run's success artifact, uses the unchanged bundle validator,
rechecks current original-key admission and immutable version availability,
uploads only a new stable DRAFT, and sends a real workflow_dispatch to the
unchanged protected main-only signer. No downloaded source or dependencies
execute in the write-token stage or key-bearing signing job.

If 1.2.14 already exists, any original identity differs, the artifact expires,
admission expires/changes incompatibly, or financial acceptance fails, STOP.
Do not delete an existing release, alter keys/policy, fabricate a proof, extend
expiry or silently rebuild. No real purchase is needed or authorized.

Local pure check (no artifact download/extraction/native execution):

```
node --test work/release-automation/continue-release-request.test.mjs work/release-automation/sign-release.test.mjs work/release-automation/purchase-admission.test.mjs
```

This validator check does not replace actual CI continuation acceptance or
publication/installation/readback checks, which remain root's work.
