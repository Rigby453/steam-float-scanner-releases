import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PIN, RETAINED, validateContinuation, validateArtifact, validateOriginalRun, verifyPayload } from './continue-release-request.mjs';
const artifact = () => ({ id: PIN.artifactId, name: PIN.artifactName, size_in_bytes: PIN.artifactBytes, expired: false,
  digest: `sha256:${PIN.artifactSha256}`, workflow_run: { id: PIN.originalRunId, head_sha: PIN.originalWorkflowCommit } });
const run = () => ({ id: PIN.originalRunId, head_sha: PIN.originalWorkflowCommit, event: 'push', head_branch: 'main', status: 'completed',
  conclusion: 'failure', path: '.github/workflows/build-release-request.yml', repository: { full_name: 'Rigby453/steam-float-scanner-releases' } });
const jobs = () => ({ jobs: [{ name: 'windows', conclusion: 'failure', steps: [
  ...['Full strict check and source build', 'Root source suite', 'Engine source suite', 'Desktop source suite', 'Financial artifact and native provenance regressions',
    'Build and fully verify the single native Windows installer', 'Require current original-key financial admission before staging',
    'Retain exact candidate files for review after a failed qualification'].map(name => ({ name, conclusion: 'success' })),
  { name: 'Create only the sanitized exact release bundle', conclusion: 'failure' },
] }, { name: 'stage', conclusion: 'skipped' }] });
test('continuation accepts only the explicitly reviewed fixed original byte identity', () => {
  assert.equal(validateContinuation({ ...PIN }).artifactId, PIN.artifactId);
  for (const [key, value] of Object.entries(PIN)) assert.throws(() => validateContinuation({ ...PIN, [key]: typeof value === 'number' ? value + 1 : `${value}x` }), /CONTINUATION_IDENTITY_MISMATCH/);
  assert.throws(() => validateContinuation({ ...PIN, extra: true }), /CONTINUATION_IDENTITY_MISMATCH/);
});
test('artifact cannot be replaced, expired, moved to another run or rehashed', () => {
  validateArtifact(artifact());
  for (const change of [{ id: PIN.artifactId + 1 }, { expired: true }, { digest: 'sha256:' + '0'.repeat(64) }, { size_in_bytes: 1 },
    { workflow_run: { id: PIN.originalRunId + 1, head_sha: PIN.originalWorkflowCommit } }, { workflow_run: { id: PIN.originalRunId, head_sha: '0'.repeat(40) } }]) {
    assert.throws(() => validateArtifact({ ...artifact(), ...change }), /ORIGINAL_ARTIFACT_IDENTITY_MISMATCH/);
  }
});
test('only bundle-only failure after actual native/source checks may continue', () => {
  validateOriginalRun(run(), jobs());
  assert.throws(() => validateOriginalRun({ ...run(), event: 'workflow_dispatch' }, jobs()), /ORIGINAL_RUN_IDENTITY_MISMATCH/);
  const missing = jobs(); missing.jobs[0].steps[1].conclusion = 'failure';
  assert.throws(() => validateOriginalRun(run(), missing), /ORIGINAL_FAILURE_SCOPE_MISMATCH/);
  const skipped = jobs(); skipped.jobs[0].steps[0].conclusion = 'skipped';
  assert.throws(() => validateOriginalRun(run(), skipped), /ORIGINAL_REQUIRED_STEP_NOT_PASS/);
  const wrong = jobs(); wrong.jobs[0].steps.at(-1).name = 'Build and fully verify the single native Windows installer';
  assert.throws(() => validateOriginalRun(run(), wrong), /ORIGINAL_FAILURE_SCOPE_MISMATCH/);
});
test('retained inventory is exactly five original assets and does not invent missing financial proof', () => {
  assert.equal(Object.keys(RETAINED).length, 5); assert.equal(RETAINED['financial-acceptance.json'], undefined);
  assert.equal(RETAINED['Steam-Float-Scanner-Setup-1.2.14.exe'][1], PIN.installerSha256);
});
test('actual payload verification requires all 221 exact files and rejects changed, extra or missing bytes', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'sfs-continuation-unit-'));
  const bytes = Buffer.from('synthetic retained bytes'), digest = createHash('sha256').update(bytes).digest('hex');
  const expected = Object.fromEntries(Array.from({ length: 221 }, (_, n) => [`file-${n}.bin`, digest]));
  try {
    for (const name of Object.keys(expected)) writeFileSync(join(directory, name), bytes);
    await verifyPayload(directory, expected);
    writeFileSync(join(directory, 'file-0.bin'), 'changed');
    await assert.rejects(verifyPayload(directory, expected), /RECOVERED_PAYLOAD_HASH_MISMATCH/);
    writeFileSync(join(directory, 'file-0.bin'), bytes);
    writeFileSync(join(directory, 'extra.bin'), bytes);
    await assert.rejects(verifyPayload(directory, expected), /RECOVERED_PAYLOAD_FILE_SET_MISMATCH/);
    unlinkSync(join(directory, 'extra.bin')); unlinkSync(join(directory, 'file-0.bin'));
    await assert.rejects(verifyPayload(directory, expected), /RECOVERED_PAYLOAD_FILE_SET_MISMATCH/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('continuation workflow cannot rebuild, impersonate context or access signing keys', () => {
  const published = new URL('../.github/workflows/build-release-request.yml', import.meta.url);
  const workflow = readFileSync(existsSync(published) ? published : new URL('./build-release-request.continuation.yml', import.meta.url), 'utf8');
  assert.match(workflow, /paths: \['release-continuations\/1\.2\.14\.json'\]/);
  assert.doesNotMatch(workflow, /paths: \['release-requests|npm run (?:build|package)|electron-builder|ELECTRON_RUN_AS_NODE:|GITHUB_EVENT_NAME:|SFS_UPDATE_PRIVATE_KEY|SFS_UPDATE_KEY_PASSPHRASE|environment: release-signing/);
  assert.match(workflow, /needs: windows/); assert.match(workflow, /node tools\/release-request\.mjs stage/);
  const helperHash = createHash('sha256').update(readFileSync(new URL('./continue-release-request.mjs', import.meta.url))).digest('hex');
  assert.equal(workflow.split(helperHash).length - 1, 2);
  for (const [file, hash] of [['release-request.mjs', '92b3dc82f05fcfc8e1fe202705ba5a50f344f425c864b8e5f9bd81a7c1d91079'],
    ['sign-release.mjs', '12088d415fc8553ee0a7491d1457813c2c42204121ca1f20b5a9d866b532c38a']]) {
    assert.equal(createHash('sha256').update(readFileSync(new URL('./' + file, import.meta.url))).digest('hex'), hash);
    assert.equal(workflow.split(hash).length - 1, 3);
  }
  const helper = readFileSync(new URL('./continue-release-request.mjs', import.meta.url), 'utf8');
  assert.match(helper, /execFileSync\(join\(payload, 'Steam Float Scanner\.exe'\)/);
  assert.match(helper, /validateFinancialAcceptance\(parse/);
  assert.match(helper, /SOURCE_EXECUTION_TOKEN_FORBIDDEN/);
  assert.doesNotMatch(helper, /createPrivateKey|GITHUB_EVENT_NAME\s*[:=]|npm run package|electron-builder --/);
});
