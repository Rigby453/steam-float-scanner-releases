import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { crc32, deflateRawSync } from 'node:zlib';
import { readFileSync, existsSync } from 'node:fs';
import { validateReleaseRequest, validateContext, decodeSupplement, safePath, readSourceZip,
  validateFinancialAcceptance, VERSION, PACK_PATH } from './release-request.mjs';
import { validateRequest as validateSignerRequest } from './sign-release.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const pack = Buffer.from('PACK-synthetic-object-transport');
const request = () => ({ schemaVersion: 1, version: VERSION, sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40), sourceSha256: 'c'.repeat(64),
  baseZip: { sha256: 'd'.repeat(64), bytes: 73_000_000 }, supplement: { path: PACK_PATH, sha256: sha(pack), bytes: pack.length },
  omittedPaths: ['docs/history/private.log'], releaseNotes: 'Reviewed source and native release.' });
const context = () => ({ GITHUB_REPOSITORY: 'Rigby453/steam-float-scanner-releases', GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'push',
  GITHUB_WORKFLOW_REF: 'Rigby453/steam-float-scanner-releases/.github/workflows/build-release-request.yml@refs/heads/main', GITHUB_SHA: 'e'.repeat(40), GITHUB_RUN_ID: '123' });

test('strict reviewed one-version request accepts only the bounded transport schema', () => {
  assert.equal(validateReleaseRequest(request()).version, VERSION);
  for (const mutate of [r => r.version = '1.2.16', r => r.sourceCommit = 'HEAD', r => r.extra = true,
    r => r.baseZip.url = 'https://example.invalid/source.zip', r => r.supplement.path = '../pack',
    r => r.supplement.bytes = 17 * 1024 * 1024, r => r.releaseNotes = '']) {
    const value = request(); mutate(value); assert.throws(() => validateReleaseRequest(value));
  }
});

test('omissions can never hide build/test/config/lock inputs or repeat entries', () => {
  for (const path of ['tools/old.log', 'apps/desktop/main/index.ts', 'packages/x.ts', 'migrations/001.sql', 'tests/x.ts', 'cloud/x.ts', 'package-lock.json', '.npmrc']) {
    const value = request(); value.omittedPaths = [path]; assert.throws(() => validateReleaseRequest(value), /BUILD_INPUT_OMISSION/);
  }
  const value = request(); value.omittedPaths.push(value.omittedPaths[0]); assert.throws(() => validateReleaseRequest(value));
  value.omittedPaths = ['release/build-records/1.2.13.json']; assert.equal(validateReleaseRequest(value), value);
});

test('canonical base64 preserves the exact binary pack and rejects mismatch/whitespace', () => {
  assert.deepEqual(decodeSupplement(pack.toString('base64') + '\n', request()), pack);
  for (const text of [pack.toString('base64') + ' ', pack.toString('base64') + '\n\n', '!!', Buffer.from('OTHER').toString('base64')]) {
    assert.throws(() => decodeSupplement(text, request()));
  }
  const value = request(); value.supplement.sha256 = 'f'.repeat(64); assert.throws(() => decodeSupplement(pack.toString('base64'), value));
});

test('request context is a real main push in exactly this repository and workflow', () => {
  validateContext(context());
  for (const [key, value] of [['GITHUB_EVENT_NAME', 'workflow_dispatch'], ['GITHUB_REF', 'refs/heads/other'], ['GITHUB_REPOSITORY', 'other/repo'], ['GITHUB_WORKFLOW_REF', 'other'], ['GITHUB_SHA', 'HEAD'], ['GITHUB_RUN_ID', '0']]) {
    assert.throws(() => validateContext({ ...context(), [key]: value }), /UNTRUSTED_REQUEST_CONTEXT/);
  }
});

test('source path rejects traversal, Windows aliases, alternate streams and git state', () => {
  assert.equal(safePath('docs/report with spaces.md'), 'docs/report with spaces.md');
  for (const value of ['../file', '/file', 'C:/file', 'a\\b', '.git/config', 'x/.GIT/config', 'docs/NUL.txt', 'x/name.', 'x/name ', 'x//y', 'x:a', 'x\nname']) assert.throws(() => safePath(value));
});

function zip(entries) {
  const locals = [], central = []; let offset = 0;
  for (const item of entries) {
    const name = Buffer.from(item.name), data = Buffer.from(item.data ?? '{}'), method = item.method ?? 8;
    const body = method === 0 ? data : deflateRawSync(data), checksum = crc32(data);
    const header = Buffer.alloc(30); header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x800, 6); header.writeUInt16LE(method, 8); header.writeUInt32LE(checksum, 14); header.writeUInt32LE(body.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(name.length, 26);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x800, 8); c.writeUInt16LE(method, 10); c.writeUInt32LE(checksum, 16); c.writeUInt32LE(body.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(name.length, 28); c.writeUInt32LE((item.mode ?? 0) >>> 0, 38); c.writeUInt32LE(offset, 42);
    locals.push(header, name, body); central.push(c, name); offset += header.length + name.length + body.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

test('bounded source ZIP accepts raw root and one wrapper with stored/deflated bytes', () => {
  assert.deepEqual(readSourceZip(zip([{ name: 'package.json', data: '{"version":"1.2.13"}', method: 0 }, { name: 'tools/a.ts', data: 'source' }])).map(r => r.path), ['package.json', 'tools/a.ts']);
  assert.deepEqual(readSourceZip(zip([{ name: 'source/package.json' }, { name: 'source/tools/a.ts' }])).map(r => r.path), ['package.json', 'tools/a.ts']);
  assert.deepEqual(readSourceZip(zip([{ name: 'package.json' }, { name: 'cloud/package.json' }])).map(r => r.path), ['package.json', 'cloud/package.json']);
});

test('source ZIP refuses traversal, case collisions, symlink entries and extra roots', () => {
  for (const entries of [
    [{ name: 'package.json' }, { name: '../outside' }],
    [{ name: 'package.json' }, { name: 'PACKAGE.JSON' }],
    [{ name: 'package.json' }, { name: 'symlink', mode: 0xa0000000 }],
    [{ name: 'source/package.json' }, { name: 'elsewhere/file' }],
    [{ name: '.git/config' }, { name: 'package.json' }],
  ]) assert.throws(() => readSourceZip(zip(entries)));
});

test('source ZIP refuses corrupted contents, truncated directory and unsupported compression', () => {
  const corrupt = zip([{ name: 'package.json', data: 'content', method: 0 }]); corrupt[30 + Buffer.byteLength('package.json')] ^= 1; assert.throws(() => readSourceZip(corrupt), /ZIP_CONTENT_MISMATCH/);
  const raw = zip([{ name: 'package.json' }]); assert.throws(() => readSourceZip(raw.subarray(0, -2)));
  const method = Buffer.from(raw); method.writeUInt16LE(99, 8); assert.throws(() => readSourceZip(method));
});

test('native financial acceptance requires original source binding and every Stop/no-write guard', () => {
  const value = { status: 'PASS', sourceSha256: request().sourceSha256, profiles: 14, roleChecks: 56, alteredChecks: 56, dynamicCodeRejected: true, downloadedCodeExecuted: false,
    actualPackagedWorkerParity: true, currentPackagedReferenceBound: true, bundledPendingBlocksBuy: true, bundledLateStopBlocked: true, externalNetworkRequests: 0, purchases: false, productionWrites: 0 };
  validateFinancialAcceptance(value, request());
  for (const [key, next] of [['sourceSha256', 'f'.repeat(64)], ['bundledLateStopBlocked', false], ['purchases', true], ['productionWrites', 1], ['externalNetworkRequests', 1], ['alteredChecks', 55]]) assert.throws(() => validateFinancialAcceptance({ ...value, [key]: next }, request()));
});

test('unchanged signer accepts explicit source materialization metadata and exact sourceZip inventory', () => {
  const names = [`Steam-Float-Scanner-Setup-${VERSION}.exe`, `Steam-Float-Scanner-Setup-${VERSION}.exe.blockmap`, `steam-float-scanner-source-${VERSION}.zip`, 'build-verification.json', 'latest.yml'];
  const assets = names.map(name => ({ name, sha256: 'a'.repeat(64), bytes: 10 }));
  const value = { version: VERSION, sourceCommit: request().sourceCommit, sourceSha256: request().sourceSha256, ciRunId: '123', releaseNotesSha256: 'b'.repeat(64),
    assets, sourceZip: assets[2], sourceTree: request().sourceTree, omittedPaths: [], requestSha256: 'c'.repeat(64), workflowCommit: 'd'.repeat(40) };
  assert.equal(validateSignerRequest(value, { version: VERSION, sourceCommit: request().sourceCommit }).linuxDeb, false);
  assert.throws(() => validateSignerRequest({ ...value, sourceZip: { ...assets[2], sha256: 'e'.repeat(64) } }, { version: VERSION, sourceCommit: request().sourceCommit }), /SOURCE_ZIP_IDENTITY_MISMATCH/);
});

test('workflow leaves key-bearing signer separate and gives write token only to staging', () => {
  const publishedWorkflow = new URL('../.github/workflows/build-release-request.yml', import.meta.url);
  const workflow = readFileSync(existsSync(publishedWorkflow) ? publishedWorkflow : new URL('./build-release-request.yml', import.meta.url), 'utf8');
  assert(workflow.includes("paths: ['release-requests/" + VERSION + ".json']"));
  assert.doesNotMatch(workflow, /SFS_UPDATE_PRIVATE_KEY|SFS_UPDATE_KEY_PASSPHRASE|environment: release-signing|GITHUB_EVENT_NAME:/);
  assert.match(workflow, /actions: write/);
  const source = readFileSync(new URL('./release-request.mjs', import.meta.url), 'utf8');
  assert.match(source, /actions\/workflows\/sign-release\.yml\/dispatches/);
  assert.match(source, /validatePurchaseAdmission\(proof,/);
  assert.doesNotMatch(source, /createPrivateKey|sign\(null/);
  const helperDigest = sha(readFileSync(new URL('./release-request.mjs', import.meta.url)));
  assert.equal(workflow.split(helperDigest).length - 1, 3, 'Every helper pin must match the exact reviewed bytes');
  assert.equal(sha(readFileSync(new URL('./sign-release.mjs', import.meta.url))), '12088d415fc8553ee0a7491d1457813c2c42204121ca1f20b5a9d866b532c38a');
});

test('failed qualification retains only named candidate bytes and never supplies staging', () => {
  const publishedWorkflow = new URL('../.github/workflows/build-release-request.yml', import.meta.url);
  const workflow = readFileSync(existsSync(publishedWorkflow) ? publishedWorkflow : new URL('./build-release-request.yml', import.meta.url), 'utf8');
  const retained = workflow.split('      - name: Retain exact candidate files for review after a failed qualification\n')[1]?.split('\n  stage:')[0];
  assert(retained, 'Failure retention step must exist in the Windows job');
  assert.match(retained, /        if: failure\(\)/);
  assert.match(retained, /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/);
  assert.match(retained, /name: scanner-retained-candidate-\$\{\{ github\.run_id \}\}/);
  const paths = retained.split('\n').filter(line => line.startsWith('            ')).map(line => line.trim());
  const prefix = '${{ runner.temp }}/scanner-source/release/';
  assert.deepEqual(paths, ['Steam-Float-Scanner-Setup-1.2.15.exe', 'Steam-Float-Scanner-Setup-1.2.15.exe.blockmap', 'latest.yml', 'build-verification.json', 'financial-acceptance.json', 'purchase-readiness.json'].map(name => prefix + name));
  assert.match(retained, /if-no-files-found: ignore/); assert.match(retained, /retention-days: 7/);
  assert.doesNotMatch(retained, /continue-on-error|run:/);
  const stage = workflow.split('\n  stage:')[1];
  assert.match(stage, /needs: windows/);
  assert.match(stage, /name: scanner-native-request-\$\{\{ github\.run_id \}\}/);
  assert.doesNotMatch(stage, /scanner-retained-candidate/);
});

test('financial CI awaits the true native exit and requires actual strict proof before admission', () => {
  const published = new URL('../.github/workflows/build-release-request.yml', import.meta.url);
  const workflow = readFileSync(existsSync(published) ? published : new URL('./build-release-request.yml', import.meta.url), 'utf8');
  const block = workflow.split('      - name: Actual packaged financial recognition and Stop receipt safeguards\n')[1]?.split('      - name: Require current original-key financial admission before staging\n')[0];
  assert(block);
  assert(block.includes('execFileSync('));
  assert(block.includes("ELECTRON_RUN_AS_NODE: '1'"));
  assert(block.includes('FINANCIAL_PROOF_ALREADY_EXISTS'));
  assert(block.includes('FINANCIAL_PROOF_MISSING_AFTER_CHILD_EXIT'));
  assert(block.includes('validateFinancialAcceptance(proof, request)'));
  assert(block.includes('timeout: 120000'));
  assert(!block.includes("& '."));
});

test('staging sparse checkout includes the actual workflow read by its pure tests', () => {
  const published = new URL('../.github/workflows/build-release-request.yml', import.meta.url);
  const workflow = readFileSync(existsSync(published) ? published : new URL('./build-release-request.yml', import.meta.url), 'utf8');
  const stage = workflow.split('\n  stage:')[1];
  assert(stage.includes('            .github/workflows/build-release-request.yml\n'));
  assert.equal(VERSION, '1.2.15');
});
