// No network, no persisted private keys, no application/source execution.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  REPOSITORY, TAG, REVISION_FLOOR, ORIGINAL_EXPIRY, createClient, digest, parseSigned,
  run, signedBytes, signPayload, validateInputs, validatePayload, validateTransition,
} from './sign-purchase-compatibility.mjs';

const now = Date.parse('2026-10-15T12:00:00.000Z');
const passphrase = 'disposable-generated-key-only-32-characters';
const pair = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ format: 'pem', type: 'spki' });
const encryptedPem = pair.privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase });
const oldPayload = () => ({ kind: 'steam-float-scanner-purchase-compatibility', schemaVersion: 1,
  contractVersion: 'steam-market-buylisting-v1', revision: REVISION_FLOOR,
  publishedAt: '2026-10-10T09:13:01.082Z', expiresAt: ORIGINAL_EXPIRY,
  deployments: [[{ file: 'Entry.js', sha256: '1'.repeat(64) }, { file: 'Init.js', sha256: '2'.repeat(64) }, { file: 'Buyer.js', sha256: '3'.repeat(64) }]] });
const policy = () => ({ version: 'steam-financial-graph-v1', shapeSha256: '4'.repeat(64), moduleCount: 4, roleLinks: [0, 1] });
const candidate = () => ({ ...oldPayload(), revision: REVISION_FLOOR + 1,
  publishedAt: '2026-10-15T11:00:00.000Z', deployments: [...oldPayload().deployments,
    [{ file: 'NewEntry.js', sha256: '4'.repeat(64) }, { file: 'NewInit.js', sha256: '5'.repeat(64) },
      { file: 'NewBuyer.js', sha256: '6'.repeat(64) }, { file: 'NewBilling.js', sha256: '7'.repeat(64) }]] });
const json = x => Buffer.from(JSON.stringify(x, null, 2) + '\n');

function fixture(payload = candidate(), previous = oldPayload()) {
  const previousBytes = signPayload(previous, encryptedPem, passphrase, publicKey);
  const payloadBytes = json(payload);
  const review = { kind: 'steam-float-scanner-purchase-compatibility-review', schemaVersion: 1,
    payloadSha256: digest(payloadBytes), previousSha256: digest(previousBytes), sourceCommit: 'a'.repeat(40),
    reviewedAt: '2026-10-15T11:30:00.000Z', scope: 'exact-initial-page-financial-static-snapshot-including-initialization',
    verdict: 'PASS_EXACT_FINANCIAL_BEHAVIOR_REVIEW', exactFinancialBehaviorUnchanged: true,
    approvedDeployment: payload.deployments.at(-1),
    dynamicImportAssessment: { scope: 'initial-page-direct-exact-buy', verdict: 'PASS_FINANCIAL_NONINTERFERENCE_WITHIN_SCOPE', evidenceSha256: 'c'.repeat(64) },
    offPathBehaviorChanges: { present: true, evidenceSha256: 'd'.repeat(64) },
    evidenceSha256: 'b'.repeat(64) };
  const reviewBytes = json(review);
  const env = { GITHUB_REPOSITORY: REPOSITORY, GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/sign-purchase-compatibility.yml@refs/heads/main`,
    SFS_COMPATIBILITY_PAYLOAD_BASE64: payloadBytes.toString('base64'), SFS_COMPATIBILITY_PAYLOAD_SHA256: digest(payloadBytes),
    SFS_COMPATIBILITY_PREVIOUS_SHA256: digest(previousBytes), SFS_COMPATIBILITY_REVIEW_BASE64: reviewBytes.toString('base64'),
    SFS_COMPATIBILITY_REVIEW_SHA256: digest(reviewBytes), GITHUB_TOKEN: 'disposable-mocked-token',
    SFS_UPDATE_PRIVATE_KEY_PEM: encryptedPem, SFS_UPDATE_KEY_PASSPHRASE: passphrase };
  return { payload, previous, previousBytes, review, env, inputs: validateInputs(env) };
}

function remote(f = fixture(), options = {}) {
  const release = { id: 10, tag_name: TAG, target_commitish: 'main', name: 'Purchase compatibility', body: 'Preserved',
    draft: false, prerelease: true, immutable: false, published_at: '2026-09-12T00:00:00.000Z' };
  const latest = { ...release, id: 20, tag_name: 'v0.2.152', name: 'Installer', prerelease: false, immutable: true };
  const tag = { ref: `refs/tags/${TAG}`, object: { sha: 'c'.repeat(40), type: 'commit', url: 'https://api.github.com/example' } };
  const stored = new Map([[100, { item: { id: 100, name: 'compatibility.json', size: f.previousBytes.length, state: 'uploaded' }, bytes: f.previousBytes }]]);
  const calls = []; let nextId = 200; let patched = 0; let stale = options.staleFinal ?? 0;
  const body = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  async function fetcher(url, init = {}) {
    const target = new URL(url); const method = init.method ?? 'GET';
    calls.push({ url: String(url), method, headers: { ...init.headers }, body: init.body });
    if (target.hostname === 'uploads.github.com') {
      assert.equal(method, 'POST');
      assert.equal(target.pathname, `/repos/${REPOSITORY}/releases/10/assets`);
      const name = target.searchParams.get('name');
      assert.ok(![...stored.values()].some(x => x.item.name === name));
      const bytes = Buffer.from(init.body);
      if (options.tamperUpload && name.endsWith('.pending.json')) bytes[bytes.length - 2] ^= 1;
      const item = { id: nextId++, name, size: bytes.length, state: 'uploaded' };
      stored.set(item.id, { item, bytes });
      if (options.afterUpload) options.afterUpload({ stored, release, latest, tag, item });
      return body(item, 201);
    }
    if (target.hostname === 'api.github.com') {
      const path = target.pathname.slice(`/repos/${REPOSITORY}`.length);
      if (path === `/releases/tags/${TAG}`) return body(release);
      if (path === '/releases/latest') return body(latest);
      if (path === `/git/ref/tags/${TAG}`) return body(tag);
      if (path === '/releases/10/assets') return body([...stored.values()].map(x => x.item));
      if (/^\/releases\/assets\/[1-9]\d*$/.test(path)) {
        const id = Number(path.split('/').at(-1)); const asset = stored.get(id);
        assert.ok(asset);
        if (method === 'PATCH') {
          patched++;
          if (options.failSecondRename && patched === 2) return body({ message: 'synthetic' }, 503);
          const value = JSON.parse(init.body);
          assert.equal(Object.keys(value).join(','), 'name');
          assert.ok(![...stored.values()].some(x => x.item.name === value.name && x.item.id !== id));
          asset.item = { ...asset.item, name: value.name };
          return body(asset.item);
        }
        assert.equal(init.headers.Accept, 'application/octet-stream');
        return new Response(null, { status: 302, headers: { Location: `https://release-assets.githubusercontent.com/asset/${id}` } });
      }
    }
    if (target.hostname === 'github.com') {
      assert.equal(init.headers.Authorization, undefined);
      const name = decodeURIComponent(target.pathname.split('/').at(-1));
      let asset = [...stored.values()].find(x => x.item.name === name);
      if (name === 'compatibility.json' && patched === 2 && stale-- > 0) asset = stored.get(100);
      if (options.staleInitial && patched === 0 && name === 'compatibility.json') return new Response('stale', { status: 200 });
      if (!asset) return new Response('missing', { status: 404 });
      return new Response(null, { status: 302, headers: { Location: `https://release-assets.githubusercontent.com/asset/${asset.item.id}` } });
    }
    if (target.hostname === 'release-assets.githubusercontent.com') {
      assert.equal(init.headers.Authorization, undefined);
      const asset = stored.get(Number(target.pathname.split('/').at(-1)));
      assert.ok(asset);
      return new Response(asset.bytes, { status: 200, headers: { 'Content-Length': String(asset.bytes.length) } });
    }
    throw new Error(`Unexpected mock request: ${method} ${url}`);
  }
  return { fetcher, stored, release, latest, tag, calls, mutations: () => calls.filter(x => x.method !== 'GET') };
}
const testOptions = { now, publicKey, delay: async () => {} };
const error = code => e => e instanceof Error && e.message === code;

test('bounded gzip dispatch preserves exact uncompressed payload/review/signature identity', async () => {
  const f = fixture();
  f.env.SFS_COMPATIBILITY_INPUT_ENCODING = 'gzip-json';
  for (const key of ['SFS_COMPATIBILITY_PAYLOAD_BASE64', 'SFS_COMPATIBILITY_REVIEW_BASE64']) f.env[key] = gzipSync(Buffer.from(f.env[key], 'base64')).toString('base64');
  const parsed = validateInputs(f.env);
  assert.deepEqual(parsed.payload, f.inputs.payload);
  assert.equal(parsed.payloadSha256, f.inputs.payloadSha256);
  assert.equal(parsed.reviewSha256, f.inputs.reviewSha256);
  const server = remote(f);
  const receipt = await run('publish', f.env, server.fetcher, testOptions);
  assert.equal(receipt.status, 'PUBLISHED_SIGNATURE_AND_PUBLIC_READBACK_VERIFIED');
  assert.equal(receipt.payloadSha256, f.inputs.payloadSha256);
});

test('gzip permits the reviewed payload above32KiB while keeping raw dispatch bounded', () => {
  const f = fixture(), bytes = Buffer.concat([json(f.payload), Buffer.alloc(32 * 1024, 32)]);
  f.review.payloadSha256 = digest(bytes);
  const review = json(f.review);
  Object.assign(f.env, { SFS_COMPATIBILITY_PAYLOAD_SHA256: digest(bytes), SFS_COMPATIBILITY_REVIEW_SHA256: digest(review),
    SFS_COMPATIBILITY_PAYLOAD_BASE64: bytes.toString('base64'), SFS_COMPATIBILITY_REVIEW_BASE64: review.toString('base64') });
  assert.throws(() => validateInputs(f.env), error('INVALID_BASE64_INPUT'));
  Object.assign(f.env, { SFS_COMPATIBILITY_INPUT_ENCODING: 'gzip-json',
    SFS_COMPATIBILITY_PAYLOAD_BASE64: gzipSync(bytes).toString('base64'), SFS_COMPATIBILITY_REVIEW_BASE64: gzipSync(review).toString('base64') });
  const inputs = validateInputs(f.env);
  validateTransition(inputs, f.previous, now);
  assert.equal(inputs.payloadSha256, digest(bytes));
});

test('gzip rejects decompression bombs, broken containers and unknown encodings before network or signing', () => {
  for (const key of ['SFS_COMPATIBILITY_PAYLOAD_BASE64', 'SFS_COMPATIBILITY_REVIEW_BASE64']) {
    for (const bytes of [Buffer.from('not-gzip'), gzipSync(Buffer.alloc(128 * 1024, 32))]) {
      const f = fixture(); f.env.SFS_COMPATIBILITY_INPUT_ENCODING = 'gzip-json';
      for (const k of ['SFS_COMPATIBILITY_PAYLOAD_BASE64', 'SFS_COMPATIBILITY_REVIEW_BASE64']) f.env[k] = gzipSync(Buffer.from(f.env[k], 'base64')).toString('base64');
      f.env[key] = bytes.toString('base64');
      assert.throws(() => validateInputs(f.env), error('INVALID_COMPRESSED_INPUT'));
    }
  }
  const f = fixture(); f.env.SFS_COMPATIBILITY_INPUT_ENCODING = 'other';
  assert.throws(() => validateInputs(f.env), error('INVALID_INPUT_ENCODING'));
});

test('both protected-environment workflow jobs pin the exact standalone helper bytes', () => {
  const helper = readFileSync(new URL('./sign-purchase-compatibility.mjs', import.meta.url));
  const localWorkflow = new URL('./.github/workflows/sign-purchase-compatibility.yml', import.meta.url);
  const workflow = readFileSync(existsSync(localWorkflow) ? localWorkflow : new URL('../.github/workflows/sign-purchase-compatibility.yml', import.meta.url), 'utf8');
  assert.equal(workflow.split(`${digest(helper)}  tools/sign-purchase-compatibility.mjs`).length - 1, 2);
  assert.equal(workflow.split('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683').length - 1, 2);
  assert.ok(workflow.includes('group: official-release-publication'));
});

test('generated Ed25519 key signs the purpose-bound canonical bytes and roundtrips', () => {
  const bytes = signPayload(candidate(), encryptedPem, passphrase, publicKey);
  assert.deepEqual(parseSigned(bytes, publicKey).payload, candidate());
  const reordered = Object.fromEntries(Object.entries(candidate()).reverse());
  assert.deepEqual(signedBytes(candidate()), signedBytes(reordered));
  const signed = JSON.parse(bytes); signed.payload.deployments[1][3].sha256 = 'e'.repeat(64);
  assert.throws(() => parseSigned(json(signed), publicKey), error('INVALID_COMPATIBILITY_SIGNATURE'));
});

test('111-module snapshot binds every dependency and fits bounded dispatch inputs', () => {
  const payload = candidate();
  for (let i = payload.deployments[1].length; i < 111; i++) payload.deployments[1].push({ file: `Dependency${i}.js`, sha256: digest(Buffer.from(String(i))) });
  const f = fixture(payload);
  assert.equal(validateTransition(f.inputs, f.previous, now).length, 111);
  assert.ok(f.env.SFS_COMPATIBILITY_PAYLOAD_BASE64.length + f.env.SFS_COMPATIBILITY_REVIEW_BASE64.length <= 60_000);
  const bytes = signPayload(payload, encryptedPem, passphrase, publicKey);
  assert.equal(parseSigned(bytes, publicKey).payload.deployments[1].length, 111);
  for (let i = 0; i < 111; i++) {
    const changed = JSON.parse(bytes); changed.payload.deployments[1][i].sha256 = 'f'.repeat(64);
    assert.throws(() => parseSigned(json(changed), publicKey), error('INVALID_COMPATIBILITY_SIGNATURE'));
  }
});

test('existing graph policies are retained without claiming a new graph approval', () => {
  const previous = { ...oldPayload(), graphPolicies: [policy()] };
  const payload = { ...candidate(), graphPolicies: [policy()] };
  const f = fixture(payload, previous);
  assert.deepEqual(validateTransition(f.inputs, f.previous, now), payload.deployments[1]);
});

test('wrong key, wrong passphrase, unencrypted key and tampered envelope fail closed', () => {
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' });
  assert.throws(() => signPayload(candidate(), encryptedPem, passphrase, other), error('WRONG_SIGNING_KEY'));
  assert.throws(() => signPayload(candidate(), encryptedPem, 'another-disposable-passphrase-32chars', publicKey), error('SIGNING_KEY_DECRYPTION_FAILED'));
  assert.throws(() => signPayload(candidate(), pair.privateKey.export({ format: 'pem', type: 'pkcs8' }), passphrase, publicKey), error('SIGNING_SECRET_UNAVAILABLE'));
  const signed = JSON.parse(signPayload(candidate(), encryptedPem, passphrase, publicKey)); signed.extra = true;
  assert.throws(() => parseSigned(json(signed), publicKey), error('INVALID_SIGNED_DOCUMENT'));
});

test('strict payload boundary rejects malformed schemas and duplicate routes', async t => {
  const cases = [
    ['unknown field', p => { p.allowUnreviewed = true; }],
    ['wrong kind', p => { p.kind = 'installer'; }],
    ['fractional revision', p => { p.revision += 0.5; }],
    ['calendar rollover', p => { p.publishedAt = '2026-02-30T11:00:00.000Z'; }],
    ['too long lifetime', p => { p.expiresAt = '2027-11-04T20:12:56.038Z'; }],
    ['empty deployments', p => { p.deployments = []; }],
    ['too short vector', p => { p.deployments[1] = p.deployments[1].slice(0, 2); }],
    ['too long vector', p => { p.deployments[1] = Array.from({ length: 129 }, (_, i) => ({ file: `Module${i}.js`, sha256: 'e'.repeat(64) })); }],
    ['duplicate vector module', p => { p.deployments[1].push(structuredClone(p.deployments[1][0])); }],
    ['path module', p => { p.deployments[0][0].file = '../Entry.js'; }],
    ['coercible module array', p => { p.deployments[0][0].file = ['Entry.js']; }],
    ['unknown module field', p => { p.deployments[0][0].trusted = true; }],
    ['duplicate route', p => { p.deployments.push(structuredClone(p.deployments[0])); }],
    ['unknown policy field', p => { p.graphPolicies = [{ ...policy(), trusted: true }]; }],
    ['wrong graph version', p => { p.graphPolicies = [{ ...policy(), version: 'heuristic' }]; }],
    ['oversized role', p => { p.graphPolicies = [{ ...policy(), roleLinks: [0, 128] }]; }],
    ['too many modules', p => { p.graphPolicies = [{ ...policy(), moduleCount: 129 }]; }],
  ];
  for (const [name, mutate] of cases) await t.test(name, () => {
    const payload = candidate(); mutate(payload); assert.throws(() => validatePayload(payload));
  });
});

test('transition cannot roll back, extend expiry, modify legacy pins or change graph policies', async t => {
  const cases = [
    ['same revision', f => { f.inputs.payload.revision = f.previous.revision; }, 'REVISION_ROLLBACK'],
    ['old baseline floor', f => { f.previous.revision--; }, 'REVISION_ROLLBACK'],
    ['expiry extension', f => { f.inputs.payload.expiresAt = '2026-11-05T20:12:56.038Z'; }, 'EXPIRY_EXTENSION_FORBIDDEN'],
    ['future timestamp', f => { f.inputs.payload.publishedAt = '2026-10-15T13:00:00.000Z'; }, 'COMPATIBILITY_NOT_CURRENT'],
    ['legacy pin addition', f => { f.inputs.payload.deployments.push([{ file: 'New.js', sha256: 'd'.repeat(64) }, ...f.inputs.payload.deployments[0].slice(1)]); }, 'LEGACY_DEPLOYMENTS_CHANGED'],
    ['legacy pin hash edit', f => { f.inputs.payload.deployments[0][2].sha256 = 'd'.repeat(64); }, 'LEGACY_DEPLOYMENTS_CHANGED'],
    ['no exact vector addition', f => { f.inputs.payload.deployments.pop(); }, 'LEGACY_DEPLOYMENTS_CHANGED'],
    ['legacy three-pin shortcut', f => { f.inputs.payload.deployments[1].pop(); }, 'INCOMPLETE_EXACT_SNAPSHOT_VECTOR'],
    ['graph policy addition', f => { f.inputs.payload.graphPolicies = [policy()]; }, 'GRAPH_POLICIES_CHANGED'],
    ['old graph policy removal', f => { f.previous.graphPolicies = [policy()]; }, 'GRAPH_POLICIES_CHANGED'],
  ];
  for (const [name, mutate, code] of cases) await t.test(name, () => {
    const f = fixture(); mutate(f); assert.throws(() => validateTransition(f.inputs, f.previous, now), error(code));
  });
  const f = fixture(); assert.throws(() => validateTransition(f.inputs, f.previous, Date.parse(ORIGINAL_EXPIRY)), error('COMPATIBILITY_NOT_CURRENT'));
});

test('external review must bind exact payload, old signed bytes, source, full snapshot and dynamic noninterference', async t => {
  for (const [field, value] of [
    ['payloadSha256', 'e'.repeat(64)], ['previousSha256', 'e'.repeat(64)], ['sourceCommit', 'main'],
    ['sourceCommit array coercion', ['a'.repeat(40)]],
    ['scope', 'selected-purchase-functions'], ['verdict', 'PARTIAL'], ['evidenceSha256', 'unavailable'],
    ['approvedDeployment', []], ['exactFinancialBehaviorUnchanged', false],
    ['dynamicImportAssessment', { scope: 'initial-page-direct-exact-buy', verdict: 'UNKNOWN', evidenceSha256: 'c'.repeat(64) }],
    ['offPathBehaviorChanges', { present: true, evidenceSha256: 'missing' }],
    ['reviewedAt', '2026-10-15T10:00:00.000Z'],
  ]) await t.test(field, () => {
    const f = fixture(); f.inputs.review[field.startsWith('sourceCommit ') ? 'sourceCommit' : field] = value;
    assert.throws(() => validateTransition(f.inputs, f.previous, now), error('REVIEW_BINDING_MISMATCH'));
  });
});

test('dispatch binds exact raw bytes and protected workflow identity', async t => {
  for (const [field, value, code] of [
    ['GITHUB_REPOSITORY', 'attacker/repo', 'UNTRUSTED_WORKFLOW_CONTEXT'],
    ['GITHUB_REF', 'refs/tags/main', 'UNTRUSTED_WORKFLOW_CONTEXT'],
    ['GITHUB_EVENT_NAME', 'pull_request_target', 'UNTRUSTED_WORKFLOW_CONTEXT'],
    ['GITHUB_WORKFLOW_REF', `${REPOSITORY}/.github/workflows/other.yml@refs/heads/main`, 'UNTRUSTED_WORKFLOW_CONTEXT'],
    ['SFS_COMPATIBILITY_PAYLOAD_SHA256', 'e'.repeat(64), 'DISPATCH_HASH_MISMATCH'],
    ['SFS_COMPATIBILITY_REVIEW_SHA256', 'e'.repeat(64), 'DISPATCH_HASH_MISMATCH'],
    ['SFS_COMPATIBILITY_PAYLOAD_BASE64', 'YQ==\n', 'INVALID_BASE64_INPUT'],
    ['SFS_COMPATIBILITY_PREVIOUS_SHA256', '$(secret)', 'INVALID_DISPATCH_HASH'],
  ]) await t.test(field, () => assert.throws(() => validateInputs({ ...fixture().env, [field]: value }), error(code)));
});

test('verify uses no signing secret and performs no remote mutation', async () => {
  const f = fixture(); const r = remote(f);
  Object.defineProperty(f.env, 'SFS_UPDATE_PRIVATE_KEY_PEM', { get: () => assert.fail('verify read a signing secret') });
  Object.defineProperty(f.env, 'SFS_UPDATE_KEY_PASSPHRASE', { get: () => assert.fail('verify read a signing secret') });
  const receipt = await run('verify', f.env, r.fetcher, testOptions);
  assert.equal(receipt.status, 'VERIFIED_WITHOUT_SIGNING_OR_MUTATION');
  assert.equal(r.mutations().length, 0);
});

test('successful publication preserves old bytes, immutable latest and tag; never deletes', async () => {
  const f = fixture(); const r = remote(f); const before = structuredClone([r.release, r.latest, r.tag]);
  const receipt = await run('publish', f.env, r.fetcher, testOptions);
  assert.equal(receipt.status, 'PUBLISHED_SIGNATURE_AND_PUBLIC_READBACK_VERIFIED');
  assert.deepEqual([r.release, r.latest, r.tag], before);
  assert.equal(r.stored.get(100).item.name, `compatibility-${REVISION_FLOOR}.json`);
  assert.deepEqual(r.stored.get(100).bytes, f.previousBytes);
  const current = [...r.stored.values()].find(x => x.item.name === 'compatibility.json');
  assert.equal(parseSigned(current.bytes, publicKey).payload.revision, REVISION_FLOOR + 1);
  assert.equal(digest(current.bytes), receipt.signedSha256);
  assert.deepEqual(r.mutations().map(x => x.method), ['POST', 'POST', 'PATCH', 'PATCH']);
  for (const call of r.calls) if (new URL(call.url).hostname === 'release-assets.githubusercontent.com') assert.equal(call.headers.Authorization, undefined);
});

test('wrong signing key fails before any write', async () => {
  const f = fixture(); const r = remote(f);
  const other = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase });
  await assert.rejects(run('publish', { ...f.env, SFS_UPDATE_PRIVATE_KEY_PEM: other }, r.fetcher, testOptions), error('WRONG_SIGNING_KEY'));
  assert.equal(r.mutations().length, 0);
});

test('baseline SHA mismatch, stale public bytes and unsuitable release state never mutate', async t => {
  for (const [name, setup, code, options] of [
    ['wrong baseline SHA', (f) => { f.env.SFS_COMPATIBILITY_PREVIOUS_SHA256 = 'e'.repeat(64); }, 'PREVIOUS_COMPATIBILITY_HASH_MISMATCH'],
    ['stale current public bytes', () => {}, 'ASSET_LENGTH_MISMATCH', { staleInitial: true }],
    ['immutable compatibility release', (f, r) => { r.release.immutable = true; }, 'COMPATIBILITY_RELEASE_NOT_MUTABLE_PUBLIC_PRERELEASE'],
    ['compatibility prerelease guard', (f, r) => { r.release.prerelease = false; }, 'COMPATIBILITY_RELEASE_NOT_MUTABLE_PUBLIC_PRERELEASE'],
    ['mutable installer latest', (f, r) => { r.latest.immutable = false; }, 'INSTALLER_LATEST_NOT_IMMUTABLE'],
    ['latest tag array coercion', (f, r) => { r.latest.tag_name = ['v0.2.152']; }, 'INSTALLER_LATEST_NOT_IMMUTABLE'],
    ['tag hash array coercion', (f, r) => { r.tag.object.sha = ['c'.repeat(40)]; }, 'INVALID_COMPATIBILITY_TAG'],
    ['compatibility is latest', (f, r) => { r.latest.id = r.release.id; }, 'INSTALLER_LATEST_NOT_IMMUTABLE'],
  ]) await t.test(name, async () => {
    const f = fixture(); const r = remote(f, options); setup(f, r);
    await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error(code));
    assert.equal(r.mutations().length, 0);
  });
});

test('tampered upload leaves current asset intact and never tries to repair by deleting', async () => {
  const f = fixture(); const r = remote(f, { tamperUpload: true });
  await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('UPLOAD_READBACK_MISMATCH'));
  assert.equal(r.stored.get(100).item.name, 'compatibility.json');
  assert.deepEqual(r.mutations().map(x => x.method), ['POST']);
});

test('concurrent latest or tag change aborts before either rename', async t => {
  for (const field of ['latest', 'tag']) await t.test(field, async () => {
    const f = fixture(); const r = remote(f, { afterUpload: state => {
      if (field === 'latest') state.latest.name = 'Concurrent change'; else state.tag.object.sha = 'd'.repeat(40);
    } });
    await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('RELEASE_OR_LATEST_CHANGED'));
    assert.equal(r.stored.get(100).item.name, 'compatibility.json');
    assert.deepEqual(r.mutations().map(x => x.method), ['POST', 'POST']);
  });
});

test('concurrent asset addition aborts before either rename', async () => {
  const f = fixture(); const r = remote(f, { afterUpload: state => {
    if (state.item.name.includes('-review-')) state.stored.set(999, {
      item: { id: 999, name: 'unrelated.json', size: f.previousBytes.length, state: 'uploaded' }, bytes: f.previousBytes,
    });
  } });
  await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('ASSETS_CHANGED_BEFORE_SWITCH'));
  assert.equal(r.stored.get(100).item.name, 'compatibility.json');
  assert.deepEqual(r.mutations().map(x => x.method), ['POST', 'POST']);
});

test('existing revision asset names require inspection and never get overwritten', async () => {
  const f = fixture(); const r = remote(f);
  r.stored.set(999, { item: { id: 999, name: `compatibility-${REVISION_FLOOR + 1}.pending.json`, size: f.previousBytes.length, state: 'uploaded' }, bytes: f.previousBytes });
  await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('PUBLICATION_NAME_ALREADY_EXISTS'));
  assert.equal(r.mutations().length, 0);
});

test('partial swap failure preserves old signed bytes and pending candidate; no automatic mutation retry', async () => {
  const f = fixture(); const r = remote(f, { failSecondRename: true });
  await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('GITHUB_API_503'));
  assert.equal(r.stored.get(100).item.name, `compatibility-${REVISION_FLOOR}.json`);
  assert.deepEqual(r.stored.get(100).bytes, f.previousBytes);
  assert.equal([...r.stored.values()].filter(x => x.item.name.endsWith('.pending.json')).length, 1);
  assert.equal([...r.stored.values()].filter(x => x.item.name === 'compatibility.json').length, 0);
  const count = r.mutations().length;
  await assert.rejects(run('publish', f.env, r.fetcher, testOptions), error('CURRENT_COMPATIBILITY_MISSING'));
  assert.equal(r.mutations().length, count);
});

test('stale canonical CDN redirects trigger only bounded public reads after one swap', async () => {
  const f = fixture(); const r = remote(f, { staleFinal: 2 });
  assert.equal((await run('publish', f.env, r.fetcher, testOptions)).status, 'PUBLISHED_SIGNATURE_AND_PUBLIC_READBACK_VERIFIED');
  assert.deepEqual(r.mutations().map(x => x.method), ['POST', 'POST', 'PATCH', 'PATCH']);
  const failure = remote(f, { staleFinal: 99 });
  await assert.rejects(run('publish', f.env, failure.fetcher, testOptions), error('FINAL_PUBLIC_READBACK_MISMATCH'));
  assert.deepEqual(failure.mutations().map(x => x.method), ['POST', 'POST', 'PATCH', 'PATCH']);
});

test('an eventually visible CDN asset after thirty stale reads does not repeat any publication mutation', async () => {
  const f = fixture(), r = remote(f, { staleFinal: 30 });
  let waits = 0;
  const result = await run('publish', f.env, r.fetcher, { ...testOptions, delay: async milliseconds => { assert.equal(milliseconds, 5000); waits++; } });
  assert.equal(result.status, 'PUBLISHED_SIGNATURE_AND_PUBLIC_READBACK_VERIFIED');
  assert.equal(waits, 30);
  assert.deepEqual(r.mutations().map(x => x.method), ['POST', 'POST', 'PATCH', 'PATCH']);
});

test('client rejects arbitrary mutations and redirects to untrusted or authenticated origins', async t => {
  const calls = []; const noFetch = async (...args) => { calls.push(args); assert.fail('forbidden call reached fetch'); };
  const client = createClient('mock-token', noFetch);
  await assert.rejects(client.api('/releases/20', 'PATCH', { make_latest: true }), error('FORBIDDEN_API_MUTATION'));
  await assert.rejects(client.api('/git/refs/tags/example'), error('FORBIDDEN_API_PATH'));
  await assert.rejects(client.upload(10, 'manifest.json', json({})), error('FORBIDDEN_ASSET_UPLOAD'));
  assert.equal(calls.length, 0);
  for (const redirect of ['https://evil.example/payload', 'http://release-assets.githubusercontent.com/a',
    `https://api.github.com/repos/${REPOSITORY}/releases/assets/100`, 'https://user:password@objects.githubusercontent.com/a',
    'https://objects.githubusercontent.com:444/a', `https://github.com/${REPOSITORY}/releases/download/${TAG}/compatibility.json`]) {
    await t.test(new URL(redirect).hostname + new URL(redirect).port, async () => {
      let requests = 0;
      const redirecting = createClient('mock-token', async (url, init) => {
        requests++;
        assert.equal(init.headers.Authorization, 'Bearer mock-token');
        return new Response(null, { status: 302, headers: { Location: redirect } });
      });
      await assert.rejects(redirecting.asset({ id: 100, size: 10 }));
      assert.equal(requests, 1);
    });
  }
});

test('bounded download rejects oversized, truncated, invalid UTF8 and invalid JSON data', async t => {
  for (const [name, response, code] of [
    ['length header', () => new Response('1234', { headers: { 'content-length': '999999' } }), 'RESPONSE_SIZE_LIMIT'],
    ['stream limit', () => new Response('12345678901'), 'RESPONSE_SIZE_LIMIT'],
    ['truncated', () => new Response('short'), 'ASSET_LENGTH_MISMATCH'],
  ]) await t.test(name, async () => {
    const client = createClient('mock-token', async () => response());
    await assert.rejects(client.asset({ id: 100, size: 10 }), error(code));
  });
  const bad = createClient('mock-token', async () => new Response(new Uint8Array([0xff])));
  await assert.rejects(bad.api('/releases/latest'), error('INVALID_JSON'));
});
