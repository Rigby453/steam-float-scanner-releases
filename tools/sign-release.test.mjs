import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { REPOSITORY, validateInputs, validateRequest, validateProof, validateFeed, createManifest, signedPayload, createClient, checkDraft } from './sign-release.mjs';

const version = '0.2.149', sourceCommit = 'a'.repeat(40), sourceSha256 = 'b'.repeat(64);
const inputs = { version, sourceCommit, releaseId: '123', requestSha256: 'c'.repeat(64) };
const baseEnv = {
  GITHUB_REPOSITORY: REPOSITORY, GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/sign-release.yml@refs/heads/main`,
  SFS_RELEASE_ID: inputs.releaseId, SFS_VERSION: version, SFS_SOURCE_COMMIT: sourceCommit, SFS_REQUEST_SHA256: inputs.requestSha256,
};
const asset = name => ({ name, sha256: 'd'.repeat(64), bytes: 1024 });
function request() {
  const zip = asset(`steam-float-scanner-source-${version}.zip`);
  return { version, sourceCommit, sourceSha256, ciRunId: '456', releaseNotesSha256: 'e'.repeat(64), sourceZip: { ...zip }, assets: [
    asset(`Steam-Float-Scanner-Setup-${version}.exe`), asset(`Steam-Float-Scanner-Setup-${version}.exe.blockmap`), zip,
    asset('build-verification.json'), asset('latest.yml'),
  ] };
}

test('accepts only the fixed repository, main, workflow_dispatch and exact inputs', () => {
  assert.deepEqual(validateInputs(baseEnv), inputs);
  for (const bad of [{ GITHUB_REF: 'refs/heads/attacker' }, { GITHUB_EVENT_NAME: 'pull_request_target' },
    { GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/other.yml@refs/heads/main` },
    { SFS_VERSION: '0.2.149-beta.1' }, { SFS_RELEASE_ID: '123; echo fail' }, { SFS_SOURCE_COMMIT: 'main' }]) {
    assert.throws(() => validateInputs({ ...baseEnv, ...bad }));
  }
});

test('rejects arbitrary names, duplicate assets, changed commits and unbound source ZIP', () => {
  assert.equal(validateRequest(request(), inputs).linuxDeb, false);
  const duplicate = request(); duplicate.assets[1] = duplicate.assets[0];
  const traversal = request(); traversal.assets[0].name = '../../private.pem';
  const extra = request(); extra.assets.push(asset('execute-me.mjs'));
  const wrongZip = request(); wrongZip.sourceZip.sha256 = 'f'.repeat(64);
  for (const bad of [duplicate, traversal, extra, wrongZip, { ...request(), sourceCommit: 'f'.repeat(40) }]) {
    assert.throws(() => validateRequest(bad, inputs));
  }
});

test('requires a fresh stable draft; published versions and prereleases cannot be signed', () => {
  const release = { id: 123, tag_name: `v${version}`, draft: true, prerelease: false, published_at: null };
  checkDraft(release, inputs);
  for (const change of [{ draft: false }, { prerelease: true }, { published_at: '2026-10-09' }, { tag_name: 'v0.2.148' }]) {
    assert.throws(() => checkDraft({ ...release, ...change }, inputs));
  }
});

test('native PASS must bind the exact source, version and installer digest', () => {
  const req = request(), exe = req.assets[0];
  const proof = { status: 'PASS', version, baseCommit: sourceCommit, sourceSha256, installerSha256: exe.sha256 };
  validateProof(proof, req, exe);
  for (const change of [{ status: 'FAIL' }, { version: '0.2.148' }, { baseCommit: 'f'.repeat(40) }, { installerSha256: 'f'.repeat(64) }]) {
    assert.throws(() => validateProof({ ...proof, ...change }, req, exe));
  }
});

test('parses only the bounded one-installer electron-builder feed and catches altered hashes', () => {
  const filename = `Steam-Float-Scanner-Setup-${version}.exe`, data = { bytes: 100, sha512: Buffer.alloc(64, 1).toString('base64') };
  const text = `version: ${version}\nfiles:\n  - url: ${filename}\n    sha512: ${data.sha512}\n    size: 100\npath: ${filename}\nsha512: ${data.sha512}\nreleaseDate: '2026-10-09T06:59:23.883Z'\n`;
  validateFeed(Buffer.from(text), version, filename, data);
  assert.throws(() => validateFeed(Buffer.from(text.replace('size: 100', 'size: 101')), version, filename, data));
  assert.throws(() => validateFeed(Buffer.from(text + 'extra: !!js/function evil\n'), version, filename, data));
});

test('signatures use the existing payload order; wrong key, wrong passphrase and tampering fail', () => {
  const keys = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
  const passphrase = 'synthetic-test-only-phrase-with-at-least-32-characters';
  const pem = keys.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
  const pub = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const unsigned = { version, releaseNotes: 'Synthetic offline proof', publishedAt: '2026-10-09T00:00:00.000Z',
    url: `https://github.com/${REPOSITORY}/releases/download/v${version}/Steam-Float-Scanner-Setup-${version}.exe`, sha256: 'd'.repeat(64) };
  const signed = createManifest(unsigned, pem, passphrase, pub);
  assert(verify(null, signedPayload(signed), pub, Buffer.from(signed.signature, 'base64')));
  assert(!verify(null, signedPayload({ ...signed, sha256: 'e'.repeat(64) }), pub, Buffer.from(signed.signature, 'base64')));
  assert.throws(() => createManifest(unsigned, pem, passphrase, other.publicKey.export({ type: 'spki', format: 'pem' })), /WRONG_SIGNING_KEY/);
  assert.throws(() => createManifest(unsigned, pem, 'incorrect-passphrase-at-least-32-characters', pub), /SIGNING_KEY_DECRYPTION_FAILED/);
});

test('asset redirects never receive the GitHub bearer credential', async () => {
  const calls = [], content = Buffer.from('fixture');
  const client = createClient('synthetic-token-never-real', async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) return new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/fixture' } });
    return new Response(content);
  });
  const result = await client.download(123, content.length);
  assert.equal(result.sha256, createHash('sha256').update(content).digest('hex'));
  assert.equal(calls[0].options.headers.Authorization, 'Bearer synthetic-token-never-real');
  assert.equal(calls[1].options.headers.Authorization, undefined);
});

test('cross-host, API-back redirects and wrong lengths fail closed', async () => {
  for (const location of ['https://attacker.example/fixture', 'https://api.github.com/user', 'http://release-assets.githubusercontent.com/file']) {
    let calls = 0;
    const client = createClient('synthetic', async () => { calls++; return new Response(null, { status: 302, headers: { location } }); });
    await assert.rejects(client.download(123, 7)); assert.equal(calls, 1);
  }
  const client = createClient('synthetic', async () => new Response('oversize'));
  await assert.rejects(client.download(123, 3), /ASSET_TOO_LARGE/);
});
