// Trusted standalone release signer. Builtins only: never import source/artifact code.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const REPOSITORY = 'Rigby453/steam-float-scanner-releases';
export const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOJb8WpemdYBC80YZzT2rnNwJBMeLc3V1f4oVvwFpVT0=\n-----END PUBLIC KEY-----';
const API = `https://api.github.com/repos/${REPOSITORY}`;
const REQUEST_NAME = 'release-source.json';
const MAX_JSON = 2 * 1024 * 1024;
const fail = code => { throw new Error(code); };
const requireThat = (value, code) => { if (!value) fail(code); };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const record = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const sha = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const exactKeys = (x, keys) => record(x) && Object.keys(x).sort().join('|') === [...keys].sort().join('|');

export function validateInputs(env) {
  requireThat(env.GITHUB_REPOSITORY === REPOSITORY && env.GITHUB_REF === 'refs/heads/main'
    && env.GITHUB_EVENT_NAME === 'workflow_dispatch', 'UNTRUSTED_WORKFLOW_CONTEXT');
  requireThat(env.GITHUB_WORKFLOW_REF === `${REPOSITORY}/.github/workflows/sign-release.yml@refs/heads/main`, 'UNTRUSTED_WORKFLOW_FILE');
  requireThat(/^[0-9]+$/.test(env.SFS_RELEASE_ID ?? ''), 'INVALID_RELEASE_ID');
  requireThat(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(env.SFS_VERSION ?? ''), 'INVALID_STABLE_VERSION');
  requireThat(/^[0-9a-f]{40}$/.test(env.SFS_SOURCE_COMMIT ?? ''), 'INVALID_SOURCE_COMMIT');
  requireThat(sha(env.SFS_REQUEST_SHA256), 'INVALID_REQUEST_HASH');
  return { releaseId: env.SFS_RELEASE_ID, version: env.SFS_VERSION, sourceCommit: env.SFS_SOURCE_COMMIT, requestSha256: env.SFS_REQUEST_SHA256 };
}

export function validateRequest(request, inputs) {
  requireThat(record(request) && request.version === inputs.version && request.sourceCommit === inputs.sourceCommit
    && sha(request.sourceSha256) && /^[0-9]+$/.test(String(request.ciRunId)) && sha(request.releaseNotesSha256)
    && Array.isArray(request.assets), 'REQUEST_IDENTITY_MISMATCH');
  const linuxDeb = request.assets.some(a => a.name === `Steam-Float-Scanner-${inputs.version}-amd64.deb`);
  const names = [
    `Steam-Float-Scanner-Setup-${inputs.version}.exe`,
    `Steam-Float-Scanner-Setup-${inputs.version}.exe.blockmap`,
    `steam-float-scanner-source-${inputs.version}.zip`,
    'build-verification.json', 'latest.yml',
    ...(linuxDeb ? [`Steam-Float-Scanner-${inputs.version}-amd64.deb`, 'linux-build-verification.json', 'latest-linux.yml'] : []),
  ];
  requireThat(Array.isArray(request.assets) && request.assets.length === names.length, 'INVALID_ASSET_COUNT');
  const seen = new Set();
  for (const asset of request.assets) {
    requireThat(exactKeys(asset, ['name', 'sha256', 'bytes']) && names.includes(asset.name) && !seen.has(asset.name), 'INVALID_ASSET_NAME');
    requireThat(sha(asset.sha256) && Number.isSafeInteger(asset.bytes) && asset.bytes > 0 && asset.bytes <= 512 * 1024 * 1024, 'INVALID_ASSET_DIGEST');
    if (asset.name.endsWith('.json') || asset.name.endsWith('.yml')) requireThat(asset.bytes <= MAX_JSON, 'METADATA_TOO_LARGE');
    seen.add(asset.name);
  }
  requireThat(names.every(name => seen.has(name)), 'MISSING_ASSET');
  const zip = request.assets.find(a => a.name === `steam-float-scanner-source-${inputs.version}.zip`);
  requireThat(record(request.sourceZip) && request.sourceZip.name === zip.name
    && request.sourceZip.sha256 === zip.sha256 && request.sourceZip.bytes === zip.bytes, 'SOURCE_ZIP_IDENTITY_MISMATCH');
  return { ...request, linuxDeb };
}

export function signedPayload(manifest) {
  return Buffer.from(JSON.stringify({
    version: manifest.version, releaseNotes: manifest.releaseNotes,
    publishedAt: manifest.publishedAt, url: manifest.url, sha256: manifest.sha256,
    ...(manifest.platform === undefined ? {} : { platform: manifest.platform }),
    ...(manifest.architecture === undefined ? {} : { architecture: manifest.architecture }),
    ...(manifest.packageType === undefined ? {} : { packageType: manifest.packageType }),
  }));
}

export function createManifest(unsigned, encryptedPem, passphrase, publicKey = PUBLIC_KEY) {
  requireThat(typeof encryptedPem === 'string' && encryptedPem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    && typeof passphrase === 'string' && passphrase.length >= 32, 'SIGNING_SECRET_UNAVAILABLE');
  let privateKey;
  try { privateKey = createPrivateKey({ key: encryptedPem, format: 'pem', passphrase }); }
  catch { fail('SIGNING_KEY_DECRYPTION_FAILED'); }
  requireThat(privateKey.asymmetricKeyType === 'ed25519', 'WRONG_KEY_TYPE');
  const expected = createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  const actual = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  requireThat(expected.equals(actual), 'WRONG_SIGNING_KEY');
  const signature = sign(null, signedPayload(unsigned), privateKey).toString('base64');
  requireThat(verify(null, signedPayload(unsigned), publicKey, Buffer.from(signature, 'base64')), 'SIGNATURE_SELF_CHECK_FAILED');
  return { ...unsigned, signature };
}

export function validateProof(proof, request, asset, linux = false) {
  requireThat(record(proof) && proof.status === 'PASS' && proof.version === request.version
    && proof.baseCommit === request.sourceCommit && proof.sourceSha256 === request.sourceSha256, 'NATIVE_PROOF_IDENTITY_MISMATCH');
  if (linux) {
    requireThat(proof.platform === 'linux' && proof.architecture === 'x64' && proof.installerPayloadVerified === true, 'LINUX_PROOF_NOT_VERIFIED');
    const matches = Array.isArray(proof.artifacts) ? proof.artifacts.filter(a => a.name === asset.name) : [];
    requireThat(matches.length === 1 && matches[0].sha256 === asset.sha256 && matches[0].bytes === asset.bytes, 'LINUX_PROOF_HASH_MISMATCH');
  } else requireThat(proof.installerSha256 === asset.sha256, 'WINDOWS_PROOF_HASH_MISMATCH');
}

function parseJson(bytes) {
  try { return JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, '')); }
  catch { fail('INVALID_JSON'); }
}

export function createClient(token, fetcher = fetch) {
  requireThat(typeof token === 'string' && token.length > 0, 'GITHUB_TOKEN_MISSING');
  async function api(path, method = 'GET', value) {
    requireThat(path.startsWith('/') && !path.includes('..'), 'INVALID_API_PATH');
    const response = await fetcher(API + path, {
      method, redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2022-11-28',
        ...(value === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(value === undefined ? {} : { body: JSON.stringify(value) }),
    });
    requireThat(response.ok, `GITHUB_API_${response.status}`);
    return parseJson(await boundedBytes(response, MAX_JSON));
  }
  async function download(assetId, expectedBytes, keep = false) {
    requireThat(Number.isSafeInteger(assetId) && assetId > 0, 'INVALID_ASSET_ID');
    let url = `${API}/releases/assets/${assetId}`;
    for (let redirects = 0; redirects <= 5; redirects++) {
      const parsed = new URL(url);
      requireThat(parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.port, 'INVALID_ASSET_URL');
      requireThat(['api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(parsed.hostname), 'UNEXPECTED_ASSET_HOST');
      const response = await fetcher(url, {
        redirect: 'manual', signal: AbortSignal.timeout(180_000),
        headers: parsed.hostname === 'api.github.com' ? { Authorization: `Bearer ${token}`, Accept: 'application/octet-stream', 'X-GitHub-Api-Version': '2022-11-28' } : {},
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        requireThat(location, 'ASSET_REDIRECT_WITHOUT_LOCATION');
        await response.body?.cancel();
        url = new URL(location, url).href;
        // Never allow a CDN redirect back to an authenticated API endpoint.
        requireThat(new URL(url).hostname !== 'api.github.com', 'ASSET_REDIRECT_TO_API');
        continue;
      }
      requireThat(response.ok && response.body, `ASSET_DOWNLOAD_${response.status}`);
      let bytes = 0; const hash256 = createHash('sha256'), hash512 = createHash('sha512'), chunks = [];
      for await (const chunk of response.body) {
        bytes += chunk.length;
        requireThat(bytes <= expectedBytes && (!keep || bytes <= MAX_JSON), 'ASSET_TOO_LARGE');
        hash256.update(chunk); hash512.update(chunk); if (keep) chunks.push(chunk);
      }
      requireThat(bytes === expectedBytes, 'ASSET_LENGTH_MISMATCH');
      return { bytes, sha256: hash256.digest('hex'), sha512: hash512.digest('base64'), body: keep ? Buffer.concat(chunks) : undefined };
    }
    fail('TOO_MANY_ASSET_REDIRECTS');
  }
  async function upload(releaseId, name, bytes) {
    requireThat(/^[0-9]+$/.test(releaseId) && /^[A-Za-z0-9.-]+$/.test(name), 'INVALID_UPLOAD_TARGET');
    const response = await fetcher(`https://uploads.github.com/repos/${REPOSITORY}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/octet-stream', 'X-GitHub-Api-Version': '2022-11-28' }, body: bytes,
    });
    requireThat(response.status === 201, `ASSET_UPLOAD_${response.status}`);
    return parseJson(await boundedBytes(response, MAX_JSON));
  }
  return { api, download, upload };
}

async function boundedBytes(response, max) {
  let count = 0; const chunks = [];
  requireThat(response.body, 'EMPTY_RESPONSE');
  for await (const chunk of response.body) {
    count += chunk.length; requireThat(count <= max, 'RESPONSE_TOO_LARGE'); chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function releaseAssets(client, releaseId) {
  const assets = await client.api(`/releases/${releaseId}/assets?per_page=100`);
  requireThat(Array.isArray(assets) && assets.length < 100, 'ASSET_LIST_LIMIT');
  return assets;
}

export function checkDraft(release, inputs) {
  requireThat(record(release) && String(release.id) === inputs.releaseId && release.tag_name === `v${inputs.version}`
    && release.draft === true && release.prerelease === false && !release.published_at, 'RELEASE_NOT_NEW_STABLE_DRAFT');
}

function catalog(assets) {
  const map = new Map();
  for (const asset of assets) {
    requireThat(record(asset) && !map.has(asset.name) && asset.state === 'uploaded'
      && Number.isSafeInteger(asset.id) && asset.id > 0 && Number.isSafeInteger(asset.size) && asset.size > 0, 'INVALID_RELEASE_ASSET');
    map.set(asset.name, asset);
  }
  return map;
}

function newer(left, right) {
  const a = left.split('.').map(BigInt), b = right.split('.').map(BigInt);
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] > b[i]; }
  return false;
}

async function checkLatest(client, version) {
  const latest = await client.api('/releases/latest');
  requireThat(typeof latest.tag_name === 'string' && /^v\d+\.\d+\.\d+$/.test(latest.tag_name)
    && newer(version, latest.tag_name.slice(1)), 'VERSION_NOT_NEWER_THAN_LATEST');
}

async function inspect(client, inputs, allowedGenerated = []) {
  const release = await client.api(`/releases/${inputs.releaseId}`); checkDraft(release, inputs);
  await checkLatest(client, inputs.version);
  const assets = catalog(await releaseAssets(client, inputs.releaseId));
  const requestAsset = assets.get(REQUEST_NAME);
  requireThat(requestAsset && requestAsset.size <= MAX_JSON, 'SIGNING_REQUEST_MISSING');
  const requestBytes = await client.download(requestAsset.id, requestAsset.size, true);
  requireThat(requestBytes.sha256 === inputs.requestSha256, 'REQUEST_HASH_MISMATCH');
  const request = validateRequest(parseJson(requestBytes.body), inputs);
  const allowed = new Set([REQUEST_NAME, ...request.assets.map(a => a.name), ...allowedGenerated]);
  requireThat([...assets.keys()].every(name => allowed.has(name)) && assets.size === allowed.size, 'UNEXPECTED_RELEASE_ASSETS');
  const actual = new Map();
  for (const expected of request.assets) {
    const asset = assets.get(expected.name);
    requireThat(asset && asset.size === expected.bytes, 'REQUEST_ASSET_SIZE_MISMATCH');
    if (asset.digest) requireThat(asset.digest === `sha256:${expected.sha256}`, 'GITHUB_ASSET_DIGEST_MISMATCH');
    const data = await client.download(asset.id, expected.bytes, expected.name.endsWith('.json') || expected.name.endsWith('.yml'));
    requireThat(data.sha256 === expected.sha256, 'REQUEST_ASSET_HASH_MISMATCH');
    actual.set(expected.name, data);
  }
  const windows = request.assets.find(a => a.name.endsWith('.exe'));
  validateProof(parseJson(actual.get('build-verification.json').body), request, windows);
  if (request.linuxDeb) validateProof(parseJson(actual.get('linux-build-verification.json').body), request, request.assets.find(a => a.name.endsWith('.deb')), true);
  const notes = typeof release.body === 'string' ? release.body.trim() : '';
  requireThat(notes.length > 0 && notes.length <= 100_000, 'INVALID_RELEASE_NOTES');
  requireThat(digest(Buffer.from(notes)) === request.releaseNotesSha256, 'RELEASE_NOTES_HASH_MISMATCH');
  validateFeed(actual.get('latest.yml').body, request.version, windows.name, actual.get(windows.name));
  if (request.linuxDeb) {
    const linux = request.assets.find(a => a.name.endsWith('.deb'));
    validateFeed(actual.get('latest-linux.yml').body, request.version, linux.name, actual.get(linux.name));
  }
  return { release, assets, request, actual, notes };
}

export function validateFeed(bytes, version, filename, data) {
  const text = bytes.toString('utf8').replace(/\r\n/g, '\n').trim();
  // Accept only the simple electron-builder feed emitted for one installer.
  const escaped = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`^version: ${escaped(version)}\\nfiles:\\n  - url: ${escaped(filename)}\\n    sha512: ${escaped(data.sha512)}\\n    size: ${data.bytes}\\npath: ${escaped(filename)}\\nsha512: ${escaped(data.sha512)}\\nreleaseDate: ['\"]?(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z)['\"]?$`);
  const match = text.match(pattern);
  requireThat(match && Number.isFinite(Date.parse(match[1])), 'UNEXPECTED_UPDATE_FEED');
}

export async function run(mode, env = process.env, fetcher = fetch) {
  requireThat(['verify', 'publish'].includes(mode), 'INVALID_MODE');
  const inputs = validateInputs(env), client = createClient(env.GITHUB_TOKEN, fetcher);
  const result = await inspect(client, inputs);
  if (mode === 'verify') return { status: 'VERIFIED_DRAFT', ...inputs, assets: result.request.assets.length };
  const publishedAt = new Date().toISOString(), generated = new Map();
  const targets = [{ name: `Steam-Float-Scanner-Setup-${inputs.version}.exe`, manifest: 'manifest.json', feed: 'latest.yml' },
    ...(result.request.linuxDeb ? [{ name: `Steam-Float-Scanner-${inputs.version}-amd64.deb`, manifest: 'manifest-linux-x64-deb.json', feed: 'latest-linux.yml', linux: true }] : [])];
  for (const target of targets) {
    const data = result.actual.get(target.name);
    const unsigned = { version: inputs.version, releaseNotes: result.notes, publishedAt,
      url: `https://github.com/${REPOSITORY}/releases/download/v${inputs.version}/${target.name}`, sha256: data.sha256,
      ...(target.linux ? { platform: 'linux', architecture: 'x64', packageType: 'deb' } : {}) };
    const manifest = createManifest(unsigned, env.SFS_UPDATE_PRIVATE_KEY_PEM, env.SFS_UPDATE_KEY_PASSPHRASE);
    generated.set(target.manifest, Buffer.from(JSON.stringify(manifest, null, 2) + '\n'));
  }
  // Drop process-environment copies before any API mutation. Private material never goes to disk.
  delete env.SFS_UPDATE_PRIVATE_KEY_PEM; delete env.SFS_UPDATE_KEY_PASSPHRASE;
  for (const [name, bytes] of generated) {
    const uploaded = await client.upload(inputs.releaseId, name, bytes);
    const readBack = await client.download(uploaded.id, bytes.length);
    requireThat(readBack.sha256 === digest(bytes), 'SIGNED_ASSET_READBACK_MISMATCH');
  }
  const checked = await inspect(client, inputs, [...generated.keys()]);
  for (const [name, bytes] of generated) {
    const current = checked.assets.get(name);
    const readBack = await client.download(current.id, bytes.length);
    requireThat(readBack.sha256 === digest(bytes), 'SIGNED_ASSET_CHANGED');
  }
  // Publish without latest first. Never overwrite or repair an already published version.
  const published = await client.api(`/releases/${inputs.releaseId}`, 'PATCH', { draft: false, prerelease: false, make_latest: 'false' });
  requireThat(published.draft === false && published.immutable === true, 'PUBLISHED_NOT_LATEST_ENABLE_IMMUTABILITY');
  const publishedAssets = catalog(await releaseAssets(client, inputs.releaseId));
  requireThat(publishedAssets.size === checked.assets.size, 'PUBLISHED_ASSET_COUNT_MISMATCH');
  for (const [name, previous] of checked.assets) {
    const current = publishedAssets.get(name);
    requireThat(current && current.id === previous.id && current.size === previous.size && current.digest === previous.digest, 'PUBLISHED_ASSET_IDENTITY_MISMATCH');
  }
  // Download each public asset without Authorization. Immutable assets cannot race after this point.
  for (const [name, previous] of checked.assets) {
    const response = await fetcher(`https://github.com/${REPOSITORY}/releases/download/v${inputs.version}/${name}`, {
      redirect: 'manual', signal: AbortSignal.timeout(30_000), headers: {},
    });
    requireThat([301, 302, 303, 307, 308].includes(response.status), 'PUBLIC_ASSET_NOT_AVAILABLE');
    const location = response.headers.get('location'); await response.body?.cancel();
    const redirectUrl = location ? new URL(location) : null;
    requireThat(redirectUrl && redirectUrl.protocol === 'https:' && !redirectUrl.username && !redirectUrl.password && !redirectUrl.port
      && ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(redirectUrl.hostname), 'UNEXPECTED_PUBLIC_REDIRECT');
    const body = await fetcher(location, { redirect: 'error', signal: AbortSignal.timeout(180_000), headers: {} });
    requireThat(body.ok && body.body, 'PUBLIC_ASSET_DOWNLOAD_FAILED');
    let bytes = 0; const hash = createHash('sha256');
    for await (const chunk of body.body) { bytes += chunk.length; requireThat(bytes <= previous.size, 'PUBLIC_ASSET_TOO_LARGE'); hash.update(chunk); }
    const expected = name === REQUEST_NAME ? inputs.requestSha256 : generated.has(name) ? digest(generated.get(name)) : result.actual.get(name).sha256;
    requireThat(bytes === previous.size && hash.digest('hex') === expected, 'PUBLIC_ASSET_HASH_MISMATCH');
  }
  await checkLatest(client, inputs.version);
  await client.api(`/releases/${inputs.releaseId}`, 'PATCH', { make_latest: 'true' });
  const latest = await client.api('/releases/latest');
  requireThat(String(latest.id) === inputs.releaseId && latest.immutable === true, 'LATEST_PROMOTION_NOT_CONFIRMED');
  return { status: 'PUBLISHED_AND_LATEST', ...inputs, signerCommit: env.GITHUB_SHA, immutable: true };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await run(process.argv[2]))); }
  catch (error) {
    // Never emit OpenSSL details, HTTP response bodies, input values, tokens, or key text.
    const message = error instanceof Error && /^[A-Z][A-Z0-9_]+$/.test(error.message) ? error.message : 'SIGN_RELEASE_FAILED';
    console.error(message); process.exitCode = 1;
  }
}
