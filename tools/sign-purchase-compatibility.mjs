// Trusted standalone metadata publisher. Node builtins only; never execute fetched data.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const REPOSITORY = 'Rigby453/steam-float-scanner-releases';
export const TAG = 'purchase-compatibility-v1';
export const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOJb8WpemdYBC80YZzT2rnNwJBMeLc3V1f4oVvwFpVT0=\n-----END PUBLIC KEY-----';
export const REVISION_FLOOR = 2026101001;
export const ORIGINAL_EXPIRY = '2026-11-04T20:12:56.038Z';
const API = `https://api.github.com/repos/${REPOSITORY}`;
const MAX_SIGNED = 128 * 1024;
const MAX_PAYLOAD = 32 * 1024;
const MAX_INFLATED_PAYLOAD = 64 * 1024;
const MAX_API = 256 * 1024;
const DAY = 86_400_000;
const fail = code => { throw new Error(code); };
const requireThat = (ok, code) => { if (!ok) fail(code); };
const record = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const sha = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const integer = (x, min, max) => Number.isSafeInteger(x) && x >= min && x <= max;
const exactKeys = (x, keys) => record(x) && Object.keys(x).sort().join('|') === [...keys].sort().join('|');
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function datetime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === value.slice(0, 19);
}

export function validatePolicy(policy) {
  requireThat(exactKeys(policy, ['version', 'shapeSha256', 'moduleCount', 'roleLinks'])
    && policy.version === 'steam-financial-graph-v1' && sha(policy.shapeSha256)
    && integer(policy.moduleCount, 4, 128) && Array.isArray(policy.roleLinks) && policy.roleLinks.length === 2
    && policy.roleLinks.every(n => integer(n, 0, 127)), 'INVALID_GRAPH_POLICY');
  return { version: policy.version, shapeSha256: policy.shapeSha256, moduleCount: policy.moduleCount, roleLinks: [...policy.roleLinks] };
}

// Mirrors the production strict schema and explicit signature order. The publisher
// accepts UTC datetimes with seconds, a deliberately narrower safe schema subset.
export function validatePayload(payload) {
  const keys = ['kind', 'schemaVersion', 'contractVersion', 'revision', 'publishedAt', 'expiresAt', 'deployments'];
  requireThat(exactKeys(payload, payload?.graphPolicies === undefined ? keys : [...keys, 'graphPolicies'])
    && payload.kind === 'steam-float-scanner-purchase-compatibility' && payload.schemaVersion === 1
    && payload.contractVersion === 'steam-market-buylisting-v1' && integer(payload.revision, 1, Number.MAX_SAFE_INTEGER)
    && datetime(payload.publishedAt) && datetime(payload.expiresAt), 'INVALID_PAYLOAD');
  const lifetime = Date.parse(payload.expiresAt) - Date.parse(payload.publishedAt);
  requireThat(lifetime > 0 && lifetime <= 90 * DAY, 'INVALID_LIFETIME');
  requireThat(Array.isArray(payload.deployments) && integer(payload.deployments.length, 1, 32), 'INVALID_DEPLOYMENTS');
  const routes = new Set();
  const deployments = payload.deployments.map(chain => {
    requireThat(Array.isArray(chain) && integer(chain.length, 3, 128), 'INVALID_DEPLOYMENT_CHAIN');
    const checked = chain.map(module => {
      requireThat(exactKeys(module, ['file', 'sha256']) && typeof module.file === 'string' && /^[A-Za-z0-9_-]{1,80}\.js$/.test(module.file)
        && sha(module.sha256), 'INVALID_MODULE_PIN');
      return { file: module.file, sha256: module.sha256 };
    });
    requireThat(new Set(checked.map(module => module.file)).size === checked.length, 'DUPLICATE_DEPLOYMENT_MODULE');
    requireThat(!routes.has(checked[0].file), 'DUPLICATE_ROUTE');
    routes.add(checked[0].file);
    return checked;
  });
  requireThat(payload.graphPolicies === undefined || (Array.isArray(payload.graphPolicies) && payload.graphPolicies.length <= 16), 'INVALID_GRAPH_POLICIES');
  return {
    kind: payload.kind, schemaVersion: payload.schemaVersion, contractVersion: payload.contractVersion,
    revision: payload.revision, publishedAt: payload.publishedAt, expiresAt: payload.expiresAt, deployments,
    ...(payload.graphPolicies === undefined ? {} : { graphPolicies: payload.graphPolicies.map(validatePolicy) }),
  };
}

export const signedBytes = payload => Buffer.from(JSON.stringify(validatePayload(payload)), 'utf8');
function parseJson(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('INVALID_JSON'); }
}

export function parseSigned(bytes, publicKey = PUBLIC_KEY) {
  requireThat(bytes.length > 0 && bytes.length <= MAX_SIGNED, 'SIGNED_SIZE_LIMIT');
  const signed = parseJson(bytes);
  requireThat(exactKeys(signed, ['payload', 'signature']) && typeof signed.signature === 'string'
    && /^[A-Za-z0-9+/]{86}==$/.test(signed.signature), 'INVALID_SIGNED_DOCUMENT');
  const payload = validatePayload(signed.payload);
  const signature = Buffer.from(signed.signature, 'base64');
  requireThat(signature.toString('base64') === signed.signature
    && verify(null, signedBytes(payload), publicKey, signature), 'INVALID_COMPATIBILITY_SIGNATURE');
  return { payload, signature: signed.signature };
}

function fromBase64(text, max) {
  requireThat(typeof text === 'string' && text.length > 0 && text.length <= Math.ceil(max / 3) * 4
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text), 'INVALID_BASE64_INPUT');
  const bytes = Buffer.from(text, 'base64');
  requireThat(bytes.length <= max && bytes.toString('base64') === text, 'INVALID_BASE64_INPUT');
  return bytes;
}

// Dispatch compression is data transport only. Hash/review/signature checks
// continue to bind the exact decoded JSON bytes, never the compressed container.
function dispatchBytes(text, encoding, limit) {
  const bytes = fromBase64(text, MAX_PAYLOAD);
  if (encoding === 'utf8-json') return bytes;
  try { return gunzipSync(bytes, { maxOutputLength: limit }); }
  catch { fail('INVALID_COMPRESSED_INPUT'); }
}

export function validateInputs(env) {
  requireThat(env.GITHUB_REPOSITORY === REPOSITORY && env.GITHUB_REF === 'refs/heads/main'
    && env.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && env.GITHUB_WORKFLOW_REF === `${REPOSITORY}/.github/workflows/sign-purchase-compatibility.yml@refs/heads/main`, 'UNTRUSTED_WORKFLOW_CONTEXT');
  requireThat(sha(env.SFS_COMPATIBILITY_PAYLOAD_SHA256) && sha(env.SFS_COMPATIBILITY_PREVIOUS_SHA256)
    && sha(env.SFS_COMPATIBILITY_REVIEW_SHA256), 'INVALID_DISPATCH_HASH');
  const encoding = env.SFS_COMPATIBILITY_INPUT_ENCODING ?? 'utf8-json';
  requireThat(['utf8-json', 'gzip-json'].includes(encoding), 'INVALID_INPUT_ENCODING');
  const payloadBytes = dispatchBytes(env.SFS_COMPATIBILITY_PAYLOAD_BASE64, encoding, MAX_INFLATED_PAYLOAD);
  const reviewBytes = dispatchBytes(env.SFS_COMPATIBILITY_REVIEW_BASE64, encoding, MAX_PAYLOAD);
  requireThat(env.SFS_COMPATIBILITY_PAYLOAD_BASE64.length + env.SFS_COMPATIBILITY_REVIEW_BASE64.length <= 60_000, 'DISPATCH_PAYLOAD_TOO_LARGE');
  requireThat(digest(payloadBytes) === env.SFS_COMPATIBILITY_PAYLOAD_SHA256
    && digest(reviewBytes) === env.SFS_COMPATIBILITY_REVIEW_SHA256, 'DISPATCH_HASH_MISMATCH');
  return { payload: validatePayload(parseJson(payloadBytes)), payloadSha256: digest(payloadBytes),
    previousSha256: env.SFS_COMPATIBILITY_PREVIOUS_SHA256, review: parseJson(reviewBytes), reviewBytes, reviewSha256: digest(reviewBytes) };
}

// This checks that an external review attestation is bound to the exact data.
// It cannot establish that the claimed review was actually completed correctly.
export function validateTransition(inputs, previous, now) {
  const payload = inputs.payload;
  requireThat(Number.isFinite(now) && previous.revision >= REVISION_FLOOR && payload.revision > previous.revision, 'REVISION_ROLLBACK');
  requireThat(payload.expiresAt === ORIGINAL_EXPIRY && previous.expiresAt === ORIGINAL_EXPIRY, 'EXPIRY_EXTENSION_FORBIDDEN');
  requireThat(Date.parse(payload.publishedAt) >= Date.parse(previous.publishedAt)
    && Date.parse(payload.publishedAt) <= now + 300_000 && Date.parse(payload.expiresAt) > now, 'COMPATIBILITY_NOT_CURRENT');
  // Preserve every approved historical vector. A new three-module pin cannot
  // bind billing/dependencies. A finite reviewed initial-page exact snapshot
  // is not approval of a general runtime graph or of unrelated navigation.
  requireThat(payload.deployments.length === previous.deployments.length + 1
    && same(payload.deployments.slice(0, previous.deployments.length), previous.deployments), 'LEGACY_DEPLOYMENTS_CHANGED');
  const addedDeployment = payload.deployments.at(-1);
  requireThat(addedDeployment.length >= 4, 'INCOMPLETE_EXACT_SNAPSHOT_VECTOR');
  requireThat(same(payload.graphPolicies, previous.graphPolicies), 'GRAPH_POLICIES_CHANGED');
  const review = inputs.review;
  requireThat(exactKeys(review, ['kind', 'schemaVersion', 'payloadSha256', 'previousSha256', 'sourceCommit',
    'reviewedAt', 'scope', 'verdict', 'exactFinancialBehaviorUnchanged', 'approvedDeployment',
    'dynamicImportAssessment', 'offPathBehaviorChanges', 'evidenceSha256'])
    && review.kind === 'steam-float-scanner-purchase-compatibility-review' && review.schemaVersion === 1
    && review.payloadSha256 === inputs.payloadSha256 && review.previousSha256 === inputs.previousSha256
    && typeof review.sourceCommit === 'string' && /^[0-9a-f]{40}$/.test(review.sourceCommit) && sha(review.evidenceSha256)
    && datetime(review.reviewedAt) && Date.parse(review.reviewedAt) <= now + 300_000
    && Date.parse(review.reviewedAt) >= Date.parse(payload.publishedAt)
    && review.scope === 'exact-initial-page-financial-static-snapshot-including-initialization'
    && review.verdict === 'PASS_EXACT_FINANCIAL_BEHAVIOR_REVIEW'
    && review.exactFinancialBehaviorUnchanged === true
    && same(review.approvedDeployment, addedDeployment)
    && exactKeys(review.dynamicImportAssessment, ['scope', 'verdict', 'evidenceSha256'])
    && review.dynamicImportAssessment.scope === 'initial-page-direct-exact-buy'
    && review.dynamicImportAssessment.verdict === 'PASS_FINANCIAL_NONINTERFERENCE_WITHIN_SCOPE'
    && sha(review.dynamicImportAssessment.evidenceSha256)
    && exactKeys(review.offPathBehaviorChanges, ['present', 'evidenceSha256'])
    && typeof review.offPathBehaviorChanges.present === 'boolean'
    && sha(review.offPathBehaviorChanges.evidenceSha256), 'REVIEW_BINDING_MISMATCH');
  return addedDeployment;
}

export function signPayload(payload, encryptedPem, passphrase, publicKey = PUBLIC_KEY) {
  requireThat(typeof encryptedPem === 'string' && encryptedPem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    && typeof passphrase === 'string' && passphrase.length >= 32, 'SIGNING_SECRET_UNAVAILABLE');
  let key;
  try { key = createPrivateKey({ key: encryptedPem, format: 'pem', passphrase }); }
  catch { fail('SIGNING_KEY_DECRYPTION_FAILED'); }
  requireThat(key.asymmetricKeyType === 'ed25519', 'WRONG_SIGNING_KEY_TYPE');
  requireThat(createPublicKey(key).export({ format: 'der', type: 'spki' })
    .equals(createPublicKey(publicKey).export({ format: 'der', type: 'spki' })), 'WRONG_SIGNING_KEY');
  const bytes = Buffer.from(JSON.stringify({ payload: validatePayload(payload), signature: sign(null, signedBytes(payload), key).toString('base64') }, null, 2) + '\n');
  parseSigned(bytes, publicKey);
  return bytes;
}

async function bounded(response, max) {
  const length = response.headers.get('content-length');
  requireThat(length === null || (/^\d+$/.test(length) && Number(length) <= max), 'RESPONSE_SIZE_LIMIT');
  requireThat(response.body, 'RESPONSE_BODY_MISSING');
  const chunks = []; let count = 0;
  for await (const chunk of response.body) {
    count += chunk.length; requireThat(count <= max, 'RESPONSE_SIZE_LIMIT'); chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export function createClient(token, fetcher = fetch) {
  requireThat(typeof token === 'string' && token.length > 0, 'GITHUB_TOKEN_MISSING');
  const auth = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  async function api(path, method = 'GET', value) {
    requireThat(method === 'GET' || (method === 'PATCH' && /^\/releases\/assets\/[1-9]\d*$/.test(path)
      && exactKeys(value, ['name']) && /^compatibility(?:-[1-9]\d*)?\.json$/.test(value.name)), 'FORBIDDEN_API_MUTATION');
    requireThat(/^\/(?:releases(?:\/tags\/purchase-compatibility-v1|\/latest|\/[1-9]\d*\/assets\?per_page=100|\/assets\/[1-9]\d*)|git\/ref\/tags\/purchase-compatibility-v1)$/.test(path), 'FORBIDDEN_API_PATH');
    const response = await fetcher(API + path, { method, redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { ...auth, ...(value === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
    requireThat(response.status === 200, `GITHUB_API_${response.status}`);
    return parseJson(await bounded(response, MAX_API));
  }
  async function download(url, expectedSize, authenticated = false) {
    requireThat(expectedSize === undefined || integer(expectedSize, 1, MAX_SIGNED), 'INVALID_ASSET_SIZE');
    for (let redirects = 0; redirects < 6; redirects++) {
      const target = new URL(url);
      const hosts = authenticated ? ['api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']
        : ['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'];
      requireThat(target.protocol === 'https:' && !target.username && !target.password && !target.port && hosts.includes(target.hostname), 'UNTRUSTED_DOWNLOAD_URL');
      if (target.hostname === 'api.github.com') requireThat(redirects === 0
        && target.origin + target.pathname === `${API}/releases/assets/${target.pathname.split('/').at(-1)}`
        && /^[1-9]\d*$/.test(target.pathname.split('/').at(-1)) && !target.search, 'UNTRUSTED_API_DOWNLOAD');
      if (target.hostname === 'github.com') requireThat(redirects === 0 && !target.search
        && target.pathname.startsWith(`/${REPOSITORY}/releases/download/${TAG}/`)
        && /^compatibility(?:-(?:[1-9]\d*(?:\.pending)?|review-[1-9]\d*))?\.json$/.test(target.pathname.split('/').at(-1)), 'UNTRUSTED_PUBLIC_DOWNLOAD');
      const response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(30_000),
        headers: target.hostname === 'api.github.com' ? { ...auth, Accept: 'application/octet-stream' } : {} });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location'); requireThat(location, 'REDIRECT_LOCATION_MISSING');
        await response.body?.cancel(); url = new URL(location, url).href; continue;
      }
      requireThat(response.status === 200, `ASSET_DOWNLOAD_${response.status}`);
      const bytes = await bounded(response, expectedSize ?? MAX_SIGNED);
      requireThat(expectedSize === undefined || bytes.length === expectedSize, 'ASSET_LENGTH_MISMATCH');
      return bytes;
    }
    fail('DOWNLOAD_REDIRECT_LIMIT');
  }
  const asset = item => download(`${API}/releases/assets/${item.id}`, item.size, true);
  const publicAsset = (name, size) => download(`https://github.com/${REPOSITORY}/releases/download/${TAG}/${name}`, size);
  async function upload(releaseId, name, bytes) {
    requireThat(integer(releaseId, 1, Number.MAX_SAFE_INTEGER)
      && /^compatibility-(?:[1-9]\d*\.pending|review-[1-9]\d*)\.json$/.test(name)
      && bytes.length > 0 && bytes.length <= MAX_SIGNED, 'FORBIDDEN_ASSET_UPLOAD');
    const response = await fetcher(`https://uploads.github.com/repos/${REPOSITORY}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { ...auth, 'Content-Type': 'application/json' }, body: bytes,
    });
    requireThat(response.status === 201, `ASSET_UPLOAD_${response.status}`);
    return parseJson(await bounded(response, MAX_API));
  }
  return { api, asset, publicAsset, upload };
}

const assetIdentity = item => [item.id, item.name, item.size, item.state];
const inventory = assets => JSON.stringify(assets.map(assetIdentity).sort((a, b) => a[0] - b[0]));
const releaseIdentity = r => JSON.stringify([r.id, r.tag_name, r.target_commitish, r.name, r.body, r.draft, r.prerelease, r.immutable, r.published_at]);
function catalog(assets) {
  requireThat(Array.isArray(assets) && assets.length < 100, 'ASSET_LIST_LIMIT');
  const map = new Map();
  for (const item of assets) {
    requireThat(record(item) && integer(item.id, 1, Number.MAX_SAFE_INTEGER) && typeof item.name === 'string'
      && integer(item.size, 1, MAX_SIGNED) && item.state === 'uploaded' && !map.has(item.name), 'INVALID_RELEASE_ASSET');
    map.set(item.name, item);
  }
  return map;
}

async function inspect(client, inputs, now, publicKey) {
  const release = await client.api(`/releases/tags/${TAG}`);
  requireThat(record(release) && integer(release.id, 1, Number.MAX_SAFE_INTEGER) && release.tag_name === TAG
    && release.draft === false && release.prerelease === true && release.immutable === false && datetime(release.published_at), 'COMPATIBILITY_RELEASE_NOT_MUTABLE_PUBLIC_PRERELEASE');
  const latest = await client.api('/releases/latest');
  requireThat(record(latest) && integer(latest.id, 1, Number.MAX_SAFE_INTEGER) && latest.id !== release.id
    && typeof latest.tag_name === 'string' && /^v\d+\.\d+\.\d+$/.test(latest.tag_name)
    && latest.immutable === true && latest.draft === false && latest.prerelease === false, 'INSTALLER_LATEST_NOT_IMMUTABLE');
  const tag = await client.api(`/git/ref/tags/${TAG}`);
  requireThat(record(tag) && tag.ref === `refs/tags/${TAG}` && record(tag.object) && typeof tag.object.sha === 'string' && /^[0-9a-f]{40}$/.test(tag.object.sha)
    && ['commit', 'tag'].includes(tag.object.type), 'INVALID_COMPATIBILITY_TAG');
  const assets = await client.api(`/releases/${release.id}/assets?per_page=100`);
  const map = catalog(assets); const current = map.get('compatibility.json');
  requireThat(current, 'CURRENT_COMPATIBILITY_MISSING');
  const previousBytes = await client.asset(current);
  requireThat(digest(previousBytes) === inputs.previousSha256, 'PREVIOUS_COMPATIBILITY_HASH_MISMATCH');
  const previous = parseSigned(previousBytes, publicKey);
  validateTransition(inputs, previous.payload, now);
  const publicBytes = await client.publicAsset('compatibility.json', current.size);
  requireThat(digest(publicBytes) === inputs.previousSha256, 'PREVIOUS_PUBLIC_READBACK_MISMATCH');
  const names = { archive: `compatibility-${previous.payload.revision}.json`,
    pending: `compatibility-${inputs.payload.revision}.pending.json`, review: `compatibility-review-${inputs.payload.revision}.json` };
  requireThat(Object.values(names).every(name => !map.has(name)), 'PUBLICATION_NAME_ALREADY_EXISTS');
  return { release, latest, tag, assets, current, previous, names };
}

async function requireControlUnchanged(client, snapshot) {
  const release = await client.api(`/releases/tags/${TAG}`);
  const latest = await client.api('/releases/latest');
  const tag = await client.api(`/git/ref/tags/${TAG}`);
  requireThat(releaseIdentity(release) === releaseIdentity(snapshot.release)
    && releaseIdentity(latest) === releaseIdentity(snapshot.latest)
    && tag.ref === snapshot.tag.ref && same(tag.object, snapshot.tag.object), 'RELEASE_OR_LATEST_CHANGED');
}

async function verifyUpload(client, item, name, bytes) {
  requireThat(item.name === name && item.size === bytes.length && item.state === 'uploaded'
    && integer(item.id, 1, Number.MAX_SAFE_INTEGER), 'UPLOADED_ASSET_IDENTITY_MISMATCH');
  requireThat(digest(await client.asset(item)) === digest(bytes)
    && digest(await client.publicAsset(name, bytes.length)) === digest(bytes), 'UPLOAD_READBACK_MISMATCH');
}

export async function run(mode, env = process.env, fetcher = fetch, testOptions = {}) {
  requireThat(['verify', 'publish'].includes(mode), 'INVALID_MODE');
  const inputs = validateInputs(env);
  // CLI never accepts a trust-key or clock override. Test calls use generated keys.
  const publicKey = testOptions.publicKey ?? PUBLIC_KEY;
  const now = testOptions.now ?? Date.now();
  const client = createClient(env.GITHUB_TOKEN, fetcher);
  const snapshot = await inspect(client, inputs, now, publicKey);
  const receipt = { repository: REPOSITORY, tag: TAG, revision: inputs.payload.revision,
    previousRevision: snapshot.previous.payload.revision, previousSha256: inputs.previousSha256,
    payloadSha256: inputs.payloadSha256, reviewSha256: inputs.reviewSha256,
    expiresAt: inputs.payload.expiresAt, retainedLegacyDeployments: snapshot.previous.payload.deployments.length,
    addedExactDeploymentModules: inputs.payload.deployments.at(-1).length,
    graphPoliciesUnchanged: true,
    installerLatestId: snapshot.latest.id, installerLatestTag: snapshot.latest.tag_name };
  if (mode === 'verify') return { ...receipt, status: 'VERIFIED_WITHOUT_SIGNING_OR_MUTATION' };
  const bytes = signPayload(inputs.payload, env.SFS_UPDATE_PRIVATE_KEY_PEM, env.SFS_UPDATE_KEY_PASSPHRASE, publicKey);
  const candidate = await client.upload(snapshot.release.id, snapshot.names.pending, bytes);
  await verifyUpload(client, candidate, snapshot.names.pending, bytes);
  const reviewAsset = await client.upload(snapshot.release.id, snapshot.names.review, inputs.reviewBytes);
  await verifyUpload(client, reviewAsset, snapshot.names.review, inputs.reviewBytes);
  await requireControlUnchanged(client, snapshot);
  const beforeSwitch = await client.api(`/releases/${snapshot.release.id}/assets?per_page=100`);
  catalog(beforeSwitch);
  requireThat(inventory(beforeSwitch) === inventory([...snapshot.assets, candidate, reviewAsset])
    && digest(await client.asset(snapshot.current)) === inputs.previousSha256, 'ASSETS_CHANGED_BEFORE_SWITCH');
  // GitHub has no atomic asset swap. Preserve the old bytes by renaming, then
  // promote the verified candidate. Never delete, overwrite, or retry a failed swap.
  const archived = await client.api(`/releases/assets/${snapshot.current.id}`, 'PATCH', { name: snapshot.names.archive });
  requireThat(archived.id === snapshot.current.id && archived.name === snapshot.names.archive
    && archived.size === snapshot.current.size, 'ARCHIVE_RENAME_FAILED');
  const promoted = await client.api(`/releases/assets/${candidate.id}`, 'PATCH', { name: 'compatibility.json' });
  requireThat(promoted.id === candidate.id && promoted.name === 'compatibility.json' && promoted.size === bytes.length, 'CANDIDATE_RENAME_FAILED');
  const afterSwitch = await client.api(`/releases/${snapshot.release.id}/assets?per_page=100`);
  catalog(afterSwitch);
  const expected = snapshot.assets.map(item => item.id === archived.id ? { ...item, name: snapshot.names.archive } : item);
  requireThat(inventory(afterSwitch) === inventory([...expected, { ...candidate, name: 'compatibility.json' }, reviewAsset]), 'ASSETS_CHANGED_AFTER_SWITCH');
  requireThat(digest(await client.asset(promoted)) === digest(bytes)
    && digest(await client.asset(archived)) === inputs.previousSha256, 'FINAL_API_READBACK_MISMATCH');
  parseSigned(await client.asset(promoted), publicKey);
  let publicReadback = false;
  for (let attempt = 0; attempt < 12; attempt++) {
    try {
      const publicBytes = await client.publicAsset('compatibility.json');
      if (digest(publicBytes) === digest(bytes)) { parseSigned(publicBytes, publicKey); publicReadback = true; break; }
    } catch { /* CDN visibility can lag; only repeat anonymous reads. */ }
    if (attempt < 11) await (testOptions.delay ?? delay)(5000);
  }
  requireThat(publicReadback, 'FINAL_PUBLIC_READBACK_MISMATCH');
  await requireControlUnchanged(client, snapshot);
  return { ...receipt, status: 'PUBLISHED_SIGNATURE_AND_PUBLIC_READBACK_VERIFIED', signedSha256: digest(bytes),
    assetId: candidate.id, archivedAssetId: archived.id, reviewAssetId: reviewAsset.id };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await run(process.argv[2]), null, 2)); }
  catch (error) {
    const code = error instanceof Error && /^[A-Z0-9_]{1,80}$/.test(error.message) ? error.message : 'COMPATIBILITY_OPERATION_FAILED';
    console.error(code); process.exitCode = 1;
  }
}
