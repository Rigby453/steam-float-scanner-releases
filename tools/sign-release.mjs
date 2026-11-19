// Trusted standalone release signer. Builtins only: never import source/artifact code.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

export const REPOSITORY = 'Rigby453/steam-float-scanner-releases';
export const SOURCE_REPOSITORY = 'parserst/steam-float-scanner';
export const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOJb8WpemdYBC80YZzT2rnNwJBMeLc3V1f4oVvwFpVT0=\n-----END PUBLIC KEY-----';
const API = `https://api.github.com/repos/${REPOSITORY}`;
const REQUEST_NAME = 'release-source.json';
const WINDOWS_QUALIFICATION_NAME = 'windows-qualification.json';
const PURCHASE_REVIEW_NAME = 'purchase-review.json';
const PURCHASE_POLICY_TAG = 'purchase-compatibility-v1';
const PURCHASE_POLICY_NAME = 'protocol.json';
const MAX_PURCHASE_POLICY = 64 * 1024;
const DAY_MS = 86_400_000;
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
  const keys = ['version', 'sourceRepository', 'sourceCommit', 'sourceSha256', 'releaseNotesSha256', 'assets'];
  const localWindows = request?.qualification === 'WINDOWS_LOCAL_V1';
  requireThat((localWindows ? exactKeys(request, [...keys, 'qualification'])
    : exactKeys(request, [...keys, 'ciRunId']) && typeof request.ciRunId === 'string'
      && /^[1-9][0-9]*$/.test(request.ciRunId))
    && request.sourceRepository === SOURCE_REPOSITORY
    && request.version === inputs.version && request.sourceCommit === inputs.sourceCommit
    && sha(request.sourceSha256) && sha(request.releaseNotesSha256)
    && Array.isArray(request.assets), 'REQUEST_IDENTITY_MISMATCH');
  const linuxDeb = request.assets.some(a => a?.name === `Steam-Float-Scanner-${inputs.version}-amd64.deb`);
  requireThat(!localWindows || !linuxDeb, 'LOCAL_QUALIFICATION_WINDOWS_ONLY');
  const names = [
    `Steam-Float-Scanner-Setup-${inputs.version}.exe`,
    `Steam-Float-Scanner-Setup-${inputs.version}.exe.blockmap`,
    'build-verification.json', 'latest.yml',
    ...(linuxDeb ? [`Steam-Float-Scanner-${inputs.version}-amd64.deb`, 'linux-build-verification.json', 'latest-linux.yml'] : []),
  ];
  if (localWindows) names.push(WINDOWS_QUALIFICATION_NAME);
  if (request.assets.some(asset => asset?.name === PURCHASE_REVIEW_NAME)) names.push(PURCHASE_REVIEW_NAME);
  requireThat(Array.isArray(request.assets) && request.assets.length === names.length, 'INVALID_ASSET_COUNT');
  const seen = new Set();
  for (const asset of request.assets) {
    requireThat(exactKeys(asset, ['name', 'sha256', 'bytes']) && names.includes(asset.name) && !seen.has(asset.name), 'INVALID_ASSET_NAME');
    requireThat(sha(asset.sha256) && Number.isSafeInteger(asset.bytes) && asset.bytes > 0 && asset.bytes <= 512 * 1024 * 1024, 'INVALID_ASSET_DIGEST');
    if (asset.name.endsWith('.json') || asset.name.endsWith('.yml')) requireThat(asset.bytes <= MAX_JSON, 'METADATA_TOO_LARGE');
    if (asset.name === PURCHASE_REVIEW_NAME) requireThat(asset.bytes <= MAX_PURCHASE_POLICY, 'PURCHASE_REVIEW_TOO_LARGE');
    seen.add(asset.name);
  }
  requireThat(names.every(name => seen.has(name)), 'MISSING_ASSET');
  return { ...request, linuxDeb };
}

export function validateWindowsQualification(proof, request, installer) {
  requireThat(exactKeys(proof, ['format', 'version', 'sourceCommit', 'sourceSha256', 'installerSha256', 'checks'])
    && proof.format === 'SFS_WINDOWS_QUALIFICATION_V1'
    && proof.version === request.version && proof.sourceCommit === request.sourceCommit
    && proof.sourceSha256 === request.sourceSha256 && proof.installerSha256 === installer.sha256,
  'WINDOWS_QUALIFICATION_IDENTITY_MISMATCH');
  const checks = ['typecheck', 'root', 'engine', 'desktop', 'nativePackage', 'packagedFinancial'];
  requireThat(exactKeys(proof.checks, checks) && checks.every(check => proof.checks[check] === 'PASS'),
    'WINDOWS_QUALIFICATION_INCOMPLETE');
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

function signWithReleaseKey(bytes, encryptedPem, passphrase, publicKey) {
  requireThat(typeof encryptedPem === 'string' && encryptedPem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    && typeof passphrase === 'string' && passphrase.length >= 32, 'SIGNING_SECRET_UNAVAILABLE');
  let privateKey;
  try { privateKey = createPrivateKey({ key: encryptedPem, format: 'pem', passphrase }); }
  catch { fail('SIGNING_KEY_DECRYPTION_FAILED'); }
  requireThat(privateKey.asymmetricKeyType === 'ed25519', 'WRONG_KEY_TYPE');
  const expected = createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  const actual = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  requireThat(expected.equals(actual), 'WRONG_SIGNING_KEY');
  const signature = sign(null, bytes, privateKey).toString('base64');
  requireThat(verify(null, bytes, publicKey, Buffer.from(signature, 'base64')), 'SIGNATURE_SELF_CHECK_FAILED');
  return signature;
}

export function createManifest(unsigned, encryptedPem, passphrase, publicKey = PUBLIC_KEY) {
  return { ...unsigned, signature: signWithReleaseKey(signedPayload(unsigned), encryptedPem, passphrase, publicKey) };
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


// Verify original-key AUTO_BUY admission before publishing a new installer.
// No artifact source is imported, no private key is needed, and no Steam request is made.
export const PURCHASE_PROTOCOL_SHA256 = '8df06ca0e4ace35169275cc290acd114db2bb6ef3a0f9cbda00efc6cf0069b53';
function isoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0,19) === value.slice(0,19);
}
function packagedPurchaseIdentity(proof) {
  const identity = proof?.purchaseImplementation;
  requireThat(exactKeys(identity, ['kind','implementationSha256','canonicalBundleSha256','platform','architecture']) && identity.kind === 'SFS_PACKAGED_PURCHASE_V1'
    && sha(identity.implementationSha256) && sha(identity.canonicalBundleSha256)
    && ['win32', 'linux'].includes(identity.platform) && ['x64', 'arm64'].includes(identity.architecture),
    'PACKAGED_PURCHASE_IDENTITY_MISSING');
  return identity;
}

function purchasePolicyBytes(payload) {
  return Buffer.from(JSON.stringify({ kind: payload.kind, schemaVersion: payload.schemaVersion, revision: payload.revision,
    publishedAt: payload.publishedAt, expiresAt: payload.expiresAt, implementations: payload.implementations.map(row => ({
      clientVersion: row.clientVersion, implementationSha256: row.implementationSha256, protocolSha256: row.protocolSha256,
      platform: row.platform, architecture: row.architecture, sourceEvidenceSha256: row.sourceEvidenceSha256,
      authenticatedAcceptanceSha256: row.authenticatedAcceptanceSha256, acceptance: row.acceptance,
    })) }));
}

function parseSignedPurchasePolicy(policyBytes, publicKey) {
  requireThat(Buffer.isBuffer(policyBytes) && policyBytes.length <= MAX_PURCHASE_POLICY, 'PURCHASE_POLICY_TOO_LARGE');
  let signed;
  try { signed = JSON.parse(policyBytes.toString('utf8')); } catch { fail('INVALID_PURCHASE_POLICY'); }
  const p = signed?.payload;
  requireThat(exactKeys(signed, ['payload', 'signature'])
    && exactKeys(p, ['kind', 'schemaVersion', 'revision', 'publishedAt', 'expiresAt', 'implementations'])
    && p.kind === 'steam-float-scanner-purchase-protocol' && p.schemaVersion === 1
    && Number.isSafeInteger(p.revision) && p.revision > 0
    && isoDate(p.publishedAt) && isoDate(p.expiresAt)
    && Array.isArray(p.implementations) && p.implementations.length >= 1 && p.implementations.length <= 32,
    'INVALID_PURCHASE_POLICY');
  const lifetime = Date.parse(p.expiresAt) - Date.parse(p.publishedAt);
  requireThat(lifetime > 0 && lifetime <= 90 * DAY_MS, 'INVALID_PURCHASE_POLICY');
  const seen = new Set();
  for (const row of p.implementations) {
    requireThat(exactKeys(row, ['clientVersion', 'implementationSha256', 'protocolSha256', 'platform', 'architecture',
      'sourceEvidenceSha256', 'authenticatedAcceptanceSha256', 'acceptance'])
      && typeof row.clientVersion === 'string' && /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(row.clientVersion)
      && [row.implementationSha256,row.protocolSha256,row.sourceEvidenceSha256,row.authenticatedAcceptanceSha256].every(sha)
      && ['win32','linux'].includes(row.platform) && ['x64','arm64'].includes(row.architecture)
      && row.protocolSha256 === PURCHASE_PROTOCOL_SHA256
      && row.acceptance === 'AUTHENTICATED_EXACT_PURCHASE_VERIFIED', 'INVALID_PURCHASE_POLICY');
    const key = [row.clientVersion,row.platform,row.architecture,row.implementationSha256].join(':');
    requireThat(!seen.has(key), 'INVALID_PURCHASE_POLICY'); seen.add(key);
  }
  requireThat(typeof signed.signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signed.signature)
    && Buffer.from(signed.signature,'base64').toString('base64') === signed.signature
    && verify(null, purchasePolicyBytes(p), publicKey, Buffer.from(signed.signature,'base64')), 'INVALID_PURCHASE_POLICY_SIGNATURE');
  return p;
}

function matchingAdmissions(policy, identity) {
  return policy.implementations.filter(row => row.implementationSha256 === identity.implementationSha256
    && row.platform === identity.platform && row.architecture === identity.architecture);
}

function requirePurchaseAdmission(identity, p, policySha256, now) {
  const end = Date.parse(p.expiresAt);
  requireThat(Number.isFinite(now) && Date.parse(p.publishedAt) <= now + 300_000 && end > now, 'PURCHASE_POLICY_EXPIRED');
  const admitted = matchingAdmissions(p, identity);
  requireThat(admitted.length === 1, 'PACKAGED_PURCHASE_NOT_ADMITTED');
  requireThat(end - now >= DAY_MS, 'PURCHASE_POLICY_RENEWAL_REQUIRED');
  return { implementationSha256:identity.implementationSha256, policyRevision:p.revision,
    policyExpiresAt:p.expiresAt, policySha256, reviewedClientVersion:admitted[0].clientVersion };
}

export function validatePurchaseAdmission(proof, policyBytes, now = Date.now(), publicKey = PUBLIC_KEY) {
  const identity = packagedPurchaseIdentity(proof);
  const policy = parseSignedPurchasePolicy(policyBytes, publicKey);
  return requirePurchaseAdmission(identity, policy, digest(policyBytes), now);
}

function validatePurchaseReview(review, request, targets, identities) {
  requireThat(exactKeys(review, ['kind', 'version', 'sourceCommit', 'sourceSha256', 'previousPolicySha256', 'targets'])
    && review.kind === 'SFS_RELEASE_PURCHASE_REVIEW_V1' && review.version === request.version
    && /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(review.version) && review.sourceCommit === request.sourceCommit
    && review.sourceSha256 === request.sourceSha256 && sha(review.previousPolicySha256)
    && Array.isArray(review.targets) && review.targets.length === targets.length, 'PURCHASE_REVIEW_IDENTITY_MISMATCH');
  for (const [index, target] of targets.entries()) {
    const identity = identities[index];
    const item = review.targets[index];
    requireThat(exactKeys(item, ['platform', 'architecture', 'implementationSha256', 'canonicalBundleSha256',
      'installerSha256', 'sourceEvidenceSha256', 'authenticatedAcceptanceSha256', 'acceptance'])
      && item.platform === identity.platform && item.architecture === identity.architecture
      && item.implementationSha256 === identity.implementationSha256 && item.canonicalBundleSha256 === identity.canonicalBundleSha256
      && item.installerSha256 === target.installerSha256 && sha(item.sourceEvidenceSha256) && sha(item.authenticatedAcceptanceSha256)
      && item.acceptance === 'AUTHENTICATED_EXACT_PURCHASE_VERIFIED', 'PURCHASE_REVIEW_TARGET_MISMATCH');
  }
}

export function planPurchaseAdmission(targets, request, review, previousBytes, now = Date.now(), publicKey = PUBLIC_KEY) {
  const previous = parseSignedPurchasePolicy(previousBytes, publicKey), previousSha256 = digest(previousBytes);
  requireThat(Number.isFinite(now) && Date.parse(previous.publishedAt) <= now, 'PURCHASE_POLICY_CLOCK_MISMATCH');
  const identities = targets.map(({ proof, platform }) => {
    const identity = packagedPurchaseIdentity(proof);
    requireThat(identity.platform === platform && identity.architecture === 'x64', 'PURCHASE_PACKAGE_TARGET_MISMATCH');
    return identity;
  });
  if (review !== undefined) validatePurchaseReview(review, request, targets, identities);
  try {
    return { reuse: identities.map(identity => requirePurchaseAdmission(identity, previous, previousSha256, now)) };
  } catch (error) {
    if (review === undefined) throw error;
  }
  requireThat(review.previousPolicySha256 === previousSha256, 'PURCHASE_REVIEW_IDENTITY_MISMATCH');

  const implementations = [...previous.implementations];
  for (const [index, item] of review.targets.entries()) {
    const identity = identities[index];
    const matches = matchingAdmissions(previous, identity);
    requireThat(matches.length <= 1, 'PURCHASE_ADMISSION_AMBIGUOUS');
    if (matches.length === 0) {
      requireThat(!previous.implementations.some(row => row.authenticatedAcceptanceSha256 === item.authenticatedAcceptanceSha256),
        'PURCHASE_REVIEW_HISTORICAL');
      implementations.push({ clientVersion: request.version, implementationSha256: identity.implementationSha256,
        protocolSha256: PURCHASE_PROTOCOL_SHA256, platform: identity.platform, architecture: identity.architecture,
        sourceEvidenceSha256: item.sourceEvidenceSha256, authenticatedAcceptanceSha256: item.authenticatedAcceptanceSha256,
        acceptance: item.acceptance });
    }
  }
  const revision = previous.revision + 1;
  requireThat(Number.isSafeInteger(revision) && implementations.length <= 32, 'PURCHASE_POLICY_CAPACITY_EXCEEDED');
  return { previousSha256, payload: { ...previous, revision, publishedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 30 * DAY_MS).toISOString(), implementations } };
}

export function signPlannedPurchasePolicy(plan, encryptedPem, passphrase, publicKey = PUBLIC_KEY) {
  const signature = signWithReleaseKey(purchasePolicyBytes(plan.payload), encryptedPem, passphrase, publicKey);
  const bytes = Buffer.from(JSON.stringify({ payload: plan.payload, signature }, null, 2) + '\n');
  parseSignedPurchasePolicy(bytes, publicKey);
  return bytes;
}

async function inspectPurchaseAdmission(client, targets, request, review) {
  const release = await client.api(`/releases/tags/${PURCHASE_POLICY_TAG}`);
  const assets = catalog(await releaseAssets(client, release.id));
  const policy = assets.get(PURCHASE_POLICY_NAME);
  requireThat(policy && policy.size <= MAX_PURCHASE_POLICY, 'PURCHASE_POLICY_NOT_PUBLISHED');
  const downloaded = await client.download(policy.id, policy.size, true);
  const plan = planPurchaseAdmission(targets, request, review, downloaded.body);
  if (plan.reuse) return { plan };
  const archiveName = `protocol-before-${plan.payload.revision}.json`;
  const pendingName = `protocol-${plan.payload.revision}.pending.json`;
  requireThat(release.tag_name === PURCHASE_POLICY_TAG && release.draft === false && release.prerelease === true
    && release.immutable === false && !assets.has(archiveName) && !assets.has(pendingName), 'PURCHASE_POLICY_ASSETS_NOT_READY');
  return { plan, releaseId: String(release.id), policy, archiveName, pendingName };
}

async function publicPurchasePolicyHash(fetcher) {
  const url = `https://github.com/${REPOSITORY}/releases/download/${PURCHASE_POLICY_TAG}/${PURCHASE_POLICY_NAME}`;
  let response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(30_000) });
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = response.headers.get('location');
    await response.body?.cancel();
    const redirect = location ? new URL(location, url) : null;
    requireThat(redirect?.protocol === 'https:' && !redirect.username && !redirect.password && !redirect.port
      && ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(redirect.hostname),
      'UNEXPECTED_PUBLIC_REDIRECT');
    response = await fetcher(redirect, { redirect: 'error', signal: AbortSignal.timeout(30_000) });
  }
  requireThat(response.ok, 'PUBLIC_PURCHASE_POLICY_UNAVAILABLE');
  return digest(await boundedBytes(response, MAX_PURCHASE_POLICY));
}

export async function activatePurchasePolicy(client, change, bytes, fetcher = fetch, pause = delay) {
  const { plan, releaseId, policy, archiveName, pendingName } = change;
  const assetPath = id => `/releases/assets/${id}`;
  const list = async () => catalog(await releaseAssets(client, releaseId));
  const confirm = (asset, id, name, size) => asset?.id === id && asset.name === name && asset.size === size;
  const nextSha256 = digest(bytes);
  requireThat(await publicPurchasePolicyHash(fetcher) === plan.previousSha256, 'PUBLIC_PURCHASE_POLICY_CHANGED');
  const candidate = await client.upload(releaseId, pendingName, bytes);
  requireThat(candidate.state === 'uploaded' && candidate.name === pendingName && candidate.size === bytes.length
    && (await client.download(candidate.id, bytes.length)).sha256 === nextSha256, 'PURCHASE_POLICY_STAGE_MISMATCH');

  const beforeSwitch = await list();
  requireThat(confirm(beforeSwitch.get(PURCHASE_POLICY_NAME), policy.id, PURCHASE_POLICY_NAME, policy.size)
    && confirm(beforeSwitch.get(pendingName), candidate.id, pendingName, bytes.length)
    && !beforeSwitch.has(archiveName) && (await client.download(policy.id, policy.size)).sha256 === plan.previousSha256,
    'PURCHASE_POLICY_CHANGED_BEFORE_SWITCH');

  try {
    const archived = await client.api(assetPath(policy.id), 'PATCH', { name: archiveName });
    requireThat(confirm(archived, policy.id, archiveName, policy.size), 'PURCHASE_POLICY_ARCHIVE_FAILED');
    const active = await client.api(assetPath(candidate.id), 'PATCH', { name: PURCHASE_POLICY_NAME });
    requireThat(confirm(active, candidate.id, PURCHASE_POLICY_NAME, bytes.length), 'PURCHASE_POLICY_PROMOTION_FAILED');
  } catch (switchError) {
    // A timeout may hide a committed rename. Only restore when the old bytes
    // remain archived under our name and the live filename is actually empty.
    const current = await list();
    if (!current.has(PURCHASE_POLICY_NAME) && confirm(current.get(archiveName), policy.id, archiveName, policy.size)) {
      const restored = await client.api(assetPath(policy.id), 'PATCH', { name: PURCHASE_POLICY_NAME });
      requireThat(confirm(restored, policy.id, PURCHASE_POLICY_NAME, policy.size), 'PURCHASE_POLICY_RESTORE_FAILED');
    }
    throw switchError;
  }

  const activated = await list();
  requireThat(confirm(activated.get(PURCHASE_POLICY_NAME), candidate.id, PURCHASE_POLICY_NAME, bytes.length)
    && confirm(activated.get(archiveName), policy.id, archiveName, policy.size)
    && (await client.download(candidate.id, bytes.length)).sha256 === nextSha256
    && (await client.download(policy.id, policy.size)).sha256 === plan.previousSha256, 'PURCHASE_POLICY_FINAL_READBACK_FAILED');

  for (let attempt = 0; attempt < 12; attempt++) {
    try { if (await publicPurchasePolicyHash(fetcher) === nextSha256) return; }
    catch { /* CDN may still serve the previous release URL. Only retry reads. */ }
    if (attempt < 11) await pause(5_000);
  }
  fail('PUBLIC_PURCHASE_POLICY_READBACK_MISMATCH');
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
  const windowsProof = parseJson(actual.get('build-verification.json').body);
  validateProof(windowsProof, request, windows);
  if (request.qualification === 'WINDOWS_LOCAL_V1') {
    validateWindowsQualification(parseJson(actual.get(WINDOWS_QUALIFICATION_NAME).body), request, windows);
  }
  const linuxProof = request.linuxDeb ? parseJson(actual.get('linux-build-verification.json').body) : null;
  if (linuxProof) validateProof(linuxProof, request, request.assets.find(a => a.name.endsWith('.deb')), true);
  const notes = typeof release.body === 'string' ? release.body.trim() : '';
  requireThat(notes.length > 0 && notes.length <= 100_000, 'INVALID_RELEASE_NOTES');
  requireThat(digest(Buffer.from(notes)) === request.releaseNotesSha256, 'RELEASE_NOTES_HASH_MISMATCH');
  validateFeed(actual.get('latest.yml').body, request.version, windows.name, actual.get(windows.name));
  if (request.linuxDeb) {
    const linux = request.assets.find(a => a.name.endsWith('.deb'));
    validateFeed(actual.get('latest-linux.yml').body, request.version, linux.name, actual.get(linux.name));
  }
  const purchaseTargets = [{ proof: windowsProof, platform: 'win32', installerSha256: windows.sha256 }];
  if (linuxProof) purchaseTargets.push({ proof: linuxProof, platform: 'linux',
    installerSha256: request.assets.find(asset => asset.name.endsWith('.deb')).sha256 });
  const reviewBytes = actual.get(PURCHASE_REVIEW_NAME)?.body;
  const purchaseAdmission = await inspectPurchaseAdmission(client, purchaseTargets, request,
    reviewBytes === undefined ? undefined : parseJson(reviewBytes));
  return { release, assets, request, actual, notes, purchaseAdmission, purchaseTargets };
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
  const purchasePlan = result.purchaseAdmission.plan;
  if (mode === 'verify') return { status: 'VERIFIED_DRAFT', ...inputs, assets: result.request.assets.length,
    purchasePolicy: purchasePlan.reuse ? 'REUSE' : 'SIGN_REVIEWED_UPDATE' };
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
  const signedPolicy = purchasePlan.reuse ? null
    : signPlannedPurchasePolicy(purchasePlan, env.SFS_UPDATE_PRIVATE_KEY_PEM, env.SFS_UPDATE_KEY_PASSPHRASE);
  if (signedPolicy) {
    for (const target of result.purchaseTargets) validatePurchaseAdmission(target.proof, signedPolicy);
  }
  // Drop process-environment copies before any API mutation. Private material never goes to disk.
  delete env.SFS_UPDATE_PRIVATE_KEY_PEM; delete env.SFS_UPDATE_KEY_PASSPHRASE;
  if (signedPolicy) await activatePurchasePolicy(client, result.purchaseAdmission, signedPolicy, fetcher);
  for (const [name, bytes] of generated) {
    const uploaded = await client.upload(inputs.releaseId, name, bytes);
    const readBack = await client.download(uploaded.id, bytes.length);
    requireThat(readBack.sha256 === digest(bytes), 'SIGNED_ASSET_READBACK_MISMATCH');
  }
  const checked = await inspect(client, inputs, [...generated.keys()]);
  requireThat(checked.purchaseAdmission.plan.reuse, 'PUBLIC_PURCHASE_POLICY_NOT_READY');
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
  await inspectPurchaseAdmission(client, checked.purchaseTargets, checked.request);
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
