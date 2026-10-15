// Public/read-only preparation. Builtins only; no credential or executable input.
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';

export const EXPECTED = Object.freeze({
  repository: 'Rigby453/steam-float-scanner-releases', version: '1.0.1', releaseId: 414157889,
  sourceCommit: '8afd1b0c4c88f4cf1046647283ce63110fe3a1af',
  sourceZipSha256: '84c7131c7853ea4e7b6405b29f8caa92d62a6494631763920f09d686dc2bd3a8',
  sourceZip: 'steam-float-scanner-source-1.0.1.zip', installer: 'Steam-Float-Scanner-Setup-1.0.1.exe',
});
const base = `https://github.com/${EXPECTED.repository}/releases/download/v${EXPECTED.version}/`;
export const fail = code => { throw new Error(code); };
export const requireThat = (condition, code) => { if (!condition) fail(code); };
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function context(env = process.env) {
  requireThat(env.GITHUB_REPOSITORY === EXPECTED.repository && env.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && env.GITHUB_REF === 'refs/heads/main'
    && env.GITHUB_WORKFLOW_REF === `${EXPECTED.repository}/.github/workflows/public-updater-acceptance.yml@refs/heads/main`, 'UNTRUSTED_ACCEPTANCE_CONTEXT');
  for (const name of ['SFS_UPDATE_PRIVATE_KEY_PEM', 'SFS_UPDATE_KEY_PASSPHRASE', 'GITHUB_TOKEN', 'GH_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_TOKEN']) {
    requireThat(!env[name], 'CREDENTIAL_PRESENT_IN_PUBLIC_JOB');
  }
  requireThat(sha(env.SFS_NATIVE_PROOF_SHA256) && sha(env.SFS_EXPECTED_INSTALLER_SHA256), 'INVALID_NATIVE_PROOF_INPUT');
  requireThat(typeof env.SFS_EXPECTED_INSTALLER_BYTES === 'string' && /^[1-9]\d{0,9}$/.test(env.SFS_EXPECTED_INSTALLER_BYTES), 'INVALID_INSTALLER_SIZE_INPUT');
  const bytes = Number(env.SFS_EXPECTED_INSTALLER_BYTES);
  requireThat(Number.isSafeInteger(bytes) && bytes <= 512 * 1024 * 1024, 'INVALID_INSTALLER_SIZE_INPUT');
  const workspace = resolve(env.GITHUB_WORKSPACE ?? process.cwd());
  return { workspace, work: join(workspace, 'public-acceptance-work'), evidence: join(workspace, 'public-acceptance-evidence'),
    nativeProofSha256: env.SFS_NATIVE_PROOF_SHA256, installerSha256: env.SFS_EXPECTED_INSTALLER_SHA256, installerBytes: bytes };
}

export async function evidence(paths, name, value) {
  requireThat(/^[a-z0-9-]+\.json$/.test(name), 'INVALID_EVIDENCE_NAME');
  const text = JSON.stringify(value, null, 2) + '\n';
  requireThat(Buffer.byteLength(text) <= 64 * 1024, 'EVIDENCE_SIZE_LIMIT');
  await mkdir(paths.evidence, { recursive: true });
  await writeFile(join(paths.evidence, name), text, { flag: 'wx' });
}

export function safeError(error) {
  const message = error instanceof Error ? error.message : '';
  return /^[A-Z0-9_]{1,90}$/.test(message) ? message : 'PUBLIC_ACCEPTANCE_OPERATION_FAILED';
}

// Manually follow only public GitHub/CDN redirects. No auth, cookies or SFS access.
export async function fetchAsset(name, maximumBytes, onChunk) {
  requireThat([EXPECTED.sourceZip, 'build-verification.json'].includes(name), 'UNEXPECTED_PUBLIC_ASSET');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000).unref();
  let url = new URL(base + name);
  try {
    for (let redirects = 0; redirects <= 5; redirects++) {
      requireThat(url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.hash
        && (redirects === 0 ? url.href === base + name
          : ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(url.hostname)), 'UNTRUSTED_PUBLIC_ASSET_URL');
      const response = await fetch(url, { redirect: 'manual', credentials: 'omit', signal: controller.signal,
        headers: { Accept: 'application/octet-stream' } });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        void response.body?.cancel().catch(() => {});
        requireThat(location && redirects < 5, 'PUBLIC_ASSET_REDIRECT_FAILED');
        url = new URL(location, url); continue;
      }
      requireThat(response.status === 200 && response.body, 'PUBLIC_ASSET_NOT_PUBLISHED');
      const declared = response.headers.get('content-length');
      requireThat(declared === null || (/^\d+$/.test(declared) && Number(declared) <= maximumBytes), 'PUBLIC_ASSET_SIZE_LIMIT');
      let count = 0; const hash = createHash('sha256');
      for await (const chunk of response.body) {
        count += chunk.length; requireThat(count <= maximumBytes, 'PUBLIC_ASSET_SIZE_LIMIT'); hash.update(chunk);
        await onChunk(chunk);
      }
      requireThat(count > 0, 'PUBLIC_ASSET_EMPTY');
      return { bytes: count, sha256: hash.digest('hex') };
    }
    fail('PUBLIC_ASSET_REDIRECT_FAILED');
  } finally { clearTimeout(timer); controller.abort(); }
}

export async function readNativeProof(paths) {
  const chunks = [];
  const downloaded = await fetchAsset('build-verification.json', 2 * 1024 * 1024, chunk => { chunks.push(chunk); });
  requireThat(downloaded.sha256 === paths.nativeProofSha256, 'NATIVE_PROOF_SHA256_MISMATCH');
  let proof;
  try { proof = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { fail('NATIVE_PROOF_INVALID_JSON'); }
  requireThat(record(proof) && proof.status === 'PASS' && proof.version === EXPECTED.version
    && proof.baseCommit === EXPECTED.sourceCommit && proof.installerSha256 === paths.installerSha256, 'NATIVE_PROOF_IDENTITY_MISMATCH');
  requireThat(typeof proof.installer === 'string' && proof.installer.replaceAll('\\', '/').split('/').at(-1) === EXPECTED.installer, 'NATIVE_PROOF_INSTALLER_NAME_MISMATCH');
  return { sha256: downloaded.sha256, version: proof.version, baseCommit: proof.baseCommit,
    installerSha256: proof.installerSha256, status: proof.status };
}

export async function prepare() {
  const paths = context();
  await mkdir(paths.work, { recursive: false });
  const releaseResponse = await fetch(`https://api.github.com/repos/${EXPECTED.repository}/releases/tags/v${EXPECTED.version}`, {
    redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(30_000), headers: { Accept: 'application/vnd.github+json' } });
  requireThat(releaseResponse.status === 200, 'PUBLIC_RELEASE_NOT_PUBLISHED');
  let releaseBytes = 0; const releaseChunks = [];
  for await (const chunk of releaseResponse.body) {
    releaseBytes += chunk.length; requireThat(releaseBytes <= 256 * 1024, 'PUBLIC_RELEASE_METADATA_LIMIT'); releaseChunks.push(chunk);
  }
  const release = JSON.parse(Buffer.concat(releaseChunks).toString('utf8'));
  requireThat(release.id === EXPECTED.releaseId && release.tag_name === `v${EXPECTED.version}`
    && release.draft === false && release.prerelease === false && release.immutable === true, 'PUBLIC_RELEASE_NOT_IMMUTABLE_STABLE');
  const proof = await readNativeProof(paths); // Public file must exist after release publication.
  const partial = join(paths.work, 'source.zip.partial');
  const output = createWriteStream(partial, { flags: 'wx', mode: 0o600 });
  const hash = createHash('sha256'); let bytes = 0;
  // A tiny Transform adapts the backpressured downloader into one owned file.
  const relay = new Transform({ transform(chunk, _encoding, done) { hash.update(chunk); bytes += chunk.length; done(null, chunk); } });
  const finished = pipeline(relay, output);
  // Attach the failure observer immediately; never leave a rejected pipeline unhandled.
  const result = finished.then(() => ({ ok: true }), error => ({ ok: false, error }));
  let downloaded;
  try {
    downloaded = await fetchAsset(EXPECTED.sourceZip, 64 * 1024 * 1024, chunk => new Promise((resolve, reject) => {
      relay.write(chunk, error => error ? reject(error) : resolve());
    }));
    relay.end();
    const settled = await result;
    if (!settled.ok) throw settled.error;
  } catch (error) { relay.destroy(); output.destroy(); await result; throw error; }
  requireThat(downloaded.sha256 === EXPECTED.sourceZipSha256 && hash.digest('hex') === EXPECTED.sourceZipSha256
    && bytes === downloaded.bytes, 'SOURCE_ZIP_SHA256_MISMATCH');
  await rename(partial, join(paths.work, 'source.zip'));
  const report = { status: 'HASH_VERIFIED_BEFORE_EXTRACTION', version: EXPECTED.version, sourceCommit: EXPECTED.sourceCommit,
    publicRelease: { id: release.id, tag: release.tag_name, immutable: release.immutable },
    sourceZipSha256: downloaded.sha256, sourceZipBytes: downloaded.bytes, nativeProof: proof,
    expectedInstallerSha256: paths.installerSha256, expectedInstallerBytes: paths.installerBytes,
    anonymous: true, signingEnvironmentUsed: false, downloadedCodeExecuted: false };
  await evidence(paths, 'public-source-proof.json', report);
  console.log(JSON.stringify({ status: report.status, sourceZipSha256: report.sourceZipSha256, sourceZipBytes: report.sourceZipBytes }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { await prepare(); }
  catch (error) {
    const code = safeError(error); console.error(code);
    try { await evidence(context(), 'preparation-failure.json', { status: 'FAIL', code, installerExecuted: false }); } catch {}
    process.exitCode = 1;
  }
}
