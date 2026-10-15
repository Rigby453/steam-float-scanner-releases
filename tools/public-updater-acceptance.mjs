// Real public source-client acceptance. No mocks, installer execution or owner data.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { EXPECTED, context, evidence, requireThat, safeError } from './public-updater-source.mjs';

const originalAnchor = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOJb8WpemdYBC80YZzT2rnNwJBMeLc3V1f4oVvwFpVT0=\n-----END PUBLIC KEY-----';
const expectedUrl = `https://github.com/${EXPECTED.repository}/releases/download/v${EXPECTED.version}/${EXPECTED.installer}`;

async function run() {
  const paths = context(); const started = performance.now();
  const controller = new AbortController();
  const budget = setTimeout(() => controller.abort(), 8 * 60_000).unref();
  const requests = { github: 0, cdn: 0 };
  let privateFallbackCalls = 0, stage = 'LOAD_PINNED_SOURCE';
  const report = { schemaVersion: 1, kind: 'steam-float-scanner-public-updater-acceptance',
    status: 'RUNNING', sourceClientVersion: EXPECTED.version, sourceCommit: EXPECTED.sourceCommit,
    sourceZipSha256: EXPECTED.sourceZipSha256, nativeCiRunId: '38789078465',
    comparatorNotice: 'Runs source client1.0.1 with supplied currentVersion parameters; does not run installed159 or152 binaries.',
    installationProven: false, electronGuiProven: false, laptopThroughputProven: false,
    installerExecuted: false, ownerProfileUsed: false, signingEnvironmentUsed: false, anonymous: true,
    runtime: { node: process.version, platform: process.platform, architecture: process.arch }, checks: [] };
  try {
    const prepared = JSON.parse(await readFile(join(paths.evidence, 'public-source-proof.json'), 'utf8'));
    requireThat(prepared.status === 'HASH_VERIFIED_BEFORE_EXTRACTION' && prepared.sourceZipSha256 === EXPECTED.sourceZipSha256
      && prepared.sourceCommit === EXPECTED.sourceCommit && prepared.nativeProof?.sha256 === paths.nativeProofSha256
      && prepared.expectedInstallerSha256 === paths.installerSha256 && prepared.expectedInstallerBytes === paths.installerBytes, 'PINNED_PREPARATION_MISMATCH');
    const sourceRoot = join(paths.work, 'source');
    const pkg = JSON.parse(await readFile(join(sourceRoot, 'package.json'), 'utf8'));
    requireThat(pkg.version === EXPECTED.version, 'SOURCE_CLIENT_VERSION_MISMATCH');
    const channel = await import(pathToFileURL(join(sourceRoot, 'apps/desktop/main/updates/release-channel.ts')).href);
    const transportModule = await import(pathToFileURL(join(sourceRoot, 'apps/desktop/main/updates/release-transport.ts')).href);
    requireThat(channel.OFFICIAL_UPDATE_PUBLIC_KEY.replaceAll('\r\n', '\n') === originalAnchor, 'SOURCE_TRUST_ANCHOR_CHANGED');
    const publicFetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const headers = new Headers(init?.headers);
      requireThat(['Authorization', 'apikey', 'Cookie'].every(name => !headers.has(name)), 'CREDENTIAL_HEADER_DETECTED');
      requireThat(url.protocol === 'https:' && !url.username && !url.password && !url.port
        && ['github.com', 'release-assets.githubusercontent.com'].includes(url.hostname)
        && init?.credentials === 'omit' && init?.redirect === 'manual', 'PRODUCTION_PUBLIC_TRANSPORT_POLICY_CHANGED');
      requests[url.hostname === 'github.com' ? 'github' : 'cdn']++;
      // This is a real fetch, with only an outer CI safety deadline added.
      return fetch(input, { ...init, signal: AbortSignal.any([controller.signal, ...(init?.signal ? [init.signal] : [])]) });
    };
    const transport = transportModule.createReleaseTransport({ publicFetch, protectedFetch: async () => {
      privateFallbackCalls++;
      throw Object.assign(new Error('OWNER_ACCESS_FORBIDDEN'), { code: 'OWNER_ACCESS_FORBIDDEN' });
    } });
    const service = currentVersion => channel.createProductionUpdateService({ currentVersion, platform: 'win32', arch: 'x64',
      downloadDirectory: join(paths.work, 'downloads'), fetch: transport });
    const clients = new Map(); let available;
    for (const currentVersion of ['0.2.159', '0.2.152', EXPECTED.version]) {
      stage = `CHECK_${currentVersion.replaceAll('.', '_')}`;
      const client = service(currentVersion); clients.set(currentVersion, client);
      const checked = await client.check();
      const expected = currentVersion === EXPECTED.version ? 'UP_TO_DATE' : 'AVAILABLE';
      requireThat(checked.type === expected, 'PUBLIC_VERSION_ORDERING_MISMATCH');
      if (checked.type === 'AVAILABLE') {
        requireThat(checked.manifest.version === EXPECTED.version && checked.manifest.url === expectedUrl
          && checked.manifest.sha256 === paths.installerSha256, 'SIGNED_MANIFEST_NATIVE_PROOF_MISMATCH');
        if (available) requireThat(available.signature === checked.manifest.signature, 'SIGNED_LATEST_CHANGED_DURING_CHECKS');
        available = checked.manifest;
      }
      report.checks.push({ currentVersionParameter: currentVersion, sourceClientVersion: EXPECTED.version,
        expected, actual: checked.type, offeredVersion: checked.type === 'AVAILABLE' ? checked.manifest.version : null });
    }
    requireThat(available, 'PUBLIC_UPDATE_NOT_AVAILABLE');
    stage = 'DOWNLOAD_COMPLETE_SIGNED_INSTALLER';
    let observedBytes = 0; const downloadStarted = performance.now();
    const downloadingClient = clients.get('0.2.159');
    const downloaded = await downloadingClient.download(available, transferred => { observedBytes = transferred; });
    const info = await stat(downloaded);
    requireThat(info.isFile() && info.size === paths.installerBytes && basename(downloaded) === EXPECTED.installer, 'DOWNLOADED_INSTALLER_SIZE_OR_NAME_MISMATCH');
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(downloaded)) hash.update(chunk);
    const actualHash = hash.digest('hex');
    requireThat(actualHash === paths.installerSha256 && actualHash === available.sha256, 'DOWNLOADED_INSTALLER_SHA256_MISMATCH');
    stage = 'REPEAT_PRODUCTION_FILE_VERIFICATION';
    await downloadingClient.verifyDownloadedFile(available, EXPECTED.version, EXPECTED.installer, downloaded);
    stage = 'FINAL_UP_TO_DATE_CHECK';
    requireThat((await clients.get(EXPECTED.version).check()).type === 'UP_TO_DATE', 'FINAL_PUBLIC_CHECK_MISMATCH');
    requireThat(privateFallbackCalls === 0, 'PRIVATE_FALLBACK_ATTEMPTED');
    report.status = 'PASS'; report.nativeProofSha256 = paths.nativeProofSha256;
    report.manifest = { version: available.version, url: available.url, sha256: available.sha256, signatureVerifiedByProduction: true };
    report.download = { sha256: actualHash, bytes: info.size, expectedBytes: paths.installerBytes,
      durationMs: Math.round(performance.now() - downloadStarted), observedProgressBytes: observedBytes,
      independentFullFileHashMatched: true, repeatProductionVerification: true, executed: false };
    report.publicRequests = requests; report.privateFallbackCalls = privateFallbackCalls;
  } catch (error) {
    report.status = controller.signal.aborted ? 'UNKNOWN' : 'FAIL';
    const code = typeof error?.code === 'string' && /^[A-Z0-9_]{1,90}$/.test(error.code) ? error.code : safeError(error);
    report.failure = { stage, code: controller.signal.aborted ? 'PUBLIC_ACCEPTANCE_BUDGET_EXCEEDED' : code };
    report.publicRequests = requests; report.privateFallbackCalls = privateFallbackCalls;
    process.exitCode = 1;
  } finally {
    clearTimeout(budget); controller.abort();
    report.elapsedMs = Math.round(performance.now() - started); report.checkedAt = new Date().toISOString();
    await evidence(paths, 'public-updater-acceptance.json', report);
    console.log(JSON.stringify({ status: report.status, sourceClientVersion: report.sourceClientVersion,
      checks: report.checks, download: report.download, failure: report.failure, elapsedMs: report.elapsedMs }));
  }
}

try { await run(); }
catch (error) { console.error(safeError(error)); process.exitCode = 1; }
