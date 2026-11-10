// One reviewed recovery of already-built immutable bytes; no signing key or build.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { constants, copyFileSync, createReadStream, readFileSync, writeFileSync, mkdirSync, readdirSync, lstatSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateContext, validateReleaseRequest, validateFinancialAcceptance, makeBundle, validateBundle, safePath } from './release-request.mjs';

export const PIN = Object.freeze({
  schemaVersion: 1, version: '1.2.14', originalRunId: 42822864217, artifactId: 13770162339,
  artifactName: 'scanner-retained-candidate-42822864217', artifactBytes: 118380570,
  artifactSha256: '7e51064d6f4b6f3a3c4de9aa064abf9cf0e3b706ac787cdb44b9f8a49d8b2ef6',
  originalWorkflowCommit: 'a279dba011634de2bf766b79dff75844dd1c52c3',
  sourceCommit: '8a4f5aa92c14b3947be36f46ab0b09d9adc13a96', sourceTree: 'ff9d674e003fc28f173281308fb4bfbd48cb1fd3',
  sourceSha256: '251f3932bfb90ad18b2b4e35415c3cc276e4a46c2aec978da500a6a9eae71d4e',
  requestSha256: '03da1283682cb43a37511b6e8565bc64a6b0f4c5a73e8117c6941df414569dce',
  installerSha256: 'ed39558d696325dfe6b0f33f665e18f3694a68d36d4b52c6cfb10a675b7cc6f4',
});
export const RETAINED = Object.freeze({
  'Steam-Float-Scanner-Setup-1.2.14.exe': [118230642, PIN.installerSha256],
  'Steam-Float-Scanner-Setup-1.2.14.exe.blockmap': [125431, '2b475a185531d2f172d2f5a0ca91b5451bee725ed3ef48c4cc6696b873c7bfb9'],
  'latest.yml': [370, '3a6dc495e8e2e7f1d9cfab8b035678e04793f2fa9a5814d4721f2f847dfa32cc'],
  'build-verification.json': [29311, '52de425d7ce954b0f5fdae98c9f003030acad5a6f593eb1c0076db0ffcf52b65'],
  'purchase-readiness.json': [705, '288019925be6d63a2db7dd538d3d565401ad70d0354cfec046e36956a59b15f4'],
});
const REPO = 'Rigby453/steam-float-scanner-releases';
const failUnless = (value, code) => { if (!value) throw Error(code); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const parse = file => JSON.parse(readFileSync(file, 'utf8'));
export function validateContinuation(value) {
  failUnless(value && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(Object.keys(PIN).sort())
    && Object.entries(PIN).every(([key, expected]) => value[key] === expected), 'CONTINUATION_IDENTITY_MISMATCH');
  return value;
}
function trustedRequest(checkout) {
  validateContinuation(parse(join(checkout, 'release-continuations/1.2.14.json')));
  const bytes = readFileSync(join(checkout, 'release-requests/1.2.14.json'));
  failUnless(sha(bytes) === PIN.requestSha256, 'ORIGINAL_REQUEST_CHANGED');
  const request = validateReleaseRequest(JSON.parse(bytes));
  failUnless(request.sourceCommit === PIN.sourceCommit && request.sourceTree === PIN.sourceTree
    && request.sourceSha256 === PIN.sourceSha256 && request.omittedPaths.length === 0, 'FROZEN_SOURCE_CHANGED');
  return request;
}
export function validateArtifact(value) {
  failUnless(value?.id === PIN.artifactId && value.name === PIN.artifactName && value.size_in_bytes === PIN.artifactBytes
    && value.expired === false && value.digest === `sha256:${PIN.artifactSha256}`
    && value.workflow_run?.id === PIN.originalRunId && value.workflow_run.head_sha === PIN.originalWorkflowCommit,
  'ORIGINAL_ARTIFACT_IDENTITY_MISMATCH');
}
export function validateOriginalRun(run, jobs) {
  failUnless(run?.id === PIN.originalRunId && run.head_sha === PIN.originalWorkflowCommit && run.event === 'push'
    && run.head_branch === 'main' && run.status === 'completed' && run.conclusion === 'failure'
    && run.path === '.github/workflows/build-release-request.yml' && run.repository?.full_name === REPO,
  'ORIGINAL_RUN_IDENTITY_MISMATCH');
  failUnless(Array.isArray(jobs?.jobs) && jobs.jobs.length === 2, 'ORIGINAL_JOB_SET_MISMATCH');
  const job = jobs.jobs.find(job => job.name === 'windows');
  failUnless(job?.conclusion === 'failure' && jobs.jobs.find(job => job.name === 'stage')?.conclusion === 'skipped'
    && job.steps?.filter(step => step.conclusion === 'failure').length === 1
    && job.steps.find(step => step.conclusion === 'failure').name === 'Create only the sanitized exact release bundle',
  'ORIGINAL_FAILURE_SCOPE_MISMATCH');
  for (const name of ['Full strict check and source build', 'Root source suite', 'Engine source suite', 'Desktop source suite',
    'Financial artifact and native provenance regressions', 'Build and fully verify the single native Windows installer',
    'Require current original-key financial admission before staging', 'Retain exact candidate files for review after a failed qualification']) {
    failUnless(job.steps.some(step => step.name === name && step.conclusion === 'success'), 'ORIGINAL_REQUIRED_STEP_NOT_PASS');
  }
  // The old GUI invocation's success is deliberately NOT treated as financial evidence.
}
async function api(path, token) {
  const response = await fetch(`https://api.github.com/repos/${REPO}${path}`, { redirect: 'manual',
    signal: AbortSignal.timeout(30000), headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } });
  failUnless(response.status === 200, 'RECOVERY_API_FAILED');
  const bytes = Buffer.from(await response.arrayBuffer()); failUnless(bytes.length <= 2 * 1024 * 1024, 'RECOVERY_METADATA_TOO_LARGE');
  return JSON.parse(bytes);
}
async function download(checkout, output) {
  trustedRequest(checkout); failUnless(!existsSync(output), 'RECOVERY_ARCHIVE_EXISTS');
  const token = process.env.GITHUB_TOKEN; failUnless(typeof token === 'string' && token.length > 0, 'READ_TOKEN_MISSING');
  validateOriginalRun(await api(`/actions/runs/${PIN.originalRunId}`, token), await api(`/actions/runs/${PIN.originalRunId}/jobs?per_page=100`, token));
  validateArtifact(await api(`/actions/artifacts/${PIN.artifactId}`, token));
  const redirect = await fetch(`https://api.github.com/repos/${REPO}/actions/artifacts/${PIN.artifactId}/zip`, {
    redirect: 'manual', signal: AbortSignal.timeout(30000), headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
  failUnless(redirect.status === 302, 'ARTIFACT_REDIRECT_MISSING');
  const url = new URL(redirect.headers.get('location'));
  failUnless(url.protocol === 'https:' && !url.username && !url.password
    && (url.hostname.endsWith('.blob.core.windows.net') || url.hostname.endsWith('.githubusercontent.com')), 'UNTRUSTED_ARTIFACT_REDIRECT');
  // Never forward the repository token to the signed blob URL.
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(120000) });
  failUnless(response.ok && Number(response.headers.get('content-length')) === PIN.artifactBytes, 'ARTIFACT_DOWNLOAD_LENGTH');
  const chunks = []; let total = 0;
  for await (const chunk of response.body) { total += chunk.length; failUnless(total <= PIN.artifactBytes, 'ARTIFACT_DOWNLOAD_TOO_LARGE'); chunks.push(chunk); }
  const bytes = Buffer.concat(chunks);
  failUnless(bytes.length === PIN.artifactBytes && sha(bytes) === PIN.artifactSha256, 'ARTIFACT_DOWNLOAD_HASH_MISMATCH');
  writeFileSync(output, bytes, { flag: 'wx' });
  console.log(JSON.stringify({ status: 'EXACT_ORIGINAL_ARTIFACT_VERIFIED', originalRunId: PIN.originalRunId, artifactId: PIN.artifactId, sha256: PIN.artifactSha256 }));
}
async function fileHash(file) {
  const stat = lstatSync(file); failUnless(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1024 * 1024 * 1024, 'INVALID_RECOVERY_FILE');
  const hash = createHash('sha256'); for await (const chunk of createReadStream(file)) hash.update(chunk);
  return { bytes: stat.size, sha256: hash.digest('hex') };
}
function fileSet(root, prefix = '') {
  return readdirSync(join(root, prefix), { withFileTypes: true }).flatMap(entry => {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name; safePath(path);
    failUnless(!entry.isSymbolicLink() && (entry.isFile() || entry.isDirectory()), 'INVALID_RECOVERY_ENTRY');
    return entry.isDirectory() ? fileSet(root, path) : [path];
  });
}
export async function verifyPayload(directory, hashes) {
  failUnless(hashes && Object.keys(hashes).length === 221
    && JSON.stringify(fileSet(directory).sort()) === JSON.stringify(Object.keys(hashes).sort()), 'RECOVERED_PAYLOAD_FILE_SET_MISMATCH');
  for (const [name, expected] of Object.entries(hashes)) {
    safePath(name); failUnless(/^[a-f0-9]{64}$/.test(expected) && (await fileHash(join(directory, name))).sha256 === expected, 'RECOVERED_PAYLOAD_HASH_MISMATCH');
  }
}
async function retainedFiles(release) {
  for (const [name, [bytes, digest]] of Object.entries(RETAINED)) {
    const actual = await fileHash(join(release, name)); failUnless(actual.bytes === bytes && actual.sha256 === digest, 'RETAINED_FILE_HASH_MISMATCH');
  }
}
async function recover(checkout, source, archive, payload, bundle) {
  failUnless(process.platform === 'win32' && process.arch === 'x64', 'RECOVERY_REQUIRES_WINDOWS_X64');
  failUnless(!process.env.GITHUB_TOKEN && !process.env.GH_TOKEN, 'SOURCE_EXECUTION_TOKEN_FORBIDDEN');
  const request = trustedRequest(checkout), archiveIdentity = await fileHash(archive);
  failUnless(archiveIdentity.bytes === PIN.artifactBytes && archiveIdentity.sha256 === PIN.artifactSha256, 'RETAINED_ARCHIVE_HASH_MISMATCH');
  const release = join(source, 'release'), retained = `${payload}.retained`;
  failUnless(!existsSync(payload) && !existsSync(bundle) && !existsSync(retained), 'RECOVERY_DESTINATION_EXISTS');
  // The real frozen tree includes these three old tracked records. Preserve them.
  failUnless(JSON.stringify(fileSet(release).sort()) === JSON.stringify(['build-records/1.0.0.json', 'build-records/1.0.1.json', 'build-records/1.0.8.json']), 'UNEXPECTED_EXISTING_RELEASE_FILES');
  failUnless(!process.env.ELECTRON_BUILDER_7ZIP_PATH, 'UNPINNED_EXTRACTOR_OVERRIDE');
  const { getPath7za } = await import(pathToFileURL(join(source, 'node_modules/app-builder-lib/out/toolsets/7zip.js')).href);
  const seven = await getPath7za(); // locked official 7zip@1.0.0 with vendor checksum verification
  mkdirSync(retained); mkdirSync(payload);
  execFileSync(seven, ['x', archive, `-o${retained}`, '-y'], { windowsHide: true, timeout: 120000, stdio: 'pipe' });
  failUnless(JSON.stringify(fileSet(retained).sort()) === JSON.stringify(Object.keys(RETAINED).sort()), 'RETAINED_ARTIFACT_FILE_SET_MISMATCH');
  await retainedFiles(retained);
  for (const name of Object.keys(RETAINED)) copyFileSync(join(retained, name), join(release, name), constants.COPYFILE_EXCL);
  await retainedFiles(release);
  const proof = parse(join(release, 'build-verification.json'));
  failUnless(proof.status === 'PASS' && proof.baseCommit === PIN.sourceCommit && proof.sourceSha256 === PIN.sourceSha256
    && proof.version === PIN.version && proof.installerSha256 === PIN.installerSha256 && proof.installerPayloadFiles === 221, 'RETAINED_NATIVE_PROOF_MISMATCH');
  execFileSync(seven, ['x', join(release, 'Steam-Float-Scanner-Setup-1.2.14.exe'), `-o${payload}`, '-y'], { windowsHide: true, timeout: 120000, stdio: 'pipe' });
  await verifyPayload(payload, proof.payloadHashes);
  // Reproduce the normal build's generated web/legal provenance INPUTS only.
  // No desktop/engine compilation, NSIS packaging or installer replacement.
  execFileSync(process.execPath, [join(source, 'tools/build-cabinet.mjs')], {
    cwd: source, windowsHide: true, timeout: 120000, stdio: 'pipe',
  });
  const provenance = await import(pathToFileURL(join(source, 'tools/build-provenance.mjs')).href);
  failUnless(provenance.sourceState(source).sourceSha256 === PIN.sourceSha256, 'RECOVERY_SOURCE_STATE_MISMATCH');
  const actualIdentity = provenance.readPackagedPurchaseImplementation(source, join(payload, 'resources/app.asar'), { platform: 'win32', architecture: 'x64' });
  failUnless(JSON.stringify(actualIdentity) === JSON.stringify(proof.purchaseImplementation), 'RECOVERY_PACKAGED_IDENTITY_MISMATCH');
  // execFileSync waits for the GUI-subsystem executable and checks its real exit.
  // A PowerShell bare '&' may finish before the Electron child writes its proof.
  execFileSync(join(payload, 'Steam Float Scanner.exe'), [join(source, 'tools/release-acceptance/packaged-financial.mjs'),
    '--root', source, '--resources', join(payload, 'resources'), '--output', join(release, 'financial-acceptance.json')], {
    cwd: source, windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024, stdio: 'pipe',
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', SFS_NETWORK_DISABLED: '1', NODE_OPTIONS: '', NODE_PATH: '' },
  });
  validateFinancialAcceptance(parse(join(release, 'financial-acceptance.json')), request);
  await verifyPayload(payload, proof.payloadHashes); await retainedFiles(release);
  makeBundle(checkout, source, bundle, request, process.env);
  validateBundle(bundle, request, readFileSync(join(checkout, 'release-requests/1.2.14.json')), process.env);
  console.log(JSON.stringify({ status: 'ORIGINAL_INSTALLER_RECOVERED_AND_QUALIFIED', originalRunId: PIN.originalRunId, continuationRunId: process.env.GITHUB_RUN_ID,
    artifactId: PIN.artifactId, installerSha256: PIN.installerSha256, sourceCommit: PIN.sourceCommit, payloadFilesVerified: 221,
    nativeBuildOrPackageExecuted: false, webInputPreparation: true, financialAcceptanceAwaited: true, signingKeyAccess: false }));
}
async function main() {
  validateContext(process.env);
  const [mode, checkout, ...args] = process.argv.slice(2); failUnless(checkout && ['download', 'recover'].includes(mode), 'INVALID_CONTINUATION_COMMAND');
  if (mode === 'download') { failUnless(args.length === 1, 'INVALID_DOWNLOAD_ARGUMENTS'); await download(resolve(checkout), resolve(args[0])); }
  if (mode === 'recover') { failUnless(args.length === 4, 'INVALID_RECOVERY_ARGUMENTS'); await recover(resolve(checkout), ...args.map(path => resolve(path))); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => {
  console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'CONTINUATION_FAILED'); process.exitCode = 1;
});
