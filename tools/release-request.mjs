// Trusted request transport/orchestration. No signing key is accepted here.
// The unchanged, separately dispatched signer remains the only key-bearing code.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, lstatSync, existsSync, unlinkSync } from 'node:fs';
import { resolve, join, dirname, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inflateRawSync, deflateRawSync, crc32 } from 'node:zlib';
import { REPOSITORY, createClient, validateRequest, validateProof, validateFeed, validatePurchaseAdmission } from './sign-release.mjs';

export const VERSION = '1.2.14';
export const REQUEST_PATH = `release-requests/${VERSION}.json`;
export const PACK_PATH = `release-requests/${VERSION}.pack.b64`;
export const BASE_ZIP_URL = 'https://github.com/Rigby453/steam-float-scanner-releases/releases/download/v1.2.13/steam-float-scanner-source-1.2.13.zip';
const MAX_JSON = 2 * 1024 * 1024;
const MAX_PACK = 16 * 1024 * 1024;
const MAX_ASSET = 512 * 1024 * 1024;
const MAX_UNPACKED = 1024 * 1024 * 1024;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const isSha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const isOid = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const requireThat = (value, code) => { if (!value) throw Error(code); };
const exact = (value, keys) => record(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|');
const json = bytes => { requireThat(bytes.length <= MAX_JSON, 'JSON_TOO_LARGE'); return JSON.parse(bytes.toString('utf8')); };

export function safePath(value) {
  requireThat(typeof value === 'string' && value.length > 0 && value.length <= 512
    && !/[\\\x00-\x1f\x7f:*?"<>|]/.test(value) && !value.startsWith('/'), 'UNSAFE_SOURCE_PATH');
  for (const part of value.split('/')) requireThat(part && part !== '.' && part !== '..'
    && !/[. ]$/.test(part) && part.toLowerCase() !== '.git'
    && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part), 'UNSAFE_SOURCE_PATH');
  return value;
}

export function validateReleaseRequest(value) {
  requireThat(exact(value, ['schemaVersion', 'version', 'sourceCommit', 'sourceTree', 'sourceSha256', 'baseZip', 'supplement', 'omittedPaths', 'releaseNotes'])
    && value.schemaVersion === 1 && value.version === VERSION && isOid(value.sourceCommit)
    && isOid(value.sourceTree) && isSha(value.sourceSha256), 'INVALID_RELEASE_REQUEST');
  requireThat(exact(value.baseZip, ['sha256', 'bytes']) && isSha(value.baseZip.sha256)
    && Number.isSafeInteger(value.baseZip.bytes) && value.baseZip.bytes > 0 && value.baseZip.bytes <= 128 * 1024 * 1024, 'INVALID_BASE_ZIP');
  requireThat(exact(value.supplement, ['path', 'sha256', 'bytes']) && value.supplement.path === PACK_PATH
    && isSha(value.supplement.sha256) && Number.isSafeInteger(value.supplement.bytes)
    && value.supplement.bytes > 0 && value.supplement.bytes <= MAX_PACK, 'INVALID_SUPPLEMENT');
  requireThat(Array.isArray(value.omittedPaths) && value.omittedPaths.length <= 256
    && new Set(value.omittedPaths).size === value.omittedPaths.length, 'INVALID_OMISSIONS');
  for (const path of value.omittedPaths) {
    safePath(path);
    requireThat(path.startsWith('docs/') || /^release\/build-records\/\d+\.\d+\.\d+\.json$/.test(path), 'BUILD_INPUT_OMISSION');
  }
  requireThat(typeof value.releaseNotes === 'string' && value.releaseNotes.trim().length > 0
    && Buffer.byteLength(value.releaseNotes) <= 100_000, 'INVALID_RELEASE_NOTES');
  return value;
}

export function validateContext(env) {
  requireThat(env.GITHUB_REPOSITORY === REPOSITORY && env.GITHUB_REF === 'refs/heads/main'
    && env.GITHUB_EVENT_NAME === 'push'
    && env.GITHUB_WORKFLOW_REF === `${REPOSITORY}/.github/workflows/build-release-request.yml@refs/heads/main`
    && isOid(env.GITHUB_SHA) && /^[1-9]\d*$/.test(env.GITHUB_RUN_ID ?? ''), 'UNTRUSTED_REQUEST_CONTEXT');
}

export function decodeSupplement(text, request) {
  requireThat(typeof text === 'string' && Buffer.byteLength(text) <= Math.ceil(MAX_PACK / 3) * 4 + 2, 'SUPPLEMENT_TOO_LARGE');
  const encoded = text.endsWith('\n') ? text.slice(0, -1) : text;
  requireThat(encoded.length % 4 === 0 && !/[^A-Za-z0-9+/=]/.test(encoded), 'INVALID_PACK_BASE64');
  const bytes = Buffer.from(encoded, 'base64');
  requireThat(bytes.toString('base64') === encoded && bytes.length === request.supplement.bytes
    && sha(bytes) === request.supplement.sha256 && bytes.subarray(0, 4).toString() === 'PACK', 'SUPPLEMENT_HASH_MISMATCH');
  return bytes;
}

// Small, bounded ZIP32 parser. Reject traversal, symlinks, encryption, duplicates,
// zip bombs and unsupported encodings before writing any file to a fresh folder.
export function readSourceZip(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= 128 * 1024 * 1024, 'INVALID_ZIP');
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (bytes.readUInt32LE(i) === 0x06054b50 && i + 22 + bytes.readUInt16LE(i + 20) === bytes.length) { end = i; break; }
  }
  requireThat(end >= 0 && bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0
    && bytes.readUInt16LE(end + 8) === bytes.readUInt16LE(end + 10), 'UNSUPPORTED_ZIP');
  const count = bytes.readUInt16LE(end + 10), centralSize = bytes.readUInt32LE(end + 12), start = bytes.readUInt32LE(end + 16);
  requireThat(count > 0 && count < 50000 && start + centralSize === end, 'INVALID_ZIP_DIRECTORY');
  const entries = [], names = new Set(); let offset = start, total = 0;
  for (let index = 0; index < count; index++) {
    requireThat(offset + 46 <= end && bytes.readUInt32LE(offset) === 0x02014b50, 'INVALID_ZIP_ENTRY');
    const flags = bytes.readUInt16LE(offset + 8), method = bytes.readUInt16LE(offset + 10);
    const checksum = bytes.readUInt32LE(offset + 16), compressed = bytes.readUInt32LE(offset + 20), size = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28), extra = bytes.readUInt16LE(offset + 30), comment = bytes.readUInt16LE(offset + 32);
    const mode = bytes.readUInt32LE(offset + 38) >>> 16, local = bytes.readUInt32LE(offset + 42);
    requireThat(offset + 46 + nameLength + extra + comment <= end && !(flags & 1) && [0, 8].includes(method)
      && size <= 64 * 1024 * 1024 && local + 30 <= start && (mode & 0xf000) !== 0xa000, 'UNSUPPORTED_ZIP_ENTRY');
    const rawName = bytes.subarray(offset + 46, offset + 46 + nameLength);
    const name = new TextDecoder('utf-8', { fatal: true }).decode(rawName), directory = name.endsWith('/');
    const clean = safePath(directory ? name.slice(0, -1) : name);
    requireThat(!names.has(clean.toLowerCase()), 'DUPLICATE_ZIP_PATH'); names.add(clean.toLowerCase());
    requireThat(bytes.readUInt32LE(local) === 0x04034b50, 'INVALID_ZIP_LOCAL');
    const localNameLength = bytes.readUInt16LE(local + 26), localExtra = bytes.readUInt16LE(local + 28);
    requireThat(bytes.readUInt16LE(local + 6) === flags && bytes.readUInt16LE(local + 8) === method
      && bytes.subarray(local + 30, local + 30 + localNameLength).equals(rawName), 'ZIP_LOCAL_MISMATCH');
    const dataStart = local + 30 + localNameLength + localExtra;
    requireThat(dataStart + compressed <= start, 'ZIP_DATA_OUTSIDE_ARCHIVE');
    total += size; requireThat(total <= MAX_UNPACKED, 'ZIP_UNPACKED_LIMIT');
    if (!directory) entries.push({ name: clean, method, checksum, size, compressed: bytes.subarray(dataStart, dataStart + compressed) });
    offset += 46 + nameLength + extra + comment;
  }
  requireThat(offset === end, 'ZIP_DIRECTORY_LENGTH');
  const directRoot = entries.find(entry => entry.name === 'package.json');
  const roots = directRoot ? [directRoot] : entries.filter(entry => /^[^/]+\/package\.json$/.test(entry.name));
  requireThat(roots.length === 1, 'ZIP_SOURCE_ROOT');
  const prefix = roots[0].name.slice(0, -'package.json'.length);
  return entries.map(entry => {
    requireThat(entry.name.startsWith(prefix), 'ZIP_OUTSIDE_SOURCE_ROOT');
    const path = safePath(entry.name.slice(prefix.length));
    const data = entry.method === 0 ? entry.compressed : inflateRawSync(entry.compressed, { maxOutputLength: entry.size + 1 });
    requireThat(data.length === entry.size && crc32(data) === entry.checksum, 'ZIP_CONTENT_MISMATCH');
    return { path, data };
  });
}

function git(root, args, input) {
  return execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.hooksPath=.git/no-hooks', ...args],
    { cwd: root, input, encoding: input ? undefined : 'utf8', windowsHide: true, timeout: 120_000, maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_TERMINAL_PROMPT: '0' } });
}

async function anonymousBaseZip(expected, fetcher) {
  let current = BASE_ZIP_URL;
  for (let i = 0; i <= 5; i++) {
    const parsed = new URL(current);
    requireThat(parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.port
      && (current === BASE_ZIP_URL || ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(parsed.hostname)), 'UNTRUSTED_BASE_URL');
    const response = await fetcher(current, { redirect: 'manual', signal: AbortSignal.timeout(180_000) });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      requireThat(response.headers.get('location'), 'BASE_REDIRECT_MISSING');
      await response.body?.cancel(); current = new URL(response.headers.get('location'), current).href; continue;
    }
    requireThat(response.status === 200 && response.body, 'BASE_DOWNLOAD_FAILED');
    const chunks = []; let length = 0;
    for await (const chunk of response.body) { length += chunk.length; requireThat(length <= expected.bytes, 'BASE_TOO_LARGE'); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks);
    requireThat(length === expected.bytes && sha(bytes) === expected.sha256, 'BASE_HASH_MISMATCH');
    return bytes;
  }
  throw Error('BASE_REDIRECT_LIMIT');
}

export async function materialize(checkout, destination, request, fetcher = fetch) {
  const root = resolve(destination); requireThat(!existsSync(root), 'SOURCE_DESTINATION_EXISTS');
  const pack = decodeSupplement(readFileSync(join(checkout, PACK_PATH), 'utf8'), request);
  const entries = readSourceZip(await anonymousBaseZip(request.baseZip, fetcher));
  mkdirSync(root, { recursive: true });
  for (const entry of entries) { const path = join(root, ...entry.path.split('/')); mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, entry.data, { flag: 'wx' }); }
  git(root, ['init', '--quiet', '--object-format=sha1']);
  // Raw hashing includes ignored files and bypasses attributes/line filters.
  // No synthetic base commit, index identity or substituted source SHA is made.
  git(root, ['hash-object', '-w', '--no-filters', '--stdin-paths'], Buffer.from(entries.map(entry => entry.path).join('\n') + '\n'));
  // Base objects remain in .git. Remove only our freshly extracted files so
  // files deleted by the real final tree do not survive as untracked inputs.
  for (const entry of entries) {
    const path = resolve(root, ...entry.path.split('/'));
    requireThat(path.startsWith(root + sep), 'SOURCE_PATH_OUTSIDE_DESTINATION'); unlinkSync(path);
  }
  writeFileSync(join(root, '.git', 'shallow'), request.sourceCommit + '\n', { flag: 'wx' });
  git(root, ['index-pack', '--stdin', '--fix-thin'], pack);
  requireThat(git(root, ['cat-file', '-t', request.sourceCommit]).trim() === 'commit', 'SOURCE_HEAD_NOT_COMMIT');
  requireThat(git(root, ['rev-parse', `${request.sourceCommit}^{tree}`]).trim() === request.sourceTree, 'SOURCE_TREE_MISMATCH');
  const rows = git(root, ['ls-tree', '-r', '-z', request.sourceTree]).split('\0').filter(Boolean).map(row => {
    const match = /^(100644|100755) blob ([a-f0-9]{40})\t([\s\S]+)$/.exec(row);
    requireThat(match, 'UNSUPPORTED_SOURCE_TREE_MODE'); safePath(match[3]); return { path: match[3], oid: match[2] };
  });
  requireThat(rows.length > 0 && rows.length < 50000, 'SOURCE_TREE_SIZE');
  const paths = new Set(rows.map(row => row.path));
  requireThat(request.omittedPaths.every(path => paths.has(path)), 'OMISSION_NOT_IN_TREE');
  git(root, ['read-tree', request.sourceTree]);
  if (request.omittedPaths.length) git(root, ['update-index', '--skip-worktree', '-z', '--stdin'], Buffer.from(request.omittedPaths.join('\0') + '\0'));
  git(root, ['checkout-index', '--all', '--force']);
  git(root, ['update-ref', 'refs/heads/main', request.sourceCommit]); git(root, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
  requireThat(git(root, ['rev-parse', 'HEAD']).trim() === request.sourceCommit
    && git(root, ['rev-parse', 'HEAD^{tree}']).trim() === request.sourceTree, 'MATERIALIZED_HEAD_MISMATCH');
  const omitted = new Set(request.omittedPaths);
  for (const row of rows) if (!omitted.has(row.path)) {
    const bytes = readFileSync(join(root, ...row.path.split('/')));
    const actual = createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
    requireThat(actual === row.oid, 'MATERIALIZED_BLOB_MISMATCH');
  }
  requireThat(git(root, ['status', '--porcelain', '--untracked-files=all']).trim() === '', 'MATERIALIZED_SOURCE_DIRTY');
  requireThat(JSON.parse(readFileSync(join(root, 'package.json'))).version === VERSION
    && JSON.parse(readFileSync(join(root, 'apps/desktop/package.json'))).version === VERSION, 'MATERIALIZED_VERSION_MISMATCH');
  return { sourceCommit: request.sourceCommit, sourceTree: request.sourceTree, materializedFiles: rows.length - omitted.size, omittedPaths: request.omittedPaths };
}

const assetNames = () => [`Steam-Float-Scanner-Setup-${VERSION}.exe`, `Steam-Float-Scanner-Setup-${VERSION}.exe.blockmap`, 'latest.yml', 'build-verification.json', `steam-float-scanner-source-${VERSION}.zip`];
const fileBytes = (directory, name, maximum = MAX_ASSET) => {
  const path = join(directory, name), stat = lstatSync(path);
  requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= maximum, 'INVALID_BUNDLE_FILE');
  return readFileSync(path);
};

export function validateFinancialAcceptance(value, request) {
  requireThat(record(value) && value.status === 'PASS' && value.sourceSha256 === request.sourceSha256
    && value.profiles === 14 && value.roleChecks === 56 && value.alteredChecks === 56
    && value.dynamicCodeRejected === true && value.downloadedCodeExecuted === false
    && value.actualPackagedWorkerParity === true && value.currentPackagedReferenceBound === true
    && value.bundledPendingBlocksBuy === true && value.bundledLateStopBlocked === true
    && value.externalNetworkRequests === 0 && value.purchases === false && value.productionWrites === 0, 'FINANCIAL_ACCEPTANCE_NOT_PASS');
}

// Reproducible ZIP32 source archive. Omitted private non-build files are declared,
// never replaced with placeholders; original commit/tree IDs stay unchanged.
function sourceArchive(source, destination, request) {
  const files = git(source, ['ls-files', '-z']).split('\0').filter(Boolean).filter(path => !request.omittedPaths.includes(path)).sort();
  requireThat(!files.includes('SOURCE_MATERIALIZATION.json'), 'SOURCE_MANIFEST_COLLISION');
  const objectIds = new Map(git(source, ['ls-tree', '-r', '-z', request.sourceTree]).split('\0').filter(Boolean).map(row => {
    const match = /^(100644|100755) blob ([a-f0-9]{40})\t([\s\S]+)$/.exec(row);
    requireThat(match, 'UNSUPPORTED_SOURCE_TREE_MODE'); return [match[3], match[2]];
  }));
  const entries = files.map(path => {
    const data = readFileSync(join(source, ...safePath(path).split('/')));
    requireThat(createHash('sha1').update(Buffer.from(`blob ${data.length}\0`)).update(data).digest('hex') === objectIds.get(path), 'SOURCE_ARCHIVE_BLOB_MISMATCH');
    return { path, data };
  });
  entries.push({ path: 'SOURCE_MATERIALIZATION.json', data: Buffer.from(JSON.stringify({ sourceCommit: request.sourceCommit, sourceTree: request.sourceTree, sourceSha256: request.sourceSha256, omittedPaths: request.omittedPaths, scope: 'Exact tracked build/test source; declared non-build omissions, not a complete historical repository' }, null, 2) + '\n') });
  const local = [], central = []; let offset = 0, total = 0;
  for (const { path, data } of entries) {
    total += data.length; requireThat(data.length <= 64 * 1024 * 1024 && total <= MAX_UNPACKED, 'SOURCE_ARCHIVE_LIMIT');
    const name = Buffer.from(`steam-float-scanner-${VERSION}/${path}`), body = deflateRawSync(data, { level: 6 }), checksum = crc32(data);
    const header = Buffer.alloc(30); header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x800, 6); header.writeUInt16LE(8, 8); header.writeUInt16LE(33, 12); header.writeUInt32LE(checksum, 14); header.writeUInt32LE(body.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(name.length, 26);
    const entry = Buffer.alloc(46); entry.writeUInt32LE(0x02014b50); entry.writeUInt16LE(20, 4); entry.writeUInt16LE(20, 6); entry.writeUInt16LE(0x800, 8); entry.writeUInt16LE(8, 10); entry.writeUInt16LE(33, 14); entry.writeUInt32LE(checksum, 16); entry.writeUInt32LE(body.length, 20); entry.writeUInt32LE(data.length, 24); entry.writeUInt16LE(name.length, 28); entry.writeUInt32LE(offset, 42);
    local.push(header, name, body); central.push(entry, name); offset += header.length + name.length + body.length;
    requireThat(offset <= MAX_ASSET, 'SOURCE_ARCHIVE_TOO_LARGE');
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  writeFileSync(destination, Buffer.concat([...local, directory, end]), { flag: 'wx' });
}

export function makeBundle(checkout, source, destination, request, env) {
  requireThat(git(source, ['rev-parse', 'HEAD']).trim() === request.sourceCommit
    && git(source, ['rev-parse', 'HEAD^{tree}']).trim() === request.sourceTree
    && git(source, ['status', '--porcelain', '--untracked-files=all']).trim() === '', 'POST_BUILD_SOURCE_CHANGED');
  const output = resolve(destination); requireThat(!existsSync(output), 'BUNDLE_DESTINATION_EXISTS'); mkdirSync(output, { recursive: true });
  const release = join(source, 'release');
  const proof = json(fileBytes(release, 'build-verification.json', MAX_JSON));
  const financialBytes = fileBytes(release, 'financial-acceptance.json', MAX_JSON);
  validateFinancialAcceptance(json(financialBytes), request);
  requireThat(proof.status === 'PASS' && proof.baseCommit === request.sourceCommit && proof.sourceSha256 === request.sourceSha256 && proof.version === VERSION, 'NATIVE_BUILD_IDENTITY_MISMATCH');
  sourceArchive(source, join(output, `steam-float-scanner-source-${VERSION}.zip`), request);
  for (const name of assetNames().filter(name => !name.endsWith('.zip'))) writeFileSync(join(output, name), fileBytes(release, name), { flag: 'wx' });
  writeFileSync(join(output, 'financial-acceptance.json'), financialBytes, { flag: 'wx' });
  const requestBytes = readFileSync(join(checkout, REQUEST_PATH)); writeFileSync(join(output, 'release-request.json'), requestBytes, { flag: 'wx' });
  const assets = assetNames().map(name => { const bytes = fileBytes(output, name); return { name, sha256: sha(bytes), bytes: bytes.length }; });
  const manifest = { schemaVersion: 1, requestSha256: sha(requestBytes), sourceCommit: request.sourceCommit, sourceTree: request.sourceTree, sourceSha256: request.sourceSha256, ciRunId: env.GITHUB_RUN_ID, workflowCommit: env.GITHUB_SHA, financialSha256: sha(financialBytes), assets };
  writeFileSync(join(output, 'bundle-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  return manifest;
}

export function validateBundle(directory, request, requestBytes, env) {
  const expectedNames = [...assetNames(), 'financial-acceptance.json', 'release-request.json', 'bundle-manifest.json'];
  requireThat(readdirSync(directory).sort().join('|') === expectedNames.sort().join('|'), 'BUNDLE_FILE_SET_MISMATCH');
  const manifest = json(fileBytes(directory, 'bundle-manifest.json', MAX_JSON));
  requireThat(exact(manifest, ['schemaVersion', 'requestSha256', 'sourceCommit', 'sourceTree', 'sourceSha256', 'ciRunId', 'workflowCommit', 'financialSha256', 'assets'])
    && manifest.schemaVersion === 1 && manifest.requestSha256 === sha(requestBytes)
    && manifest.sourceCommit === request.sourceCommit && manifest.sourceTree === request.sourceTree
    && manifest.sourceSha256 === request.sourceSha256 && manifest.ciRunId === env.GITHUB_RUN_ID
    && manifest.workflowCommit === env.GITHUB_SHA && isSha(manifest.financialSha256), 'BUNDLE_IDENTITY_MISMATCH');
  requireThat(fileBytes(directory, 'release-request.json', MAX_JSON).equals(requestBytes), 'BUNDLE_REQUEST_MISMATCH');
  const sourceZip = manifest.assets?.find(asset => asset.name === `steam-float-scanner-source-${VERSION}.zip`);
  const releaseRequest = { version: VERSION, sourceCommit: request.sourceCommit, sourceSha256: request.sourceSha256,
    ciRunId: env.GITHUB_RUN_ID, releaseNotesSha256: sha(Buffer.from(request.releaseNotes.trim())), sourceZip, assets: manifest.assets,
    sourceTree: request.sourceTree, omittedPaths: request.omittedPaths, requestSha256: manifest.requestSha256, workflowCommit: env.GITHUB_SHA };
  const identity = { version: VERSION, sourceCommit: request.sourceCommit };
  validateRequest(releaseRequest, identity);
  const actual = new Map();
  for (const asset of manifest.assets) {
    const bytes = fileBytes(directory, asset.name, /\.(json|yml)$/.test(asset.name) ? MAX_JSON : MAX_ASSET);
    requireThat(bytes.length === asset.bytes && sha(bytes) === asset.sha256, 'BUNDLE_ASSET_HASH_MISMATCH');
    actual.set(asset.name, { bytes: bytes.length, sha256: asset.sha256, sha512: createHash('sha512').update(bytes).digest('base64') });
  }
  const proof = json(fileBytes(directory, 'build-verification.json', MAX_JSON));
  validateProof(proof, releaseRequest, manifest.assets.find(asset => asset.name.endsWith('.exe')));
  requireThat(proof.purchaseImplementation?.platform === 'win32' && proof.purchaseImplementation.architecture === 'x64', 'NATIVE_PACKAGE_TARGET_MISMATCH');
  validateFeed(fileBytes(directory, 'latest.yml', MAX_JSON), VERSION, `Steam-Float-Scanner-Setup-${VERSION}.exe`, actual.get(`Steam-Float-Scanner-Setup-${VERSION}.exe`));
  const financial = fileBytes(directory, 'financial-acceptance.json', MAX_JSON);
  requireThat(sha(financial) === manifest.financialSha256, 'FINANCIAL_PROOF_HASH_MISMATCH'); validateFinancialAcceptance(json(financial), request);
  return { proof, releaseRequest };
}

export async function stageAndDispatch(directory, request, requestBytes, env, fetcher = fetch) {
  validateContext(env);
  const { proof, releaseRequest } = validateBundle(directory, request, requestBytes, env);
  const client = createClient(env.GITHUB_TOKEN, fetcher);
  requireThat((await client.api('/git/ref/heads/main')).object?.sha === env.GITHUB_SHA, 'REQUEST_MAIN_MOVED');
  try { await client.api(`/releases/tags/v${VERSION}`); throw Error('RELEASE_VERSION_ALREADY_EXISTS'); }
  catch (error) { if (error.message !== 'GITHUB_API_404') throw error; }
  const latest = await client.api('/releases/latest');
  requireThat(/^v\d+\.\d+\.\d+$/.test(latest.tag_name ?? ''), 'LATEST_VERSION_UNKNOWN');
  const left = VERSION.split('.').map(BigInt), right = latest.tag_name.slice(1).split('.').map(BigInt);
  requireThat(left.some((n, i) => left.slice(0, i).every((x, j) => x === right[j]) && n > right[i]), 'VERSION_NOT_NEWER');
  const metadata = await client.api('/releases/tags/purchase-compatibility-v1');
  const assets = await client.api(`/releases/${metadata.id}/assets?per_page=100`);
  const policy = assets.filter(asset => asset.name === 'protocol.json');
  requireThat(policy.length === 1 && policy[0].size > 0 && policy[0].size <= 64 * 1024, 'PURCHASE_POLICY_MISSING');
  validatePurchaseAdmission(proof, (await client.download(policy[0].id, policy[0].size, true)).body);
  const draft = await client.api('/releases', 'POST', { tag_name: `v${VERSION}`, target_commitish: env.GITHUB_SHA, name: `Steam Float Scanner ${VERSION}`, body: request.releaseNotes.trim(), draft: true, prerelease: false, make_latest: 'false' });
  requireThat(Number.isSafeInteger(draft.id) && draft.id > 0 && draft.draft === true && draft.tag_name === `v${VERSION}`, 'DRAFT_CREATE_IDENTITY_MISMATCH');
  const releaseId = String(draft.id);
  for (const asset of releaseRequest.assets) await client.upload(releaseId, asset.name, fileBytes(directory, asset.name));
  const recordBytes = Buffer.from(JSON.stringify(releaseRequest, null, 2) + '\n'); await client.upload(releaseId, 'release-source.json', recordBytes);
  requireThat((await client.api('/git/ref/heads/main')).object?.sha === env.GITHUB_SHA, 'REQUEST_MAIN_MOVED');
  // A real workflow_dispatch preserves the unchanged signer's context checks.
  // GITHUB_EVENT_NAME is never overridden or impersonated.
  const response = await fetcher(`https://api.github.com/repos/${REPOSITORY}/actions/workflows/sign-release.yml/dispatches`, {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(30_000),
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${env.GITHUB_TOKEN}`, 'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28' },
    body: JSON.stringify({ ref: 'main', inputs: { release_id: releaseId, version: VERSION, source_commit: request.sourceCommit, source_record_sha256: sha(recordBytes) } }),
  });
  requireThat(response.status === 204, 'SIGNER_DISPATCH_FAILED');
  return { status: 'DRAFT_UPLOADED_SIGNER_DISPATCHED', version: VERSION, releaseId, sourceCommit: request.sourceCommit, sourceRecordSha256: sha(recordBytes) };
}

async function main() {
  const [mode, checkout, source, output] = process.argv.slice(2); validateContext(process.env);
  requireThat(['prepare', 'bundle', 'stage'].includes(mode) && checkout, 'INVALID_REQUEST_COMMAND');
  const directory = resolve(checkout), bytes = readFileSync(join(directory, REQUEST_PATH));
  const request = validateReleaseRequest(json(bytes));
  if (mode === 'prepare') { requireThat(source && !output, 'INVALID_PREPARE_ARGUMENTS'); console.log(JSON.stringify(await materialize(directory, source, request))); }
  if (mode === 'bundle') { requireThat(source && output, 'INVALID_BUNDLE_ARGUMENTS'); console.log(JSON.stringify(makeBundle(directory, resolve(source), output, request, process.env))); }
  if (mode === 'stage') { requireThat(source && !output, 'INVALID_STAGE_ARGUMENTS'); console.log(JSON.stringify(await stageAndDispatch(resolve(source), request, bytes, process.env))); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => {
  // No URLs, response bodies, raw git errors, credentials or source text in logs.
  console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'RELEASE_REQUEST_FAILED'); process.exitCode = 1;
});
