import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const env = process.env;
for (const key of ['SFS_SOURCE_COMMIT', 'SFS_ZIP_SHA256', 'SFS_PACK_SHA256']) assert.match(env[key] ?? '', key.endsWith('COMMIT') ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/);
for (const key of ['SFS_RELEASE_ID', 'SFS_ZIP_ASSET_ID', 'SFS_PACK_ASSET_ID']) assert.match(env[key] ?? '', /^[0-9]{1,20}$/);
assert.match(env.SFS_VERSION ?? '', /^\d+\.\d+\.\d+$/);
const root = path.resolve('snapshot-input');
const git = (args, cwd, input) => execFileSync('git', args, { cwd, input, windowsHide: true, maxBuffer: 512 * 1024 * 1024 });
if (process.argv[2] === 'download') {
  assert(env.GITHUB_TOKEN);
  const headers = { Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  const base = 'https://api.github.com/repos/Rigby453/steam-float-scanner-releases';
  const releaseResponse = await fetch(`${base}/releases/${env.SFS_RELEASE_ID}`, { headers });
  assert.equal(releaseResponse.status, 200, 'DRAFT_METADATA_UNAVAILABLE');
  const release = await releaseResponse.json();
  assert.equal(release.draft, true); assert.equal(release.tag_name, `v${env.SFS_VERSION}`);
  fs.mkdirSync(root, { recursive: false });
  for (const [id, expectedName, digest, filename] of [
    [env.SFS_ZIP_ASSET_ID, `steam-float-scanner-source-${env.SFS_VERSION}.zip`, env.SFS_ZIP_SHA256, 'source.zip'],
    [env.SFS_PACK_ASSET_ID, `ci-source-${env.SFS_VERSION}.pack`, env.SFS_PACK_SHA256, 'source.pack'],
  ]) {
    const asset = release.assets.find(a => String(a.id) === id);
    assert(asset && asset.name === expectedName && asset.size > 0 && asset.size <= 512 * 1024 * 1024);
    let url = `${base}/releases/assets/${id}`, response;
    for (let redirects = 0; redirects < 5; redirects++) {
      const target = new URL(url);
      assert.equal(target.protocol, 'https:');
      assert(['api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(target.hostname));
      response = await fetch(url, { headers: target.hostname === 'api.github.com' ? { ...headers, Accept: 'application/octet-stream' } : {}, redirect: 'manual', signal: AbortSignal.timeout(120000) });
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      const location = response.headers.get('location'); assert(location); url = new URL(location, url).href; await response.body?.cancel();
    }
    assert.equal(response.status, 200, 'SNAPSHOT_DOWNLOAD_FAILED');
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(bytes.length, asset.size); assert.equal(sha(bytes), digest);
    fs.writeFileSync(path.join(root, filename), bytes, { flag: 'wx' });
    console.log(JSON.stringify({ asset: expectedName, bytes: bytes.length, sha256: digest }));
  }
} else if (process.argv[2] === 'restore-git') {
  const source = path.resolve('source');
  assert(!fs.existsSync(path.join(source, '.git')), 'ARCHIVE_MUST_NOT_CONTAIN_GIT_STATE');
  const pack = fs.readFileSync(path.join(root, 'source.pack')); assert.equal(sha(pack), env.SFS_PACK_SHA256);
  git(['init', '--initial-branch=main'], source);
  git(['config', 'core.autocrlf', 'false'], source);
  git(['unpack-objects', '-q'], source, pack);
  fs.writeFileSync(path.join(source, '.git/shallow'), env.SFS_SOURCE_COMMIT + '\n');
  git(['update-ref', 'refs/heads/main', env.SFS_SOURCE_COMMIT], source);
  git(['read-tree', env.SFS_SOURCE_COMMIT], source);
  git(['fsck', '--connectivity-only', '--no-reflogs'], source);
  assert.equal(git(['status', '--porcelain=v1', '--untracked-files=all'], source).toString().trim(), '', 'SOURCE_ARCHIVE_TREE_MISMATCH');
  assert.equal(JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8')).version, env.SFS_VERSION);
  console.log(JSON.stringify({ exactSourceCommit: env.SFS_SOURCE_COMMIT, shallowSnapshot: true, credentialsIncluded: false }));
} else throw Error('UNKNOWN_SNAPSHOT_ACTION');
