
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {activatePurchasePolicy, planPurchaseAdmission, signPlannedPurchasePolicy,
 validatePurchaseAdmission, PURCHASE_PROTOCOL_SHA256, run, REPOSITORY, SOURCE_REPOSITORY} from './sign-release.mjs';
const keys=generateKeyPairSync('ed25519'), key=keys.publicKey.export({type:'spki',format:'pem'});
const now=Date.parse('2026-11-10T12:00:00Z');
const identity={kind:'SFS_PACKAGED_PURCHASE_V1',implementationSha256:'a'.repeat(64),
 canonicalBundleSha256:'b'.repeat(64),platform:'win32',architecture:'x64'};
function policy(changes={}) {
 const payload={kind:'steam-float-scanner-purchase-protocol',schemaVersion:1,revision:3,
 publishedAt:'2026-11-10T00:00:00Z',expiresAt:'2026-11-23T00:00:00Z',implementations:[{
 clientVersion:'1.2.13',implementationSha256:identity.implementationSha256,protocolSha256:PURCHASE_PROTOCOL_SHA256,
 platform:'win32',architecture:'x64',sourceEvidenceSha256:'d'.repeat(64),
 authenticatedAcceptanceSha256:'e'.repeat(64),acceptance:'AUTHENTICATED_EXACT_PURCHASE_VERIFIED'}],...changes};
 return Buffer.from(JSON.stringify({payload,signature:sign(null,Buffer.from(JSON.stringify(payload)),keys.privateKey).toString('base64')}));
}
test('new app version reuses original-key admission for identical actual financial bytes',()=>{
 const result=validatePurchaseAdmission({version:'1.2.14',purchaseImplementation:identity},policy(),now,key);
 assert.equal(result.reviewedClientVersion,'1.2.13');assert.equal(result.policyRevision,3);
});
test('missing admission or actual identity fails before publication',()=>{
 assert.throws(()=>validatePurchaseAdmission({},policy(),now,key),/IDENTITY_MISSING/);
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:{...identity,implementationSha256:'f'.repeat(64)}},policy(),now,key),/NOT_ADMITTED/);
});
test('wrong OS or architecture cannot borrow another platform admission',()=>{
 for(const changed of [{platform:'linux'},{architecture:'arm64'}])
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:{...identity,...changed}},policy(),now,key),/NOT_ADMITTED/);
});
test('expired and near-expiry policies do not reach latest',()=>{
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({expiresAt:'2026-11-10T11:00:00Z'}),now,key),/EXPIRED/);
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({expiresAt:'2026-11-11T00:00:00Z'}),now,key),/RENEWAL_REQUIRED/);
});
test('policy tampering, untrusted signatures and mock acceptance remain blocked',()=>{
 const data=JSON.parse(policy());data.payload.revision++;assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},Buffer.from(JSON.stringify(data)),now,key),/SIGNATURE/);
 const other=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy(),now,other),/SIGNATURE/);
 const rows=JSON.parse(policy()).payload.implementations; rows[0].acceptance='MOCK_ONLY';
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({implementations:rows}),now,key),/INVALID_PURCHASE_POLICY/);
});

test('signed wrong protocol and non-ISO dates cannot pass a production-incompatible gate',()=>{
 const rows=JSON.parse(policy()).payload.implementations; rows[0].protocolSha256='c'.repeat(64);
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({implementations:rows}),now,key),/INVALID_PURCHASE_POLICY/);
 for (const date of ['November 10, 2026', '2026-02-30T00:00:00Z', '2026-11-10T24:00:00Z'])
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({publishedAt:date}),now,key),/INVALID_PURCHASE_POLICY/);
});
test('noncanonical base64 signature pad bits remain rejected even when OpenSSL decodes the same bytes',()=>{
 const data=JSON.parse(policy()); const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
 const last=alphabet.indexOf(data.signature.at(-3)); data.signature=data.signature.slice(0,-3)+alphabet[last+1]+'==';
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},Buffer.from(JSON.stringify(data)),now,key),/SIGNATURE/);
});

test('BOM-prefixed signed policy stays incompatible with the production JSON parser',()=>{
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),policy()]),now,key),/INVALID_PURCHASE_POLICY/);
});

test('array-shaped version and unknown package identity fields cannot bypass production schemas',()=>{
 const rows=JSON.parse(policy()).payload.implementations; rows[0].clientVersion=['1.2.13'];
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:identity},policy({implementations:rows}),now,key),/INVALID_PURCHASE_POLICY/);
 assert.throws(()=>validatePurchaseAdmission({purchaseImplementation:{...identity,skip:true}},policy(),now,key),/IDENTITY_MISSING/);
});

function releaseHarness(admitted=true) {
 const version='1.2.14', sourceCommit='1'.repeat(40),sourceSha256='2'.repeat(64);
 const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
 const installer=Buffer.from('synthetic installer only');
 const filename='Steam-Float-Scanner-Setup-'+version+'.exe';
 const data=new Map([[filename,installer],[filename+'.blockmap',Buffer.from('fixture blockmap')]]);
 const proof={status:'PASS',version,sourceSha256,baseCommit:sourceCommit,installerSha256:digest(installer),purchaseImplementation:identity};
 data.set('build-verification.json',Buffer.from(JSON.stringify(proof)));
 const sha512=createHash('sha512').update(installer).digest('base64');
 data.set('latest.yml',Buffer.from('version: '+version+'\nfiles:\n  - url: '+filename+'\n    sha512: '+sha512+'\n    size: '+installer.length+'\npath: '+filename+'\nsha512: '+sha512+'\nreleaseDate: 2026-11-10T00:00:00.000Z\n'));
 const assets=[...data].map(([name,bytes])=>({name,sha256:digest(bytes),bytes:bytes.length}));
 const request={version,sourceRepository:SOURCE_REPOSITORY,sourceCommit,sourceSha256,ciRunId:'456',
 releaseNotesSha256:digest(Buffer.from('Fixture release')),assets};
 const requestBytes=Buffer.from(JSON.stringify(request));data.set('release-source.json',requestBytes);
 const policyBytes=policy(admitted?{}:{implementations:[]});
 // run uses real wall time; generate a current, bounded policy for this isolated fixture.
 const p=JSON.parse(policyBytes).payload;p.publishedAt=new Date(Date.now()-3600000).toISOString();p.expiresAt=new Date(Date.now()+7*86400000).toISOString();
 const current=Buffer.from(JSON.stringify({payload:p,signature:sign(null,Buffer.from(JSON.stringify(p)),keys.privateKey).toString('base64')}));
 // Production run deliberately pins PUBLIC_KEY, so intercept only the pure policy verifier key for fixture below is impossible.
 // The rejected-flow test uses a malformed current policy and must stop before private-key access or any write.
 const catalog=[...data].map(([name,bytes],i)=>({name,id:100+i,size:bytes.length,state:'uploaded',digest:'sha256:'+digest(bytes)}));
 const byId=new Map(catalog.map(a=>[String(a.id),data.get(a.name)]));byId.set('999',current);
 const calls=[];
 const fetcher=async(url,options={})=>{
  calls.push({url:String(url),method:options.method??'GET'});
  const path=new URL(url).pathname.replace('/repos/'+REPOSITORY,'');
  if(path==='/releases/123') return Response.json({id:123,tag_name:'v'+version,draft:true,prerelease:false,published_at:null,body:'Fixture release'});
  if(path==='/releases/latest') return Response.json({id:1,tag_name:'v1.2.13'});
  if(path==='/releases/123/assets') return Response.json(catalog);
  if(path==='/releases/tags/purchase-compatibility-v1') return Response.json({id:77});
  if(path==='/releases/77/assets') return Response.json([{name:'protocol.json',id:999,size:current.length,state:'uploaded'}]);
  const id=/^\/releases\/assets\/(\d+)$/.exec(path)?.[1];
  if(id&&byId.has(id)) return new Response(byId.get(id));
  throw Error('UNEXPECTED_FIXTURE_URL');
 };
 const env={GITHUB_REPOSITORY:REPOSITORY,GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',
 GITHUB_WORKFLOW_REF:REPOSITORY+'/.github/workflows/sign-release.yml@refs/heads/main',
 SFS_RELEASE_ID:'123',SFS_VERSION:version,SFS_SOURCE_COMMIT:sourceCommit,SFS_REQUEST_SHA256:digest(requestBytes),GITHUB_TOKEN:'fixture-not-a-real-token'};
 return {env,fetcher,calls};
}
test('full publication path blocks an untrusted admission before signing or any API mutation',async()=>{
 const h=releaseHarness();
 await assert.rejects(run('publish',h.env,h.fetcher),/INVALID_PURCHASE_POLICY_SIGNATURE/);
 assert(h.calls.every(call=>call.method==='GET'));
 assert(!h.calls.some(call=>call.url.startsWith('https://uploads.github.com')));
});

const sha256 = value => createHash('sha256').update(value).digest('hex');
const reviewedRequest = { version: '1.3.0', sourceCommit: '1'.repeat(40), sourceSha256: '2'.repeat(64) };
function reviewCase(previous = policy(), purchaseImplementation = { ...identity, implementationSha256: 'f'.repeat(64) }) {
 const targets = [{ proof: { purchaseImplementation }, installerSha256: '9'.repeat(64), platform: 'win32' }];
 const { kind, ...identityFields } = purchaseImplementation;
 const review = { kind: 'SFS_RELEASE_PURCHASE_REVIEW_V1', ...reviewedRequest, previousPolicySha256: sha256(previous),
  targets: [{ ...identityFields, installerSha256: targets[0].installerSha256, sourceEvidenceSha256: '3'.repeat(64),
   authenticatedAcceptanceSha256: '4'.repeat(64), acceptance: 'AUTHENTICATED_EXACT_PURCHASE_VERIFIED' }] };
 return { targets, review, previous };
}

test('approved new financial bytes receive new signed admission while retaining previous clients', () => {
 const { targets, review, previous } = reviewCase();
 const planned = planPurchaseAdmission(targets, reviewedRequest, review, previous, now, key);
 const oldPolicy = JSON.parse(previous).payload;
 assert.equal(planned.previousSha256, sha256(previous));
 assert.equal(planned.payload.revision, oldPolicy.revision + 1);
 assert.deepEqual(planned.payload.implementations.slice(0, -1), oldPolicy.implementations);
 assert.equal(planned.payload.implementations.at(-1).implementationSha256, targets[0].proof.purchaseImplementation.implementationSha256);
 const passphrase = 'temporary-passphrase-for-this-test-only';
 const encrypted = keys.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
 const bytes = signPlannedPurchasePolicy(planned, encrypted, passphrase, key);
 assert.equal(validatePurchaseAdmission(targets[0].proof, bytes, now, key).reviewedClientVersion, '1.3.0');
 assert.equal(validatePurchaseAdmission({ purchaseImplementation: identity }, bytes, now, key).reviewedClientVersion, '1.2.13');
 assert.throws(() => signPlannedPurchasePolicy(planned, encrypted, passphrase), /WRONG_SIGNING_KEY/);
 assert.ok(planPurchaseAdmission(targets, reviewedRequest, review, bytes, now, key).reuse, 'rerun reuses the activated policy');
});

test('new admission requires review of the exact source, installer, platform, bundle and previous policy', () => {
 const { targets, review, previous } = reviewCase();
 assert.throws(() => planPurchaseAdmission(targets, reviewedRequest, undefined, previous, now, key), /NOT_ADMITTED/);
 for (const field of ['sourceCommit', 'sourceSha256', 'previousPolicySha256']) {
  assert.throws(() => planPurchaseAdmission(targets, reviewedRequest, { ...review, [field]: '0'.repeat(64) }, previous, now, key), /REVIEW_IDENTITY_MISMATCH/);
 }
 for (const field of ['implementationSha256', 'canonicalBundleSha256', 'installerSha256', 'architecture', 'acceptance']) {
  const modified = { ...review, targets: [{ ...review.targets[0], [field]: 'INVALID' }] };
  assert.throws(() => planPurchaseAdmission(targets, reviewedRequest, modified, previous, now, key), /REVIEW_TARGET_MISMATCH/);
 }
 const otherKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
 assert.throws(() => planPurchaseAdmission(targets, reviewedRequest, review, previous, now, otherKey), /POLICY_SIGNATURE/);
});

test('expiring policy renews with a matching review and keeps one entry per existing implementation', () => {
 const { targets, review, previous } = reviewCase(policy({ expiresAt: '2026-11-10T11:00:00Z' }), identity);
 assert.throws(() => planPurchaseAdmission(targets, reviewedRequest, undefined, previous, now, key), /EXPIRED/);
 const planned = planPurchaseAdmission(targets, reviewedRequest, review, previous, now, key);
 assert.deepEqual(planned.payload.implementations, JSON.parse(previous).payload.implementations);
 assert.equal(Date.parse(planned.payload.expiresAt) - now, 30 * 86_400_000);
});

function publicationCase({ failPromotion = false, ambiguousPromotion = false, publicStale = false } = {}) {
 const previous = Buffer.from('old approved metadata'), next = Buffer.from('new approved metadata');
 const describe = (id, name, bytes) => ({ id, name, size: bytes.length, state: 'uploaded' });
 const records = new Map([[10, describe(10, 'protocol.json', previous)]]);
 const contents = new Map([[10, previous]]);
 const archiveName = 'protocol-before-4.json', pendingName = 'protocol-4.pending.json';
 const change = { plan: { previousSha256: sha256(previous) }, releaseId: '77', policy: { ...records.get(10) }, archiveName, pendingName };
 const history = [];
 const client = {
  async upload(releaseId, name, bytes) {
   assert.equal(releaseId, '77');
   history.push(['upload', name]);
   contents.set(20, bytes); records.set(20, describe(20, name, bytes));
   return { ...records.get(20) };
  },
  async download(id, size) {
   assert.equal(contents.get(id).length, size);
   return { sha256: sha256(contents.get(id)) };
  },
  async api(path, method, body) {
   if (path === '/releases/77/assets?per_page=100') return [...records.values()].map(asset => ({ ...asset }));
   assert.equal(method, 'PATCH');
   const id = Number(path.split('/').at(-1));
   history.push([id, body.name]);
   if (id === 20 && failPromotion) throw Error('TEST_PROMOTION_FAILED');
   assert.ok(![...records.values()].some(asset => asset.name === body.name));
   records.set(id, { ...records.get(id), name: body.name });
   if (id === 20 && ambiguousPromotion) throw Error('TEST_PROMOTION_RESPONSE_LOST');
   return { ...records.get(id) };
  },
 };
 const fetcher = async (url, options) => {
  assert.equal(String(url), 'https://github.com/' + REPOSITORY + '/releases/download/purchase-compatibility-v1/protocol.json');
  assert.equal(options.headers, undefined);
  const active = [...records.values()].find(asset => asset.name === 'protocol.json');
  if (publicStale && active?.id === 20) return new Response(previous);
  return new Response(contents.get(active?.id));
 };
 return { activate: () => activatePurchasePolicy(client, change, next, fetcher, async () => {}),
  records, history, archiveName, pendingName };
}

test('verified staged policy becomes public before the preserved old asset can be dropped', async () => {
 const h = publicationCase();
 await h.activate();
 assert.deepEqual(h.history, [['upload', h.pendingName], [10, h.archiveName], [20, 'protocol.json']]);
 assert.equal(h.records.get(10).name, h.archiveName);
 assert.equal(h.records.get(20).name, 'protocol.json');
});

test('failed promotion restores the original public name when the slot is empty', async () => {
 const h = publicationCase({ failPromotion: true });
 await assert.rejects(h.activate(), /TEST_PROMOTION_FAILED/);
 assert.equal(h.records.get(10).name, 'protocol.json');
 assert.equal(h.records.get(20).name, h.pendingName);
});

test('lost promotion response never overwrites an active new policy', async () => {
 const h = publicationCase({ ambiguousPromotion: true });
 await assert.rejects(h.activate(), /TEST_PROMOTION_RESPONSE_LOST/);
 assert.equal(h.records.get(10).name, h.archiveName);
 assert.equal(h.records.get(20).name, 'protocol.json');
 assert.equal(h.history.length, 3);
});

test('anonymous readback must see the new revision before installer publication can continue', async () => {
 const h = publicationCase({ publicStale: true });
 await assert.rejects(h.activate(), /PUBLIC_PURCHASE_POLICY_READBACK_MISMATCH/);
 assert.equal(h.records.get(10).name, h.archiveName);
});
