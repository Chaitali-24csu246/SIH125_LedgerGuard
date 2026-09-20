import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import request from 'supertest';
import pg from 'pg';
import {memoryPool} from './database.mjs';
import {fixture} from './fixture.mjs';
import {createApp} from '../server/app.mjs';
let f,pool,app,admin,user,auditor,manager;
async function login(i){const c=await request(app).post('/api/auth/challenge').send({controller:f.wallets[i].address});assert.equal(c.status,200);const r=await request(app).post('/api/auth/verify').send({id:c.body.id,signature:await f.wallets[i].signMessage(c.body.message)});assert.equal(r.status,200);return r.body.token;}
const auth=t=>({Authorization:'Bearer '+t});
before(async()=>{
 f=await fixture();
 if(process.env.TEST_DATABASE_URL){pool=new pg.Pool({connectionString:process.env.TEST_DATABASE_URL});await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');}
 else {pool=await memoryPool();}
 ({app}=await createApp({...f,pool,encryptionKey:crypto.randomBytes(32),advisory:!!process.env.TEST_DATABASE_URL,rateLimit:10000}));
 admin=await login(0);manager=await login(1);auditor=await login(2);user=await login(3);
});
after(async()=>{await pool?.end();await f?.close();});
test('Forged role header grants no authority',async()=>{
 const r=await request(app).post('/api/files').set('X-Role','ADMIN').send({});assert.equal(r.status,401);
 const r2=await request(app).post('/api/files').set(auth(user)).set('X-Role','ADMIN').send({});assert.equal(r2.status,403);
});
test('Signed authentication rejects replay and wrong-key proofs',async()=>{
 const c=await request(app).post('/api/auth/challenge').send({controller:f.wallets[3].address});const payload={id:c.body.id,signature:await f.wallets[3].signMessage(c.body.message)};
 const results=await Promise.all([request(app).post('/api/auth/verify').send(payload),request(app).post('/api/auth/verify').send(payload)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,401]);
 const other=await request(app).post('/api/auth/challenge').send({controller:f.wallets[3].address});const bad=await request(app).post('/api/auth/verify').send({id:other.body.id,signature:await f.wallets[4].signMessage(other.body.message)});assert.equal(bad.status,401);
});
test('Origin restrictions reject cross-origin authenticated requests',async()=>{const r=await request(app).get('/api/me').set(auth(user)).set('Origin','https://untrusted.example');assert.equal(r.status,403);});
test('Expired challenges fail even with the correct signature',async()=>{
 const c=await request(app).post('/api/auth/challenge').send({controller:f.wallets[3].address});
 await pool.query('UPDATE challenges SET expires_at=$1 WHERE id=$2',[new Date(Date.now()-1000),c.body.id]);
 const r=await request(app).post('/api/auth/verify').send({id:c.body.id,signature:await f.wallets[3].signMessage(c.body.message)});assert.equal(r.status,401);
});
test('Encrypted upload, mint, ownership ACL and ciphertext tamper rejection',async()=>{
 const bytes=Buffer.from('Synthetic confidential test document');const uploaded=await request(app).post('/api/files').set(auth(admin)).send({name:'sample.txt',code:'API-001',description:'Test',mime:'text/plain',data:bytes.toString('base64')});assert.equal(uploaded.status,201);
 const id=Number(await f.platform.nextId());await(await f.platform.mint(uploaded.body.codeHash,uploaded.body.contentHash,uploaded.body.uri)).wait();await(await f.platform.allocate(id,f.wallets[3].address)).wait();
 const denied=await request(app).get(`/api/assets/${id}/content`).set(auth(manager));assert.equal(denied.status,403);
 const allowed=await request(app).get(`/api/assets/${id}/content`).set(auth(user));assert.equal(allowed.status,200);assert.deepEqual(allowed.body,bytes);
 const row=(await pool.query('SELECT * FROM files WHERE id=$1',[uploaded.body.fileId])).rows[0];assert.notDeepEqual(row.encrypted,bytes);
 const changed=Buffer.from(row.encrypted);changed[0]^=1;await pool.query('UPDATE files SET encrypted=$1 WHERE id=$2',[changed,row.id]);
 const tampered=await request(app).get(`/api/assets/${id}/content`).set(auth(user));assert.equal(tampered.status,409);
 await pool.query('UPDATE files SET encrypted=$1 WHERE id=$2',[row.encrypted,row.id]);
 await request(app).post(`/api/assets/${id}/cache`).set(auth(admin));await pool.query('UPDATE asset_cache SET owner=$1 WHERE token_id=$2',[f.wallets[4].address,id]);
 const check=await request(app).get(`/api/assets/${id}/integrity`).set(auth(auditor));assert.equal(check.body.status,'MISMATCH');assert.equal(check.body.chainOwner,f.wallets[3].address);
});
test('Previously authenticated session cannot retain a revoked audit role',async()=>{
 assert.equal((await request(app).get('/api/audit').set(auth(auditor))).status,200);
 await(await f.platform.setRole(f.wallets[2].address,0)).wait();assert.equal((await request(app).get('/api/audit').set(auth(auditor))).status,403);
 await(await f.platform.setRole(f.wallets[2].address,3)).wait();
});
test('Audit assistant enforces permissions, filtering, minimised context and receipt scope',async()=>{
 assert.equal((await request(app).post('/api/audit-assistant').send({})).status,401);
 assert.equal((await request(app).post('/api/audit-assistant').set(auth(user)).send({})).status,403);
 assert.equal((await request(app).post('/api/audit-assistant').set(auth(auditor)).send({hours:999})).status,400);
 const response=await request(app).post('/api/audit-assistant').set(auth(auditor)).send({hours:24,identity:f.wallets[1].address});
 assert.equal(response.status,200);assert.equal(response.body.mode,'rules-only');
 assert.ok(response.body.evidence.every(e=>e.source!=='security'||e.actor.toLowerCase()===f.wallets[1].address.toLowerCase()));
 assert.ok(response.body.evidence.every(e=>!('details' in e)&&!('encrypted' in e)));
 await(await f.platform.setRole(f.wallets[2].address,0)).wait();
 assert.equal((await request(app).post('/api/audit-assistant').set(auth(auditor)).send({})).status,403);
 await(await f.platform.setRole(f.wallets[2].address,3)).wait();
 const tx=await f.platform.anchorEvidence('0x'+'ab'.repeat(32),'audit-test');await tx.wait();
 const rejected=await f.platform.connect(f.signers[3]).setPaused(true,{gasLimit:200000});await rejected.wait().catch(()=>{});
 const receipts=await request(app).post('/api/audit-assistant').set(auth(auditor)).send({transactionHashes:[tx.hash,rejected.hash]});
 assert.equal(receipts.status,200);assert.equal(receipts.body.counts.confirmed,1);assert.equal(receipts.body.counts.reverted,1);
});
test('Audit assistant withholds output if permission is revoked during model inference',async()=>{
 const configured=await createApp({...f,pool,encryptionKey:crypto.randomBytes(32),advisory:false,rateLimit:10000,auditAI:{url:'http://localhost:11434',model:'test',fetchImpl:async()=>{
  await(await f.platform.setRole(f.wallets[2].address,0)).wait();
  return new Response(JSON.stringify({message:{content:'{"findings":[]}'}}));
 }}});
 const response=await request(configured.app).post('/api/audit-assistant').set(auth(auditor)).send({useAI:true});
 assert.equal(response.status,403);assert.equal(response.body.evidence,undefined);
 await(await f.platform.setRole(f.wallets[2].address,3)).wait();
});
test('Suspension and controller rotation invalidate sessions',async()=>{
 await(await f.platform.setSuspended(f.wallets[3].address,true)).wait();assert.equal((await request(app).get('/api/me').set(auth(user))).status,401);
 await(await f.platform.setSuspended(f.wallets[3].address,false)).wait();
 await(await f.registry.connect(f.signers[3]).rotate(f.wallets[8].address)).wait();assert.equal((await request(app).get('/api/me').set(auth(user))).status,401);
});
test('Log chain detects altered history and anchored deletion',async()=>{
 const first=(await request(app).get('/api/security').set(auth(auditor))).body;assert.equal(first.verification.valid,true);
 await(await f.platform.anchorEvidence('0x'+first.verification.head,'security-log')).wait();
 const last=(await pool.query('SELECT id FROM security_logs ORDER BY id DESC LIMIT 1')).rows[0];await pool.query('DELETE FROM security_logs WHERE id=$1',[last.id]);
 const missing=(await request(app).get('/api/security').set(auth(auditor))).body;assert.equal(missing.missingAnchors.length,1);
 const row=(await pool.query('SELECT id FROM security_logs ORDER BY id LIMIT 1')).rows[0];await pool.query('UPDATE security_logs SET outcome=$1 WHERE id=$2',['FORGED',row.id]);
 const changed=(await request(app).get('/api/security').set(auth(auditor))).body;assert.equal(changed.verification.valid,false);
});
test('Rate limiting stops repeated requests with a retry interval',async()=>{
 await pool.query('DELETE FROM rate_limits');
 const limited=await createApp({...f,pool,encryptionKey:crypto.randomBytes(32),advisory:false,rateLimit:2});
 assert.equal((await request(limited.app).get('/api/health')).status,200);
 assert.equal((await request(limited.app).get('/api/health')).status,200);
 const last=await request(limited.app).get('/api/health');assert.equal(last.status,429);assert.equal(last.headers['retry-after'],'60');
});
