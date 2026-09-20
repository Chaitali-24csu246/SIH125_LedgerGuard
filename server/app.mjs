import express from 'express';
import {summarizeEvidence,explainEvidence} from './audit-assistant.mjs';
import helmet from 'helmet';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {z} from 'zod';
import {getAddress,verifyMessage,Contract,keccak256,toUtf8Bytes} from 'ethers';
import {sha,canonical,encrypt,decrypt,makeLogger,verifyLogs} from './security.mjs';

const address=z.string().refine(v=>{try{getAddress(v);return true;}catch{return false;}},'Invalid address').transform(v=>getAddress(v));
const idSchema=z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const ZERO='0x0000000000000000000000000000000000000000';
const roles=['Unassigned','Admin','Manager','Auditor','User'];
export async function createApp({pool,provider,deployment,artifacts,encryptionKey,origin='http://localhost:8080',nodeUrls=[],advisory=true,rateLimit=120,auditAI={}}) {
 if(encryptionKey.length!==32) throw Error('Encryption key must contain 32 bytes');
 await pool.query(fs.readFileSync(new URL('./schema.sql',import.meta.url),'utf8'));
 const registry=new Contract(deployment.registry,artifacts.IdentityRegistry.abi,provider);
 const platform=new Contract(deployment.platform,artifacts.AssetPlatform.abi,provider);
 const log=makeLogger(pool,{advisory});
 const app=express(); app.disable('x-powered-by');
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'",'http://localhost:8545','http://127.0.0.1:8545'],objectSrc:["'none'"],frameAncestors:["'none'"],upgradeInsecureRequests:null}}}));
 app.use(express.json({limit:'3mb'}));
 app.use('/api',async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  if(req.headers.origin && req.headers.origin!==origin) return res.status(403).json({error:'Origin not allowed'});
  const requestId=crypto.randomUUID();res.set('X-Request-ID',requestId);req.requestId=requestId;
  try {
   const bucket=`${req.ip}:${req.path.startsWith('/auth')?'auth':'api'}`;
   const limit=req.path.startsWith('/auth')?30:rateLimit;
   await pool.query('DELETE FROM rate_limits WHERE bucket=$1 AND expires_at < now()',[bucket]);
   const result=await pool.query("INSERT INTO rate_limits(bucket,hits,expires_at) VALUES($1,1,now() + interval '1 minute') ON CONFLICT(bucket) DO UPDATE SET hits=rate_limits.hits+1 RETURNING hits",[bucket]);
   if(result.rows[0].hits>limit) {res.set('Retry-After','60');return res.status(429).json({error:'Too many requests. Try again in a minute.'});}
   next();
  }catch(e){next(e);}
 });
 const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
 app.get('/api/config',(req,res)=>res.json({chainId:deployment.chainId,registry:deployment.registry,platform:deployment.platform,registryAbi:artifacts.IdentityRegistry.abi,platformAbi:artifacts.AssetPlatform.abi,method:'did:sih',rpcUrl:'http://localhost:8545'}));
 app.get('/api/health',wrap(async(req,res)=>{await pool.query('SELECT 1');res.json({ok:true,block:await provider.getBlockNumber(),chainId:Number((await provider.getNetwork()).chainId)});}));
 app.post('/api/auth/challenge',wrap(async(req,res)=>{
  const controller=address.parse(req.body.controller);const id=crypto.randomUUID();const expires=new Date(Date.now()+120000);
  const message=`LedgerGuard authentication\nOrigin: ${origin}\nChain ID: ${deployment.chainId}\nRegistry: ${deployment.registry}\nController: ${controller}\nNonce: ${crypto.randomBytes(24).toString('hex')}\nExpires: ${expires.toISOString()}\nChallenge: ${id}`;
  await pool.query('INSERT INTO challenges(id,controller,message,expires_at) VALUES($1,$2,$3,$4)',[id,controller,message,expires]);
  res.json({id,message,expiresAt:expires});
 }));
 app.post('/api/auth/verify',wrap(async(req,res)=>{
  const body=z.object({id:z.string().uuid(),signature:z.string().max(300)}).parse(req.body);
  // Atomic consume: even concurrent replays cannot create a second session.
  const result=await pool.query('UPDATE challenges SET used=true WHERE id=$1 AND used=false AND expires_at > now() RETURNING *',[body.id]);
  const row=result.rows[0];if(!row) return res.status(401).json({error:'Challenge expired or already used'});
  let recovered;try{recovered=verifyMessage(row.message,body.signature);}catch{recovered=ZERO;}
  if(recovered.toLowerCase()!==row.controller.toLowerCase()){await log(row.controller,'AUTH','DENIED','Signature mismatch');return res.status(401).json({error:'Invalid signature'});}
  const identity=await registry.identityForController(recovered);
  if(!await registry.active(identity) || await platform.suspended(identity)) return res.status(403).json({error:'Identity inactive, unregistered or suspended'});
  const token=crypto.randomBytes(32).toString('base64url');
  await pool.query('INSERT INTO sessions(token_hash,identity,controller,identity_version,expires_at) VALUES($1,$2,$3,$4,$5)',[sha(token),identity,recovered,Number(await registry.versionOf(identity)),new Date(Date.now()+1800000)]);
  await log(identity,'AUTH','ALLOWED','Signed challenge');res.json({token,identity,expiresIn:1800});
 }));
 async function auth(req,res,next) {
  try {
   const token=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization||'')?.[1];
   if(!token) return res.status(401).json({error:'Signed authentication required'});
   const q=await pool.query('SELECT * FROM sessions WHERE token_hash=$1 AND expires_at > now()',[sha(token)]);const s=q.rows[0];
   if(!s) return res.status(401).json({error:'Session expired'});
   const [active,controller,version,suspended]=await Promise.all([registry.active(s.identity),registry.controllerOf(s.identity),registry.versionOf(s.identity),platform.suspended(s.identity)]);
   if(!active || suspended || controller.toLowerCase()!==s.controller.toLowerCase() || Number(version)!==Number(s.identity_version)) return res.status(401).json({error:'Identity changed or access suspended. Sign in again.'});
   req.identity=s.identity;req.tokenHash=sha(token);req.role=Number(await platform.roles(s.identity));next();
  }catch(e){next(e);}
 }
 const admin=wrap(async(req,res,next)=>{if(!await platform.isAdmin(req.identity)){await log(req.identity,req.path,'DENIED','Admin required');return res.status(403).json({error:'Admin permission required'});}next();});
 const auditor=wrap(async(req,res,next)=>{if(!await platform.can(req.identity,2)) return res.status(403).json({error:'Audit permission required'});next();});
 app.use('/api',auth);
 app.get('/api/me',wrap(async(req,res)=>{const identity=await registry.identities(req.identity),recovery=await registry.recoveries(req.identity);res.json({identity:req.identity,role:roles[req.role],roleId:req.role,guardian:identity.guardian,version:Number(identity.version),recovery:{controller:recovery.controller,readyAt:Number(recovery.readyAt)},canAudit:await platform.can(req.identity,2),canTransfer:await platform.can(req.identity,1),canCatalogue:await platform.can(req.identity,4),paused:await platform.paused()});}));
 app.post('/api/auth/logout',wrap(async(req,res)=>{await pool.query('DELETE FROM sessions WHERE token_hash=$1',[req.tokenHash]);res.json({ok:true});}));
 const did=id=>`did:sih:${deployment.chainId}:${id.toLowerCase()}`;
 app.get('/api/identities',wrap(async(req,res)=>{
  if(!await platform.can(req.identity,4) && req.role!==0) return res.status(403).json({error:'Catalogue permission required'});
  const count=Number(await registry.count());const result=[];
  for(let i=0;i<count;i++){const id=await registry.members(i);const data=await registry.identities(id);const role=Number(await platform.roles(id));const recovery=await registry.recoveries(id);
   result.push({identity:id,did:did(id),controller:data.controller,guardian:data.guardian,active:data.active,version:Number(data.version),role:roles[role],roleId:role,suspended:await platform.suspended(id),recovery:{controller:recovery.controller,readyAt:Number(recovery.readyAt)}});
  }res.json(result);
 }));
 app.get('/api/did/:identity',wrap(async(req,res)=>{
  const id=address.parse(req.params.identity);const data=await registry.identities(id);if(data.controller===ZERO)return res.status(404).json({error:'Unknown identity'});
  const document={id:did(id),verificationMethod:[{id:did(id)+'#controller',type:'EcdsaSecp256k1RecoveryMethod2020',controller:did(id),blockchainAccountId:`eip155:${deployment.chainId}:${data.controller}`}],authentication:[did(id)+'#controller'],assertionMethod:[did(id)+'#controller']};
  res.json({didDocument:document,didDocumentMetadata:{deactivated:!data.active,versionId:String(data.version)},didResolutionMetadata:{contentType:'application/did+json',prototypeMethod:true}});
 }));
 app.get('/api/policies',wrap(async(req,res)=>res.json(await Promise.all([1,2,3,4].map(async role=>({role:roles[role],roleId:role,bits:Number(await platform.permissions(role))}))))));
 app.post('/api/files',admin,wrap(async(req,res)=>{
  const b=z.object({name:z.string().trim().min(1).max(120),code:z.string().trim().min(1).max(80).regex(/^[A-Za-z0-9._-]+$/),description:z.string().max(1000).default(''),mime:z.string().max(100),data:z.string().max(2800000)}).parse(req.body);
  if(!/^[A-Za-z0-9+/]*={0,2}$/.test(b.data)) return res.status(400).json({error:'Invalid base64'});
  const bytes=Buffer.from(b.data,'base64');if(!bytes.length || bytes.length>2*1024*1024)return res.status(400).json({error:'File must be between 1 byte and 2 MiB'});
  const fileId=crypto.randomUUID(),digest=sha(bytes),encrypted=encrypt(bytes,encryptionKey);
  await pool.query('INSERT INTO files(id,name,code,description,mime,digest,encrypted,nonce,tag,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[fileId,b.name,b.code,b.description,b.mime,digest,encrypted.encrypted,encrypted.nonce,encrypted.tag,req.identity]);
  await log(req.identity,'FILE_STAGED','ALLOWED',fileId);
  res.status(201).json({uri:`urn:ledgerguard:${fileId}`,contentHash:'0x'+digest,codeHash:keccak256(toUtf8Bytes(b.code.toUpperCase())),fileId});
 }));
 async function assetData(id,identity) {
  const a=await platform.assets(id),owner=await platform.ownerOf(id);
  const fileId=/^urn:ledgerguard:([a-f0-9-]{36})$/.exec(a.uri)?.[1];
  const f=fileId?(await pool.query('SELECT id,name,code,description,digest,mime FROM files WHERE id=$1',[fileId])).rows[0]:null;
  return {id,owner,ownerDid:owner.toLowerCase()===deployment.platform.toLowerCase()?null:did(owner),allocated:owner.toLowerCase()!==deployment.platform.toLowerCase(),retired:a.retired,uri:a.uri,contentHash:a.contentHash,codeHash:a.codeHash,name:f?.name||`Asset #${id}`,code:f?.code||a.codeHash.slice(0,12),description:f?.description||'',metadataVerified:!!f&&'0x'+f.digest===a.contentHash&&keccak256(toUtf8Bytes(f.code.toUpperCase()))===a.codeHash,canRead:await platform.canRead(id,identity)};
 }
 app.get('/api/assets',wrap(async(req,res)=>{
  const start=Math.max(1,Number(req.query.start)||1);const max=Math.min(Number(await platform.nextId()),start+100);const catalogue=await platform.can(req.identity,4);const items=[];
  for(let id=start;id<max;id++){if(!catalogue && !await platform.canRead(id,req.identity))continue;items.push(await assetData(id,req.identity));}
  res.json({items,next:max<Number(await platform.nextId())?max:null});
 }));
 app.get('/api/assets/:id/content',wrap(async(req,res)=>{
  const id=idSchema.parse(req.params.id);
  if(!await platform.canRead(id,req.identity)){await log(req.identity,'FILE_READ','DENIED',String(id));return res.status(403).json({error:'Current on-chain policy denies access'});}
  const a=await platform.assets(id);const fileId=/^urn:ledgerguard:([a-f0-9-]{36})$/.exec(a.uri)?.[1];
  const row=fileId?(await pool.query('SELECT * FROM files WHERE id=$1',[fileId])).rows[0]:null;
  if(!row)return res.status(404).json({error:'File unavailable'});
  let bytes;try{bytes=decrypt(row,encryptionKey);}catch{await log(req.identity,'FILE_INTEGRITY','DENIED',String(id));return res.status(409).json({error:'Encrypted file integrity verification failed'});}
  if('0x'+sha(bytes)!==a.contentHash){await log(req.identity,'FILE_INTEGRITY','DENIED',String(id));return res.status(409).json({error:'Content integrity mismatch'});}
  // Recheck after decryption so a policy change during work is less likely to use stale authority.
  if(!await platform.canRead(id,req.identity))return res.status(403).json({error:'Access changed'});
  await log(req.identity,'FILE_READ','ALLOWED',String(id));
  res.set('Content-Type','application/octet-stream');res.set('Content-Disposition',`attachment; filename="${row.name.replace(/[^a-zA-Z0-9._-]/g,'_')}"`);res.send(bytes);
 }));
 app.post('/api/assets/:id/cache',admin,wrap(async(req,res)=>{
  const id=idSchema.parse(req.params.id),owner=await platform.ownerOf(id),block=await provider.getBlockNumber();
  await pool.query('INSERT INTO asset_cache(token_id,owner,block_number) VALUES($1,$2,$3) ON CONFLICT(token_id) DO UPDATE SET owner=$2,block_number=$3,updated_at=now()',[id,owner,block]);res.json({ok:true});
 }));
 app.get('/api/assets/:id/integrity',auditor,wrap(async(req,res)=>{
  const id=idSchema.parse(req.params.id),owner=await platform.ownerOf(id);const cache=(await pool.query('SELECT * FROM asset_cache WHERE token_id=$1',[id])).rows[0];
  res.json({tokenId:id,chainOwner:owner,cachedOwner:cache?.owner||null,status:!cache?'NOT_INDEXED':cache.owner.toLowerCase()===owner.toLowerCase()?'MATCH':'MISMATCH',blockNumber:await provider.getBlockNumber()});
 }));
 async function chainEvents(from,to) {
  const output=[];
  for(const [kind,contract] of [['Identity',registry],['Asset',platform]]) {
   const logs=await provider.getLogs({address:await contract.getAddress(),fromBlock:from,toBlock:to});
   for(const l of logs){try{const event=contract.interface.parseLog(l);const args={};event.fragment.inputs.forEach((p,i)=>args[p.name]=typeof event.args[i]==='bigint'?event.args[i].toString():event.args[i]);output.push({kind,event:event.name,args,transactionHash:l.transactionHash,blockNumber:l.blockNumber,index:l.index,address:l.address});}catch{}}
  }return output.sort((a,b)=>b.blockNumber-a.blockNumber||b.index-a.index);
 }
 app.get('/api/audit',auditor,wrap(async(req,res)=>{
  const head=await provider.getBlockNumber();const to=Math.min(head,Math.max(0,Number(req.query.to)||head));const from=Math.max(deployment.blockNumber||0,to-1999);
  res.json({source:'Besu JSON-RPC',fromBlock:from,toBlock:to,previousTo:from>(deployment.blockNumber||0)?from-1:null,events:await chainEvents(from,to)});
 }));
 app.get('/api/network',auditor,wrap(async(req,res)=>{
  const head=await provider.getBlockNumber();const block=await provider.getBlock(head);const nodes=[];
  for(const url of nodeUrls){try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_blockNumber',params:[]}),signal:AbortSignal.timeout(1500)});const j=await r.json();if(!j.result)throw Error();nodes.push({node:nodes.length+1,online:true,block:parseInt(j.result,16)});}catch{nodes.push({node:nodes.length+1,online:false});}}
  res.json({chainId:deployment.chainId,block:head,hash:block?.hash,parentHash:block?.parentHash,timestamp:block?.timestamp,validators:nodes,contracts:{registry:deployment.registry,platform:deployment.platform}});
 }));
 app.get('/api/transactions/:hash',auditor,wrap(async(req,res)=>{
  const hash=z.string().regex(/^0x[a-fA-F0-9]{64}$/).parse(req.params.hash);
  const transaction=await provider.getTransaction(hash);if(!transaction)return res.status(404).json({error:'Transaction not found on this chain'});
  const receipt=await provider.getTransactionReceipt(hash);
  res.json({hash,from:transaction.from,to:transaction.to,status:!receipt?'PENDING':receipt.status===1?'CONFIRMED':'REVERTED',blockNumber:receipt?.blockNumber||null,gasUsed:receipt?.gasUsed.toString()||null,logCount:receipt?.logs.length||0,note:receipt?.status===0?'Reverted transactions keep a failed receipt but do not retain emitted contract logs.':undefined});
 }));
 app.get('/api/security',auditor,wrap(async(req,res)=>{
  const rows=(await pool.query('SELECT * FROM security_logs ORDER BY id')).rows;const verification=verifyLogs(rows);
  const anchors=await platform.queryFilter(platform.filters.EvidenceAnchored(),deployment.blockNumber||0,'latest');
  const anchored=new Set(anchors.filter(x=>x.args.category==='security-log').map(x=>x.args.digest.slice(2)));
  const anchorMatches=rows.filter(r=>anchored.has(r.digest)).map(r=>r.id);
  res.json({logs:rows.slice(-200).reverse(),verification,anchorMatches,anchorCount:anchored.size,missingAnchors:[...anchored].filter(h=>!rows.some(r=>r.digest===h))});
 }));
 const auditJobs=new Set();
 app.post('/api/audit-assistant',auditor,wrap(async(req,res)=>{
  const b=z.object({hours:z.number().int().min(1).max(168).default(24),identity:address.optional(),transactionHashes:z.array(z.string().regex(/^0x[a-fA-F0-9]{64}$/)).max(5).default([]),useAI:z.boolean().default(false)}).strict().parse(req.body);
  if(auditJobs.size>=2)return res.status(429).json({error:'Audit assistant busy. Try again shortly.'});
  const bucket='audit-assistant:'+req.identity.toLowerCase();
  await pool.query('DELETE FROM rate_limits WHERE bucket=$1 AND expires_at < now()',[bucket]);
  const quota=await pool.query("INSERT INTO rate_limits(bucket,hits,expires_at) VALUES($1,1,now() + interval '1 minute') ON CONFLICT(bucket) DO UPDATE SET hits=rate_limits.hits+1 RETURNING hits",[bucket]);
  if(quota.rows[0].hits>3)return res.status(429).json({error:'Limit: three audit reports per identity per minute.'});
  if(auditJobs.size>=2)return res.status(429).json({error:'Audit assistant busy. Try again shortly.'});
  const job=crypto.randomUUID();auditJobs.add(job);
  try{
   const now=new Date(),since=new Date(now.getTime()-b.hours*3600000).toISOString(),until=now.toISOString();
   const rows=(await pool.query('SELECT id,at,actor,action,outcome,digest FROM security_logs WHERE at >= $1 AND at <= $2'+(b.identity?' AND lower(actor)=$3':'')+' ORDER BY id DESC LIMIT 101',b.identity?[since,until,b.identity.toLowerCase()]:[since,until])).rows;
   const evidence=rows.slice(0,100).map(r=>({id:'log:'+r.id,source:'security',at:r.at,actor:r.actor,action:r.action.slice(0,80),outcome:r.outcome,digest:r.digest}));
   const head=await provider.getBlockNumber(),from=Math.max(deployment.blockNumber||0,head-1999);
   const events=await chainEvents(from,head),blocks=new Map();
   let matching=events;
   if(b.identity)matching=events.filter(e=>Object.values(e.args).some(v=>typeof v==='string'&&v.toLowerCase()===b.identity.toLowerCase()));
   const candidates=matching.slice(0,100);
   for(const e of candidates){
    if(!blocks.has(e.blockNumber))blocks.set(e.blockNumber,await provider.getBlock(e.blockNumber));
    const block=blocks.get(e.blockNumber);if(!block)continue;
    const at=new Date(block.timestamp*1000).toISOString();if(at<since||at>until)continue;
    const args=Object.fromEntries(Object.entries(e.args).filter(([,v])=>typeof v==='boolean'||(typeof v==='string'&&(/^(0x[a-fA-F0-9]+|[0-9]+)$/.test(v)))));
    evidence.push({id:'chain:'+e.transactionHash+':'+e.index,source:'chain',at,event:e.event,args,transactionHash:e.transactionHash,blockNumber:e.blockNumber});
   }
   const receiptNotes=[];
   for(const hash of [...new Set(b.transactionHashes)]){
    const tx=await provider.getTransaction(hash),receipt=await provider.getTransactionReceipt(hash);
    if(!tx||![deployment.registry,deployment.platform].some(a=>a.toLowerCase()===tx.to?.toLowerCase())){receiptNotes.push({hash,note:'Not a transaction to a LedgerGuard contract.'});continue;}
    if(!receipt){receiptNotes.push({hash,note:'No mined receipt available.'});continue;}
    const block=await provider.getBlock(receipt.blockNumber);if(!block)continue;
    const at=new Date(block.timestamp*1000).toISOString();
    // A controller address is not interchangeable with a stable identity after rotation.
    if(b.identity){receiptNotes.push({hash,note:'Receipt excluded from identity-filtered report; historical controller attribution is not established.'});continue;}
    if(at<since||at>until){receiptNotes.push({hash,note:'Outside selected time window.'});continue;}
    evidence.push({id:'tx:'+hash,source:'receipt',at,from:tx.from,to:tx.to,outcome:receipt.status===1?'CONFIRMED':'REVERTED',transactionHash:hash,blockNumber:receipt.blockNumber});
   }
   const summary=summarizeEvidence(evidence);
   const ai=b.useAI&&evidence.length?await explainEvidence(evidence,summary,auditAI):{mode:'rules-only',findings:[],notice:'Rule-calculated report. AI explanation was not requested or no evidence was found.'};
   // Recheck after potentially slow inference; revoked audit authority cannot receive the report.
   if(!await registry.active(req.identity)||await platform.suspended(req.identity)||!await platform.can(req.identity,2))return res.status(403).json({error:'Audit permission changed during report generation'});
   const session=(await pool.query('SELECT * FROM sessions WHERE token_hash=$1 AND expires_at > now()',[req.tokenHash])).rows[0];
   if(!session||Number(await registry.versionOf(req.identity))!==Number(session.identity_version))return res.status(401).json({error:'Session changed. Sign in again.'});
   res.json({generatedAt:until,window:{since,until,identity:b.identity||null},coverage:{fromBlock:from,toBlock:head,securityTruncated:rows.length>100,chainTruncated:matching.length>100},...summary,...ai,evidence,receiptNotes,limitations:['Bounded sample: up to 100 application records and 100 contract events from the latest 2000 blocks. Counts describe included evidence only.','Reverted transactions require supplied receipt hashes; contract events alone do not include failures.','Application log digests are references, not proof of log completeness or verified checkpoints in this report.','Identity matching uses recorded actor/event addresses, not reconstructed historical wallet ownership.','No conclusion that the system is attack-free can be drawn from this report.']});
  }finally{auditJobs.delete(job);}
 }));
 app.get('/api/reports',auditor,wrap(async(req,res)=>res.json((await pool.query('SELECT * FROM experiment_reports ORDER BY created_at DESC LIMIT 20')).rows)));
 app.post('/api/reports',admin,wrap(async(req,res)=>{
  const report=z.object({title:z.string().max(120),environment:z.record(z.any()),tests:z.array(z.object({name:z.string(),passed:z.boolean(),details:z.string(),durationMs:z.number().nonnegative()}).passthrough()).max(1000)}).passthrough().parse(req.body);
  const digest=sha(canonical(report));const id=crypto.randomUUID();await pool.query('INSERT INTO experiment_reports(id,report,digest) VALUES($1,$2,$3)',[id,report,digest]);res.status(201).json({id,digest:'0x'+digest});
 }));
 app.use('/api',(req,res)=>res.status(404).json({error:'Endpoint not found'}));
 app.use(express.static('dist',{index:'index.html'}));
 app.use((err,req,res,next)=>{
  if(err instanceof z.ZodError)return res.status(400).json({error:err.issues.map(x=>x.message).join('; ')});
  if(err.type==='entity.too.large')return res.status(413).json({error:'Request too large'});
  if(err instanceof SyntaxError && 'body' in err)return res.status(400).json({error:'Malformed JSON'});
  console.error('Request failed',req.requestId,err.code||err.name);
  res.status(503).json({error:'Service could not verify this request. Check database and blockchain availability.',requestId:req.requestId});
 });
 return {app,registry,platform};
}
