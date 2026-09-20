import {test} from 'node:test';
import assert from 'node:assert/strict';
import {summarizeEvidence,validateFindings,explainEvidence} from '../server/audit-assistant.mjs';

const evidence=Array.from({length:5},(_,i)=>({id:'log:'+i,source:'security',actor:'0x123',at:new Date(1700000000000+i*60000).toISOString(),action:'FILE_READ',outcome:'DENIED'}));
test('Repeated-denial signal is windowed; events are not counted as transactions',()=>{
 const report=summarizeEvidence([...evidence,{id:'chain:1',source:'chain'},{id:'tx:1',source:'receipt',outcome:'REVERTED'}]);
 assert.equal(report.counts.denied,5);assert.equal(report.counts.contractEvents,1);assert.equal(report.counts.reverted,1);assert.equal(report.flags.length,1);
 assert.equal(summarizeEvidence(evidence.map((e,i)=>({...e,at:new Date(1700000000000+i*3600000).toISOString()}))).flags.length,0);
});
test('Model output rejects invented references and unexpected action fields',()=>{
 assert.throws(()=>validateFindings({findings:[{explanation:'Claim',evidenceIds:['unknown']}]},evidence));
 assert.throws(()=>validateFindings({findings:[],transfer:'asset'},evidence));
 assert.equal(validateFindings({findings:[{explanation:'Review denials',evidenceIds:['log:0']}]},evidence).length,1);
});
test('Inference uses no tools and returns only schema-validated advisory findings',async()=>{
 let sent;
 const result=await explainEvidence(evidence,summarizeEvidence(evidence),{url:'http://localhost:11434',model:'test',fetchImpl:async(url,options)=>{sent=JSON.parse(options.body);return new Response(JSON.stringify({message:{content:JSON.stringify({findings:[{explanation:'Review repeated denials',evidenceIds:['log:0']}]})}}));}});
 assert.equal(result.mode,'ai-assisted');assert.equal(sent.tools,undefined);assert.equal(sent.stream,false);assert.match(sent.messages[0].content,/untrusted/);
});
test('Unavailable or invalid models fall back honestly',async()=>{
 const settings={url:'http://localhost:11434',model:'test'};
 for(const fetchImpl of [async()=>{throw Error('offline');},async()=>new Response(JSON.stringify({message:{content:'{"findings":[{"explanation":"fake","evidenceIds":["unknown"]}]}'}}))])assert.equal((await explainEvidence(evidence,{}, {...settings,fetchImpl})).mode,'rules-only');
 assert.equal((await explainEvidence(evidence,{})).mode,'rules-only');
});
