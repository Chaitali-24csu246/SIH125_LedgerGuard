import React,{useState} from 'react';

export default function AuditAssistant({api}){
 const [report,setReport]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
 async function generate(e){
  e.preventDefault();const form=new FormData(e.currentTarget);setBusy(true);setError('');setReport(null);
  try{const identity=String(form.get('identity')).trim();const hashes=String(form.get('hashes')).trim();setReport(await api('/audit-assistant',{method:'POST',body:JSON.stringify({hours:Number(form.get('hours')),...(identity?{identity}:{}),transactionHashes:hashes?hashes.split(/[\s,]+/):[],useAI:form.get('useAI')==='on'})}));}
  catch(e){setError(e.message);}finally{setBusy(false);}
 }
 function save(){const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='ledgerguard-audit-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 return <section className="panel report audit-assistant"><h2>AI Audit Assistant</h2><p>Read-only investigation assistance. Reports never change roles, permissions or assets.</p>
  <form onSubmit={generate}>
   <label className="field"><span>Time window</span><select name="hours" disabled={busy}><option value="24">Last 24 hours</option><option value="1">Last hour</option><option value="168">Last 7 days</option></select></label>
   <label className="field"><span>Identity address (optional)</span><input name="identity" placeholder="0x… stable identity address" pattern="0x[a-fA-F0-9]{40}" disabled={busy}/></label>
   <label className="field"><span>Transaction hashes (optional, maximum five)</span><textarea name="hashes" maxLength={340} placeholder="Include receipt hashes to inspect successful or reverted transactions. Leave identity blank for receipt analysis." disabled={busy}/></label>
   <label><input name="useAI" type="checkbox" disabled={busy}/> Add AI explanations using the configured model</label>
   <p><button className="primary" disabled={busy}>{busy?'Preparing report…':'Generate audit report'}</button></p>
  </form>
  {error&&<p role="alert">{error}</p>}
  {report&&<><div className="panel-top"><h3>{report.mode==='ai-assisted'?'AI-assisted report':'Rules-only report'}</h3><button onClick={save}>Save report JSON</button></div>
   <p>{report.notice}</p><p className="muted">{report.window.since} to {report.window.until}. Blockchain scan: {report.coverage.fromBlock}–{report.coverage.toBlock}.</p>
   {(report.coverage.securityTruncated||report.coverage.chainTruncated)&&<p role="status">Evidence limit reached. This is a partial sample; narrow the window or identity filter.</p>}
   <table><thead><tr><th>Included evidence</th><th>Count</th></tr></thead><tbody><tr><td>Application actions allowed / denied</td><td>{report.counts.allowed} / {report.counts.denied}</td></tr><tr><td>Contract events (not transaction count)</td><td>{report.counts.contractEvents}</td></tr><tr><td>Supplied receipts confirmed / reverted</td><td>{report.counts.confirmed} / {report.counts.reverted}</td></tr></tbody></table>
   <h3>Rule-based review signals</h3>{!report.flags.length&&<p>No repeated-denial threshold reached in the included sample. This does not establish that activity is safe.</p>}
   {report.flags.map((f,i)=><div key={i}><p>{f.reason}</p><code className="hash">{f.actor}</code><p className="hash">{f.evidenceIds.join(', ')}</p></div>)}
   {report.findings.length>0&&<><h3>AI explanations — verify before use</h3>{report.findings.map((f,i)=><div key={i}><p>{f.explanation}</p><p className="hash">Evidence: {f.evidenceIds.join(', ')}</p></div>)}</>}
   {report.receiptNotes.map((n,i)=><p key={i} className="hash">{n.hash}: {n.note}</p>)}
   <details><summary>Scope and limitations</summary><ul>{report.limitations.map(x=><li key={x}>{x}</li>)}</ul></details>
   <details><summary>Inspect evidence ({report.evidence.length} records)</summary>{report.evidence.map(e=><pre key={e.id}>{JSON.stringify(e,null,2)}</pre>)}</details>
  </>}
 </section>;
}
