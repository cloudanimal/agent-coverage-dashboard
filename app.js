'use strict';
// ---------- state ----------
const STATE = { ad:[], me:[], ten:[], cs:[], adCols:[], src:{}, staleDays:30, denom:'enabled',
  excludeNonReal:true, logonFilter:true, logonDays:15 };
const $ = s => document.querySelector(s);
const fmt = n => (n==null?'—':Number(n).toLocaleString());
const pct = (a,b) => b? Math.round(a/b*100) : 0;
const showLoading = m => { $('#loadingMsg').textContent=m||'Working…'; $('#loading').style.display='flex'; };
const hideLoading = () => { $('#loading').style.display='none'; };
const nextPaint = () => new Promise(r=>setTimeout(r,30));

// ---------- theme ----------
(function(){ const s=localStorage.getItem('acd-theme'); if(s) document.documentElement.dataset.theme=s; })();
$('#themeBtn').addEventListener('click', ()=>{ const d=document.documentElement.dataset.theme==='light'?'dark':'light';
  document.documentElement.dataset.theme=d; localStorage.setItem('acd-theme',d); if(STATE.built) render(); });

// ---------- file pickers ----------
function pick(k){ $('#file-'+k).click(); }
['ad','me','ten','cs'].forEach(k=>{
  $('#file-'+k).addEventListener('change', e=>{ const f=e.target.files[0]; if(f) handleFile(k,f); });
});
async function handleFile(kind, file){
  showLoading('Reading '+file.name+'…'); await nextPaint();
  try{
    const text = await file.text();
    const isJson = /\.json$/i.test(file.name) || /^[\[{]/.test(text.trim());
    const records = isJson ? flattenAd(text) : Papa.parse(text, {header:true, skipEmptyLines:true}).data;   // flattenAd flattens any JSON array of objects
    STATE[kind] = records;
    if(kind==='ad') STATE.adCols = unionCols(records);
    STATE.src[kind] = file.name;
    markLoaded(kind, file.name);
  }catch(err){ console.error(err); markStatus(kind, '⚠️ '+(err.message||err)); }
  finally{ hideLoading(); }
}
const FLATBTN = { ad:'adFlatBtn', me:'meFlatBtn', ten:'tenFlatBtn', cs:'csFlatBtn' };
function markLoaded(kind, name){ const slot=document.getElementById('slot-'+slotId(kind)); slot.classList.add('loaded');
  markStatus(kind, '✓ '+name+' · '+(STATE[kind].length).toLocaleString()+' rows');
  const fb=document.getElementById(FLATBTN[kind]); if(fb) fb.classList.remove('hidden');
  maybeAutoBuild(); }
function markStatus(kind, msg){ document.getElementById('st-'+slotId(kind)).textContent=msg; }
function slotId(k){ return k==='ten'?'ten':k; }   // ids match
let _autoT=null;
function maybeAutoBuild(){
  if(STATE._loadingSample) return;                                   // loadSample renders once at the end
  const hasAgent = AKEYS.some(k=>(STATE[k]||[]).length);
  if(!STATE.ad.length || !hasAgent) return;                          // need AD + ≥1 agent
  clearTimeout(_autoT); _autoT=setTimeout(()=>render(), 200);        // debounce multiple uploads
}
// collapse the uploader to a one-line summary after build; expand to edit
function toggleUploader(expand){
  document.getElementById('dropZone').style.display = expand ? '' : 'none';
  document.getElementById('srcBar').classList.toggle('hidden', !!expand);
  if(!expand){
    const parts=[['ad','Active Directory'],['me','ManageEngine'],['ten','Tenable'],['cs','CrowdStrike']]
      .filter(([k])=>(STATE[k]||[]).length).map(([k,l])=>`${l} <span style="color:var(--ok)">✓</span> <span style="color:var(--muted)">${(STATE[k].length).toLocaleString()}</span>`);
    document.getElementById('srcBarList').innerHTML = parts.join(' &nbsp;·&nbsp; ');
  }
}

// ---------- AD JSON → flattened records ----------
function flattenValue(v){ if(typeof v==='string'){ const m=v.match(/^\/Date\((-?\d+)\)\/$/); if(m) return new Date(+m[1]).toISOString(); } return v; }
function flatten(obj, prefix, out){
  for(const k in obj){ if(!Object.prototype.hasOwnProperty.call(obj,k)) continue;
    const key = prefix? prefix+'.'+k : k; const v = obj[k];
    if(v===null||v===undefined) out[key]='';
    else if(Array.isArray(v)){
      if(v.every(x=>x===null||typeof x!=='object')) out[key]=v.map(flattenValue).join('; ');
      else out[key]=v.map(x=>{try{return JSON.stringify(x);}catch(e){return String(x);}}).join('; ');
    } else if(typeof v==='object'){ flatten(v, key, out); }
    else out[key]=flattenValue(v);
  }
  return out;
}
function flattenAd(text){
  let data = JSON.parse(text);
  if(!Array.isArray(data)) data = (data && (data.value || data.Computers || data.results)) || [data];
  return data.map(o => (o && typeof o==='object') ? flatten(o,'',{}) : {value:o});
}
function unionCols(rows){ const s=new Set(); rows.forEach(r=>Object.keys(r).forEach(k=>s.add(k))); return [...s]; }

// ---------- matching helpers ----------
const norm = h => String(h==null?'':h).trim().split('.')[0].toUpperCase();
function findCol(cols, patterns){ for(const p of patterns){ const c=cols.find(c=>p.test(c)); if(c) return c; } return null; }
const daysSince = v => { if(!v) return null; const t=new Date(v).getTime(); return isNaN(t)? null : (Date.now()-t)/86400000; };
function ouTokens(dn){ return (String(dn||'').match(/OU=([^,]+)/gi)||[]).map(s=>s.slice(3)); }
function adField(r, names){ for(const n of names){ if(r[n]!=null && r[n]!=='') return r[n]; } return ''; }

// column maps per source (tolerant of naming drift)
function colsFor(kind){
  const c = unionCols(STATE[kind]);
  if(kind==='me') return { name:findCol(c,[/^computer.?name$/i,/computer.?name/i,/host.?name/i,/^machine.?name/i,/^device.?name/i,/^name$/i]),
    seen:findCol(c,[/last.?contact/i,/last.?seen/i,/last.?communicat/i]), ver:findCol(c,[/agent.?version/i,/version/i]),
    scan:findCol(c,[/last.?success.*scan/i,/last.?scan/i]), patch:findCol(c,[/last.?patch/i]), group:findCol(c,[/custom.?group/i,/group/i]) };
  if(kind==='ten') return { name:findCol(c,[/host.?name/i,/^name$/i,/computer/i]),
    seen:findCol(c,[/last.?connect/i,/last.?seen/i,/lastconnectutc/i]), scan:findCol(c,[/last.?scan/i,/lastscannedutc/i]),
    group:findCol(c,[/^groups?$/i,/group/i]), ver:null };
  if(kind==='cs') return { name:findCol(c,[/host.?name/i,/^host$/i,/^name$/i,/computer/i]),
    seen:findCol(c,[/last.?seen/i,/last.?contact/i]), ver:findCol(c,[/sensor.?version/i,/agent.?version/i,/version/i]),
    status:findCol(c,[/status/i,/rfm/i,/reduced/i]), group:findCol(c,[/^ou$/i,/group/i]) };
}

// ---------- build the coverage model ----------
function buildModel(){
  const STALE = STATE.staleDays;
  const adNameCol = findCol(STATE.adCols,[/^name$/i,/^cn$/i,/computer.?name/i]) || STATE.adCols[0];
  const adDnsCol  = findCol(STATE.adCols,[/dnshostname/i,/^dns/i]);
  const adEnCol   = findCol(STATE.adCols,[/^enabled$/i]);
  const adOsCol   = findCol(STATE.adCols,[/^operatingsystem$/i,/^os$/i]);
  const adDnCol   = findCol(STATE.adCols,[/distinguishedname/i]);
  const adLogonCol= findCol(STATE.adCols,[/lastlogondate/i,/lastlogontimestamp/i,/lastlogon/i]);
  const adSpnCol  = findCol(STATE.adCols,[/serviceprincipalname/i]);

  const sources = Object.fromEntries(AKEYS.map(k=>[k, colsFor(k)]));
  // index each agent source by normalized hostname
  const idx = {}; const matched = Object.fromEntries(AKEYS.map(k=>[k, new Set()]));
  AKEYS.forEach(k=>{ idx[k]=new Map(); const nm=sources[k].name;
    (STATE[k]||[]).forEach(r=>{ const key=norm(nm?r[nm]:r[Object.keys(r)[0]]); if(key && !idx[k].has(key)) idx[k].set(key, r); }); });

  const ad = STATE.ad.map(r=>{
    const name = adField(r,[adNameCol]) || '';
    const key = norm(name);
    const toks = ouTokens(adField(r,[adDnCol]));
    const seg = toks.find(t=>/^bu[\s_-]?\d+$/i.test(t)) || toks.find(t=>!/^(servers?|workstations?|computers?)$/i.test(t)) || '—';
    const osStr = adField(r,[adOsCol])||'';
    const type = /windows server/i.test(osStr) ? 'Windows Server'
      : /windows (10|11|7|8)/i.test(osStr) ? 'Windows Workstation'
      : /(red hat|rhel)/i.test(osStr) ? 'RHEL'
      : 'Other';
    const enabledRaw = adField(r,[adEnCol]); const enabled = /true|1|yes/i.test(String(enabledRaw)) || enabledRaw===true;
    const os = adField(r,[adOsCol]) || '—';
    const cov = {};
    AKEYS.forEach(k=>{ const rec=idx[k].get(key); if(rec){ matched[k].add(key);
      const s=sources[k].seen; const days = s? daysSince(rec[s]) : null;
      cov[k]={present:true, rec, days, stale: days!=null && days>STALE}; }
      else cov[k]={present:false}; });
    const nAgents = AKEYS.filter(k=>cov[k].present).length;
    const spn = adField(r,[adSpnCol]);
    const isReal = !!String(os).trim() && os!=='—' && !/cluster/i.test(String(spn));
    const logonDays = daysSince(adField(r,[adLogonCol]));
    return { name, key, seg, type, os, enabled, cov, nAgents, isReal, logonDays,
      lastLogon: adField(r,[adLogonCol]), dn: adField(r,[adDnCol]), raw:r };
  });

  // orphans: agent records with no matching AD computer
  const adKeys = new Set(ad.map(c=>c.key));
  const orphans = [];
  AKEYS.forEach(k=>{ const nm=sources[k].name;
    (STATE[k]||[]).forEach(r=>{ const key=norm(nm?r[nm]:r[Object.keys(r)[0]]); if(key && !adKeys.has(key))
      orphans.push({ source:AGENT_NAME[k], host:(nm?r[nm]:key), seen:(sources[k].seen?r[sources[k].seen]:'') }); }); });

  return { ad, sources, matched, orphans, adNameCol };
}

// Intune temporarily removed — needs a different inventory-model approach (AD ∪ Intune), to be reintroduced.
const AGENTS = [ ['me','ManageEngine','#b9770b'], ['ten','Tenable','#003f73'], ['cs','CrowdStrike','#1f9d57'] ];
const AKEYS = AGENTS.map(a=>a[0]);
const AGENT_NAME = Object.fromEntries(AGENTS.map(a=>[a[0],a[1]]));

// ---------- render ----------
let CHARTS = [];
function render(){
  if(!STATE.ad.length){ alert('Load Active Directory data first (the denominator).'); return; }
  CHARTS.forEach(c=>{try{c.destroy();}catch(e){}}); CHARTS=[];
  const M = buildModel(); window._model = M;
  const inScope = M.ad.filter(c => {
    if(STATE.denom!=='all' && !c.enabled) return false;
    if(STATE.excludeNonReal && !c.isReal) return false;
    if(STATE.logonFilter && !(c.logonDays!=null && c.logonDays<=STATE.logonDays)) return false;
    return true;
  });
  const denom = inScope.length || 1;
  const nNonReal = M.ad.filter(c=>!c.isReal).length;
  const cov = k => inScope.filter(c=>c.cov[k].present).length;
  const stale = k => inScope.filter(c=>c.cov[k].present && c.cov[k].stale).length;
  const fully = inScope.filter(c=>c.nAgents===AKEYS.length).length;
  const none  = inScope.filter(c=>c.nAgents===0).length;
  const noEdr = inScope.filter(c=>!c.cov.cs.present).length;
  const single= inScope.filter(c=>c.nAgents===1).length;

  const d = $('#dashboard'); d.innerHTML='';
  if(!STATE.built) window.scrollTo({top:0});   // only jump to top on the first build, not on filter re-renders

  // KPI cards
  const kpi = (l,v,s,col)=>`<div class="card"><div class="l">${l}</div><div class="v"${col?` style="color:${col}"`:''}>${v}</div>${s?`<div class="s">${s}</div>`:''}</div>`;
  let cards = kpi('AD computers', fmt(M.ad.length), `${fmt(denom)} in scope · ${fmt(nNonReal)} cluster/alias`);
  AGENTS.forEach(([k,label,c])=>{ const n=cov(k); cards += kpi(label+' coverage', pct(n,denom)+'%', `${fmt(n)} / ${fmt(denom)} · ${fmt(stale(k))} stale`, c); });
  cards += kpi('Fully covered', pct(fully,denom)+'%', `${fmt(fully)} on all ${AKEYS.length} agents`, 'var(--ok)');
  cards += kpi('No coverage', fmt(none), 'in-scope, 0 agents', none? 'var(--crit)':null);
  cards += kpi('No EDR (CrowdStrike)', fmt(noEdr), pct(noEdr,denom)+'% of in-scope', noEdr? 'var(--crit)':null);
  cards += kpi('Single-agent hosts', fmt(single), `only 1 of ${AKEYS.length} agents`, single? 'var(--warn)':null);
  cards += kpi('Orphan agents', fmt(M.orphans.length), 'agents with no AD match', M.orphans.length?'var(--warn)':null);
  d.insertAdjacentHTML('beforeend', `<div class="cards">${cards}</div>`);

  // scope + stale controls
  d.insertAdjacentHTML('beforeend', `<div class="panel"><div class="controls">
    <label class="sub">Coverage denominator
      <select id="denomSel"><option value="enabled"${STATE.denom==='enabled'?' selected':''}>Enabled AD computers</option><option value="all"${STATE.denom==='all'?' selected':''}>All AD computers</option></select></label>
    <label class="sub" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="realChk"${STATE.excludeNonReal?' checked':''}> Real systems only <span class="sub" title="Excludes objects with no OperatingSystem or a cluster service principal name (cluster name objects, aliases)">(exclude cluster/alias)</span></label>
    <label class="sub" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="logonChk"${STATE.logonFilter?' checked':''}> Logged on within <input id="logonDays" type="number" min="1" value="${STATE.logonDays}" style="width:58px"> days</label>
    <label class="sub">Stale threshold <input id="staleInp" type="number" min="1" value="${STATE.staleDays}" style="width:64px"> days</label>
  </div><div class="sub">Scope = ${fmt(denom)} of ${fmt(M.ad.length)} AD objects (excluded: ${STATE.excludeNonReal?fmt(nNonReal)+' cluster/alias':'none'}${STATE.logonFilter?', plus anything not logged on in '+STATE.logonDays+'d':''}). An agent is “stale” if its last check-in is older than the stale threshold.</div></div>`);
  $('#denomSel').addEventListener('change',e=>{ STATE.denom=e.target.value; render(); });
  $('#realChk').addEventListener('change',e=>{ STATE.excludeNonReal=e.target.checked; render(); });
  $('#logonChk').addEventListener('change',e=>{ STATE.logonFilter=e.target.checked; render(); });
  $('#logonDays').addEventListener('change',e=>{ STATE.logonDays=Math.max(1,parseInt(e.target.value)||15); render(); });
  $('#staleInp').addEventListener('change',e=>{ STATE.staleDays=Math.max(1,parseInt(e.target.value)||30); render(); });

  // charts
  d.insertAdjacentHTML('beforeend', `<div class="grid2">
    <div class="panel"><h3>Coverage by agent</h3><div class="chartbox"><canvas id="cAgent"></canvas></div></div>
    <div class="panel"><h3>Coverage by segment</h3><div class="chartbox"><canvas id="cSeg"></canvas></div></div>
  </div>
  <div class="grid2">
    <div class="panel"><h3>Coverage by OS / type</h3><div class="chartbox"><canvas id="cType"></canvas></div></div>
    <div class="panel"><h3>Coverage depth <span class="sub">— how many agents each host has</span></h3><div class="chartbox"><canvas id="cDepth"></canvas></div></div>
  </div>`);
  drawAgentChart(inScope, denom);
  drawSegChart(inScope);
  drawTypeChart(inScope);
  drawDepthChart(inScope);

  // coverage matrix
  buildMatrix(M, inScope);

  // orphans
  buildOrphans(M);

  STATE.built = true; STATE._inScope = inScope; STATE._M = M;
  buildExportMenu();
  attachSaveControls();
  toggleUploader(false);   // collapse the sources panel to a summary once built
}

function chartGrid(){ return getComputedStyle(document.documentElement).getPropertyValue('--line').trim()||'#2a2f3e'; }
function chartTick(){ return getComputedStyle(document.documentElement).getPropertyValue('--muted').trim()||'#9aa3b2'; }

function drawAgentChart(inScope, denom){
  const covered = AGENTS.map(([k])=>inScope.filter(c=>c.cov[k].present && !c.cov[k].stale).length);
  const staleA  = AGENTS.map(([k])=>inScope.filter(c=>c.cov[k].present && c.cov[k].stale).length);
  const gap     = AGENTS.map(([k])=>inScope.filter(c=>!c.cov[k].present).length);
  CHARTS.push(new Chart($('#cAgent'),{type:'bar',
    data:{labels:AGENTS.map(a=>a[1]),datasets:[
      {label:'Covered',data:covered,backgroundColor:'#1f9d57'},
      {label:'Stale',data:staleA,backgroundColor:'#b9770b'},
      {label:'Gap',data:gap,backgroundColor:'#7a3340'} ]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:chartTick()}}},
      scales:{x:{stacked:true,grid:{display:false},ticks:{color:chartTick()}},y:{stacked:true,grid:{color:chartGrid()},ticks:{color:chartTick()}}}}}));
}
function drawSegChart(inScope){
  const segs=[...new Set(inScope.map(c=>c.seg))].sort();
  CHARTS.push(new Chart($('#cSeg'),{type:'bar',
    data:{labels:segs,datasets:AGENTS.map(([k,label,col])=>({label,backgroundColor:col,
      data:segs.map(s=>{ const rows=inScope.filter(c=>c.seg===s); return pct(rows.filter(c=>c.cov[k].present).length, rows.length); }) }))},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:chartTick()}},tooltip:{callbacks:{label:c=>c.dataset.label+': '+c.parsed.y+'%'}}},
      scales:{x:{grid:{display:false},ticks:{color:chartTick()}},y:{max:100,grid:{color:chartGrid()},ticks:{color:chartTick(),callback:v=>v+'%'}}}}}));
}
function drawTypeChart(inScope){
  const order=['Windows Server','Windows Workstation','RHEL','Other'];
  const types=order.filter(t=>inScope.some(c=>c.type===t));
  CHARTS.push(new Chart($('#cType'),{type:'bar',
    data:{labels:types,datasets:AGENTS.map(([k,label,col])=>({label,backgroundColor:col,
      data:types.map(t=>{ const rows=inScope.filter(c=>c.type===t); return pct(rows.filter(c=>c.cov[k].present).length, rows.length); }) }))},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:chartTick()}},tooltip:{callbacks:{label:c=>c.dataset.label+': '+c.parsed.y+'%'}}},
      scales:{x:{grid:{display:false},ticks:{color:chartTick()}},y:{max:100,grid:{color:chartGrid()},ticks:{color:chartTick(),callback:v=>v+'%'}}}}}));
}
function drawDepthChart(inScope){
  const N=AKEYS.length; const labels=[]; const data=[]; const colors=[];
  for(let i=0;i<=N;i++){ labels.push(i+(i===1?' agent':' agents')); data.push(inScope.filter(c=>c.nAgents===i).length);
    colors.push(i===0?'#7a3340':i===N?'#1f9d57':i===1?'#b9770b':'#378add'); }
  CHARTS.push(new Chart($('#cDepth'),{type:'bar',
    data:{labels,datasets:[{label:'Hosts',data,backgroundColor:colors}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>fmt(c.parsed.y)+' hosts'}}},
      scales:{x:{grid:{display:false},ticks:{color:chartTick()}},y:{grid:{color:chartGrid()},ticks:{color:chartTick()}}}}}));
}

// ---------- coverage matrix ----------
const cell = c => c.present ? (c.stale? `<span class="pill stale" title="${Math.round(c.days)}d ago">stale</span>` : `<span class="pill ok">✓</span>`) : `<span class="pill gap">✗</span>`;
function buildMatrix(M, inScope){
  const segs=[...new Set(M.ad.map(c=>c.seg))].sort();
  const oses=[...new Set(M.ad.map(c=>c.os))].sort();
  const TYPE_ORDER=['Windows Server','Windows Workstation','RHEL','Other'];
  const types=TYPE_ORDER.filter(t=>M.ad.some(c=>c.type===t));
  const html = `<div class="panel" id="matrixPanel"><h3>Coverage matrix</h3>
    <div class="controls">
      <input id="mxSearch" placeholder="Search host…" style="min-width:160px">
      <select id="mxView"><option value="all">All in-scope</option><option value="gaps">Has a gap</option><option value="none">No coverage</option><option value="full">Fully covered</option><option value="stale">Any stale</option></select>
      <select id="mxSeg"><option value="">All segments</option>${segs.map(s=>`<option>${s}</option>`).join('')}</select>
      <select id="mxOs"><option value="">All OS</option>${oses.map(s=>`<option>${s}</option>`).join('')}</select>
      <select id="mxType"><option value="">All types</option>${types.map(t=>`<option>${t}</option>`).join('')}</select>
      <span class="sub" id="mxCount"></span>
    </div>
    <div class="legend"><span><span class="sw" style="background:#1f9d57"></span>Covered</span><span><span class="sw" style="background:#b9770b"></span>Stale (&gt;${STATE.staleDays}d)</span><span><span class="sw" style="background:#7a3340"></span>Gap</span></div>
    <div class="scrollwrap"><table><thead><tr>
      <th data-s="name">Computer</th><th data-s="seg">Segment</th><th data-s="os">OS</th><th data-s="type">Type</th><th data-s="enabled">Enabled</th>
      ${AGENTS.map(a=>`<th data-s="cov:${a[0]}">${a[1]}</th>`).join('')}<th class="num" data-s="nAgents">Agents</th>
    </tr></thead><tbody id="mxBody"></tbody></table></div></div>`;
  $('#dashboard').insertAdjacentHTML('beforeend', html);
  const fill = ()=>{
    const q=$('#mxSearch').value.trim().toUpperCase(), view=$('#mxView').value, seg=$('#mxSeg').value, os=$('#mxOs').value, type=$('#mxType').value;
    let rows = inScope.filter(c=>{
      if(q && !c.name.toUpperCase().includes(q)) return false;
      if(seg && c.seg!==seg) return false; if(os && c.os!==os) return false; if(type && c.type!==type) return false;
      if(view==='gaps' && c.nAgents===AKEYS.length) return false;
      if(view==='none' && c.nAgents!==0) return false;
      if(view==='full' && c.nAgents!==AKEYS.length) return false;
      if(view==='stale' && !AKEYS.some(k=>c.cov[k].stale)) return false;
      return true;
    });
    if(STATE._sort){ const {k,dir}=STATE._sort;
      const keyVal=c=>{ if(k.startsWith('cov:')){ const co=c.cov[k.slice(4)]; return co.present?(co.stale?1:2):0; } return c[k]; };
      rows.sort((a,b)=>{ let x=keyVal(a),y=keyVal(b); if(typeof x==='string'){x=x.toUpperCase();y=String(y).toUpperCase();} return (x>y?1:x<y?-1:0)*dir; }); }
    $('#mxCount').textContent = rows.length.toLocaleString()+' of '+inScope.length.toLocaleString();
    $('#mxBody').innerHTML = rows.slice(0,2000).map(c=>`<tr>
      <td>${c.name}</td><td>${c.seg}</td><td style="font-size:12px">${c.os}</td><td>${c.type}</td>
      <td>${c.enabled?'<span class="pill ok">Yes</span>':'<span class="pill muted">No</span>'}</td>
      ${AGENTS.map(a=>`<td>${cell(c.cov[a[0]])}</td>`).join('')}
      <td class="num">${c.nAgents===AKEYS.length?`<span class="pill ok">${AKEYS.length}/${AKEYS.length}</span>`:c.nAgents===0?`<span class="pill gap">0/${AKEYS.length}</span>`:c.nAgents+'/'+AKEYS.length}</td></tr>`).join('')
      + (rows.length>2000?`<tr><td colspan="9" class="sub">Showing first 2,000 of ${rows.length.toLocaleString()} — refine filters or export the full set.</td></tr>`:'');
  };
  ['mxSearch','mxView','mxSeg','mxOs','mxType'].forEach(id=>$('#'+id).addEventListener('input',fill));
  $('#matrixPanel').querySelectorAll('th[data-s]').forEach(th=>{ th.style.cursor='pointer';
    th.addEventListener('click',()=>{
      const k=th.dataset.s; STATE._sort = STATE._sort && STATE._sort.k===k ? {k,dir:-STATE._sort.dir} : {k,dir:1};
      $('#matrixPanel').querySelectorAll('th .sortind').forEach(s=>s.remove());
      const ind=document.createElement('span'); ind.className='sortind'; ind.style.cssText='margin-left:4px;opacity:.7';
      ind.textContent=STATE._sort.dir===1?'▲':'▼'; th.appendChild(ind); fill(); }); });
  STATE._matrixFill = fill; fill();
}

function buildOrphans(M){
  if(!M.orphans.length){ return; }
  const rows = M.orphans.slice(0,2000).map(o=>`<tr><td>${o.host}</td><td>${o.source}</td><td style="font-size:12px">${o.seen||''}</td></tr>`).join('');
  $('#dashboard').insertAdjacentHTML('beforeend', `<div class="panel" id="orphanPanel"><h3>Orphan agents <span class="sub">— reporting in but not found in Active Directory (decommissioned, renamed, or rogue)</span></h3>
    <div class="scrollwrap"><table><thead><tr><th>Host</th><th>Source</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table></div></div>`);
  makeSortable($('#orphanPanel table'));
}
// ---------- clickable column-header sorting (generic, DOM-based) ----------
function makeSortable(table){
  if(!table || table._sortable) return; const thead=table.tHead, tbody=table.tBodies[0]; if(!thead||!tbody) return;
  table._sortable=true; const ths=[...thead.rows[0].cells];
  const numOf=s=>{ const n=parseFloat(String(s).replace(/[,$%\s]/g,'')); return isNaN(n)?null:n; };
  ths.forEach((th,idx)=>{ if(th.dataset.nosort!==undefined) return; th.style.cursor='pointer'; if(!th.title) th.title='Sort';
    th.addEventListener('click',()=>{
      const dir = th._dir = (th._dir===1?-1:1);
      ths.forEach(o=>{ if(o!==th){ o._dir=0; const s=o.querySelector('.sortind'); if(s) s.remove(); } });
      let ind=th.querySelector('.sortind'); if(!ind){ ind=document.createElement('span'); ind.className='sortind'; ind.style.cssText='margin-left:4px;opacity:.7'; th.appendChild(ind); }
      ind.textContent = dir===1?'▲':'▼';
      const rows=[...tbody.rows]; const val=r=>{ const c=r.cells[idx]; return c? c.textContent.trim():''; };
      const allNum=rows.length && rows.every(r=>{ const t=val(r); return t===''||t==='—'||numOf(t)!==null; });
      rows.sort((a,b)=>{ let x=val(a),y=val(b);
        if(allNum){ x=numOf(x); y=numOf(y); x=x==null?-Infinity:x; y=y==null?-Infinity:y; return (x-y)*dir; }
        return (x.toUpperCase()>y.toUpperCase()?1:x.toUpperCase()<y.toUpperCase()?-1:0)*dir; });
      rows.forEach(r=>tbody.appendChild(r));
    });
  });
}

// ---------- per-card save controls (PNG/JPEG/WEBP/GIF/clipboard image+text) ----------
function toast(msg){ let t=document.querySelector('.toast'); if(!t){ t=document.createElement('div'); t.className='toast'; document.body.appendChild(t); }
  t.textContent=msg; t.classList.add('show'); clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),1800); }
function panelBg(){ return getComputedStyle(document.documentElement).getPropertyValue('--panel').trim()||'#171a23'; }
function attachSaveControls(){
  document.querySelectorAll('#dashboard .panel').forEach(p=>{
    if(!(p.querySelector('canvas')||p.querySelector('table')) || p.querySelector('.savewrap')) return;
    const h=p.querySelector('h3'); const name=(h?h.textContent:'panel').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');
    const wrap=document.createElement('div'); wrap.className='savewrap';
    const sel=document.createElement('select'); sel.title='Save as';
    [['png','PNG'],['jpeg','JPEG'],['webp','WEBP'],['gif','GIF'],['clipboard-img','Clipboard (image)'],['clipboard-text','Clipboard (text)']]
      .forEach(([v,l])=>{ const o=document.createElement('option'); o.value=v; o.textContent=l; sel.appendChild(o); });
    const b=document.createElement('button'); b.textContent='Save';
    b.addEventListener('click',()=>savePanel(p,name,sel.value,b));
    wrap.appendChild(sel); wrap.appendChild(b); p.appendChild(wrap);
    if(h) h.style.paddingRight=(wrap.offsetWidth+18)+'px';
  });
}
async function rasterPanel(el){
  const bg=panelBg(); const cv=el.querySelector('canvas');
  if(cv && el.querySelectorAll('canvas').length===1 && !el.querySelector('table')){
    const t=document.createElement('canvas'); t.width=cv.width; t.height=cv.height;
    const x=t.getContext('2d'); x.fillStyle=bg; x.fillRect(0,0,t.width,t.height); x.drawImage(cv,0,0); return t;
  }
  const ctrl=el.querySelector('.savewrap'); const cv0=ctrl?ctrl.style.visibility:''; if(ctrl) ctrl.style.visibility='hidden';
  const sw=el.querySelector('.scrollwrap'); const om=sw?sw.style.maxHeight:''; if(sw) sw.style.maxHeight='none';
  let canvas; try{ canvas=await html2canvas(el,{backgroundColor:bg,scale:2,logging:false,useCORS:true}); }
  finally{ if(sw) sw.style.maxHeight=om; if(ctrl) ctrl.style.visibility=cv0; }
  return canvas;
}
const canvasToBlob=(c,m,q)=>new Promise(r=>c.toBlob(r,m,q));
function canvasToGifBlob(c){ const g=window.gifenc; const {width,height}=c; const data=c.getContext('2d').getImageData(0,0,width,height).data;
  const pal=g.quantize(data,256); const idx=g.applyPalette(data,pal); const e=g.GIFEncoder(); e.writeFrame(idx,width,height,{palette:pal}); e.finish();
  return new Blob([e.bytesView()],{type:'image/gif'}); }
function cardToText(p){
  const cellText=c=>{ const i=c.querySelector('input,select'); return (i?i.value:c.textContent).trim().replace(/\s+/g,' '); };
  const tbl=p.querySelector('table');
  if(tbl){ const rows=[...tbl.querySelectorAll(':scope>thead>tr, :scope>tbody>tr')];
    return rows.map(r=>[...r.children].map(cellText).join('\t')).join('\n'); }
  const cv=p.querySelector('canvas');
  if(cv && window.Chart){ const ch=Chart.getChart(cv); if(ch){ const d=ch.data, ds=d.datasets||[];
    return ['Label',...ds.map(x=>x.label||'Value')].join('\t')+'\n'+(d.labels||[]).map((l,i)=>[l,...ds.map(x=>x.data[i])].join('\t')).join('\n'); } }
  const cards=[...p.querySelectorAll('.card')];
  if(cards.length) return cards.map(c=>{ const l=c.querySelector('.l'),v=c.querySelector('.v'); return ((l?l.textContent:'').trim().replace(/\s+/g,' '))+'\t'+((v?v.textContent:'').trim()); }).join('\n');
  return '';
}
function tsvToHtmlTable(tsv){ const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return '<table>'+tsv.split('\n').map(l=>l===''?'<tr><td></td></tr>':'<tr>'+l.split('\t').map(c=>`<td>${esc(c)}</td>`).join('')+'</tr>').join('')+'</table>'; }
function sectionsToHtmlTable(secs){ const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const cw=[]; const maxCols=Math.max(1,...secs.map(s=>Math.max(...s.aoa.map(r=>r.length))));
  for(let i=0;i<maxCols;i++){ let m=4; secs.forEach(s=>s.aoa.forEach(r=>{ if(r[i]!=null){ const L=String(r[i]).length; if(L>m) m=L; } })); cw[i]=Math.min(Math.max(m*7+18,48),360); }
  const colgroup='<colgroup>'+cw.map(w=>`<col style="width:${w}px">`).join('')+'</colgroup>';
  const pad='<td style="border:0"></td>'; let rows='';
  secs.forEach((s,si)=>{ if(si>0) rows+=`<tr><td colspan="${maxCols}" style="height:8px"></td></tr>`;
    rows+=`<tr><td colspan="${maxCols}" style="font-weight:bold;background:#28415d;color:#fff;padding:5px 8px;white-space:nowrap">${esc(s.name)}</td></tr>`;
    s.aoa.forEach((r,ri)=>{ const head=ri===0; const cells=r.map(c=>`<td style="${head?'font-weight:bold;background:#e9edf2;':''}padding:3px 8px;border:1px solid #c9cdd4;white-space:nowrap">${esc(c)}</td>`);
      while(cells.length<maxCols) cells.push(pad); rows+='<tr>'+cells.join('')+'</tr>'; }); });
  return `<table style="border-collapse:collapse;table-layout:fixed;font-family:-apple-system,Segoe UI,sans-serif;font-size:12px;color:#1b2530">${colgroup}${rows}</table>`; }
function copyTable(tsv,msg,htmlOverride){ const html=htmlOverride||tsvToHtmlTable(tsv);
  if(window.ClipboardItem && navigator.clipboard?.write){
    return navigator.clipboard.write([new ClipboardItem({'text/plain':new Blob([tsv],{type:'text/plain'}),'text/html':new Blob([html],{type:'text/html'})})]).then(()=>toast(msg),e=>{console.error(e);toast('Clipboard write failed');}); }
  if(navigator.clipboard?.writeText) return navigator.clipboard.writeText(tsv).then(()=>toast(msg),()=>toast('Clipboard write failed'));
  toast('Clipboard not supported here'); return Promise.resolve(); }
async function savePanel(el,name,fmt,btn){ const stamp=new Date().toISOString().slice(0,10);
  if(btn){ btn.textContent='…'; }
  try{
    if(fmt==='clipboard-text'){ const txt=cardToText(el); if(!txt){ toast('No data to copy'); return; } await copyTable(txt,'Data copied — paste into Excel or Numbers'); return; }
    const canvas=await rasterPanel(el);
    if(fmt==='clipboard-img'){ if(!(navigator.clipboard && window.ClipboardItem)){ toast('Clipboard not supported here'); return; }
      const blob=await canvasToBlob(canvas,'image/png'); await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]); toast('Image copied to clipboard'); return; }
    if(fmt==='gif'){ const a=document.createElement('a'); a.href=URL.createObjectURL(canvasToGifBlob(canvas)); a.download=name+'_'+stamp+'.gif'; a.click(); return; }
    const blob=await canvasToBlob(canvas,'image/'+fmt,(fmt==='jpeg'||fmt==='webp')?0.95:undefined);
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name+'_'+stamp+'.'+(fmt==='jpeg'?'jpg':fmt); a.click();
  }catch(e){ console.error('savePanel',e); toast('Save failed'); }
  finally{ if(btn){ btn.textContent='Save'; } }
}

// ---------- sample data ----------
$('#loadSample').addEventListener('click', loadSample);
if(/[?&]autosample=1/.test(location.search)) window.addEventListener('load', loadSample);   // demo links / headless screenshots
async function loadSample(){
  if(location.protocol==='file:'){ $('#loadHint').innerHTML='⚠️ Sample auto-load needs the page served over http (browsers block local file reads). Run <code>python3 -m http.server</code> here, or load your own files.'; return; }
  try{
    STATE._loadingSample = true;
    showLoading('Loading sample data…'); await nextPaint();
    const [adTxt, meTxt, tenTxt, csTxt] = await Promise.all([
      fetch('sample-data/ad-computers.json').then(r=>r.text()),
      fetch('sample-data/manageengine.csv').then(r=>r.text()),
      fetch('sample-data/tenable-agents.csv').then(r=>r.text()),
      fetch('sample-data/crowdstrike.csv').then(r=>r.text()) ]);
    STATE.ad = flattenAd(adTxt); STATE.adCols = unionCols(STATE.ad); STATE.src.ad='ad-computers.json'; markLoaded('ad','ad-computers.json (sample)');
    STATE.me = Papa.parse(meTxt,{header:true,skipEmptyLines:true}).data; STATE.src.me='manageengine.csv'; markLoaded('me','manageengine.csv (sample)');
    STATE.ten = Papa.parse(tenTxt,{header:true,skipEmptyLines:true}).data; STATE.src.ten='tenable-agents.csv'; markLoaded('ten','tenable-agents.csv (sample)');
    STATE.cs = Papa.parse(csTxt,{header:true,skipEmptyLines:true}).data; STATE.src.cs='crowdstrike.csv'; markLoaded('cs','crowdstrike.csv (sample)');
    STATE._loadingSample = false;
    showLoading('Building dashboard…'); await nextPaint(); render();
  }catch(e){ console.error(e); alert('Could not load sample (serve over http, or load files manually).'); }
  finally{ STATE._loadingSample=false; hideLoading(); }
}

// ---------- exports ----------
function csvEsc(v){ v=v==null?'':String(v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; }
function toCsv(cols, rows){ return [cols.map(csvEsc).join(',')].concat(rows.map(r=>r.map(csvEsc).join(','))).join('\n'); }
function dl(name, text, mime){ const b=new Blob([text],{type:mime||'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),800); }

const FLATNAME = { ad:'ad', me:'manageengine', ten:'tenable', cs:'crowdstrike' };
function downloadFlat(kind){ if(!STATE[kind] || !STATE[kind].length){ alert('Load this source first.'); return; }
  const cols = kind==='ad' ? STATE.adCols : unionCols(STATE[kind]);
  dl(FLATNAME[kind]+'_flattened.csv', toCsv(cols, STATE[kind].map(r=>cols.map(c=>r[c]??''))), 'text/csv'); }
function downloadFlatAd(){ downloadFlat('ad'); }

function matrixRows(){ const ad=STATE._inScope||[];
  const fld=(c,k)=>c.cov[k].present?(c.cov[k].stale?'stale':'present'):'missing';
  const seen=(c,k)=>{ const co=c.cov[k]; if(!co.present) return ''; const s=STATE._M.sources[k].seen; return s?co.rec[s]:''; };
  return ad.map(c=>{ const o={ computer:c.name, segment:c.seg, os:c.os, type:c.type, enabled:c.enabled };
    AGENTS.forEach(([k,label])=>{ const key=label.toLowerCase(); o[key]=fld(c,k); o[key+'_last_seen']=seen(c,k); });
    o.agents=c.nAgents+'/'+AKEYS.length; return o; }); }
function objCols(objs){ return objs.length? Object.keys(objs[0]) : []; }
function objRows(objs,cols){ return objs.map(o=>cols.map(c=>o[c])); }

function summaryAoa(){ const ad=STATE._inScope||[]; const denom=ad.length||1;
  const r=[['metric','value']];
  r.push(['AD computers (total)', STATE.ad.length]); r.push(['AD computers (in scope)', ad.length]); r.push(['Scope', STATE.denom]);
  AGENTS.forEach(([k,l])=>{ const n=ad.filter(c=>c.cov[k].present).length; r.push([l+' covered', n]); r.push([l+' coverage %', pct(n,denom)]); r.push([l+' stale', ad.filter(c=>c.cov[k].present&&c.cov[k].stale).length]); });
  r.push([`Fully covered (${AKEYS.length}/${AKEYS.length})`, ad.filter(c=>c.nAgents===AKEYS.length).length]);
  r.push([`No coverage (0/${AKEYS.length})`, ad.filter(c=>c.nAgents===0).length]);
  r.push(['Orphan agents', (STATE._M.orphans||[]).length]);
  return r; }

// every report section as {name, aoa} — drives the full-report exports
function reportSections(){
  const M=STATE._M, ad=STATE._inScope||[]; const denom=ad.length||1;
  const aoaObjs=objs=>{ if(!objs||!objs.length) return [['(none)']]; const cols=[...new Set(objs.flatMap(o=>Object.keys(o)))]; return [cols, ...objs.map(o=>cols.map(c=>o[c]==null?'':o[c]))]; };
  const byAgent=[['agent','covered','coverage_%','stale','gap']];
  AGENTS.forEach(([k,l])=>{ const cov=ad.filter(c=>c.cov[k].present).length; byAgent.push([l,cov,pct(cov,denom),ad.filter(c=>c.cov[k].present&&c.cov[k].stale).length,denom-cov]); });
  const segs=[...new Set(ad.map(c=>c.seg))].sort();
  const bySeg=[['segment','computers',...AGENTS.map(a=>a[1]+' %')]];
  segs.forEach(s=>{ const rows=ad.filter(c=>c.seg===s); bySeg.push([s,rows.length,...AGENTS.map(([k])=>pct(rows.filter(c=>c.cov[k].present).length,rows.length))]); });
  const gaps=ad.filter(c=>c.nAgents<AKEYS.length).map(c=>({computer:c.name,segment:c.seg,os:c.os,type:c.type,missing:AGENTS.filter(([k])=>!c.cov[k].present).map(a=>a[1]).join('; '),agents:c.nAgents+'/'+AKEYS.length}));
  return [
    {name:'Summary', aoa:summaryAoa()},
    {name:'Coverage by Agent', aoa:byAgent},
    {name:'Coverage by Segment', aoa:bySeg},
    {name:'Coverage Matrix', aoa:aoaObjs(matrixRows())},
    {name:'Gaps', aoa:aoaObjs(gaps)},
    {name:'Orphans', aoa:aoaObjs((M.orphans||[]).map(o=>({host:o.host,source:o.source,last_seen:o.seen})))},
  ];
}
function reportHtml(stamp){
  const bg=panelBg(); const src=$('#dashboard'); const live=src.querySelectorAll('canvas'); const clone=src.cloneNode(true);
  clone.querySelectorAll('canvas').forEach((c,i)=>{ const l=live[i]; if(!l) return; const t=document.createElement('canvas'); t.width=l.width; t.height=l.height;
    const x=t.getContext('2d'); x.fillStyle=bg; x.fillRect(0,0,t.width,t.height); x.drawImage(l,0,0); const img=document.createElement('img'); img.src=t.toDataURL('image/png'); img.style.width='100%'; c.replaceWith(img); });
  clone.querySelectorAll('.savewrap,.noprint,select,button').forEach(e=>e.remove());
  clone.querySelectorAll('input').forEach(inp=>{ const s=document.createElement('span'); s.textContent=inp.value; inp.replaceWith(s); });
  const theme=document.documentElement.dataset.theme||'dark'; const styles=document.querySelector('style').outerHTML;
  return `<!DOCTYPE html><html data-theme="${theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent Coverage Report — ${stamp}</title>${styles}</head><body><main style="padding:24px 28px"><h1>Agent Coverage Dashboard</h1><p class="sub">Generated ${stamp} · all analysis performed locally in-browser.</p>${clone.outerHTML}</main></body></html>`;
}
function reportMarkdown(stamp){ const ad=STATE._inScope||[]; const denom=ad.length||1;
  let md=`# Agent Coverage Report\n\n_Generated ${stamp} · all analysis performed locally in-browser._\n\n`;
  md+=`- AD computers in scope: **${denom.toLocaleString()}** (of ${STATE.ad.length.toLocaleString()})\n`;
  AGENTS.forEach(([k,l])=>{ const n=ad.filter(c=>c.cov[k].present).length; md+=`- ${l} coverage: **${pct(n,denom)}%** (${n.toLocaleString()}/${denom.toLocaleString()}, ${ad.filter(c=>c.cov[k].present&&c.cov[k].stale).length} stale)\n`; });
  md+=`- Fully covered: **${pct(ad.filter(c=>c.nAgents===AKEYS.length).length,denom)}%**\n- No coverage: **${ad.filter(c=>c.nAgents===0).length}**\n- Orphan agents: **${(STATE._M.orphans||[]).length}**\n`;
  return md; }

function buildExportMenu(){ const sel=$('#exportSel'); if(!sel) return;
  sel.innerHTML = [
    ['report-html','Full report (HTML)'],['report-pdf','Full report (PDF / print)'],
    ['full-csv','Full report (CSV)'],['full-xlsx','Full report (XLSX)'],
    ['full-csv-clip','Full report (CSV → clipboard)'],['full-tsv-clip','Full report (Excel paste → clipboard)'],['full-img-clip','Full report (image → clipboard)'],
    ['exec-md','Executive report (Markdown)'],
    ['matrix-csv','Coverage matrix (CSV)'],['gaps-csv','Coverage gaps (CSV)'],['orphans-csv','Orphan agents (CSV)'],
    ['metrics-json','Computed metrics (JSON)'],['flatad-csv','Flattened AD (CSV)']
  ].map(([v,l])=>`<option value="${v}">${l}</option>`).join('');
}
$('#exportBtn').addEventListener('click', ()=>{
  if(!STATE.built){ alert('Build the dashboard first.'); return; }
  const kind=$('#exportSel').value, stamp=new Date().toISOString().slice(0,10);
  if(kind==='report-pdf'){ window.print(); return; }
  if(kind==='report-html'){ dl(`agent_coverage_report_${stamp}.html`, reportHtml(stamp), 'text/html'); return; }
  if(kind==='exec-md'){ dl(`agent_coverage_report_${stamp}.md`, reportMarkdown(stamp), 'text/markdown'); return; }
  if(kind==='flatad-csv'){ downloadFlatAd(); return; }
  if(kind==='matrix-csv'){ const m=matrixRows(); const c=objCols(m); dl(`coverage_matrix_${stamp}.csv`, toCsv(c, objRows(m,c)), 'text/csv'); return; }
  if(kind==='gaps-csv'){ const gaps=(STATE._inScope||[]).filter(c=>c.nAgents<AKEYS.length).map(c=>({computer:c.name,segment:c.seg,os:c.os,type:c.type,
      missing:AGENTS.filter(([k])=>!c.cov[k].present).map(a=>a[1]).join('; '), agents:c.nAgents+'/'+AKEYS.length}));
    const c=objCols(gaps); dl(`coverage_gaps_${stamp}.csv`, toCsv(c, objRows(gaps,c)), 'text/csv'); return; }
  if(kind==='orphans-csv'){ const o=STATE._M.orphans; const c=['host','source','seen']; dl(`orphan_agents_${stamp}.csv`, toCsv(c, o.map(x=>[x.host,x.source,x.seen])), 'text/csv'); return; }
  if(kind==='metrics-json'){ dl(`agent_coverage_metrics_${stamp}.json`, JSON.stringify(Object.fromEntries(summaryAoa().slice(1)), null, 2), 'application/json'); return; }
  if(kind==='full-csv'){ const parts=reportSections().map(s=>`# ${s.name}\n`+toCsv(s.aoa[0]||[], s.aoa.slice(1))); dl(`agent_coverage_full_${stamp}.csv`, parts.join('\n\n\n'), 'text/csv'); return; }
  if(kind==='full-csv-clip'){ const txt=reportSections().map(s=>`# ${s.name}\n`+toCsv(s.aoa[0]||[], s.aoa.slice(1))).join('\n\n\n'); copyTable(txt, 'Full report CSV copied to clipboard'); return; }
  if(kind==='full-tsv-clip'){ const secs=reportSections(); const cell=c=>String(c==null?'':c).replace(/[\t\r\n]+/g,' ');
    const txt=secs.map(s=>`# ${s.name}\n`+s.aoa.map(r=>r.map(cell).join('\t')).join('\n')).join('\n\n\n'); copyTable(txt, 'Full report copied — paste into Excel or Numbers', sectionsToHtmlTable(secs)); return; }
  if(kind==='full-img-clip'){ if(!(navigator.clipboard && window.ClipboardItem)){ toast('Clipboard not supported here'); return; }
    showLoading('Rendering full report image…'); const safety=setTimeout(hideLoading,12000);
    const blobP=(async()=>{ const c=await rasterPanel($('#dashboard')); return await canvasToBlob(c,'image/png'); })();
    navigator.clipboard.write([new ClipboardItem({'image/png':blobP})]).then(()=>toast('Full report image copied to clipboard')).catch(e=>{console.error(e);toast('Image copy failed');}).finally(()=>{clearTimeout(safety);hideLoading();}); return; }
  if(kind==='full-xlsx'){ const wb=XLSX.utils.book_new();
    reportSections().forEach(s=>{ const ws=XLSX.utils.aoa_to_sheet(s.aoa);
      ws['!cols']=(s.aoa[0]||[]).map((_,i)=>{ let m=4; s.aoa.forEach(r=>{ if(r[i]!=null){const L=String(r[i]).length; if(L>m)m=L;} }); return {wch:Math.min(Math.max(m+2,8),60)}; });
      XLSX.utils.book_append_sheet(wb, ws, s.name.slice(0,31)); });
    XLSX.writeFile(wb, `agent_coverage_full_${stamp}.xlsx`); return; }
});
buildExportMenu();
