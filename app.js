'use strict';
// ---------- state ----------
const STATE = { ad:[], me:[], ten:[], cs:[], intune:[], adCols:[], src:{}, staleDays:30, denom:'enabled',
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
['ad','me','ten','cs','intune'].forEach(k=>{
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
const FLATBTN = { ad:'adFlatBtn', me:'meFlatBtn', ten:'tenFlatBtn', cs:'csFlatBtn', intune:'intuneFlatBtn' };
function markLoaded(kind, name){ const slot=document.getElementById('slot-'+slotId(kind)); slot.classList.add('loaded');
  markStatus(kind, '✓ '+name+' · '+(STATE[kind].length).toLocaleString()+' rows');
  const fb=document.getElementById(FLATBTN[kind]); if(fb) fb.classList.remove('hidden');
  maybeAutoBuild(); }
function markStatus(kind, msg){ document.getElementById('st-'+slotId(kind)).textContent=msg; }
function slotId(k){ return k==='ten'?'ten':k; }   // ids match
function maybeAutoBuild(){ if(STATE.ad.length){ /* AD is enough to start */ } }

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
  if(kind==='intune') return { name:findCol(c,[/device.?name/i,/computer.?name/i,/host.?name/i,/^name$/i]),
    seen:findCol(c,[/last.?check.?in/i,/last.?sync/i,/last.?contact/i,/last.?seen/i]), ver:findCol(c,[/os.?version/i,/version/i]),
    status:findCol(c,[/compliance/i,/status/i]), group:findCol(c,[/ownership/i,/group/i]) };
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
    const type = toks.find(t=>/server/i.test(t)) ? 'Server' : (toks.find(t=>/workstation/i.test(t)) ? 'Workstation' : (/(server|linux)/i.test(adField(r,[adOsCol]))?'Server':'Workstation'));
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

const AGENTS = [ ['me','ManageEngine','#b9770b'], ['ten','Tenable','#003f73'], ['cs','CrowdStrike','#1f9d57'], ['intune','Intune','#534ab7'] ];
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

  const d = $('#dashboard'); d.innerHTML='';
  document.getElementById('uploader').scrollIntoView({block:'start'});

  // KPI cards
  const kpi = (l,v,s,col)=>`<div class="card"><div class="l">${l}</div><div class="v"${col?` style="color:${col}"`:''}>${v}</div>${s?`<div class="s">${s}</div>`:''}</div>`;
  let cards = kpi('AD computers', fmt(M.ad.length), `${fmt(denom)} in scope · ${fmt(nNonReal)} cluster/alias`);
  AGENTS.forEach(([k,label,c])=>{ const n=cov(k); cards += kpi(label+' coverage', pct(n,denom)+'%', `${fmt(n)} / ${fmt(denom)} · ${fmt(stale(k))} stale`, c); });
  cards += kpi('Fully covered', pct(fully,denom)+'%', `${fmt(fully)} on all ${AKEYS.length} agents`, 'var(--ok)');
  cards += kpi('No coverage', fmt(none), 'in-scope, 0 agents', none? 'var(--crit)':null);
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
  </div>`);
  drawAgentChart(inScope, denom);
  drawSegChart(inScope);

  // coverage matrix
  buildMatrix(M, inScope);

  // orphans
  buildOrphans(M);

  STATE.built = true; STATE._inScope = inScope; STATE._M = M;
  buildExportMenu();
  attachSaveControls();
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

// ---------- coverage matrix ----------
const cell = c => c.present ? (c.stale? `<span class="pill stale" title="${Math.round(c.days)}d ago">stale</span>` : `<span class="pill ok">✓</span>`) : `<span class="pill gap">✗</span>`;
function buildMatrix(M, inScope){
  const segs=[...new Set(M.ad.map(c=>c.seg))].sort();
  const oses=[...new Set(M.ad.map(c=>c.os))].sort();
  const html = `<div class="panel" id="matrixPanel"><h3>Coverage matrix</h3>
    <div class="controls">
      <input id="mxSearch" placeholder="Search host…" style="min-width:160px">
      <select id="mxView"><option value="all">All in-scope</option><option value="gaps">Has a gap</option><option value="none">No coverage</option><option value="full">Fully covered</option><option value="stale">Any stale</option></select>
      <select id="mxSeg"><option value="">All segments</option>${segs.map(s=>`<option>${s}</option>`).join('')}</select>
      <select id="mxOs"><option value="">All OS</option>${oses.map(s=>`<option>${s}</option>`).join('')}</select>
      <select id="mxType"><option value="">All types</option><option>Server</option><option>Workstation</option></select>
      <span class="sub" id="mxCount"></span>
    </div>
    <div class="legend"><span><span class="sw" style="background:#1f9d57"></span>Covered</span><span><span class="sw" style="background:#b9770b"></span>Stale (&gt;${STATE.staleDays}d)</span><span><span class="sw" style="background:#7a3340"></span>Gap</span></div>
    <div class="scrollwrap"><table><thead><tr>
      <th data-s="name">Computer</th><th data-s="seg">Segment</th><th data-s="os">OS</th><th data-s="type">Type</th><th data-s="enabled">Enabled</th>
      ${AGENTS.map(a=>`<th>${a[1]}</th>`).join('')}<th class="num" data-s="nAgents">Agents</th>
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
      if(view==='stale' && !['ten','me','cs'].some(k=>c.cov[k].stale)) return false;
      return true;
    });
    if(STATE._sort){ const {k,dir}=STATE._sort; rows.sort((a,b)=>{ let x=a[k],y=b[k]; if(typeof x==='string'){x=x.toUpperCase();y=String(y).toUpperCase();} return (x>y?1:x<y?-1:0)*dir; }); }
    $('#mxCount').textContent = rows.length.toLocaleString()+' of '+inScope.length.toLocaleString();
    $('#mxBody').innerHTML = rows.slice(0,2000).map(c=>`<tr>
      <td>${c.name}</td><td>${c.seg}</td><td style="font-size:12px">${c.os}</td><td>${c.type}</td>
      <td>${c.enabled?'<span class="pill ok">Yes</span>':'<span class="pill muted">No</span>'}</td>
      ${AGENTS.map(a=>`<td>${cell(c.cov[a[0]])}</td>`).join('')}
      <td class="num">${c.nAgents===AKEYS.length?`<span class="pill ok">${AKEYS.length}/${AKEYS.length}</span>`:c.nAgents===0?`<span class="pill gap">0/${AKEYS.length}</span>`:c.nAgents+'/'+AKEYS.length}</td></tr>`).join('')
      + (rows.length>2000?`<tr><td colspan="9" class="sub">Showing first 2,000 of ${rows.length.toLocaleString()} — refine filters or export the full set.</td></tr>`:'');
  };
  ['mxSearch','mxView','mxSeg','mxOs','mxType'].forEach(id=>$('#'+id).addEventListener('input',fill));
  $('#matrixPanel').querySelectorAll('th[data-s]').forEach(th=>th.addEventListener('click',()=>{
    const k=th.dataset.s; STATE._sort = STATE._sort && STATE._sort.k===k ? {k,dir:-STATE._sort.dir} : {k,dir:1}; fill(); }));
  STATE._matrixFill = fill; fill();
}

function buildOrphans(M){
  if(!M.orphans.length){ return; }
  const rows = M.orphans.slice(0,2000).map(o=>`<tr><td>${o.host}</td><td>${o.source}</td><td style="font-size:12px">${o.seen||''}</td></tr>`).join('');
  $('#dashboard').insertAdjacentHTML('beforeend', `<div class="panel"><h3>Orphan agents <span class="sub">— reporting in but not found in Active Directory (decommissioned, renamed, or rogue)</span></h3>
    <div class="scrollwrap"><table><thead><tr><th>Host</th><th>Source</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table></div></div>`);
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
function copyTable(tsv,msg){ if(window.ClipboardItem && navigator.clipboard?.write){
    return navigator.clipboard.write([new ClipboardItem({'text/plain':new Blob([tsv],{type:'text/plain'}),'text/html':new Blob([tsvToHtmlTable(tsv)],{type:'text/html'})})]).then(()=>toast(msg),e=>{console.error(e);toast('Clipboard write failed');}); }
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
    showLoading('Loading sample data…'); await nextPaint();
    const [adTxt, meTxt, tenTxt, csTxt, intuneTxt] = await Promise.all([
      fetch('sample-data/ad-computers.json').then(r=>r.text()),
      fetch('sample-data/manageengine.csv').then(r=>r.text()),
      fetch('sample-data/tenable-agents.csv').then(r=>r.text()),
      fetch('sample-data/crowdstrike.csv').then(r=>r.text()),
      fetch('sample-data/intune.csv').then(r=>r.text()) ]);
    STATE.ad = flattenAd(adTxt); STATE.adCols = unionCols(STATE.ad); STATE.src.ad='ad-computers.json'; markLoaded('ad','ad-computers.json (sample)');
    STATE.me = Papa.parse(meTxt,{header:true,skipEmptyLines:true}).data; STATE.src.me='manageengine.csv'; markLoaded('me','manageengine.csv (sample)');
    STATE.ten = Papa.parse(tenTxt,{header:true,skipEmptyLines:true}).data; STATE.src.ten='tenable-agents.csv'; markLoaded('ten','tenable-agents.csv (sample)');
    STATE.cs = Papa.parse(csTxt,{header:true,skipEmptyLines:true}).data; STATE.src.cs='crowdstrike.csv'; markLoaded('cs','crowdstrike.csv (sample)');
    STATE.intune = Papa.parse(intuneTxt,{header:true,skipEmptyLines:true}).data; STATE.src.intune='intune.csv'; markLoaded('intune','intune.csv (sample)');
    showLoading('Building dashboard…'); await nextPaint(); render();
  }catch(e){ console.error(e); alert('Could not load sample (serve over http, or load files manually).'); }
  finally{ hideLoading(); }
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

function buildExportMenu(){
  const sel=$('#exportSel'); if(!sel) return;
  sel.innerHTML = [
    ['matrix-csv','Coverage matrix (CSV)'],['full-xlsx','Full report (XLSX)'],
    ['gaps-csv','Coverage gaps (CSV)'],['orphans-csv','Orphan agents (CSV)'],
    ['flatad-csv','Flattened AD (CSV)']
  ].map(([v,l])=>`<option value="${v}">${l}</option>`).join('');
}
$('#exportBtn').addEventListener('click', ()=>{
  if(!STATE.built){ alert('Build the dashboard first.'); return; }
  const kind=$('#exportSel').value, stamp=new Date().toISOString().slice(0,10);
  if(kind==='flatad-csv'){ downloadFlatAd(); return; }
  if(kind==='matrix-csv'){ const m=matrixRows(); const c=objCols(m); dl(`coverage_matrix_${stamp}.csv`, toCsv(c, objRows(m,c)), 'text/csv'); return; }
  if(kind==='gaps-csv'){ const gaps=(STATE._inScope||[]).filter(c=>c.nAgents<AKEYS.length).map(c=>({computer:c.name,segment:c.seg,os:c.os,type:c.type,
      missing:AGENTS.filter(([k])=>!c.cov[k].present).map(a=>a[1]).join('; '), agents:c.nAgents+'/'+AKEYS.length}));
    const c=objCols(gaps); dl(`coverage_gaps_${stamp}.csv`, toCsv(c, objRows(gaps,c)), 'text/csv'); return; }
  if(kind==='orphans-csv'){ const o=STATE._M.orphans; const c=['host','source','seen']; dl(`orphan_agents_${stamp}.csv`, toCsv(c, o.map(x=>[x.host,x.source,x.seen])), 'text/csv'); return; }
  if(kind==='full-xlsx'){
    const wb=XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(summaryAoa()), 'Summary');
    const m=matrixRows(); XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(m), 'Coverage Matrix');
    const gaps=(STATE._inScope||[]).filter(c=>c.nAgents<AKEYS.length).map(c=>({computer:c.name,segment:c.seg,os:c.os,type:c.type,missing:AGENTS.filter(([k])=>!c.cov[k].present).map(a=>a[1]).join('; ')}));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(gaps.length?gaps:[{computer:'(none)'}]), 'Gaps');
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet((STATE._M.orphans.length?STATE._M.orphans:[{host:'(none)'}])), 'Orphans');
    XLSX.writeFile(wb, `agent_coverage_${stamp}.xlsx`); return; }
});
buildExportMenu();
