// Generates the agent-coverage sample from the SAME systems as the Tenable VM dashboard sample,
// so the two dashboards line up. Adds cluster/alias objects + stale-logon hosts to exercise the AD filters.
const fs = require('fs');
const path = require('path');
const OUT = path.join(__dirname, 'sample-data');
const TEN = process.env.TEN_SAMPLE || '/tmp/tenable-vm-dashboard/sample-data';

let SEED = 20260625;
const rnd = () => { SEED = (SEED*1103515245 + 12345) & 0x7fffffff; return SEED/0x7fffffff; };
const pick = a => a[Math.floor(rnd()*a.length)];
const pad = (n,w)=>String(n).padStart(w,'0');
const daysAgoMs = d => Date.now() - Math.floor(d*86400000);
const psDate = ms => `/Date(${ms})/`;
const iso = ms => new Date(ms).toISOString();

// ---- pull distinct systems from the Tenable sample (proper CSV parse — fields contain quoted commas/newlines) ----
const Papa = require('./vendor/papaparse.min.js');
function loadHosts(){
  const hosts = new Map();
  for(const f of ['cumulative.csv','mitigated.csv']){
    const txt = fs.readFileSync(path.join(TEN,f),'utf8');
    const rows = Papa.parse(txt,{header:true,skipEmptyLines:true}).data;
    rows.forEach(r=>{ const d=r.dnsName; if(d && /^[a-z0-9-]+\.[a-z0-9.-]+$/i.test(d) && !hosts.has(d))
      hosts.set(d,{ dns:d, ip:r.ip, os:(r.operatingSystem||'').replace(/^Microsoft\s+/,''), repo:r.repository }); });
  }
  return [...hosts.values()];
}
const src = loadHosts();
const typeOf = os => /windows (10|11)/i.test(os) ? 'Workstation' : 'Server';
const segOf  = repo => String(repo||'').replace(/_Repo$/i,'').toUpperCase();

// ---- AD computer objects (the real systems) ----
const real = src.map(s=>{
  const name = s.dns.split('.')[0].toUpperCase();
  const seg = segOf(s.repo); const type = typeOf(s.os);
  const enabled = rnd() > 0.04;
  // last logon: ~70% within 15d, ~20% 15–90d, ~10% 90–400d; disabled → old
  let logonDays; const r=rnd();
  if(!enabled) logonDays = 60 + rnd()*400;
  else if(r<0.70) logonDays = rnd()*15;
  else if(r<0.90) logonDays = 15 + rnd()*75;
  else logonDays = 90 + rnd()*310;
  return { name, dns:s.dns, ip:s.ip, os:s.os, seg, type, enabled, logon:daysAgoMs(logonDays),
    created:daysAgoMs(120+rnd()*1500), real:true };
});

// ---- cluster/alias objects (CNOs/VCOs): no OS, cluster SPNs — should be filtered out as "not real systems" ----
const SEGS=[...new Set(real.map(r=>r.seg))];
const CLU_APPS=['sql','fci','exch','ag','fs','dtc','rds'];
const clusters=[];
for(let i=0;i<60;i++){ const seg=pick(SEGS); const app=pick(CLU_APPS);
  const name=`${seg}-${app}clu${pad(1+Math.floor(rnd()*40),2)}`.toUpperCase();
  clusters.push({ name, dns:`${name.toLowerCase()}.${seg.toLowerCase()}.local`, ip:'', os:'', seg, type:'Cluster',
    enabled:true, logon: rnd()<0.5? daysAgoMs(rnd()*30): null, created:daysAgoMs(200+rnd()*1200), real:false }); }

const all = real.concat(clusters);

// ---- AD JSON (Get-ADComputer -Properties * | ConvertTo-Json style) ----
const adJson = all.map(c=>{
  const o = {
    Name: c.name, DNSHostName: c.dns, SamAccountName: c.name+'$',
    Enabled: c.enabled,
    OperatingSystem: c.os || null,
    OperatingSystemVersion: c.os ? (/server 2022|11 ent/i.test(c.os)?'10.0 (22621)':'10.0') : null,
    DistinguishedName: c.real
      ? `CN=${c.name},OU=${c.type}s,OU=${c.seg},OU=Computers,DC=corp,DC=local`
      : `CN=${c.name},OU=Clusters,OU=${c.seg},OU=Computers,DC=corp,DC=local`,
    IPv4Address: c.ip || null,
    whenCreated: psDate(c.created),
    LastLogonDate: c.logon ? psDate(c.logon) : null,
    lastLogonTimestamp: c.logon ? String(c.logon*1e4) : '0',
    ObjectClass: 'computer',
    ServicePrincipalName: c.real
      ? [`HOST/${c.name}`, `HOST/${c.dns}`, `TERMSRV/${c.name}`]
      : [`MSServerCluster/${c.name}`, `MSServerClusterMgmtAPI/${c.dns}`],
    MemberOf: c.type==='Server' ? [`CN=Servers-${c.seg},OU=Groups,DC=corp,DC=local`] : [],
    Location: { Site: c.seg, Building: 'B'+(1+Math.floor(rnd()*4)) },
    Description: c.real ? '' : 'Failover cluster virtual network name account',
  };
  return o;
});
fs.writeFileSync(path.join(OUT,'ad-computers.json'), JSON.stringify(adJson, null, 2));

// ---- CSV helper ----
const csv = (rows, cols) => { const esc=v=>{v=v==null?'':String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  return [cols.join(',')].concat(rows.map(r=>cols.map(c=>esc(r[c])).join(','))).join('\n'); };
const has = (c, base) => { let p=base; if(c.type==='Server') p+=0.05; if(!c.enabled) p-=0.45; return rnd()<p; };

// ---- agent sources (subsets of REAL systems) + orphans ----
const me=[], ten=[], cs=[];
real.forEach(c=>{
  if(has(c,0.90)){ const stale=rnd()<0.07; me.push({ 'Computer Name':c.name,
    'Agent Version':`10.1.${2400+Math.floor(rnd()*40)}.${Math.floor(rnd()*20)}`,
    'Last Contact Time':iso(daysAgoMs(stale?30+rnd()*120:rnd()*3)),
    'Last Successful Scan Time':iso(daysAgoMs(stale?35+rnd()*120:rnd()*7)),
    'Last Patch Date':iso(daysAgoMs(rnd()*45)), 'Custom Group':`${c.seg} ${c.type}s` }); }
  if(has(c,0.86)){ const stale=rnd()<0.06; ten.push({ Hostname: rnd()<0.3?c.dns:c.name,
    AgentId:[...Array(32)].map(()=>'0123456789abcdef'[Math.floor(rnd()*16)]).join(''),
    Groups:`${c.seg}-Agents`, LastConnectUtc:iso(daysAgoMs(stale?30+rnd()*90:rnd()*2)),
    LastScannedUtc:iso(daysAgoMs(stale?40+rnd()*90:rnd()*9)), RestartPending: rnd()<0.05?'True':'False' }); }
  if(has(c,0.83)){ const rfm=rnd()<0.04; cs.push({ Hostname:c.name,
    'Sensor Version':`7.${14+Math.floor(rnd()*6)}.${17000+Math.floor(rnd()*900)}`,
    'Last Seen':iso(daysAgoMs(rnd()<0.06?30+rnd()*60:rnd()*2)), 'First Seen':iso(daysAgoMs(60+rnd()*1000)),
    'OS Version':c.os, Platform: c.os.includes('Linux')?'Linux':'Windows',
    Status: rfm?'Reduced Functionality Mode':(rnd()<0.01?'Contained':'Normal'),
    'OU':`${c.seg}/${c.type}s`, 'Device ID':[...Array(32)].map(()=>'0123456789abcdef'[Math.floor(rnd()*16)]).join('') }); }
});
for(let i=0;i<40;i++) me.push({ 'Computer Name':`OLD-PC${pad(i,3)}`,'Agent Version':'10.1.2390.4','Last Contact Time':iso(daysAgoMs(90+rnd()*200)),'Last Successful Scan Time':iso(daysAgoMs(95+rnd()*200)),'Last Patch Date':iso(daysAgoMs(120+rnd()*200)),'Custom Group':'Decommissioned' });
for(let i=0;i<30;i++) ten.push({ Hostname:`LAB-TEST${pad(i,3)}`,AgentId:'ff00ff00ff00ff00ff00ff00ff00ff00',Groups:'Lab-Agents',LastConnectUtc:iso(daysAgoMs(rnd()*5)),LastScannedUtc:iso(daysAgoMs(rnd()*10)),RestartPending:'False' });
for(let i=0;i<24;i++) cs.push({ Hostname:`BYOD-LT${pad(i,3)}`,'Sensor Version':'7.19.17888','Last Seen':iso(daysAgoMs(rnd()*3)),'First Seen':iso(daysAgoMs(30+rnd()*200)),'OS Version':'Windows 11 Pro',Platform:'Windows',Status:'Normal','OU':'Unmanaged','Device ID':'aa11bb22cc33dd44ee55ff66aa77bb88' });

fs.writeFileSync(path.join(OUT,'manageengine.csv'), csv(me, ['Computer Name','Agent Version','Last Contact Time','Last Successful Scan Time','Last Patch Date','Custom Group']));
fs.writeFileSync(path.join(OUT,'tenable-agents.csv'), csv(ten, ['Hostname','AgentId','Groups','LastConnectUtc','LastScannedUtc','RestartPending']));
fs.writeFileSync(path.join(OUT,'crowdstrike.csv'), csv(cs, ['Hostname','Sensor Version','Last Seen','First Seen','OS Version','Platform','Status','OU','Device ID']));

const within15 = real.filter(c=>c.enabled && (Date.now()-c.logon)/86400000<=15).length;
console.log(`real=${real.length} clusters=${clusters.length} | enabled=${real.filter(c=>c.enabled).length} loggedIn<=15d=${within15} | ME=${me.length} Tenable=${ten.length} CS=${cs.length}`);
