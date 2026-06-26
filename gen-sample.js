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
  // ~3% of systems were created in the last 30 days (newly-built hosts that may not have agents yet)
  const created = rnd()<0.03 ? daysAgoMs(rnd()*30) : daysAgoMs(120+rnd()*1500);
  return { name, dns:s.dns, ip:s.ip, os:s.os, seg, type, enabled, logon:daysAgoMs(logonDays), created, real:true };
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
    // machine account passwords auto-rotate ~30d while online; offline hosts don't rotate, so pwd age tracks logon age
    PasswordLastSet: psDate(daysAgoMs(Math.max((c.logon?(Date.now()-c.logon)/86400000:300)*0.9, rnd()*28))),
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

// ---- ManageEngine Endpoint Central real export schema (matches a real UEMS_Agent CSV; see Joe's export) ----
// Dates are M/D/YYYY H:MM (the format ManageEngine emits), host fields lowercased like the real tool.
const macAddr = () => [...Array(6)].map(()=>pad(Math.floor(rnd()*256).toString(16),2)).join(':');
const meDate  = ms => { const d=new Date(ms); return `${d.getMonth()+1}/${d.getDate()}/${d.getFullYear()} ${d.getHours()}:${pad(d.getMinutes(),2)}`; };
function osMeta(os){
  const s=os||'';
  if(/linux|red hat|rhel|centos/i.test(s)) return { name:s||'Red Hat Enterprise Linux Server', ver:/(\b8\b|rhel ?8)/i.test(s)?'5.14.0-362.el8.x86_64':'3.10.0-1160.el7.x86_64', plat:'Linux', sp:'' };
  let ver='10.0.19045', sp='';
  if(/2012 r2/i.test(s)){ ver='6.3.9600'; sp='Windows Server 2012 R2 (x64)'; }
  else if(/server 2016/i.test(s)){ ver='10.0.14393'; sp='Windows Server 2016 Gold (x64)'; }
  else if(/server 2019/i.test(s)){ ver='10.0.17763'; sp='Windows Server 2019 Gold (x64)'; }
  else if(/server 2022/i.test(s)){ ver='10.0.20348'; sp='Windows Server 2022 Gold (x64)'; }
  else if(/windows 11/i.test(s)){ ver='10.0.22631'; sp='Windows 11 (x64)'; }
  else if(/windows 10/i.test(s)){ ver='10.0.19045'; sp='Windows 10 (x64)'; }
  const name = s ? (/\(x64\)/.test(s)?s:s+' (x64)') : 'Windows Server 2019 Datacenter Edition (x64)';
  return { name, ver, plat:'Windows', sp };
}
function meRow(c, { stale, contactMs, installMs }){
  const om = osMeta(c.os);
  const missingMS  = rnd()<0.55 ? 0 : Math.floor(rnd()*900);
  const installedMS= 750 + Math.floor(rnd()*350);
  const totalMS    = installedMS + missingMS;
  const critical   = missingMS>0 ? Math.floor(rnd()*15) : 0;
  const important  = missingMS>0 ? Math.floor(rnd()*40) : 0;
  const moderate   = missingMS>0 ? Math.floor(rnd()*20) : 0;
  const low        = missingMS>0 ? Math.floor(rnd()*10) : 0;
  const installedTP= 250 + Math.floor(rnd()*120);
  const missingTP  = rnd()<0.7 ? 0 : Math.floor(rnd()*40);
  const totalTP    = installedTP + missingTP;
  const health     = critical>0 ? 'Highly Vulnerable' : (missingMS>0 ? 'Vulnerable' : 'Healthy');
  const grpIdx     = Math.max(0, SEGS.indexOf(c.seg));
  return {
    computer_name: c.name.toLowerCase(), full_name: c.name.toLowerCase(), fqdn_name: (c.dns||c.name).toLowerCase(),
    Custom_group_name: `PatchGroup${1+(grpIdx%9)}`, domain_name: (c.seg||'corp').toLowerCase(),
    agent_version: stale ? `11.4.${2400+Math.floor(rnd()*60)}.${Math.floor(rnd()*20)}.W` : `11.5.${2600+Math.floor(rnd()*40)}.${Math.floor(rnd()*20)}.W`,
    Last_Contact_Time: meDate(contactMs), Last_Bootup_Time: meDate(daysAgoMs(rnd()*25)),
    Agent_Installed_on: meDate(installMs!=null?installMs:daysAgoMs(60+rnd()*340)), Agent_Upgraded_on: meDate(daysAgoMs(rnd()*60)),
    Agent_Executed_on: meDate(daysAgoMs(rnd()*3)), 'Last Patched Time': meDate(daysAgoMs(rnd()*45)),
    // most agents scan within ~1.5d; ~15% lag into a 3–40d tail → "not scanning" minority (esp. vs the 2d server threshold)
    'Last Successful Scan': meDate(daysAgoMs(stale ? 35+rnd()*120 : (rnd()<0.15 ? 3+rnd()*37 : rnd()*1.5))),
    IP_Address: c.ip || `10.${1+Math.floor(rnd()*20)}.${Math.floor(rnd()*255)}.${1+Math.floor(rnd()*254)}`, Mac_Address: macAddr(),
    OS_Name: om.name, OS_Version: om.ver, Service_Pack: om.sp, 'OS Platform Name': om.plat,
    Agent_installed_dir: om.plat==='Linux' ? '/opt/manageengine/uems_agent/' : 'C:\\Program Files (x86)\\ManageEngine\\UEMS_Agent\\',
    Branch_Office_Name: `${c.seg||'CORP'}_BranchOffice`, Logged_on_User: rnd()<0.75 ? '0' : `${(c.seg||'corp').toLowerCase()}\\user${Math.floor(rnd()*900)}`,
    'Total Driver Patches': 0, 'Missing BIOS Patches': 0, 'Total TP Patches': totalTP, 'Missing MS Patches': missingMS,
    'Important Patch Count': important, 'Missing Driver Patches': 0, 'Total MS Patches': totalMS, 'Installed MS Patches': installedMS,
    'Low Patch Count': low, 'Installed TP Patches': installedTP, 'Critical Patch Count': critical, 'Installed BIOS Patches': 0,
    'Total BIOS Patches': 0, 'Installed Driver Patches': 0, 'MODERATE Patch Count': moderate,
    'Deployment Status': (missingMS>0 && rnd()<0.08) ? 'Deployment Failed' : 'Deployment Success', Location: '0',
    'Resource Live Status': stale ? 'DOWN' : 'UP', 'Reboot Status': (missingMS>0 && rnd()<0.3) ? 'Required' : 'Not Required',
    'Health Status': health, Owner: '0', 'Scan Status': 'Scanning Completed',
    'Scan Remarks': 'dc.patch.util.Scanning_completedsuccessfully', 'Customer Name': 'user@company.com',
  };
}
// Real export order. 'Total TP Patches' intentionally appears twice — that duplicate column is in the real ManageEngine CSV.
const ME_COLS = ['computer_name','full_name','fqdn_name','Custom_group_name','domain_name','agent_version','Last_Contact_Time','Last_Bootup_Time','Agent_Installed_on','Agent_Upgraded_on','Agent_Executed_on','Last Patched Time','Last Successful Scan','IP_Address','Mac_Address','OS_Name','OS_Version','Service_Pack','OS Platform Name','Agent_installed_dir','Branch_Office_Name','Logged_on_User','Total Driver Patches','Missing BIOS Patches','Total TP Patches','Missing MS Patches','Important Patch Count','Missing Driver Patches','Total MS Patches','Installed MS Patches','Low Patch Count','Total TP Patches','Installed TP Patches','Critical Patch Count','Installed BIOS Patches','Total BIOS Patches','Installed Driver Patches','MODERATE Patch Count','Deployment Status','Location','Resource Live Status','Reboot Status','Health Status','Owner','Scan Status','Scan Remarks','Customer Name'];

// ---- CrowdStrike Falcon host export real schema (Hostname, IP address history, OS version, Sensor version, Manufacturer, Last seen) ----
// Real exports may carry many more columns; the app finds these by fuzzy header match and ignores the rest.
const isoZ = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/,'Z');     // CrowdStrike timestamps have no millis
const MANUF = [['VMware, Inc.',0.55],['Microsoft Corporation',0.25],['Dell Inc.',0.12],['HPE',0.08]];
const manuf = () => { let r=rnd(),a=0; for(const [m,w] of MANUF){ a+=w; if(r<a) return m; } return 'VMware, Inc.'; };
function csOs(os){ const s=os||'';
  if(/2012 r2/i.test(s)) return 'Windows Server 2012 R2';
  let m=s.match(/server (20\d\d)/i); if(m) return 'Windows Server '+m[1];
  if(/windows 11/i.test(s)) return 'Windows 11'; if(/windows 10/i.test(s)) return 'Windows 10';
  if(/red hat|rhel|linux/i.test(s)){ m=s.match(/(\d+(?:\.\d+)?)/); return 'RHEL '+(m?m[1]:'8.10'); }
  return s || 'Windows Server 2019';
}
function csRow(c, { contactMs }){
  const ip2 = `10.${1+Math.floor(rnd()*20)}.${Math.floor(rnd()*255)}.${1+Math.floor(rnd()*254)}`;
  return {
    Hostname: (rnd()<0.18 && c.dns) ? c.dns.toUpperCase() : c.name,        // ~18% FQDN to exercise hostname normalization
    'IP address history': (rnd()<0.2 && c.ip) ? `${c.ip}, ${ip2}` : (c.ip || `100.${64+Math.floor(rnd()*40)}.${Math.floor(rnd()*255)}.${1+Math.floor(rnd()*254)}`),
    'OS version': csOs(c.os),
    'Sensor version': `7.${30+Math.floor(rnd()*12)}.${19000+Math.floor(rnd()*2000)}.0`,
    Manufacturer: manuf(),
    'Last seen': isoZ(contactMs),
    Status: rnd()<0.04 ? 'Reduced Functionality Mode' : (rnd()<0.012 ? 'Contained' : 'Normal'),   // real Falcon exports carry a sensor status
  };
}
const CS_COLS = ['Hostname','IP address history','OS version','Sensor version','Manufacturer','Last seen','Status'];

// ---- agent sources (subsets of REAL systems) + orphans ----
const me=[], ten=[], cs=[];
real.forEach(c=>{
  if(has(c,0.90)){ const stale=rnd()<0.07; me.push(meRow(c,{ stale, contactMs:daysAgoMs(stale?30+rnd()*120:rnd()*3) })); }
  if(has(c,0.86)){ const stale=rnd()<0.06; ten.push({ Hostname: rnd()<0.3?c.dns:c.name,
    AgentId:[...Array(32)].map(()=>'0123456789abcdef'[Math.floor(rnd()*16)]).join(''),
    Groups:`${c.seg}-Agents`, LastConnectUtc:iso(daysAgoMs(stale?30+rnd()*90:rnd()*2)),
    LastScannedUtc:iso(daysAgoMs(stale?40+rnd()*90:(rnd()<0.15?3+rnd()*37:rnd()*1.5))), RestartPending: rnd()<0.05?'True':'False' }); }
  // CrowdStrike check-in: mostly fresh, ~6% stale (>30d), ~12% a 3-12d tail → "unhealthy" vs a 2d check-in threshold
  if(has(c,0.83)){ cs.push(csRow(c,{ contactMs:daysAgoMs(rnd()<0.06 ? 30+rnd()*60 : rnd()<0.12 ? 3+rnd()*9 : rnd()*1.5) })); }
});
for(let i=0;i<40;i++){ const nm=`OLD-PC${pad(i,3)}`;
  me.push(meRow({ name:nm, dns:`${nm.toLowerCase()}.corp.local`, ip:'', os:'Windows Server 2012 R2 Standard', seg:'DECOM', type:'Server' },
    { stale:true, contactMs:daysAgoMs(90+rnd()*200), installMs:daysAgoMs(400+rnd()*400) })); }
for(let i=0;i<30;i++) ten.push({ Hostname:`LAB-TEST${pad(i,3)}`,AgentId:'ff00ff00ff00ff00ff00ff00ff00ff00',Groups:'Lab-Agents',LastConnectUtc:iso(daysAgoMs(rnd()*5)),LastScannedUtc:iso(daysAgoMs(rnd()*10)),RestartPending:'False' });
for(let i=0;i<24;i++){ const nm=`BYOD-LT${pad(i,3)}`;
  cs.push(csRow({ name:nm, dns:`${nm.toLowerCase()}.archgroup.io`, ip:`100.81.${Math.floor(rnd()*255)}.${1+Math.floor(rnd()*254)}`, os:'Windows 11 Pro' }, { contactMs:daysAgoMs(rnd()*3) })); }

fs.writeFileSync(path.join(OUT,'manageengine.csv'), csv(me, ME_COLS));
fs.writeFileSync(path.join(OUT,'tenable-agents.csv'), csv(ten, ['Hostname','AgentId','Groups','LastConnectUtc','LastScannedUtc','RestartPending']));
fs.writeFileSync(path.join(OUT,'crowdstrike.csv'), csv(cs, CS_COLS));

const within15 = real.filter(c=>c.enabled && (Date.now()-c.logon)/86400000<=15).length;
console.log(`real=${real.length} clusters=${clusters.length} | enabled=${real.filter(c=>c.enabled).length} loggedIn<=15d=${within15} | ME=${me.length} Tenable=${ten.length} CS=${cs.length}`);
