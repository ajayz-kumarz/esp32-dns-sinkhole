// ESP32 DNS ad-blocking sinkhole + web dashboard
// Board: ESP32 Dev Module. Partition scheme: "No OTA (1MB APP/3MB SPIFFS)".
// Put blocklist.bin (from build_blocklist.py) in ./data and upload it with the LittleFS uploader.
// Dashboard: http://sinkhole.local  or  http://<LOCAL_IP>   (login: UI_USER / UI_PASS)

#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <time.h>
#include <vector>
#include <algorithm>

// ---------- config ----------
const char* WIFI_SSID    = "YOUR_SSID";
const char* WIFI_PASS    = "YOUR_PASSWORD";
const char* UI_USER      = "admin";
const char* UI_PASS      = "changeme";        // change this
const char* HOSTNAME     = "sinkhole";        // http://sinkhole.local
const char* DASHBOARD_NAME = "My Home";       // title shown on the dashboard only (not the Wi-Fi name)
const long  TZ_OFFSET_SEC = 4 * 3600;         // your UTC offset in seconds (UTC+4 here)

IPAddress LOCAL_IP(192, 168, 1, 53);
IPAddress GATEWAY (192, 168, 1, 1);
IPAddress SUBNET  (255, 255, 255, 0);
IPAddress UPSTREAM(1, 1, 1, 1);
const uint32_t UPSTREAM_TIMEOUT_MS = 2000;
const uint32_t BLOCK_TTL = 300;

// Friendly names for devices (give them DHCP reservations on the router so the IP stays fixed).
// type: laptop, phone, tv, tablet, other
struct NamedDevice { const char* ip; const char* name; const char* type; };
const NamedDevice DEVICES[] = {
  {"192.168.1.24", "MacBook",        "laptop"},
  {"192.168.1.31", "iPhone",         "phone"},
  {"192.168.1.40", "Living room TV", "tv"},
};
// ----------------------------

WiFiUDP server;
WiFiUDP upstream;
WebServer web(80);
Preferences prefs;

File blocklist;
uint32_t blCount = 0;
uint8_t buf[1500];

uint32_t statTotal = 0, statBlocked = 0;
bool paused = false;
uint32_t pauseUntil = 0;                      // 0 = indefinite

std::vector<String> allowList, blockList;     // stored in NVS, survive blocklist uploads

// ---------- pending forwarded queries ----------
const int MAXP = 64;
struct Pending {
  bool used;
  uint16_t origId, newId;
  IPAddress ip;
  uint16_t port;
  uint32_t ts;
} pend[MAXP];

// ---------- stats: log, hourly, today, devices ----------
struct LogEntry { char name[64]; uint32_t ip; uint32_t t; bool blocked; };
const int LOG_N = 50;
LogEntry logBuf[LOG_N];
int logHead = 0, logCount = 0;

struct Hour { uint32_t key, t, b; };
const int HOURS = 24;
Hour hours[HOURS];

uint32_t dayKey = 0, todayTotal = 0, todayBlocked = 0;

struct Dev { uint32_t ip, t, b, last; };
const int DEV_N = 32;
Dev devs[DEV_N];

bool timeSynced() { return time(nullptr) > 1700000000; }

uint32_t hourKey() {
  return timeSynced() ? (uint32_t)(time(nullptr) / 3600) : millis() / 3600000UL;
}

void addLog(const char* name, IPAddress ip, bool blocked) {
  LogEntry& e = logBuf[logHead];
  strlcpy(e.name, name, sizeof(e.name));
  e.ip = (uint32_t)ip;
  e.t = millis();
  e.blocked = blocked;
  logHead = (logHead + 1) % LOG_N;
  if (logCount < LOG_N) logCount++;
}

void countQuery(IPAddress ip, bool blocked) {
  statTotal++;
  if (blocked) statBlocked++;

  uint32_t k = hourKey();
  Hour& h = hours[k % HOURS];
  if (h.key != k) { h.key = k; h.t = 0; h.b = 0; }
  h.t++;
  if (blocked) h.b++;

  uint32_t d = timeSynced() ? (uint32_t)((time(nullptr) + TZ_OFFSET_SEC) / 86400) : 0;
  if (d != dayKey) { dayKey = d; todayTotal = 0; todayBlocked = 0; }
  todayTotal++;
  if (blocked) todayBlocked++;

  uint32_t v = (uint32_t)ip;
  int slot = -1, oldest = 0;
  for (int i = 0; i < DEV_N; i++) {
    if (devs[i].ip == v) { slot = i; break; }
    if (devs[i].last < devs[oldest].last) oldest = i;
  }
  if (slot < 0) { slot = oldest; devs[slot] = {v, 0, 0, 0}; }
  devs[slot].t++;
  if (blocked) devs[slot].b++;
  devs[slot].last = millis() | 1;
}

// ---------- blocklist ----------
uint64_t fnv1a64(const char* s) {
  uint64_t h = 0xcbf29ce484222325ULL;
  while (*s) { h ^= (uint8_t)tolower(*s++); h *= 0x100000001b3ULL; }
  return h;
}

bool hashInList(uint64_t h) {
  if (!blCount) return false;
  int32_t lo = 0, hi = (int32_t)blCount - 1;
  uint64_t v;
  while (lo <= hi) {
    int32_t mid = lo + (hi - lo) / 2;
    blocklist.seek((uint32_t)mid * 8);
    blocklist.read((uint8_t*)&v, 8);
    if (v == h) return true;
    if (v < h) lo = mid + 1; else hi = mid - 1;
  }
  return false;
}

bool inList(const std::vector<String>& l, const char* d) {
  for (const auto& s : l) if (s.equals(d)) return true;
  return false;
}

bool isPaused() {
  if (paused && pauseUntil && (int32_t)(millis() - pauseUntil) >= 0) paused = false;
  return paused;
}

// Allowlist wins, then custom blocklist, then the big list. Parent domains are checked too.
bool isBlocked(const char* name) {
  if (isPaused()) return false;
  for (const char* p = name; p;) {
    if (inList(allowList, p)) return false;
    const char* d = strchr(p, '.');
    p = d ? d + 1 : nullptr;
  }
  for (const char* p = name;;) {
    const char* d = strchr(p, '.');
    if (!d) return false;
    if (inList(blockList, p) || hashInList(fnv1a64(p))) return true;
    p = d + 1;
  }
}

// ---------- custom lists (NVS) ----------
void parseList(const String& s, std::vector<String>& l) {
  l.clear();
  int start = 0;
  while (start < (int)s.length()) {
    int nl = s.indexOf('\n', start);
    if (nl < 0) nl = s.length();
    String d = s.substring(start, nl);
    d.trim();
    if (d.length()) l.push_back(d);
    start = nl + 1;
  }
}

void loadLists() {
  prefs.begin("sinkhole", true);
  parseList(prefs.getString("allow", ""), allowList);
  parseList(prefs.getString("block", ""), blockList);
  prefs.end();
}

bool saveList(const char* key, const std::vector<String>& l) {
  String s;
  for (const auto& d : l) { s += d; s += '\n'; }
  if (s.length() > 3900) return false;        // NVS string limit
  prefs.begin("sinkhole", false);
  prefs.putString(key, s);
  prefs.end();
  return true;
}

String cleanDomain(String d) {
  d.trim();
  d.toLowerCase();
  int i = d.indexOf("://");
  if (i >= 0) d = d.substring(i + 3);
  i = d.indexOf('/');
  if (i >= 0) d = d.substring(0, i);
  i = d.indexOf(':');
  if (i >= 0) d = d.substring(0, i);
  while (d.startsWith("*.") || d.startsWith(".")) d = d.substring(d.startsWith("*.") ? 2 : 1);
  while (d.endsWith(".")) d.remove(d.length() - 1);
  if (d.length() < 3 || d.length() > 253 || d.indexOf('.') < 0) return "";
  for (unsigned int k = 0; k < d.length(); k++) {
    char c = d[k];
    if (!(isalnum(c) || c == '-' || c == '.' || c == '_')) return "";
  }
  return d;
}

String jsonEsc(const char* s) {
  String o;
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') o += '\\';
    if ((uint8_t)*s >= 0x20) o += *s;
  }
  return o;
}

// ---------- DNS ----------
bool parseQuestion(const uint8_t* m, int len, char* out, int outLen, uint16_t& qtype, int& qEnd) {
  if (len < 17) return false;
  int pos = 12, o = 0;
  while (pos < len) {
    uint8_t l = m[pos];
    if (l == 0) { pos++; break; }
    if (l & 0xC0) return false;
    if (pos + 1 + l > len || o + l + 2 > outLen) return false;
    if (o) out[o++] = '.';
    for (int k = 0; k < l; k++) {
      char c = tolower(m[pos + 1 + k]);
      out[o++] = (isalnum(c) || c == '-' || c == '_') ? c : '?';
    }
    pos += l + 1;
  }
  out[o] = 0;
  if (pos + 4 > len) return false;
  qtype = (m[pos] << 8) | m[pos + 1];
  qEnd = pos + 4;
  return o > 0;
}

int buildBlockedReply(uint8_t* m, int qEnd, uint16_t qtype) {
  m[2] = (m[2] & 0x79) | 0x80;
  m[3] = 0x80;
  m[4] = 0; m[5] = 1;
  m[6] = 0; m[7] = 0;
  m[8] = m[9] = m[10] = m[11] = 0;
  int p = qEnd;
  uint16_t rdlen = (qtype == 1) ? 4 : (qtype == 28) ? 16 : 0;
  if (rdlen) {
    m[7] = 1;
    m[p++] = 0xC0; m[p++] = 0x0C;
    m[p++] = qtype >> 8; m[p++] = qtype & 0xFF;
    m[p++] = 0; m[p++] = 1;
    m[p++] = BLOCK_TTL >> 24; m[p++] = BLOCK_TTL >> 16;
    m[p++] = BLOCK_TTL >> 8;  m[p++] = BLOCK_TTL;
    m[p++] = 0; m[p++] = rdlen;
    memset(m + p, 0, rdlen);
    p += rdlen;
  }
  return p;
}

void forwardQuery(uint8_t* m, int len, IPAddress ip, uint16_t port) {
  uint32_t now = millis();
  int slot = -1;
  for (int i = 0; i < MAXP; i++) {
    if (!pend[i].used || now - pend[i].ts > UPSTREAM_TIMEOUT_MS) { slot = i; break; }
  }
  if (slot < 0) return;
  Pending& p = pend[slot];
  p.used = true;
  p.origId = (m[0] << 8) | m[1];
  p.newId = (uint16_t)((esp_random() & 0xFFC0) | slot);
  p.ip = ip; p.port = port; p.ts = now;
  m[0] = p.newId >> 8; m[1] = p.newId & 0xFF;
  upstream.beginPacket(UPSTREAM, 53);
  upstream.write(m, len);
  upstream.endPacket();
}

void handleUpstream() {
  int len = upstream.parsePacket();
  if (len <= 0) return;
  len = upstream.read(buf, sizeof(buf));
  if (len < 12) return;
  uint16_t id = (buf[0] << 8) | buf[1];
  Pending& p = pend[id & 0x3F];
  if (!p.used || p.newId != id) return;
  buf[0] = p.origId >> 8; buf[1] = p.origId & 0xFF;
  server.beginPacket(p.ip, p.port);
  server.write(buf, len);
  server.endPacket();
  p.used = false;
}

void handleClient() {
  int len = server.parsePacket();
  if (len <= 0) return;
  IPAddress ip = server.remoteIP();
  uint16_t port = server.remotePort();
  len = server.read(buf, sizeof(buf));
  if (len < 12 || (buf[2] & 0x80)) return;

  char name[256];
  uint16_t qtype;
  int qEnd;
  if (!parseQuestion(buf, len, name, sizeof(name), qtype, qEnd)) return;

  bool blocked = isBlocked(name);
  countQuery(ip, blocked);
  addLog(name, ip, blocked);

  if (blocked) {
    int rlen = buildBlockedReply(buf, qEnd, qtype);
    server.beginPacket(ip, port);
    server.write(buf, rlen);
    server.endPacket();
  } else {
    forwardQuery(buf, len, ip, port);
  }
}

// ---------- web UI ----------
const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sinkhole</title>
<style>
:root{--bg:#f4f3ef;--card:#fff;--line:#e6e4dd;--fg:#1f1e1b;--mute:#6d6b64;--faint:#a3a19a;--bar:#cfcdc5;--coral:#D85A30;--rbg:#fcebeb;--rfg:#a32d2d;--gbg:#eaf3de;--gfg:#3b6d11}
@media(prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--line:#2e2d2a;--fg:#ecebe6;--mute:#a19f97;--faint:#6f6d66;--bar:#4a4944;--rbg:#3a1a1a;--rfg:#f09595;--gbg:#1f2c12;--gfg:#97c459}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,system-ui,sans-serif}
main{max-width:520px;margin:auto;padding:16px 16px 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;margin-top:12px}
.lbl{font-size:12px;color:var(--mute)}.row{display:flex;align-items:center;gap:8px}
.pill{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:999px;padding:7px 14px;font-size:13px;cursor:pointer;display:inline-flex;gap:6px;align-items:center}
button.s{border:1px solid var(--line);background:transparent;color:var(--fg);border-radius:8px;padding:4px 10px;font-size:12px;cursor:pointer}
button.s.on{background:var(--bg)}
.tag{font-size:11px;padding:2px 8px;border-radius:999px;white-space:nowrap}
.b{background:var(--rbg);color:var(--rfg)}.a{background:var(--gbg);color:var(--gfg)}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
.li{display:flex;align-items:center;gap:8px;padding:7px 0;border-top:1px solid var(--line)}
input{flex:1;min-width:0;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:14px}
svg.i{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex:none}
.x{border:none;background:none;color:var(--faint);cursor:pointer;font-size:14px;padding:0 4px}
.legend{display:inline-block;width:8px;height:8px;border-radius:2px;margin:0 4px 0 8px}
</style></head><body><main>
<div class="row" style="justify-content:space-between">
<div><div class="lbl" id="net"></div><div id="hd" style="font-size:17px;font-weight:600">Protection on</div></div>
<button class="pill" id="tg" onclick="toggle()"></button>
</div>
<div class="row" style="gap:18px;margin-top:14px">
<svg width="120" height="120" viewBox="0 0 120 120" style="flex:none">
<circle cx="60" cy="60" r="50" fill="none" stroke="var(--line)" stroke-width="12"/>
<circle id="ring" cx="60" cy="60" r="50" fill="none" stroke="var(--coral)" stroke-width="12" stroke-linecap="round" stroke-dasharray="0 315" transform="rotate(-90 60 60)"/>
<text id="pct" x="60" y="60" text-anchor="middle" fill="var(--fg)" font-size="22" font-weight="600">–</text>
<text x="60" y="78" text-anchor="middle" fill="var(--mute)" font-size="11">blocked</text></svg>
<div style="flex:1;display:grid;gap:10px">
<div><div class="lbl" id="bl">Ads blocked today</div><div id="bt" style="font-size:24px;font-weight:600">–</div></div>
<div><div class="lbl">Total queries</div><div id="tt" style="font-size:16px;font-weight:600">–</div></div>
<div class="lbl" id="sys">–</div>
</div></div>
<div class="card">
<div class="row lbl" style="justify-content:space-between"><span>Last 24 hours</span><span><span class="legend" style="background:var(--coral)"></span>Blocked<span class="legend" style="background:var(--bar)"></span>Allowed</span></div>
<div id="bars" style="display:flex;align-items:flex-end;gap:3px;height:70px;margin-top:10px"></div>
<div id="ax" class="row" style="justify-content:space-between;font-size:11px;color:var(--faint);margin-top:4px"></div>
</div>
<div class="card"><div class="row" style="justify-content:space-between;margin-bottom:6px"><span class="lbl">Devices</span><button class="s" id="pv" onclick="priv()"></button></div><div id="dev"></div></div>
<div class="card">
<div class="row" style="justify-content:space-between;margin-bottom:6px"><span class="lbl">Live feed</span>
<span class="row" style="gap:4px"><button class="s" id="f0" onclick="setF(0)">All</button><button class="s" id="f1" onclick="setF(1)">Blocked</button></span></div>
<div id="feed"></div></div>
<div class="card"><div class="lbl" style="margin-bottom:8px">Custom lists</div>
<div class="row"><input id="dom" placeholder="example.com"><button class="s" onclick="add('block')">Block</button><button class="s" onclick="add('allow')">Allow</button></div>
<div id="err" style="font-size:12px;color:var(--rfg);margin-top:4px"></div>
<div id="lists"></div></div>
<div id="foot" style="text-align:center;font-size:11px;color:var(--faint);margin-top:14px"></div>
</main>
<script>
const $=id=>document.getElementById(id),fmt=n=>n.toLocaleString();
const dur=s=>s<60?s+'s':s<3600?Math.floor(s/60)+'m':s<86400?Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m':Math.floor(s/86400)+'d '+Math.floor(s%86400/3600)+'h';
const esc=s=>{const d=document.createElement('div');d.textContent=s;return d.innerHTML};
const getj=u=>fetch(u).then(r=>r.json());
const post=(u,p)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(p)}).then(r=>r.json());
const P={home:'<path d="M5 12H3l9-9 9 9h-2M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-7"/>',
shield:'<path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/><path d="m9 12 2 2 4-4"/>',
pause:'<path d="M7 5h3v14H7zM14 5h3v14h-3z"/>',
wifi:'<path d="M12 18h.01M9.2 15.2a4 4 0 0 1 5.6 0M6.3 12.3a8 8 0 0 1 11.4 0M3.5 9.5a12 12 0 0 1 17 0"/>',
laptop:'<path d="M3 19h18M5 16V6a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v10z"/>',
phone:'<rect x="7" y="3" width="10" height="18" rx="2"/><path d="M11 17h2"/>',
tablet:'<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M11 17h2"/>',
tv:'<rect x="3" y="7" width="18" height="13" rx="2"/><path d="m16 3-4 4-4-4"/>',
other:'<rect x="4" y="4" width="16" height="12" rx="1"/><path d="M8 20h8M12 16v4"/>',
eye:'<path d="M10 12a2 2 0 1 0 4 0 2 2 0 0 0-4 0"/><path d="M21 12c-2.4 4-5.4 6-9 6s-6.6-2-9-6c2.4-4 5.4-6 9-6s6.6 2 9 6"/>',
eyeoff:'<path d="M10.6 10.6a2 2 0 0 0 2.8 2.8M16.7 16.7A9.5 9.5 0 0 1 12 18c-3.6 0-6.6-2-9-6 1.3-2.1 2.7-3.7 4.3-4.7M9.9 6.2A9 9 0 0 1 12 6c3.6 0 6.6 2 9 6-.7 1.1-1.4 2.1-2.2 2.9M3 3l18 18"/>'};
let HIDE=false,DEVS=[];
try{HIDE=localStorage.getItem('hideDevices')==='1'}catch(e){}
const ic=n=>`<svg class="i" viewBox="0 0 24 24">${P[n]||P.other}</svg>`;
let S={},feedF=0,LOG=[];
async function stats(){S=await getj('/api/stats');
$('net').innerHTML=ic('home')+' '+esc(S.name);document.title=S.name+' · Sinkhole';
const t=S.today.t,b=S.today.b,r=t?b/t:0;
$('pct').textContent=Math.round(r*100)+'%';
$('ring').setAttribute('stroke-dasharray',(r*314.16).toFixed(1)+' 315');
$('ring').setAttribute('stroke',S.paused?'var(--bar)':'var(--coral)');
$('bl').textContent=S.synced?'Ads blocked today':'Ads blocked since boot';
$('bt').textContent=fmt(b);$('tt').textContent=fmt(t);
$('sys').innerHTML=ic('wifi')+' '+S.rssi+' dBm · up '+dur(S.uptime);
$('hd').textContent=S.paused?'Protection paused'+(S.pauseLeft?' · '+dur(S.pauseLeft):''):'Protection on';
$('tg').innerHTML=S.paused?ic('pause')+' Paused':ic('shield')+' Active';
$('foot').textContent=S.host+'.local · '+(HIDE?'IP hidden':S.ip)+' · '+fmt(S.domains)+' domains on blocklist'}
async function hours(){const H=await getj('/api/hours'),mx=Math.max(1,...H.hours.map(h=>h.t));
$('bars').innerHTML=H.hours.map(h=>`<div title="${h.t} queries, ${h.b} blocked" style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%"><div style="height:${(h.t-h.b)/mx*100}%;background:var(--bar);border-radius:2px 2px 0 0"></div><div style="height:${h.b/mx*100}%;background:var(--coral)"></div></div>`).join('');
const lab=h=>H.synced?((h%12)||12)+(h<12?'am':'pm'):h+'h';
$('ax').innerHTML=[0,6,12,18].map(i=>`<span>${lab(H.hours[i].h)}</span>`).join('')+'<span>now</span>'}
async function devices(){DEVS=await getj('/api/devices');renderDevices()}
function renderDevices(){
$('pv').innerHTML=HIDE?ic('eye')+' Show':ic('eyeoff')+' Hide';
$('pv').title=HIDE?'Show device names and IPs':'Hide device names and IPs';
$('dev').innerHTML=DEVS.map((d,i)=>{const r=d.t?Math.round(d.b/d.t*100):0;
const name=HIDE?'Device '+(i+1):esc(d.n||'Device .'+d.ip.split('.').pop());
const sub=HIDE?fmt(d.t)+' queries':d.ip+' · '+fmt(d.t)+' queries';
return `<div class="li"><span style="color:var(--mute)">${ic(HIDE?'other':d.k)}</span><div style="flex:1;min-width:0"><div style="font-size:13px">${name}</div><div style="font-size:11px;color:var(--faint)">${sub}</div></div><div style="width:70px;height:6px;background:var(--line);border-radius:3px"><div style="width:${r}%;height:100%;background:var(--coral);border-radius:3px"></div></div><span class="lbl" style="width:34px;text-align:right">${r}%</span></div>`}).join('')||'<div class="lbl">No devices yet</div>'}
async function feed(){LOG=await getj('/api/log');renderFeed()}
function renderFeed(){$('f0').classList.toggle('on',!feedF);$('f1').classList.toggle('on',!!feedF);
const L=LOG.filter(e=>!feedF||e.b).slice(0,25);
$('feed').innerHTML=L.map(e=>`<div class="li"><span class="tag ${e.b?'b':'a'}">${e.b?'Blocked':'Allowed'}</span><span class="mono" style="flex:1">${esc(e.n)}</span><span style="font-size:11px;color:var(--faint)">${dur(e.a)}</span><button class="s" onclick="edit('${e.b?'allow':'block'}','add','${esc(e.n)}')">${e.b?'Allow':'Block'}</button></div>`).join('')||'<div class="lbl">No queries yet</div>'}
function setF(x){feedF=x;renderFeed()}
function priv(){HIDE=!HIDE;try{localStorage.setItem('hideDevices',HIDE?'1':'0')}catch(e){}renderDevices();if(S.ip)stats()}
function renderLists(L){const part=(k,cls,label)=>`<div class="lbl" style="margin-top:10px">${label}</div>`+(L[k].map(d=>`<div class="li"><span class="tag ${cls}" style="font-size:12px">${esc(d)}</span><span style="flex:1"></span><button class="x" title="Remove" onclick="edit('${k}','del','${esc(d)}')">✕</button></div>`).join('')||'<div class="li"><span style="font-size:12px;color:var(--faint)">Empty</span></div>');
$('lists').innerHTML=part('block','b','Always block')+part('allow','a','Always allow')}
async function edit(list,op,d){const r=await post('/api/list',{list,op,d});if(r.error){$('err').textContent=r.error;return}$('err').textContent='';renderLists(r);feed()}
function add(list){const d=$('dom').value.trim();if(!d){$('err').textContent='Enter a domain first';return}edit(list,'add',d);$('dom').value=''}
$('dom').addEventListener('input',()=>$('err').textContent='');
async function toggle(){await post('/api/pause',{min:S.paused?0:-1});stats()}
function fast(){stats();feed()}
function slow(){hours();devices()}
fast();slow();getj('/api/lists').then(renderLists);setInterval(fast,3000);setInterval(slow,15000);
</script></body></html>)HTML";

bool auth() {
  if (web.authenticate(UI_USER, UI_PASS)) return true;
  web.requestAuthentication();
  return false;
}

String jsonArray(const std::vector<String>& l) {
  String s = "[";
  for (size_t i = 0; i < l.size(); i++) { if (i) s += ','; s += '"' + l[i] + '"'; }
  return s + "]";
}

void sendLists() {
  web.send(200, "application/json",
           "{\"allow\":" + jsonArray(allowList) + ",\"block\":" + jsonArray(blockList) + "}");
}

const NamedDevice* lookupDevice(const String& ip) {
  for (const auto& d : DEVICES) if (ip == d.ip) return &d;
  return nullptr;
}

void setupWeb() {
  web.on("/", HTTP_GET, [] { if (auth()) web.send_P(200, "text/html", PAGE); });

  web.on("/api/stats", HTTP_GET, [] {
    if (!auth()) return;
    bool p = isPaused();
    uint32_t left = (p && pauseUntil) ? (pauseUntil - millis()) / 1000 : 0;
    String j = "{\"name\":\"" + jsonEsc(DASHBOARD_NAME) + "\",\"host\":\"" + jsonEsc(HOSTNAME) +
               "\",\"ip\":\"" + WiFi.localIP().toString() + "\"" +
               ",\"synced\":" + (timeSynced() ? "true" : "false") +
               ",\"today\":{\"t\":" + String(todayTotal) + ",\"b\":" + String(todayBlocked) + "}" +
               ",\"total\":" + String(statTotal) + ",\"blocked\":" + String(statBlocked) +
               ",\"domains\":" + String(blCount) + ",\"uptime\":" + String(millis() / 1000) +
               ",\"heap\":" + String(ESP.getFreeHeap()) + ",\"rssi\":" + String(WiFi.RSSI()) +
               ",\"paused\":" + (p ? "true" : "false") + ",\"pauseLeft\":" + String(left) + "}";
    web.send(200, "application/json", j);
  });

  web.on("/api/hours", HTTP_GET, [] {
    if (!auth()) return;
    bool s = timeSynced();
    uint32_t cur = hourKey();
    String j = "{\"synced\":" + String(s ? "true" : "false") + ",\"hours\":[";
    for (int i = HOURS - 1; i >= 0; i--) {
      uint32_t k = cur - i;
      const Hour& h = hours[k % HOURS];
      bool valid = (h.key == k);
      int label = s ? (int)(((uint64_t)k * 3600 + TZ_OFFSET_SEC) / 3600 % 24) : -i;
      if (i != HOURS - 1) j += ',';
      j += "{\"h\":" + String(label) + ",\"t\":" + String(valid ? h.t : 0) +
           ",\"b\":" + String(valid ? h.b : 0) + "}";
    }
    web.send(200, "application/json", j + "]}");
  });

  web.on("/api/devices", HTTP_GET, [] {
    if (!auth()) return;
    std::vector<Dev> v;
    for (int i = 0; i < DEV_N; i++) if (devs[i].ip) v.push_back(devs[i]);
    std::sort(v.begin(), v.end(), [](const Dev& a, const Dev& b) { return a.t > b.t; });
    String j = "[";
    for (size_t i = 0; i < v.size() && i < 6; i++) {
      String ip = IPAddress(v[i].ip).toString();
      const NamedDevice* nd = lookupDevice(ip);
      if (i) j += ',';
      j += "{\"ip\":\"" + ip + "\",\"n\":\"" + (nd ? jsonEsc(nd->name) : String("")) +
           "\",\"k\":\"" + (nd ? jsonEsc(nd->type) : String("other")) +
           "\",\"t\":" + String(v[i].t) + ",\"b\":" + String(v[i].b) + "}";
    }
    web.send(200, "application/json", j + "]");
  });

  web.on("/api/log", HTTP_GET, [] {
    if (!auth()) return;
    String j = "[";
    uint32_t now = millis();
    for (int k = 0; k < logCount; k++) {
      const LogEntry& e = logBuf[(logHead - 1 - k + LOG_N) % LOG_N];
      if (k) j += ',';
      j += "{\"n\":\"" + String(e.name) + "\",\"c\":\"" + IPAddress(e.ip).toString() +
           "\",\"b\":" + (e.blocked ? "1" : "0") + ",\"a\":" + String((now - e.t) / 1000) + "}";
    }
    web.send(200, "application/json", j + "]");
  });

  web.on("/api/lists", HTTP_GET, [] { if (auth()) sendLists(); });

  web.on("/api/list", HTTP_POST, [] {
    if (!auth()) return;
    String list = web.arg("list"), op = web.arg("op");
    String d = cleanDomain(web.arg("d"));
    if (d == "" || (list != "allow" && list != "block")) {
      web.send(400, "application/json", "{\"error\":\"Enter a valid domain, like example.com\"}");
      return;
    }
    std::vector<String>& target = (list == "allow") ? allowList : blockList;
    std::vector<String>& other  = (list == "allow") ? blockList : allowList;
    auto rm = [&](std::vector<String>& l) { l.erase(std::remove(l.begin(), l.end(), d), l.end()); };

    if (op == "add") {
      if (!inList(target, d.c_str())) target.push_back(d);
      rm(other);                                // a domain can't be in both lists
    } else {
      rm(target);
    }
    if (!saveList("allow", allowList) || !saveList("block", blockList)) {
      rm(target);
      web.send(400, "application/json", "{\"error\":\"List is full\"}");
      return;
    }
    sendLists();
  });

  web.on("/api/pause", HTTP_POST, [] {
    if (!auth()) return;
    int m = web.arg("min").toInt();
    if (m == 0) { paused = false; }
    else { paused = true; pauseUntil = (m > 0) ? millis() + (uint32_t)m * 60000UL : 0; }
    web.send(200, "application/json", "{\"ok\":true}");
  });

  web.onNotFound([] { web.send(404, "text/plain", "Not found"); });
  web.begin();
}

// ---------- setup / loop ----------
void setup() {
  Serial.begin(115200);

  if (!LittleFS.begin()) {
    Serial.println("LittleFS mount failed (upload the data folder first)");
  } else {
    blocklist = LittleFS.open("/blocklist.bin", "r");
    if (blocklist) blCount = blocklist.size() / 8;
  }
  loadLists();
  Serial.printf("Blocklist: %u domains, custom block: %u, allow: %u\n",
                blCount, blockList.size(), allowList.size());

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setHostname(HOSTNAME);
  WiFi.config(LOCAL_IP, GATEWAY, SUBNET, UPSTREAM);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  Serial.printf("\nSinkhole running at %s\n", WiFi.localIP().toString().c_str());

  configTime(TZ_OFFSET_SEC, 0, "pool.ntp.org", "time.google.com");   // for "today" and the 24h chart

  if (MDNS.begin(HOSTNAME)) MDNS.addService("http", "tcp", 80);
  Serial.printf("Dashboard: http://%s.local or http://%s\n", HOSTNAME, WiFi.localIP().toString().c_str());

  server.begin(53);
  upstream.begin(5353);
  setupWeb();
}

void loop() {
  handleClient();
  handleUpstream();
  web.handleClient();

  static uint32_t lastReconnect = 0;
  if (WiFi.status() != WL_CONNECTED && millis() - lastReconnect > 10000) {
    lastReconnect = millis();
    WiFi.reconnect();
  }
}
