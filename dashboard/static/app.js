"use strict";
// Everything shown here comes from attacker-controlled logs. Text is only ever inserted with
// textContent / createTextNode, never as HTML.

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const CLASS_LABEL = {
  script: "Script or scanner", known_bot: "Known bot (signature)", agent_suspected: "AI agent, suspected",
  agent_confirmed: "AI agent, followed canary", human_like: "Human-like", unknown: "Not enough data",
};
const INTEL = [
  { group: "Origin", items: [
    ["countries", "Countries", "Country", "Sessions per country of the source IP.", false],
    ["networks", "Networks", "Network (ASN)", "The provider that owns each source IP. Hosting and cloud networks usually mean rented attack infrastructure.", false],
    ["nettypes", "Network types", "Type", "Unique source IPs split into hosting/cloud providers and home or business ISPs (often infected devices).", false],
    ["ips", "Source IPs", "IP address", "The busiest individual addresses, counted in sessions.", true],
    ["clients", "SSH clients", "Client version string", "SSH client software announced during the handshake. Bots often use Go or libssh clients.", true],
    ["hassh", "SSH fingerprints", "HASSH (client; IPs)", "HASSH: a hash of the encryption choices an SSH client offers. It stays the same when a tool changes IP or lies about its version, so one fingerprint across many IPs usually means one toolkit or botnet. Click a row to list its sessions.", true],
    ["ja4h", "Web fingerprints", "JA4H (user agent; IPs)", "JA4H: method, HTTP version, header order and cookies of a web client, hashed. Spoofed user agents don't change it. Click a row to list its sessions.", true],
    ["uas", "Web user agents", "User agent", "The User-Agent header sent with web requests.", true],
  ] },
  { group: "Behaviour", items: [
    ["paths", "Web paths", "Path", "Every URL path requested from the web honeypot, counted per request.", true],
    ["web_logins", "Web logins", "User / password", "Credentials typed into the fake admin login page.", true],
    ["pairs", "SSH logins", "User / password", "Username and password pairs tried over SSH and Telnet.", true],
    ["users", "SSH usernames", "Username", "Usernames tried over SSH and Telnet.", true],
    ["passwords", "SSH passwords", "Password", "Passwords tried over SSH and Telnet.", true],
    ["commands", "Commands", "Command", "Commands typed into the fake shell after a successful login.", true],
    ["downloads", "File fetches", "URL or file", "Files the attacker tried to download or upload, usually malware droppers.", true],
  ] },
  { group: "Network IDS", items: [
    ["ids_sigs", "IDS alerts", "Rule (SID and signature)", "Suricata alerts on the front VM's public interface, from the ET Open rules: exploit attempts, scanners, known-bad IPs. Counts every alert in the period, also from visitors that never opened a session.", true],
    ["ids_cats", "Alert categories", "Category", "The same alerts grouped by the rule's category.", false],
    ["ids_cves", "CVEs targeted", "CVE", "Vulnerabilities named by the rules that fired. A CVE here means someone sent an exploit for it, not that anything here is vulnerable.", true],
    ["tls_fp", "TLS fingerprints", "JA4 (or JA3) client fingerprint (IPs)", "How each TLS client opened its connection (web 443, Kubernetes 6443, RDP). Like HASSH for SSH: it stays the same when a tool changes IP or user agent.", true],
  ] },
  { group: "MITRE ATT&CK", items: [
    ["techniques", "Techniques", "Technique (tactic)", "ATT&CK techniques each session showed, mapped from its own commands, requests, real-shell programs and file changes. Counted once per session. Click a row to list its sessions.", true],
    ["tactics", "Tactics", "Tactic", "The same, rolled up to the attacker's goal at that step: from reconnaissance through persistence to impact.", false],
  ] },
  { group: "Campaigns", items: [
    ["campaigns", "Command campaigns", "Campaign: first step (steps, IPs, where)", "Sessions that ran the same sequence of commands, after blanking out IPs, URLs, numbers and random file names. One campaign across many IPs is one operator or botnet. Click a row to list its sessions.", true],
  ] },
  { group: "Decoy services", items: [
    ["decoy_services", "Services hit", "Service", "Sessions per fake service: Redis (6379), Docker API (2375), Elasticsearch (9200), MySQL (3306), Ollama (11434), Kubernetes API (6443), RDP (3389) and SMB (445).", false],
    ["decoy_cmds", "Commands and requests", "Service: command", "Every Redis command and Docker or Elasticsearch request sent to the decoys.", true],
    ["decoy_payloads", "Payloads", "Payload", "What attackers tried to plant: Redis values (cron jobs, SSH keys), containers they started, documents they wrote. Nothing was executed.", true],
    ["decoy_urls", "Payload links", "URL", "Download links found inside decoy commands and payloads. They were not fetched.", true],
    ["mysql_logins", "MySQL logins", "User (client program)", "Usernames tried against the fake MySQL. Passwords arrive hashed; each session's timeline has the hash for offline cracking.", true],
    ["ntlm_logins", "RDP and SMB logins", "Domain/user (service, workstation)", "Windows logins against the fake RDP and SMB servers. The NetNTLMv2 response in each session's timeline can be cracked offline (hashcat -m 5600).", true],
    ["llm_prompts", "AI API prompts", "Prompt", "What people asked the fake Ollama server. Free LLM endpoints get hijacked for spam, jailbreaks and proxy resale.", true],
  ] },
  { group: "Real shell", items: [
    ["programs", "Programs run", "Program", "Every program the attacker actually started on the real server, from the kernel's audit log. Login welcome scripts are left out.", true],
    ["captured", "Captured files", "File (type)", "Files attackers created or changed, and binaries running only from memory. Each one is saved by hash in the root-only quarantine on the backend VM, and never leaves it.", true],
    ["fetch_urls", "Fetched URLs", "URL", "Download links from attackers' commands. The server has no internet, so the backend fetched each one separately into the quarantine.", true],
    ["egress", "Connection attempts", "Destination", "Outgoing network connections attempted from the server (all blocked). Local DNS lookups are left out.", true],
  ] },
];
const VIEWS = ["overview", "sessions", "traps", "stats", "intel", "samples", "llm", "report", "status", "settings"];
const INTEL_BY_KEY = {};
for (const g of INTEL) for (const it of g.items) INTEL_BY_KEY[it[0]] = it;

const state = { view: "overview", intel: "countries", range: "24h", funnel: "ssh", shown: 100 };
let token = "", data = null, meta = null, basemap = null, timer = null;

// ---- helpers -----------------------------------------------------------------------------
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function svg(tag, attrs) {
  const e = document.createElementNS(SVG, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function svgText(attrs, text) { const t = svg("text", attrs); t.textContent = text; return t; }
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
const nf = new Intl.NumberFormat();
function fmtN(n) { return nf.format(n || 0); }
function fmtPct(part, total) {
  if (!total || !part) return "0%";
  const p = (part / total) * 100;
  return (p > 0 && p < 0.1 ? "<0.1" : p < 10 ? p.toFixed(1) : Math.round(p)) + "%";
}
function fmtGap(ms) {
  if (ms === null || ms === undefined) return "–";
  if (ms < 1000) return Math.round(ms) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(1) + " s";
  if (ms < 3600000) return (ms / 60000).toFixed(1) + " min";
  return (ms / 3600000).toFixed(1) + " h";
}
function fmtTime(t, withSec) {
  const o = { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" };
  if (withSec) o.second = "2-digit";
  return new Date(t).toLocaleString(undefined, o);
}
function fmtAgo(t) {
  if (!t) return "never";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + " s ago";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
}
const KIND_LABEL = { web: "Web", ssh: "SSH", telnet: "Telnet", redis: "Redis", docker: "Docker API", elastic: "Elasticsearch", mysql: "MySQL",
  ollama: "Ollama (AI API)", k8s: "Kubernetes API", rdp: "RDP", smb: "SMB" };
function kindLabel(k) { return KIND_LABEL[k] || k; }
// flags worth catching the eye in a long table: something was planted, captured, or bait was acted on
const ALERT_FLAGS = new Set(["tripwire", "canary", "persistence", "sample captured", "privileged container",
  "host filesystem mounted", "host namespaces", "ntlm hash", "jailbreak or bulk prompt", "ids: high severity"]);
function dot(cls) { const d = el("span", "dot"); d.style.background = `var(--c-${cls})`; return d; }
function classChip(cls) {
  const c = el("span", "chip");
  c.append(dot(cls), document.createTextNode(CLASS_LABEL[cls] || cls));
  return c;
}
function activate(node, fn) {
  node.tabIndex = 0;
  node.addEventListener("click", fn);
  node.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); fn(); } });
}

// ---- tooltip -----------------------------------------------------------------------------
const tip = $("tip");
function attachTip(node, textFn) {
  node.addEventListener("mousemove", (ev) => {
    tip.textContent = textFn();
    tip.hidden = false;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = ev.clientX + 14, y = ev.clientY + 14;
    if (x + w > window.innerWidth - 8) x = ev.clientX - w - 14;
    if (y + h > window.innerHeight - 8) y = ev.clientY - h - 14;
    tip.style.left = Math.max(4, x) + "px";
    tip.style.top = Math.max(4, y) + "px";
  });
  node.addEventListener("mouseleave", () => { tip.hidden = true; });
}

// ---- routing -----------------------------------------------------------------------------
function readHash() {
  const [view, sub] = location.hash.replace(/^#/, "").split("/");
  state.view = VIEWS.includes(view) ? view : "overview";
  if (sub && INTEL_BY_KEY[sub]) state.intel = sub;
}
function go(view, sub) {
  const h = "#" + view + (view === "intel" ? "/" + (sub || state.intel) : "");
  if (location.hash !== h) location.hash = h; else applyView();
}
function applyView() {
  readHash();
  for (const v of VIEWS) {
    $("view-" + v).hidden = v !== state.view;
    $("tab-" + v).setAttribute("aria-selected", String(v === state.view));
  }
  tip.hidden = true;
  if (state.view === "status") loadVmStatus(false);
  if (state.view === "settings") loadSettings();
  if (state.view === "samples") loadSamples();
  if (state.view === "llm") loadLlm(false);
  if (state.view === "report") loadReport();
  if (state.view === "stats") { if (ST.data) renderStats(); loadStats(); }
  if (state.view === "intel") iocCounts();
  if (!data) return;
  if (state.view === "overview") renderActivity();
  if (state.view === "intel") renderIntel();
}

// ---- figures -----------------------------------------------------------------------------
let prevFigs = null;
function renderFigures(k) {
  const box = $("kpis");
  const before = prevFigs;
  prevFigs = [];
  clear(box);
  const figs = [
    [k.sessions, "Sessions", `${fmtN(k.web_sessions)} web, ${fmtN(k.ssh_sessions)} SSH, ${fmtN(k.decoy_sessions)} decoy`],
    [k.unique_ips, "Source IPs", `from ${fmtN(k.countries)} countries`],
    [k.web_requests, "Web requests", "all paths, all methods"],
    [k.login_attempts, "Login attempts", `${fmtN(k.logins_ok)} let in`],
    [k.commands, "Commands", `typed in; ${fmtN(k.programs)} programs ran`],
    [k.decoy_actions, "Decoy hits", "on the fake services"],
    [k.captured, "Files captured", "saved to the quarantine", true],
    [k.agents, "Likely AI agents", "by timing or canary", true],
    [k.trip_sessions, "Tripwire hits", "sessions that acted on a bait file", true],
  ];
  for (const [v, label, detail, hot] of figs) {
    const f = el("div", "fig" + (hot && v ? " hot" : ""));
    const vEl = el("div", "v", fmtN(v));
    if (before && before[prevFigs.length] !== undefined && before[prevFigs.length] !== v) vEl.classList.add("bump");
    prevFigs.push(v);
    f.append(vEl, el("div", "l", label), el("div", "d", detail));
    f.lastChild.title = detail;
    box.append(f);
  }
}

// ---- activity chart ----------------------------------------------------------------------
function niceStep(max, ticks) {
  const raw = Math.max(1, max / ticks), p = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const m of [1, 2, 5, 10]) if (raw <= m * p) return Math.max(1, m * p);
  return 10 * p;
}
function topRounded(x, y, w, h, r) {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
function stepName(step) {
  return { 300000: "5 minutes", 900000: "15 minutes", 3600000: "hour", 21600000: "6 hours", 86400000: "day" }[step] || "period";
}
function tickLabel(t, step, prev) {
  const d = new Date(t);
  if (step >= 86400000) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const newDay = !prev || new Date(prev).getDate() !== d.getDate();
  return newDay && step >= 3600000 ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + time : time;
}
function renderActivity() {
  const box = $("activity"), legend = $("activity-legend");
  clear(box); clear(legend);
  for (const [cls, label] of [["web", "Web"], ["ssh", "SSH / Telnet"], ["svc", "Decoy services"]]) {
    const item = el("span");
    const sw = el("span", "sw");
    sw.style.background = `var(--series-${cls})`;
    item.append(sw, document.createTextNode(label));
    legend.append(item);
  }
  const { step, points: pts } = data.series;
  if (!pts.some((p) => p[1] + p[2] + (p[3] || 0))) { box.append(el("div", "empty", "No sessions in this period yet.")); return; }
  const W = Math.max(480, box.clientWidth || 860), H = 250, L = 38, R = 6, T = 10, B = 26;
  const iw = W - L - R, ih = H - T - B;
  const peak = Math.max(...pts.map((p) => p[1] + p[2] + (p[3] || 0)));
  const st = niceStep(peak, 4), max = Math.ceil(peak / st) * st;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Sessions started per ${stepName(step)}` });
  for (let v = 0; v <= max; v += st) {
    const y = T + ih - (v / max) * ih;
    root.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "gridline" : "baseline" }));
    root.append(svgText({ x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" }, fmtN(v)));
  }
  const band = iw / pts.length, bw = Math.max(2, Math.min(24, band - 2));
  const every = Math.max(1, Math.ceil(pts.length / Math.max(1, Math.floor(iw / 84))));
  let prevLabelT = null;
  pts.forEach(([t, web, ssh, svc = 0], i) => {
    const x = L + i * band + (band - bw) / 2;
    let y = T + ih;
    const segs = [[web, "web"], [ssh, "ssh"], [svc, "svc"]].filter((s) => s[0] > 0);
    segs.forEach(([v, cls], j) => {
      const gap = j > 0 ? 2 : 0;
      const h = Math.max(1.5, (v / max) * ih - gap);
      y -= h + gap;
      const node = j === segs.length - 1 ? svg("path", { d: topRounded(x, y, bw, h, 4) }) : svg("rect", { x, y, width: bw, height: h });
      node.setAttribute("fill", `var(--series-${cls})`);
      root.append(node);
    });
    if (i % every === 0) {
      root.append(svgText({ x: L + i * band + band / 2, y: H - 8, "text-anchor": "middle", class: "axis" }, tickLabel(t, step, prevLabelT)));
      prevLabelT = t;
    }
    const hit = svg("rect", { x: L + i * band, y: T, width: band, height: ih, class: "hit" });
    attachTip(hit, () => `${fmtTime(t)}, ${stepName(step)}\nWeb: ${fmtN(web)}\nSSH / Telnet: ${fmtN(ssh)}\nDecoy services: ${fmtN(svc)}`);
    root.append(hit);
  });
  box.append(root);
}

// ---- map ---------------------------------------------------------------------------------
// Zoom changes the viewBox of the map and the live layer together; dot and label sizes are divided
// by the zoom factor, so zooming in spreads places apart instead of blowing the dots up.
const MAP_REGIONS = [  // name, west, north, east, south
  ["World", -180, 80, 180, -58], ["Europe", -14, 70, 44, 34], ["Asia", 55, 58, 150, -12],
  ["Americas", -135, 62, -30, -56],
];
const DEPTH_LABEL = ["Connected, probed or guessed passwords", "Logged in or read data", "Ran commands or changed something"];
const mapView = { x: 0, y: 0, w: 0, h: 0, base: null, region: "World", anim: 0 };
function dotR(n) { return Math.min(15, 2.6 + 3.1 * Math.log10(Math.max(1, n))); }   // 1 → 2.6, 10 → 5.7, 1,000 → 11.9
function mapK() { return mapView.base ? mapView.base.w / mapView.w : 1; }
function clampView(v) {
  const b = mapView.base;
  v.w = Math.min(b.w, Math.max(b.w / 24, v.w));
  v.h = v.w * b.h / b.w;
  v.x = Math.min(b.x + b.w - v.w, Math.max(b.x, v.x));
  v.y = Math.min(b.y + b.h - v.h, Math.max(b.y, v.y));
  return v;
}
function setView(v, animate) {
  const to = clampView({ ...v });
  cancelAnimationFrame(mapView.anim);
  const from = { x: mapView.x, y: mapView.y, w: mapView.w, h: mapView.h };
  const still = !animate || matchMedia("(prefers-reduced-motion: reduce)").matches || !from.w;
  if (still) { Object.assign(mapView, to); applyMapView(); return; }
  const t0 = performance.now(), dur = 320;
  const tick = (now) => {
    const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    // interpolate the zoom geometrically so it feels even
    const w = from.w * Math.pow(to.w / from.w, e);
    const cx = from.x + from.w / 2 + (to.x + to.w / 2 - from.x - from.w / 2) * e;
    const cy = from.y + from.h / 2 + (to.y + to.h / 2 - from.y - from.h / 2) * e;
    const h = w * mapView.base.h / mapView.base.w;
    Object.assign(mapView, { x: cx - w / 2, y: cy - h / 2, w, h });
    applyMapView(p < 1);
    if (p < 1) mapView.anim = requestAnimationFrame(tick);
  };
  mapView.anim = requestAnimationFrame(tick);
}
function regionView(name) {
  const [, w, n, e, s] = MAP_REGIONS.find((r) => r[0] === name);
  const b = mapView.base, W = basemap.w, H = basemap.h;
  const x0 = (w + 180) / 360 * W, x1 = (e + 180) / 360 * W, y0 = (90 - n) / 180 * H, y1 = (90 - s) / 180 * H;
  let vw = x1 - x0, vh = y1 - y0;
  if (vw / vh < b.w / b.h) vw = vh * b.w / b.h; else vh = vw * b.h / b.w;
  return { x: (x0 + x1) / 2 - vw / 2, y: (y0 + y1) / 2 - vh / 2, w: vw, h: vh };
}
function zoomAt(factor, sx, sy, animate) {
  const w = mapView.w / factor, h = mapView.h / factor;
  const fx = (sx - mapView.x) / mapView.w, fy = (sy - mapView.y) / mapView.h;
  mapView.region = "";
  syncRegionButtons();
  setView({ x: sx - fx * w, y: sy - fy * h, w, h }, animate);
}
function syncRegionButtons() {
  for (const b of $("map-regions").children) b.setAttribute("aria-checked", String(b.dataset.region === mapView.region));
}
function applyMapView(moving) {
  const vb = `${mapView.x} ${mapView.y} ${mapView.w} ${mapView.h}`;
  const root = $("map").querySelector("svg");
  if (!root) return;
  root.setAttribute("viewBox", vb);
  const layer = $("live-layer");
  layer.setAttribute("viewBox", vb);
  const k = mapK();
  live.k = k;
  layer.classList.toggle("zoomed", k > 1.02);
  for (const c of root.querySelectorAll("[data-r]")) c.setAttribute("r", c.dataset.r / k);
  for (const c of layer.querySelectorAll(".target, .target-ring")) c.setAttribute("r", (c.classList.contains("target") ? 3 : 4) / k);
  $("map").classList.toggle("grab", k > 1.02);
  if (!moving) placeLabels(root);
}
// Name the five busiest places in view, skipping any label that would overlap another or a bigger dot.
function placeLabels(root) {
  root.querySelectorAll(".maplabel").forEach((n) => n.remove());
  // label text and gaps in screen pixels, whatever the map's width or zoom
  const k = mapK(), u = mapView.w / Math.max(1, $("map").getBoundingClientRect().width), fs = 11 * u, pts = root._points || [];
  const inView = pts.filter((p) => p.x >= mapView.x && p.x <= mapView.x + mapView.w && p.y >= mapView.y && p.y <= mapView.y + mapView.h);
  const boxes = [];
  let n = 0;
  for (const p of inView) {   // already sorted by sessions
    if (n >= 5) break;
    const city = (p.place || "").split(",")[0].replace(/\s*\(.*\)$/, "") || "Unknown";
    const r = dotR(p.sessions) / k, count = " " + fmtN(p.sessions);
    const w = (city.length + count.length) * fs * 0.56, h = fs * 1.1;
    let x = p.x + r + 3 * u, anchor = "start";
    if (x + w > mapView.x + mapView.w - 4 * u) { x = p.x - r - 3 * u; anchor = "end"; }
    const bx = anchor === "start" ? x : x - w, by = p.y - h / 2;
    if (boxes.some((b) => bx < b[0] + b[2] && bx + w > b[0] && by < b[1] + b[3] && by + h > b[1])) continue;
    boxes.push([bx, by, w, h]);
    const t = svg("text", { x, y: p.y + fs * 0.36, "text-anchor": anchor, class: "maplabel", "font-size": fs });
    t.append(document.createTextNode(city));
    const s = svg("tspan", { class: "n" });
    s.textContent = count;
    t.append(s);
    root.append(t);
    n++;
  }
}
function renderMapLegend(points) {
  const box = $("map-legend");
  clear(box);
  box.hidden = !points.length;
  const sw = (cls, r = 5) => {
    const s = svg("svg", { width: 2 * r + 2, height: 2 * r + 2, viewBox: `${-r - 1} ${-r - 1} ${2 * r + 2} ${2 * r + 2}`, "aria-hidden": "true" });
    if (cls.startsWith("mapring")) {
      s.append(svg("circle", { r: r - 1.5, class: "mapdot d0" }));
      s.append(svg("circle", { r: r, class: cls }));
    } else s.append(svg("circle", { r, class: cls }));
    return s;
  };
  const item = (node, text) => { const i = el("span", "it"); i.append(node, el("span", "", text)); return i; };
  const depth = el("div", "grp");
  depth.append(el("span", "", "Furthest step:"));
  DEPTH_LABEL.forEach((t, i) => depth.append(item(sw("mapdot d" + i), t)));
  const rings = el("div", "grp");
  rings.append(item(sw("mapring agent", 6), "AI agent likely"), item(sw("mapring human", 6), "Human-like"));
  const size = el("div", "grp");
  size.append(el("span", "", "Sessions:"));
  for (const n of [1, 10, 100, 1000]) {
    const r = dotR(n);
    const s = svg("svg", { width: 2 * r + 2, height: 2 * dotR(1000) + 2, viewBox: `${-r - 1} ${-dotR(1000) - 1} ${2 * r + 2} ${2 * dotR(1000) + 2}`, "aria-hidden": "true" });
    s.append(svg("circle", { r, class: "mapdot d0" }));
    size.append(item(s, fmtN(n)));
  }
  box.append(depth, rings, size, el("span", "hint", "Ctrl + scroll or drag to move around"));
}
function setupMapControls() {
  const ctl = $("map-ctl"), regions = $("map-regions"), box = $("map");
  ctl.hidden = false;
  if (regions.childElementCount) return;
  for (const [name] of MAP_REGIONS) {
    const b = el("button", "", name);
    b.type = "button";
    b.setAttribute("role", "radio");
    b.dataset.region = name;
    b.addEventListener("click", () => { mapView.region = name; syncRegionButtons(); setView(regionView(name), true); });
    regions.append(b);
  }
  syncRegionButtons();
  window.addEventListener("resize", () => { const r = box.querySelector("svg"); if (r) placeLabels(r); });
  const centre = () => [mapView.x + mapView.w / 2, mapView.y + mapView.h / 2];
  $("map-in").addEventListener("click", () => zoomAt(2, ...centre(), true));
  $("map-out").addEventListener("click", () => zoomAt(0.5, ...centre(), true));
  const toMap = (ev) => {
    const r = box.getBoundingClientRect();
    return [mapView.x + (ev.clientX - r.left) / r.width * mapView.w, mapView.y + (ev.clientY - r.top) / r.height * mapView.h];
  };
  // Ctrl/Cmd + wheel zooms (plain wheel keeps scrolling the page)
  box.addEventListener("wheel", (ev) => {
    if (!ev.ctrlKey && !ev.metaKey) return;
    ev.preventDefault();
    zoomAt(Math.pow(1.0018, -ev.deltaY), ...toMap(ev), false);
  }, { passive: false });
  box.addEventListener("dblclick", (ev) => { ev.preventDefault(); zoomAt(2, ...toMap(ev), true); });
  let drag = null;
  box.addEventListener("pointerdown", (ev) => {
    if (ev.button !== 0 || mapK() <= 1.02) return;
    drag = { x: ev.clientX, y: ev.clientY, vx: mapView.x, vy: mapView.y, moved: false, id: ev.pointerId };
  });
  box.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) { drag.moved = true; box.setPointerCapture(drag.id); box.classList.add("dragging"); tip.hidden = true; }
    const r = box.getBoundingClientRect();
    mapView.region = "";
    syncRegionButtons();
    setView({ x: drag.vx - dx / r.width * mapView.w, y: drag.vy - dy / r.height * mapView.h, w: mapView.w, h: mapView.h }, false);
  });
  const end = () => {
    if (drag && drag.moved) { box.classList.remove("dragging"); box._justDragged = true; setTimeout(() => { box._justDragged = false; }, 0); }
    drag = null;
  };
  box.addEventListener("pointerup", end);
  box.addEventListener("pointercancel", end);
}
async function renderMap() {
  const box = $("map"), note = $("map-note"), points = data.map, g = data.geo;
  clear(box);
  note.textContent = "";
  if (!g.ready) {
    $("map-ctl").hidden = true;
    $("map-legend").hidden = true;
    box.append(el("div", "empty", g.downloading ? "Downloading the IP location database (one time, about 65 MB)…"
      : "Location data unavailable" + (g.error ? ": " + g.error : ".")));
    return;
  }
  if (!basemap) basemap = await (await fetch("/api/basemap")).json();
  const latTop = 80, latBot = -58;
  const y0 = (90 - latTop) / 180 * basemap.h, y1 = (90 - latBot) / 180 * basemap.h;
  const first = !mapView.base;
  mapView.base = { x: 0, y: y0, w: basemap.w, h: y1 - y0 };
  if (first) Object.assign(mapView, mapView.base);
  const root = svg("svg", { viewBox: `${mapView.x} ${mapView.y} ${mapView.w} ${mapView.h}`, role: "img", "aria-label": "World map of session origins" });
  live.mapReady = true;
  for (let lon = -150; lon <= 150; lon += 30) {
    const x = (lon + 180) / 360 * basemap.w;
    root.append(svg("line", { x1: x, x2: x, y1: y0, y2: y1, class: "grat" }));
  }
  for (let lat = -30; lat <= 60; lat += 30) {
    const y = (90 - lat) / 180 * basemap.h;
    root.append(svg("line", { x1: 0, x2: basemap.w, y1: y, y2: y, class: "grat" }));
  }
  if (basemap.path) root.append(svg("path", { d: basemap.path, class: "land" }));
  if (basemap.borders) root.append(svg("path", { d: basemap.borders, class: "borders" }));
  const sorted = points.slice().sort((a, b) => b.sessions - a.sessions);
  root._points = sorted;
  for (const p of sorted) {   // biggest first, so small places stay on top and clickable
    const depth = p.depth ? (p.depth[2] ? 2 : p.depth[1] ? 1 : 0) : (p.deep ? 1 : 0);
    const r = dotR(p.sessions);
    const ring = p.agent ? "agent" : p.human ? "human" : "";
    if (ring) root.append(svg("circle", { cx: p.x, cy: p.y, r, "data-r": r + 2.4, class: "mapring " + ring }));
    const c = svg("circle", { cx: p.x, cy: p.y, r, "data-r": r, class: "mapdot d" + depth });
    attachTip(c, () => {
      const cls = Object.entries(p.cls).map(([k, v]) => `${CLASS_LABEL[k] || k}: ${fmtN(v)}`).join("\n");
      const steps = p.depth ? DEPTH_LABEL.map((t, i) => p.depth[i] ? `${t}: ${fmtN(p.depth[i])}` : "").filter(Boolean).join("\n") : "";
      return `${p.place || "Unknown place"}\n${fmtN(p.sessions)} sessions from ${fmtN(p.ips)} IPs` +
        (steps ? `\n\n${steps}` : "") + (p.agent ? `\nAI agent likely: ${fmtN(p.agent)}` : "") +
        (p.human ? `\nHuman-like: ${fmtN(p.human)}` : "") + `\n\nNetworks: ${p.orgs.join(", ")}\n${cls}`;
    });
    c.addEventListener("click", () => {
      if (box._justDragged) return;
      $("f-text").value = (p.place || "").split(",")[0];
      state.shown = 100;
      go("sessions");
      renderSessions();
    });
    root.append(c);
  }
  box.append(root);
  setupMapControls();
  applyMapView();
  renderMapLegend(points);
  note.textContent = points.length
    ? `${fmtN(points.length)} places. Select one to list its sessions.`
    : "No located sessions in this period yet.";
}

// ---- latest feed -------------------------------------------------------------------------
function renderFeed() {
  const box = $("feed");
  clear(box);
  const list = data.sessions.slice().sort((a, b) => b.start - a.start).slice(0, 14);
  if (!list.length) { box.append(el("li", "empty", "No sessions in this period yet.")); return; }
  for (const s of list) {
    const li = el("li");
    const who = el("div", "who");
    who.append(el("span", "mono", s.ip));
    const where = el("span", "note", [kindLabel(s.kind), s.cc || s.country].filter(Boolean).join(", "));
    who.append(where);
    const d = dot(s.cls);
    d.title = CLASS_LABEL[s.cls] || s.cls;
    li.append(d, who, el("span", "ago", fmtAgo(s.start)), el("div", "what", s.summary || s.stage_label));
    li.title = (CLASS_LABEL[s.cls] || s.cls) + "\n" + (s.summary || "");
    activate(li, () => openSession(s.id));
    box.append(li);
  }
}

// ---- actor mix and funnel ----------------------------------------------------------------
function renderClasses() {
  const box = $("classes"), classes = data.classes;
  clear(box);
  const total = classes.reduce((a, c) => a + c.count, 0);
  if (!total) { box.append(el("div", "empty", "No sessions in this period yet.")); return; }
  const bar = el("div", "segbar");
  for (const c of classes) {
    if (!c.count) continue;
    const seg = el("div");
    seg.style.flex = c.count + " 1 0";
    seg.style.background = `var(--c-${c.key})`;
    attachTip(seg, () => `${CLASS_LABEL[c.key] || c.label}: ${fmtN(c.count)} (${fmtPct(c.count, total)})`);
    bar.append(seg);
  }
  box.append(bar);
  for (const c of classes) {
    const row = el("div", "classrow");
    row.append(dot(c.key), el("span", "", CLASS_LABEL[c.key] || c.label), el("span", "val", fmtN(c.count)), el("span", "pct", fmtPct(c.count, total)));
    activate(row, () => { $("f-class").value = c.key; state.shown = 100; go("sessions"); renderSessions(); });
    row.style.cursor = "pointer";
    box.append(row);
  }
}
function renderFunnel() {
  const box = $("funnel");
  clear(box);
  for (const b of $("funnel-kind").querySelectorAll("button")) b.setAttribute("aria-checked", String(b.dataset.kind === state.funnel));
  const stages = state.funnel === "web" ? data.web_funnel : state.funnel === "svc" ? data.decoy_funnel : data.ssh_funnel;
  const total = stages.reduce((a, s) => a + s.count, 0);
  if (!total) { box.append(el("div", "empty", "No sessions of this kind in this period.")); return; }
  // Each session is counted at the furthest stage it reached; show "reached at least" totals.
  let remaining = total;
  const wrap = el("div", "stages");
  const color = `var(--series-${state.funnel})`;
  for (const s of stages) {
    const reached = remaining;
    remaining -= s.count;
    const row = el("div", "stage");
    const track = el("div", "track"), fill = el("div", "fill");
    fill.style.width = (reached / total) * 100 + "%";
    fill.style.background = color;
    if (!reached) fill.style.visibility = "hidden";
    track.append(fill);
    row.append(el("span", "", s.label), el("span", "val", `${fmtN(reached)}  (${fmtPct(reached, total)})`), track);
    attachTip(row, () => `${fmtN(reached)} sessions reached "${s.label}"\n${fmtN(s.count)} stopped here`);
    wrap.append(row);
  }
  box.append(wrap);
}

// ---- agents, tripwires, decoy services ---------------------------------------------------
function listSessions(text, kind) {
  $("f-text").value = text || "";
  $("f-class").value = "";
  $("f-kind").value = kind || "";
  state.shown = 100;
  go("sessions");
  renderSessions();
}
function renderAgents() {
  const box = $("agents"), a = data.agents || { hist: [], board: [], top: [] };
  clear(box);
  const left = el("div", "acol"), right = el("div", "acol");
  box.append(left, right);
  const total = a.hist.reduce((n, h) => n + h.count, 0);
  const hits = a.board.filter((b) => b.sessions).length;
  const tc = $("count-traps"), ts = (data.kpi || {}).trip_sessions || 0;
  tc.hidden = !ts;
  tc.textContent = fmtN(ts);
  tc.title = `${fmtN(ts)} sessions acted on a bait file`;
  $("agents-note").textContent = `${fmtN(hits)} of ${fmtN(a.board.length)} lures touched`;

  // score histogram: one horizontal bar per band, the sequential ramp darkening with the score
  const hist = el("div", "ahist");
  const max = Math.max(1, ...a.hist.map((h) => h.count));
  a.hist.forEach((h, i) => {
    const row = el("div", "arow");
    const track = el("div", "track"), fill = el("div", "fill");
    fill.style.width = (h.count / max) * 100 + "%";
    fill.style.background = `var(--score-${i})`;
    if (!h.count) fill.style.visibility = "hidden";
    track.append(fill);
    row.append(el("span", "lab", h.label), track, el("span", "val", fmtN(h.count)));
    attachTip(row, () => `${fmtN(h.count)} sessions scored ${h.label} (${fmtPct(h.count, total)})`);
    hist.append(row);
  });
  left.append(el("h3", "", "Agent likelihood, sessions per score band"), hist);

  if (a.top.length) {
    const ol = el("ol", "feed atop");
    for (const s of a.top) {
      const li = el("li");
      const who = el("div", "who");
      who.append(el("span", "mono", s.ip), el("span", "note", kindLabel(s.kind)));
      li.append(dot(s.cls), who, el("span", "score", String(s.score)), el("div", "what", s.summary));
      li.title = `Agent likelihood ${s.score} / 100\n${CLASS_LABEL[s.cls] || s.cls}`;
      activate(li, () => openSession(s.id));
      ol.append(li);
    }
    left.append(el("h3", "", "Highest scoring sessions"), ol);
  }

  const hot = a.board.filter((b) => b.sessions), cold = a.board.filter((b) => !b.sessions);
  right.append(el("h3", "", "Tripwires"));
  if (hot.length) {
    const tb = el("table", "grid board");
    const hr = el("tr");
    for (const [h, c] of [["Lure", ""], ["Type", ""], ["Sessions", "num"], ["IPs", "num"], ["Last hit", ""]]) hr.append(el("th", c, h));
    const thead = el("thead"); thead.append(hr); tb.append(thead);
    const body = el("tbody");
    for (const b of hot) {
      const tr = el("tr", "hot");
      tr.append(el("td", "", b.where), el("td", "note", b.kind === "token" ? "Instruction" : "Credential"),
        el("td", "num", fmtN(b.sessions)), el("td", "num", fmtN(b.ips)), el("td", "note", fmtAgo(b.last)));
      if (b.last_id) { tr.title = "Open the latest session that hit this"; activate(tr, () => openSession(b.last_id)); }
      body.append(tr);
    }
    tb.append(body);
    const wrap = el("div", "tablewrap");
    wrap.append(tb);
    right.append(wrap);
  } else {
    right.append(el("p", "note", "No visitor has acted on a bait file in this period."));
  }
  if (cold.length) {
    const d = el("details", "cold");
    d.append(el("summary", "", `${fmtN(cold.length)} lure${cold.length > 1 ? "s" : ""} not touched`));
    const ul = el("ul", "lures");
    for (const b of cold) {
      const li = el("li");
      li.append(el("span", "", b.where), el("span", "note", b.kind === "token" ? "instruction" : "credential"));
      ul.append(li);
    }
    d.append(ul);
    right.append(d);
  }
}
function renderDecoySvc() {
  const box = $("decoys");
  clear(box);
  for (const d of data.decoy_svc || []) {
    const card = el("div", "svc" + (d.sessions ? "" : " idle"));
    const head = el("div", "svchead");
    head.append(el("span", "tag", KIND_TAG[d.kind] || d.kind.toUpperCase()), el("span", "name", d.label));
    card.append(head);
    if (!d.sessions) {
      card.append(el("div", "note", "No visitors in this period"));
    } else {
      const nums = el("div", "svcnums");
      for (const [v, l] of [[d.sessions, "sessions"], [d.ips, "IPs"], [d.actions, "actions"]]) {
        const n = el("span"); n.append(el("b", "", fmtN(v)), document.createTextNode(" " + l)); nums.append(n);
      }
      card.append(nums, el("div", "note", `Furthest: ${d.stage}. Last ${fmtAgo(d.last)}.`));
      const notable = d.notable.length ? d.notable : d.top;
      if (notable.length) {
        const fl = el("div", "svcflags");
        for (const [name, n] of notable) fl.append(el("span", d.notable.length ? "flag" : "flag plain", `${name} ${n}`));
        card.append(fl);
      }
    }
    card.title = `List ${d.label} sessions`;
    // agent-surface cards are web sessions carrying a flag, not a protocol of their own
    activate(card, () => (d.flag ? listSessions(d.flag, "web") : listSessions("", d.kind)));
    box.append(card);
  }
}

// ---- intel -------------------------------------------------------------------------------
function renderSubnav() {
  const nav = $("subnav");
  clear(nav);
  for (const g of INTEL) {
    nav.append(el("h3", "", g.group));
    for (const [key, label] of g.items) {
      const b = el("button");
      b.type = "button";
      b.append(el("span", "", label), el("span", "n", fmtN((data.distinct || {})[key])));
      if (key === state.intel) b.setAttribute("aria-current", "true");
      b.addEventListener("click", () => { $("intel-filter").value = ""; go("intel", key); });
      nav.append(b);
    }
  }
}
function renderIntel() {
  renderSubnav();
  const [key, label, col, desc, mono] = INTEL_BY_KEY[state.intel];
  $("intel-title").textContent = label;
  $("intel-desc").textContent = desc;
  $("intel-col").textContent = col;
  const body = $("intel-table").tBodies[0];
  clear(body);
  const all = data.tops[key] || [];
  const total = (data.totals || {})[key] || all.reduce((a, r) => a + r[1], 0);
  const q = $("intel-filter").value.trim().toLowerCase();
  const rows = all.map((r, i) => [i + 1, r[0], r[1]]).filter((r) => !q || String(r[1]).toLowerCase().includes(q));
  const max = Math.max(1, ...all.map((r) => r[1]));
  for (const [rank, name, count] of rows) {
    const tr = el("tr");
    const item = el("td", "item" + (mono ? " mono" : ""), name === "" ? "(empty)" : name);
    const share = el("div", "share");
    const track = el("div", "track"), fill = el("div", "fill");
    fill.style.width = (count / max) * 100 + "%";
    track.append(fill);
    share.append(track, el("span", "pct", fmtPct(count, total)));
    const sc = el("td");
    sc.append(share);
    tr.append(el("td", "num", rank), item, el("td", "num", fmtN(count)), sc);
    if (["ips", "countries", "networks", "hassh", "ja4h", "campaigns", "techniques"].includes(key)) {
      tr.style.cursor = "pointer";
      tr.title = "List these sessions";
      tr.addEventListener("click", () => {
        $("f-text").value = key === "networks" ? String(name).replace(/ \(AS\d+\)$/, "")
          : ["hassh", "ja4h", "campaigns", "techniques"].includes(key) ? String(name).split(" ")[0] : String(name);
        state.shown = 100;
        go("sessions");
        renderSessions();
      });
    }
    body.append(tr);
  }
  if (!rows.length) {
    const tr = el("tr"), td = el("td", "empty", all.length ? "Nothing matches the filter." : "Nothing recorded in this period.");
    td.colSpan = 4;
    tr.append(td);
    body.append(tr);
  }
  const distinct = (data.distinct || {})[key] || 0;
  $("intel-foot").textContent = all.length
    ? `${fmtN(distinct)} distinct values, ${fmtN(total)} in total.` + (distinct > all.length ? ` Showing the top ${all.length}.` : "")
    : "";
}

// ---- sessions table ----------------------------------------------------------------------
// When the period has more sessions than the page holds (data.truncated), filters run on the server
// over all of them; the page's own list is used until that answer arrives.
const search = { key: "", list: null, matched: 0, pending: "", timer: 0 };
function searchKey() {
  return [state.range, $("own").checked ? 1 : 0, $("f-text").value.trim().toLowerCase(), $("f-class").value,
    $("f-kind").value, $("f-sort").value, data && data.meta ? data.meta.built || "" : ""].join("\u0001");
}
function remoteSearch() {
  const q = $("f-text").value.trim(), cls = $("f-class").value, kind = $("f-kind").value;
  if (!data || !data.truncated || (!q && !cls && !kind)) return null;
  const key = searchKey();
  if (search.key === key) return search;
  if (search.pending !== key) {
    search.pending = key;
    clearTimeout(search.timer);
    search.timer = setTimeout(async () => {
      const p = new URLSearchParams({ range: state.range, own: $("own").checked ? 1 : 0, q, cls, kind, sort: $("f-sort").value });
      try {
        const r = await (await fetch("/api/sessions?" + p)).json();
        if (search.pending !== key) return;
        Object.assign(search, { key, list: r.sessions, matched: r.matched, pending: "" });
        renderSessions();
      } catch { search.pending = ""; }
    }, 250);
  }
  return null;
}
function filteredSessions() {
  const remote = remoteSearch();
  if (remote) return remote.list;
  const cls = $("f-class").value, kind = $("f-kind").value, q = $("f-text").value.trim().toLowerCase();
  let list = data.sessions.filter((s) =>
    (!cls || s.cls === cls) && (!kind || s.kind === kind) &&
    (!q || [s.ip, s.summary, s.client, s.flags.join(" "), s.country, s.city, s.org, s.cc, "AS" + s.asn, s.fp, s.campaign, (s.tech || []).join(" ")]
      .join(" ").toLowerCase().includes(q)));
  const sort = $("f-sort").value;
  list = sort === "interest" ? list.slice().sort((a, b) => b.interest - a.interest || b.start - a.start)
    : sort === "agent" ? list.slice().sort((a, b) => (b.ascore || 0) - (a.ascore || 0) || b.start - a.start)
    : list.slice().sort((a, b) => b.start - a.start);
  return list;
}
function renderSessions() {
  const body = $("sessions").tBodies[0];
  clear(body);
  const list = filteredSessions();
  for (const s of list.slice(0, state.shown)) {
    const tr = el("tr");
    const started = el("td", "", fmtTime(s.start));
    started.append(el("span", "kind", kindLabel(s.kind)));
    const origin = el("td", "origin");
    if (s.cc) origin.append(el("span", "cc", s.cc));
    origin.append(document.createTextNode(s.city || s.country || "Unknown"));
    if (s.org) { const o = el("span", "org", s.org); o.title = s.org + (s.asn ? " (AS" + s.asn + ")" : ""); origin.append(o); }
    const actor = el("td");
    actor.append(classChip(s.cls));
    const what = el("td", "what");
    for (const f of s.flags) what.append(el("span", "flag" + (ALERT_FLAGS.has(f) ? " alert" : ""), f));
    const sc = el("td", "num ascore");
    const v = s.ascore || 0;
    const mini = el("span", "mini"), mf = el("span");
    mf.style.width = v + "%";
    mf.style.background = `var(--score-${v >= 100 ? 4 : v >= 60 ? 3 : v >= 30 ? 2 : v >= 10 ? 1 : 0})`;
    mini.append(mf);
    sc.append(el("span", v >= 60 ? "hi" : "", String(v)), mini);
    sc.title = `Agent likelihood ${v} / 100`;
    what.append(el("div", "mono", s.summary));
    const src = el("td", "mono", s.ip);
    if (s.rep && s.rep.score !== null && s.rep.score !== undefined) {
      const b = el("span", "rep" + (s.rep.score >= 75 ? " hi" : s.rep.score >= 25 ? " mid" : ""), s.rep.score + "%");
      b.title = `AbuseIPDB abuse confidence ${s.rep.score}%, ${s.rep.reports} reports` + (s.rep.gn ? `\nGreyNoise: ${s.rep.gn}` : "");
      src.append(b);
    }
    if (s.campaign) src.append(el("div", "note", s.campaign));
    tr.append(started, src, origin, actor, sc, el("td", "", s.stage_label),
      el("td", "num", fmtN(s.n)), el("td", "num", fmtGap(s.med_gap)), what);
    activate(tr, () => openSession(s.id));
    body.append(tr);
  }
  if (!list.length) {
    const tr = el("tr"), td = el("td", "empty", search.pending === searchKey() ? "Searching all sessions in this period…" : "No sessions match these filters.");
    td.colSpan = 9;
    tr.append(td);
    body.append(tr);
  }
  $("more").hidden = list.length <= state.shown;
  const remote = search.key === searchKey() && search.list === list;
  const searching = !remote && search.pending === searchKey();
  const unfiltered = !$("f-text").value.trim() && !$("f-class").value && !$("f-kind").value;
  const total = remote ? search.matched : unfiltered && data.truncated ? (data.kpi.sessions || list.length) : list.length;
  $("sessions-note").textContent = searching ? "Searching all sessions in this period…"
    : list.length
      ? `Showing ${fmtN(Math.min(state.shown, list.length))} of ${fmtN(total)}.` +
        (remote ? (total > list.length ? ` The newest ${fmtN(list.length)} matches are listed; narrow the filter to see the rest.` : "")
          : data.truncated ? " Only the newest 3,000 sessions are loaded; filters search all of them." : "")
      : "";
}

// ---- session drawer ----------------------------------------------------------------------
function timingStrip(gaps) {
  const W = 820, H = 150, L = 50, R = 6, T = 8, B = 10, iw = W - L - R, ih = H - T - B;
  const lo = Math.log10(10), hi = Math.log10(600000);
  const yOf = (ms) => T + ih - ((Math.log10(Math.min(600000, Math.max(10, ms))) - lo) / (hi - lo)) * ih;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Pause before each action, log scale" });
  for (const [ms, label] of [[100, "100 ms"], [1000, "1 s"], [10000, "10 s"], [60000, "1 min"], [600000, "10 min"]]) {
    const y = yOf(ms);
    root.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: "gridline" }));
    root.append(svgText({ x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" }, label));
  }
  const band = iw / gaps.length, bw = Math.max(1.5, Math.min(16, band - 2));
  gaps.forEach((g, i) => {
    const y = yOf(g), x = L + i * band + (band - bw) / 2;
    root.append(svg("path", { d: topRounded(x, y, bw, Math.max(1.5, T + ih - y), 3), fill: "var(--bar)" }));
    const hit = svg("rect", { x: L + i * band, y: T, width: band, height: ih, class: "hit" });
    attachTip(hit, () => `Before action ${i + 2}: waited ${fmtGap(g)}`);
    root.append(hit);
  });
  return root;
}
// Suricata alerts on this session, one row per rule, and the TLS client fingerprints it used
function idsSection(s) {
  const box = el("div", "idsbox");
  if (s.ids && s.ids.length) {
    const ul = el("ul", "techs");
    for (const g of s.ids) {
      const li = el("li");
      const sev = el("span", "sev s" + Math.min(3, Math.max(1, g.sev)), g.sev === 1 ? "high" : g.sev === 2 ? "medium" : "low");
      li.append(sev, el("span", "", " " + g.sig), el("span", "note", `  ${g.cat}${g.n > 1 ? `, ×${fmtN(g.n)}` : ""}, port ${g.port}`));
      if (g.cve && g.cve.length) li.append(el("div", "note", "Targets " + g.cve.join(", ")));
      if (g.payload) {
        const d = el("details");
        d.append(el("summary", "", "Matched packet"), el("pre", "", g.payload));
        li.append(d);
      }
      ul.append(li);
    }
    box.append(ul);
  }
  if (s.tls && s.tls.length) {
    const ul = el("ul", "reasons");
    for (const t of s.tls)
      ul.append(el("li", "mono", `port ${t.port}: JA4 ${t.ja4 || "-"}  JA3 ${t.ja3 || "-"}${t.sni ? "  SNI " + t.sni : ""}${t.ver ? "  " + t.ver : ""}`));
    box.append(el("div", "tactic", "TLS client fingerprints"), ul);
  }
  const n = (s.ids || []).length;
  return sectionK("IDS", n ? `Network IDS, ${n} rule${n > 1 ? "s" : ""} fired` : "Network IDS", box,
    el("p", "note", "Suricata with ET Open rules, watching the front VM's public interface. It only observes; nothing is blocked."));
}
// ATT&CK techniques grouped by tactic, in kill-chain order (the server sorts them)
function attackSection(list) {
  const box = el("div", "attack");
  let tactic = null, ul = null;
  for (const f of list) {
    if (f.tactic !== tactic) {
      tactic = f.tactic;
      box.append(el("div", "tactic", tactic));
      ul = el("ul", "techs");
      box.append(ul);
    }
    const li = el("li");
    const a = el("a", "mono", f.id);
    a.href = "https://attack.mitre.org/techniques/" + f.id.replace(".", "/") + "/";
    a.target = "_blank"; a.rel = "noopener noreferrer";
    a.title = "Open on attack.mitre.org";
    li.append(a, el("span", "", " " + f.name), el("span", "note", f.n > 1 ? `  ×${fmtN(f.n)}` : ""));
    for (const ev of f.ev) li.append(el("div", "mono note ev", ev));
    ul.append(li);
  }
  return sectionK("ATT&CK", `MITRE ATT&CK, ${list.length} technique${list.length > 1 ? "s" : ""}`, box,
    el("p", "note", "Mapped from this session's own commands, requests and file changes. Links open the MITRE ATT&CK site."));
}
// Drawer sections fold; which ones the viewer closed is remembered per section kind (not per session).
const FOLD_KEY = "hp.folded";
function foldedSet() {
  try { return new Set(JSON.parse(localStorage.getItem(FOLD_KEY) || "[]")); } catch { return new Set(); }
}
function section(title, ...nodes) {
  return sectionK(title, title, ...nodes);
}
function sectionK(key, title, ...nodes) {
  const s = el("section", "fold");
  const d = el("details");
  d.open = !foldedSet().has(key);
  const sum = el("summary");
  sum.append(el("h3", "", title));
  d.append(sum, ...nodes);
  d.addEventListener("toggle", () => {
    const f = foldedSet();
    if (d.open) f.delete(key); else f.add(key);
    try { localStorage.setItem(FOLD_KEY, JSON.stringify([...f])); } catch { /* storage blocked: folding still works */ }
  });
  s.append(d);
  return s;
}
async function openSession(id) {
  const r = await fetch("/api/session?id=" + encodeURIComponent(id));
  if (!r.ok) return;
  const s = await r.json();
  const body = $("d-body");
  clear(body);
  $("d-title").textContent = `${kindLabel(s.kind)} session from ${s.ip}`;
  $("d-sub").textContent = `${fmtTime(s.start, true)}, lasted ${fmtGap(s.end - s.start)}`;

  const facts = el("div", "facts");
  const fact = (label, value, node) => {
    const f = el("div", "fact"), v = el("div", "v");
    if (node) v.append(node); else v.textContent = value;
    f.append(el("div", "l", label), v);
    facts.append(f);
  };
  fact("Actor estimate", "", classChip(s.cls));
  fact("Agent likelihood", `${s.ascore ?? 0} / 100`);
  fact("Got as far as", s.stage_label);
  fact("Actions", fmtN(s.n));
  fact("Typical pause", fmtGap(s.med_gap) + (s.cv !== null && s.cv !== undefined ? `, variation ${s.cv.toFixed(2)}` : ""));
  fact("Location", [s.city, s.region, s.country].filter(Boolean).join(", ") || "Unknown");
  fact("Network", s.org ? `${s.org} (AS${s.asn})` : "Unknown");
  fact("Network type", s.net_label);
  fact("Client", s.client || "Not sent");
  if (s.fp) {
    const v = el("span");
    v.append(el("span", "mono", s.fp.length > 40 ? s.fp.slice(0, 40) + "…" : s.fp));
    v.title = s.fp;
    if (s.fp_ips) {
      const b = el("button", "link", ` shared by ${fmtN(s.fp_ips)} other IP${s.fp_ips > 1 ? "s" : ""}`);
      b.type = "button";
      b.addEventListener("click", () => { $("drawer").close(); $("f-text").value = s.fp; state.shown = 100; go("sessions"); renderSessions(); });
      v.append(b);
    }
    fact(s.fp_label || "Fingerprint", "", v);
  }
  // one-line verdict: what happened, with the flags that matter most first
  const verdict = el("div", "verdict");
  const vf = el("div");
  for (const f of [...s.flags].sort((a, b) => ALERT_FLAGS.has(b) - ALERT_FLAGS.has(a)))
    vf.append(el("span", "flag" + (ALERT_FLAGS.has(f) ? " alert" : ""), f));
  verdict.append(el("div", "mono", s.summary || s.stage_label), vf);
  body.append(verdict, facts);

  // assessment first: what this visitor is, and the evidence for it
  if (s.trips && s.trips.length) {
    const ul = el("ul", "reasons");
    for (const t of s.trips)
      ul.append(el("li", "", t.kind === "token"
        ? `${fmtTime(t.t, true)}: echoed ${t.token}, the instruction in ${t.where}`
        : `${fmtTime(t.t, true)}: used the credential from ${t.where}, ${t.how}`));
    body.append(section("Tripwires", ul, el("p", "note",
      "Each token and each credential exists in one bait file only, so a hit shows exactly what this visitor read and acted on.")));
  }
  const sig = el("ul", "reasons");
  for (const x of s.asignals || []) sig.append(el("li", "", x));
  if (!sig.childNodes.length) sig.append(el("li", "", "No agent signals."));
  const am = el("div", "meter" + ((s.ascore ?? 0) >= 60 ? " warn" : "")), at = el("div", "track"), af = el("div", "fill");
  af.style.width = (s.ascore ?? 0) + "%"; at.append(af); am.append(at);
  body.append(sectionK("Agent likelihood", `Agent likelihood: ${s.ascore ?? 0} / 100`, am, sig));
  const why = el("ul", "reasons");
  for (const reason of s.reasons.length ? s.reasons : ["No strong signals."]) why.append(el("li", "", reason));
  body.append(section("Why this estimate", why));
  if (s.attack && s.attack.length) body.append(attackSection(s.attack));
  if ((s.ids && s.ids.length) || (s.tls && s.tls.length)) body.append(idsSection(s));

  if (s.replay) body.append(section("Replay", replayPlayer(s.id, s.replay)));

  if (s.campaign_info) {
    const c = s.campaign_info, ol = el("ol", "reasons mono");
    for (const st of c.steps) ol.append(el("li", "", st));
    if (c.n_steps > c.steps.length) ol.append(el("li", "note", `+${c.n_steps - c.steps.length} more steps`));
    const b = el("button", "link", `List all ${fmtN(c.sessions)} sessions`);
    b.type = "button";
    b.addEventListener("click", () => { $("drawer").close(); $("f-text").value = c.id; state.shown = 100; go("sessions"); renderSessions(); });
    body.append(sectionK("Campaign", `Campaign ${c.id}`, el("p", "note",
      `The same ${c.n_steps}-step sequence ran in ${fmtN(c.sessions)} sessions from ${fmtN(c.ips)} IPs, ${fmtTime(c.first)} to ${fmtTime(c.last)}. ` +
      "IPs, URLs, numbers and random file names are blanked out (<ip>, <url>…) before comparing."), ol, b));
  }

  if (s.tunnel_targets && s.tunnel_targets.length) {
    const ul = el("ul", "reasons");
    for (const t of s.tunnel_targets)
      ul.append(el("li", "mono", `${t.target}${t.where ? "  (" + t.where + (t.org ? ", " + t.org : "") + ")" : ""}`));
    body.append(section("Tried to use the honeypot as a proxy to reach", ul,
      el("p", "note", "Nothing was forwarded: Cowrie only pretends to open tunnels, and the cloud firewall blocks these ports.")));
  }

  body.append(repSection(s));

  if (s.gaps.length >= 2) {
    const holder = el("div", "chart");
    holder.append(timingStrip(s.gaps));
    body.append(section("Rhythm", holder,
      el("p", "note", "Pause before each action, in order, on a log scale. Flat and low means a script; a steady 2 to 30 s points to an AI agent; uneven means a person.")));
  }

  const wrap = el("div", "tablewrap");
  const table = el("table", "timeline");
  const hr = el("tr");
  for (const h of ["Time", "Pause", "Event", "Result"]) hr.append(el("th", "", h));
  table.append(hr);
  for (const e of s.events) {
    const tr = el("tr"), main = el("td", "title");
    main.append(el("div", "mono", e.title));
    for (const n of e.notes) main.append(el("div", "note", n));
    if (e.sample) main.append(sampleTools(e.sample));
    const more = Object.entries(e.more || {}).filter((kv) => kv[1]);
    if (more.length) {
      const d = el("details");
      d.append(el("summary", "", s.kind === "web" || s.kind === "docker" || s.kind === "elastic" ? "Request details" : "Details"));
      for (const [k, v] of more) d.append(el("div", "note", k), el("pre", "", v));
      main.append(d);
    }
    tr.append(el("td", "t", new Date(e.t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })),
      el("td", "t", e.gap === null ? "" : "+" + fmtGap(e.gap)), main,
      el("td", "t", [e.status, e.tag].filter(Boolean).join(" ")));
    table.append(tr);
  }
  wrap.append(table);
  if (s.backend_note) wrap.append(el("p", "note", s.backend_note));
  body.append(sectionK("Timeline", "Timeline" + (s.events_truncated ? ", first 1,500 events" : ""), wrap));

  const dlg = $("drawer");
  dlg.append(tip);
  if (!dlg.open) dlg.showModal();
  dlg.scrollTop = 0;
}
// ---- samples: encrypted download and hash reputation -----------------------------------------
function lookupLines(lk) {
  const out = [];
  if (lk.vt) {
    const v = lk.vt;
    out.push(v.error ? "VirusTotal: " + v.error
      : !v.found ? "VirusTotal: not known (new or rare sample)"
      : `VirusTotal: ${v.malicious} of ${v.engines} engines flag it` + (v.label ? `, ${v.label}` : "")
        + (v.first_seen ? `, first seen ${new Date(v.first_seen * 1000).toLocaleDateString()}` : ""));
  }
  if (lk.mb) {
    const m = lk.mb;
    out.push(m.error ? "MalwareBazaar: " + m.error
      : !m.found ? "MalwareBazaar: not known"
      : "MalwareBazaar: " + [m.signature, m.file_type, m.tags.join(", "), m.first_seen && "first seen " + m.first_seen].filter(Boolean).join(", "));
  }
  return out;
}
function sampleTools(smp) {
  const box = el("div", "sampletools");
  const dl = el("button", "small", "Download (zip, password infected)");
  const ck = el("button", "small", smp.lookup ? "Check hash again" : "Check hash");
  const res = el("div", "lookup");
  const msg = el("span", "note");
  const show = (lk) => { clear(res); for (const l of lookupLines(lk)) res.append(el("div", "note", l)); };
  if (smp.lookup) show(smp.lookup);
  dl.title = "Zipped and encrypted on the VM; the raw file never reaches this PC. Unpack it only on an isolated analysis machine.";
  dl.addEventListener("click", async () => {
    dl.disabled = true; msg.textContent = "Packing on the VM…";
    try {
      const r = await fetch("/api/sample", { method: "POST", headers: { "X-HP-Token": token, "Content-Type": "application/json" },
        body: JSON.stringify({ sha: smp.sha, where: smp.where }) });
      if (!r.ok) throw new Error((await r.json()).error || r.status);
      const url = URL.createObjectURL(await r.blob());
      const a = el("a"); a.href = url; a.download = smp.sha.slice(0, 16) + "-infected.zip";
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      msg.textContent = "Saved to your Downloads folder.";
    } catch (err) { msg.textContent = "Download failed: " + err.message; }
    dl.disabled = false;
  });
  ck.addEventListener("click", async () => {
    ck.disabled = true; msg.textContent = "Asking VirusTotal / MalwareBazaar…";
    try {
      const r = await fetch("/api/lookup", { method: "POST", headers: { "X-HP-Token": token, "Content-Type": "application/json" },
        body: JSON.stringify({ sha: smp.sha }) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.status);
      smp.lookup = j; show(j); msg.textContent = ""; ck.textContent = "Check hash again";
    } catch (err) { msg.textContent = err.message; }
    ck.disabled = false;
  });
  box.append(dl, ck, uploadMenu(smp, msg), msg, res);
  return box;
}

// ---- status view ------------------------------------------------------------------------------
function fmtBytes(n) {
  if (n === null || n === undefined) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i];
}
function fmtUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}
function meter(label, used, total, detail) {
  const pct = total ? Math.min(100, Math.round(used / total * 100)) : 0;
  const w = el("div", "meter" + (pct >= 90 ? " bad" : pct >= 75 ? " warn" : ""));
  const bar = el("div", "track"); const fill = el("div", "fill"); fill.style.width = pct + "%"; bar.append(fill);
  w.append(el("div", "ml", label), el("div", "mv", pct + "%"), bar, el("div", "note", detail));
  return w;
}
const OK_STATES = new Set(["active", "running", "Running"]);
function factRow(cls, label, value) {
  const r = el("div", "fact");
  r.append(el("span", "led" + (cls ? " " + cls : "")), el("span", "", label), el("span", "note", value));
  return r;
}
function freshness(label, t, now, warnMin) {
  const age = t ? (now - t) / 60000 : null;
  return factRow(age === null ? "bad" : age > warnMin ? "warn" : "ok", label, t ? fmtAgo(t) : "never");
}
let vmBusy = false, vmTimer = null;
async function loadVmStatus(force) {
  if (vmBusy) return;
  vmBusy = true;
  $("status-note").textContent = "Checking the VMs over SSH…";
  try {
    const r = await fetch("/api/vmstatus" + (force ? "?force=1" : ""));
    renderVmStatus(await r.json());
  } catch (e) { $("status-note").textContent = "Dashboard server not answering."; }
  vmBusy = false;
  clearTimeout(vmTimer);
  if (state.view === "status") vmTimer = setTimeout(() => loadVmStatus(false), 30000);
}
function renderVmStatus(st) {
  const grid = $("vmgrid");
  clear(grid);
  let worst = "ok";
  const bump = (c) => { if (c === "bad" || (c === "warn" && worst === "ok")) worst = c; };
  for (const vm of st.vms) {
    const p = el("section", "panel vm");
    const head = el("div", "phead");
    const t = el("div");
    t.append(el("h2", "", vm.label), el("p", "note mono", vm.address + (vm.hostname ? "  ·  " + vm.hostname : "")));
    const bad = (vm.services || []).filter((x) => !OK_STATES.has(x.state));
    const cls = !vm.ok || bad.length ? "bad" : "ok";
    head.append(t, el("span", "badge " + cls, !vm.ok ? "Unreachable" : bad.length ? `${bad.length} problem${bad.length > 1 ? "s" : ""}` : "Healthy"));
    p.append(head);
    if (!vm.ok) { p.append(el("p", "note", vm.error)); bump("bad"); grid.append(p); continue; }

    const facts = el("div", "facts");
    for (const [k, v] of [["Uptime", fmtUptime(vm.uptime_s)],
      ["Load 1 / 5 / 15 min", vm.load.map((x) => x.toFixed(2)).join(" / ") + ` (${vm.cpus} CPU)`],
      ["Kernel", vm.kernel], ["SSH round trip", vm.rtt_ms + " ms"]]) {
      const f = el("div", "kv"); f.append(el("span", "note", k), el("span", "", v)); facts.append(f);
    }
    p.append(facts);
    const meters = el("div", "meters");
    meters.append(meter("Memory", vm.mem_total - vm.mem_avail, vm.mem_total, `${fmtBytes(vm.mem_avail)} free of ${fmtBytes(vm.mem_total)}`));
    meters.append(meter("Disk", vm.disk_total - vm.disk_free, vm.disk_total, `${fmtBytes(vm.disk_free)} free of ${fmtBytes(vm.disk_total)}`));
    if (vm.swap_total) meters.append(meter("Swap", vm.swap_total - vm.swap_free, vm.swap_total, fmtBytes(vm.swap_total) + " total"));
    p.append(meters);

    const svc = el("div", "rows");
    svc.append(el("h3", "", "Services"));
    for (const x of vm.services) {
      const c = OK_STATES.has(x.state) ? "ok" : "bad"; bump(c);
      svc.append(factRow(c, x.name, x.detail || x.state));
    }
    p.append(svc);

    const d = vm.data || {}, dat = el("div", "rows");
    dat.append(el("h3", "", "Data"));
    if (vm.key === "front") {
      dat.append(freshness("Last Cowrie event", d.cowrie_log, vm.now, 180), freshness("Last web request", d.web_log, vm.now, 180),
        freshness("Last decoy service event", d.decoy_log, vm.now, 24 * 60),
        ...(d.ids_rules ? [freshness("Last IDS event", d.ids_log, vm.now, 24 * 60), freshness("IDS rules updated", d.ids_rules, vm.now, 2 * 24 * 60)] : []),
        factRow("", "Logs on disk", fmtBytes(d.log_bytes)), factRow("", "Old Cowrie samples", fmtN(d.cowrie_samples)));
    } else {
      const c = vm.container || {};
      const cc = c.status === "Running" ? "ok" : "bad"; bump(cc);
      dat.append(factRow(cc, "Container " + (c.name || ""), c.error || `${c.status}, ${c.processes} processes, ${fmtBytes(c.mem)} RAM`),
        freshness("Collector last ran", d.collector_run, vm.now, 5),
        freshness("Last nightly reset", d.last_reset, vm.now, 26 * 60),
        factRow("", "Samples in quarantine", `${fmtN(d.samples)} (${fmtBytes(d.sample_bytes)})`),
        factRow("", "Event export", fmtBytes(d.export_bytes)), factRow("", "Audit log", fmtBytes(d.audit_bytes)),
        factRow("", "Nightly harvests", fmtN(d.harvests)),
        factRow(c.clean_snapshot ? "" : "bad", "Clean snapshot", c.clean_snapshot ? fmtTime(Date.parse(c.clean_snapshot)) : "missing"));
    }
    p.append(dat);
    grid.append(p);
  }

  const ds = st.dashboard, sy = ds.sync, p = el("section", "panel vm");
  const head = el("div", "phead"), t = el("div");
  t.append(el("h2", "", "This dashboard"), el("p", "note", "Runs on your PC, listens on 127.0.0.1 only"));
  const sc = sy.error ? "bad" : sy.backend_error ? "warn" : "ok"; bump(sc);
  head.append(t, el("span", "badge " + sc, sy.error ? "Sync failing" : sy.backend_error ? "Backend sync failing" : "Syncing"));
  p.append(head);
  const rows = el("div", "rows");
  rows.append(freshness("Last successful sync", sy.last_ok, st.t, Math.max(2, ds.sync_seconds * 4 / 60)),
    factRow("", "Pull interval", ds.sync_seconds + " s"),
    factRow("", "Log lines, web / Cowrie", `${fmtN(ds.lines.web)} / ${fmtN(ds.lines.cowrie)}`),
    factRow("", "Hash lookups cached", fmtN(ds.lookups) + (ds.auto_lookup ? ", automatic" : ", manual")),
    factRow("", "IP reputations cached", fmtN(ds.iprep) + (ds.auto_iprep ? ", automatic" : ", manual")));
  for (const [k, v] of Object.entries(ds.scans || {})) {
    const c = v.error ? "bad" : v.yara === false ? "warn" : "ok"; bump(c);
    rows.append(factRow(c, `YARA scan, ${k === "front" ? "front" : "backend"} VM`,
      v.error ? v.error.split("\n")[0] : `${fmtAgo(v.t)}, ${fmtN(v.files)} files, ${fmtN(v.rules)} rules`));
  }
  const rz = ds.resets;
  if (sy.error || sy.backend_error) rows.append(el("p", "note", sy.error || sy.backend_error));
  p.append(rows);
  grid.append(p);

  // container reset history: nightly restores, early ones after planted persistence, persona updates
  if (rz && rz.recent && rz.recent.length) {
    const cp = el("section", "panel vm");
    const ch = el("div", "phead"), ct = el("div");
    ct.append(el("h2", "", "Container resets"), el("p", "note", "Each reset harvests changed files, then restores the clean snapshot"));
    ch.append(ct, el("span", "badge " + (rz.early ? "warn" : "ok"), `${fmtN(rz.week)} in 7 days`));
    cp.append(ch);
    const ul = el("ul", "resets");
    for (const r of rz.recent) {
      const li = el("li", r.reason === "persistence" ? "early" : "");
      const why = r.reason === "persistence" ? "Early: persistence planted" : r.reason === "persona update" ? "Persona update"
        : r.reason === "nightly" || !r.reason ? "Nightly" : r.reason;
      li.append(el("span", "when", fmtTime(r.t, true)), el("span", "why", why),
        el("span", "note", r.harvested ? `${fmtN(r.harvested)} file${r.harvested > 1 ? "s" : ""} harvested` : "nothing changed"));
      if (r.paths && r.paths.length) li.append(el("div", "mono note", r.paths.join("  ")));
      ul.append(li);
    }
    cp.append(ul);
    grid.append(cp);
  }
  $("status-led").className = "led tiny " + worst;
  $("status-note").textContent = `Checked ${new Date(st.t).toLocaleTimeString()}. Refreshes every 30 s while this tab is open.`;
}

// ---- settings view ----------------------------------------------------------------------------
async function loadSettings() {
  const st = await (await fetch("/api/settings")).json();
  for (const [id, k, name, help] of [["s-vt", "virustotal_api_key", "VirusTotal", "Free key: sign in at virustotal.com, then your profile, API key."],
    ["s-mb", "malwarebazaar_auth_key", "MalwareBazaar", "Free key: sign in at auth.abuse.ch."],
    ["s-ab", "abuseipdb_api_key", "AbuseIPDB", "Free key (1,000 checks a day): abuseipdb.com, then Account, API."],
    ["s-gn", "greynoise_api_key", "GreyNoise", "Optional. Works without a key at a low daily limit; a free community key raises it."]]) {
    $(id).value = "";
    $(id).placeholder = st[k].set ? `Saved (${st[k].hint}). Type to replace it.` : "Not set";
    const stEl = $(id + "-state");
    clear(stEl);
    if (st[k].set) {
      const b = el("button", "link", "Remove saved key");
      b.type = "button";
      b.addEventListener("click", () => saveSettings({ [k]: "" }));
      stEl.append(document.createTextNode(name + " key saved. "), b);
    } else stEl.textContent = help;
  }
  $("s-auto").checked = st.auto_lookup;
  $("s-iprep").checked = st.auto_iprep;
  $("s-sync").value = st.sync_seconds;
  $("s-own").value = st.own_ips.join(", ");
  const fw = st.forward;
  $("s-fw-on").checked = fw.enabled;
  $("s-fw-type").value = fw.type;
  $("s-fw-addr").value = fw.address;
  $("s-fw-proto").value = fw.proto;
  $("s-fw-index").value = fw.index;
  $("s-fw-sensor").value = fw.sensor;
  $("s-fw-ca").value = fw.ca_file;
  for (const c of document.querySelectorAll("input[name=fw-src]")) c.checked = fw.sources.includes(c.value);
  $("s-fw-token").value = "";
  $("s-fw-token").placeholder = fw.token.set ? `Saved (${fw.token.hint}). Type to replace it.` : "Not set";
  const ts = $("s-fw-token-state");
  clear(ts);
  if (fw.token.set) {
    const b = el("button", "link", "Remove saved token");
    b.type = "button";
    b.addEventListener("click", () => saveSettings({ forward: { token: "" } }));
    ts.append(document.createTextNode("Token saved. "), b);
  }
  fwTypeChanged();
  fwStatus(st.forward_status, fw);
  const vt = st.virustotal_api_key.set, mb = st.malwarebazaar_auth_key.set;
  setChip("lookups", vt || mb ? `${(vt ? 1 : 0) + (mb ? 1 : 0)} of 2 keys` + (st.auto_lookup ? ", automatic" : "") : "No keys",
    vt || mb ? "ok" : "muted", `${(vt ? 1 : 0) + (mb ? 1 : 0)}/2`);
  const ab = st.abuseipdb_api_key.set, gn = st.greynoise_api_key.set;
  setChip("iprep", ab ? "AbuseIPDB" + (gn ? " and GreyNoise" : "") + (st.auto_iprep ? ", automatic" : "") : gn ? "GreyNoise only" : "No keys",
    ab ? "ok" : "muted", `${(ab ? 1 : 0) + (gn ? 1 : 0)}/2`);
  setChip("dash", `Every ${st.sync_seconds} s`, "muted", st.sync_seconds + " s");
  $("s-ab-auto").checked = st.abuse_auto;
  loadAbout();
  loadAbuse();
}

// A status label on each Settings card, and a short copy of it in the side menu.
function setChip(key, text, cls, short) {
  const c = $("chip-" + key);
  c.className = "badge " + (cls || "muted");
  c.textContent = text;
  $("nav-" + key).textContent = short === undefined ? "" : short;
}

function kvGrid(rows) {
  const g = el("div", "kvgrid");
  for (const [label, value, mono, note] of rows) {
    if (value === null || value === undefined || value === "") continue;
    const kv = el("div", "kv");
    kv.append(el("span", "note", label), el("span", "v" + (mono ? " mono" : ""), value));
    if (note) kv.append(el("span", "note", note));
    g.append(kv);
  }
  return g;
}
function kvSection(title, ...children) {
  const s = el("div", "kvsec");
  if (title) s.append(el("h3", "", title));
  s.append(...children);
  return s;
}
function feats(items) {
  const f = el("div", "feats");
  for (const [label, on] of items) {
    const x = el("span", "feat" + (on ? " on" : ""), label);
    x.title = on ? "On" : "Off";
    f.append(x);
  }
  return f;
}
const DECOY_NAMES = { redis: "Redis 6379", docker: "Docker API 2375", elastic: "Elasticsearch 9200", mysql: "MySQL 3306",
  ollama: "Ollama 11434", k8s: "Kubernetes 6443", rdp: "RDP 3389", smb: "SMB 445" };

async function loadAbout() {
  let a;
  try { a = await (await fetch("/api/about")).json(); } catch (e) { return; }
  // ---- deployment (honeypot.conf, read-only)
  const d = $("deploy-body"), c = a.conf;
  clear(d);
  if (!c || !Object.keys(c).length) {
    d.append(el("p", "callout", "No honeypot.conf next to the dashboard. Run hotpot setup to create one."));
    setChip("deploy", "Not found", "bad", "–");
  } else {
    const on = (k) => c[k] === "1";
    const days = (k) => (c[k] === "0" ? "Forever" : `${c[k]} days`);
    const dflt = (k) => (a.conf_defaults.includes(k) ? "default" : "");
    d.append(kvSection("", feats([["Real-shell backend", on("BACKEND_ENABLED")], ["Decoy services", on("DECOYS_ENABLED")],
      ["Suricata IDS", on("IDS_ENABLED")], ["LLM pages for unknown paths", on("LLM_ENABLED")]])));
    d.append(kvSection("Front VM", kvGrid([["Public IP", c.FRONT_PUBLIC_IP, true], ["Private IP", c.FRONT_PRIVATE_IP, true],
      ["Admin SSH port", c.ADMIN_SSH_PORT, true]])));
    if (on("BACKEND_ENABLED"))
      d.append(kvSection("Backend VM", kvGrid([["Private IP", c.BACKEND_IP, true], ["Container", c.CT_NAME, true],
        ["Container memory", c.CT_MEMORY], ["Container disk", c.CT_DISK_POOL_SIZE]])));
    if (on("DECOYS_ENABLED")) {
      const svc = (c.DECOY_SERVICES || "").split(",").map((x) => x.trim()).filter(Boolean);
      d.append(kvSection("Decoys", feats(Object.keys(DECOY_NAMES).map((k) => [DECOY_NAMES[k], svc.includes(k)]))));
    }
    if (on("LLM_ENABLED"))
      d.append(kvSection("Web honeypot fallback", kvGrid([["Models, tried in order", (c.LLM_MODELS || "").split(",").join(", "), true],
        ["Daily cap", c.LLM_DAILY_CAP], ["Per minute", c.LLM_PER_MINUTE]])));
    d.append(kvSection("Clean-up on the VMs", kvGrid([["Rotated logs and recordings", days("LOG_KEEP_DAYS"), false, dflt("LOG_KEEP_DAYS")],
      ["Samples and harvests", days("SAMPLE_KEEP_DAYS"), false, dflt("SAMPLE_KEEP_DAYS")],
      ["Oldest data goes above", c.DISK_MAX_PERCENT + "% disk", false, dflt("DISK_MAX_PERCENT")]])));
    const two = on("BACKEND_ENABLED");
    setChip("deploy", two ? "Two VMs, real shell" : "One VM, emulated shell", "muted", two ? "2 VMs" : "1 VM");
  }
  // ---- identity (persona.json)
  const id = a.identity, ib = $("identity-body");
  clear(ib);
  ib.append(kvSection("", kvGrid([["Company", `${id.brand} ${id.industry}`], ["Host name", id.host, true],
    ["Internal IP", id.ip, true], ["Canary word", id.check, true], ["Canary tokens", fmtN(id.tokens)],
    ["Tripwire credentials", fmtN(id.creds)]])));
  if (id.reference) {
    const w = el("p", "callout");
    w.append(document.createTextNode("This install still uses the public reference identity from the repository, so anyone who reads it can recognise the sensor. Run "),
      el("code", "", "hotpot identity new"), document.createTextNode(", then "), el("code", "", "hotpot deploy"), document.createTextNode("."));
    ib.append(w);
    setChip("identity", "Public reference", "warn", "public");
  } else setChip("identity", "Own identity", "ok", "own");
  // ---- about
  const ab = $("about-body"), dt = a.data;
  clear(ab);
  const lines = Object.values(dt.lines || {}).reduce((x, y) => x + (y || 0), 0);
  ab.append(kvSection("", kvGrid([["HotPot", a.version], ["Python", a.python], ["Sessions loaded", fmtN(dt.sessions)],
    ["Log lines read", fmtN(lines)], ["Synced logs", `${fmtBytes(dt.mirror_bytes)} in ${fmtN(dt.mirror_files)} files`],
    ["Dashboard data", fmtBytes(dt.bytes)], ["Last sync", fmtAgo(a.sync.last_ok)]])),
  kvSection("Data folder", kvGrid([["Everything this dashboard keeps", dt.path, true]])));
  setChip("about", "Version " + a.version, "muted", a.version);
}

// side menu: jump to a card, and mark the card in view
for (const b of document.querySelectorAll("#set-nav button")) {
  b.addEventListener("click", () => {
    $(b.dataset.sec).scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    markNav(b.dataset.sec);
  });
}
function markNav(id) {
  for (const b of document.querySelectorAll("#set-nav button")) b.setAttribute("aria-current", String(b.dataset.sec === id));
}
{
  // the card under the top of the view is current; at the very bottom, the last card is
  let queued = false;
  const pick = () => {
    queued = false;
    const cards = [...document.querySelectorAll(".scard")];
    if (!cards.length || !cards[0].offsetParent) return;  // Settings tab hidden
    let cur = cards[0];
    for (const c of cards) if (c.getBoundingClientRect().top <= 140) cur = c;
    if (innerHeight + scrollY >= document.documentElement.scrollHeight - 4) cur = cards[cards.length - 1];
    markNav(cur.id);
  };
  addEventListener("scroll", () => { if (!queued) { queued = true; requestAnimationFrame(pick); } }, { passive: true });
}
const FW_HELP = {
  syslog: ["host:port, e.g. siem.example.lan:6514", null, null],
  elasticsearch: ["Cluster URL, e.g. https://es.example.lan:9200 (the bulk API is added)", "API key (optional; base64 form)", "Index or data stream"],
  splunk: ["HEC URL, e.g. https://splunk.example.lan:8088", "HEC token", "Index (optional; empty uses the token's default)"],
  http: ["Full URL that accepts POSTed NDJSON", "Bearer token (optional)", null],
};
function fwTypeChanged() {
  const [addr, tok, idx] = FW_HELP[$("s-fw-type").value];
  $("s-fw-addr-help").textContent = addr;
  $("s-fw-proto-row").hidden = $("s-fw-type").value !== "syslog";
  $("s-fw-token-row").hidden = !tok;
  $("s-fw-index-row").hidden = !idx;
  if (tok) $("s-fw-token-label").textContent = tok;
  if (idx) $("s-fw-index-label").textContent = idx;
}
const FW_NAME = { syslog: "syslog", elasticsearch: "Elasticsearch", splunk: "Splunk", http: "HTTP" };
function fwStatus(s, fw) {
  const on = fw.enabled;
  $("s-fw-stats").hidden = !on;
  if (s) {
    $("fw-sent").textContent = fmtN(s.sent);
    $("fw-rej").textContent = fmtN(s.rejected);
    $("fw-wait").textContent = s.pending > 0 ? fmtBytes(s.pending) : "nothing";
    $("fw-last").textContent = fmtAgo(s.last_ok);
  }
  $("s-fw-state").textContent = on && s && s.error ? "Last error: " + s.error : "";
  if (!on) setChip("forward", "Off", "muted", "off");
  else if (s && s.error) setChip("forward", "Can't reach " + FW_NAME[fw.type], "bad", "error");
  else setChip("forward", "On, to " + FW_NAME[fw.type], "ok", "on");
}
function fwBody() {
  const f = { enabled: $("s-fw-on").checked, type: $("s-fw-type").value, address: $("s-fw-addr").value.trim(),
    proto: $("s-fw-proto").value, index: $("s-fw-index").value.trim(), sensor: $("s-fw-sensor").value.trim(),
    ca_file: $("s-fw-ca").value.trim(), sources: [...document.querySelectorAll("input[name=fw-src]:checked")].map((c) => c.value) };
  if ($("s-fw-token").value.trim()) f.token = $("s-fw-token").value.trim();
  return f;
}
$("s-fw-type").addEventListener("change", fwTypeChanged);

// ---- reporting to AbuseIPDB (Settings) ----------------------------------------------------------
let abusePending = 0;
async function loadAbuse() {
  let a;
  try { a = await (await fetch("/api/abuse")).json(); } catch (e) { return; }
  const s = a.status;
  abusePending = a.pending;
  $("ab-pending").textContent = fmtN(a.pending);
  $("ab-today").textContent = `${fmtN(s.today)} of ${fmtN(s.cap)}`;
  $("ab-total").textContent = fmtN(s.total);
  $("ab-last").textContent = s.running ? "running…" : s.last_run ? `${fmtAgo(s.last_run)}, ${fmtN(s.sent)} sent` : "never";
  const rows = $("ab-rows");
  clear(rows);
  for (const r of a.preview) {
    const tr = el("tr");
    tr.append(el("td", "mono", r.ip), el("td", "", r.categories.join(", ")), el("td", "", r.comment), el("td", "", fmtAgo(r.last)));
    rows.append(tr);
  }
  if (a.pending > a.preview.length) {
    const tr = el("tr");
    const td = el("td", "note", `and ${fmtN(a.pending - a.preview.length)} more`);
    td.colSpan = 4;
    tr.append(td);
    rows.append(tr);
  }
  $("ab-send").disabled = !a.key_set || !a.pending || s.running;
  $("ab-state").textContent = !a.key_set ? "Add an AbuseIPDB key above first." : s.error ? "Last error: " + s.error : "";
  if (!a.key_set) setChip("report", "No key", "muted", "off");
  else if (s.error) setChip("report", "Error", "bad", "error");
  else if (a.auto) setChip("report", "Automatic", "ok", "auto");
  else setChip("report", "By hand", "muted", "manual");
  if (s.running) setTimeout(loadAbuse, 3000);
}
$("ab-send").addEventListener("click", async () => {
  const n = Math.min(abusePending, 60);
  if (!confirm(`Report ${n} attacker IP${n === 1 ? "" : "s"} to AbuseIPDB now?\n\nReports are public and can't be taken back from here.`)) return;
  $("ab-send").disabled = true;
  try {
    await postJSON("/api/abuse-report", {});
    $("ab-state").textContent = "Reporting…";
    setTimeout(loadAbuse, 1500);
  } catch (e) {
    $("ab-state").textContent = "Not sent: " + e.message;
    $("ab-send").disabled = false;
  }
});
$("s-ab-auto").addEventListener("change", (ev) => {
  if (ev.target.checked && !confirm("Report new attackers to AbuseIPDB automatically while this dashboard runs?\n\nReports are public."))
    ev.target.checked = false;
});

// ---- indicator export (Intel tab) --------------------------------------------------------------
function iocQuery(format) {
  const kinds = [...document.querySelectorAll("input[name=ioc-kind]:checked")].map((c) => c.value);
  return "/api/ioc?" + new URLSearchParams({ format, range: $("ioc-range").value, scope: $("ioc-scope").value,
    tlp: $("ioc-tlp").value, kinds: kinds.join(",") });
}
async function iocCounts() {
  try {
    const n = await (await fetch(iocQuery("count"))).json();
    for (const s of document.querySelectorAll("#ioc-form [data-n]")) s.textContent = "(" + fmtN(n[s.dataset.n]) + ")";
  } catch (e) { /* counts are only a hint */ }
}
function iocFormatChanged() {
  const txt = $("ioc-format").value === "txt";
  $("ioc-tlp-label").hidden = !["stix", "misp"].includes($("ioc-format").value);
  // a plain list holds one kind: turn the boxes into a choice of one
  for (const c of document.querySelectorAll("input[name=ioc-kind]")) c.type = txt ? "radio" : "checkbox";
  if (txt && !document.querySelector("input[name=ioc-kind]:checked")) document.querySelector("input[name=ioc-kind]").checked = true;
}
$("ioc-format").addEventListener("change", iocFormatChanged);
for (const id of ["ioc-range", "ioc-scope"]) $(id).addEventListener("change", iocCounts);
$("ioc-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  if (!document.querySelector("input[name=ioc-kind]:checked")) { $("ioc-msg").textContent = "Choose at least one kind."; return; }
  const a = document.createElement("a");
  a.href = iocQuery($("ioc-format").value);
  a.download = "";
  document.body.append(a);
  a.click();
  a.remove();
  $("ioc-msg").textContent = "Downloading…";
  setTimeout(() => { $("ioc-msg").textContent = ""; }, 4000);
});
$("s-fw-test").addEventListener("click", async () => {
  const st = $("s-fw-state");
  $("s-fw-test").disabled = true;
  try {
    st.textContent = "Saving…";
    await postJSON("/api/settings", { forward: fwBody() });
    st.textContent = "Sending a test event…";
    await postJSON("/api/forward-test", {});
    await loadSettings();
    st.textContent = "Test event sent. Look for source \"hotpot\" at the destination.";
  } catch (e) {
    st.textContent = "Test failed: " + e.message;
  } finally {
    $("s-fw-test").disabled = false;
  }
});
async function saveSettings(body) {
  const msg = $("settings-msg");
  msg.textContent = "Saving…";
  const r = await fetch("/api/settings", { method: "POST", headers: { "X-HP-Token": token, "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  const j = await r.json();
  msg.textContent = r.ok ? "Saved." : "Not saved: " + j.error;
  if (r.ok) { await loadSettings(); load(); }
}
$("settings-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const body = { auto_lookup: $("s-auto").checked, auto_iprep: $("s-iprep").checked, abuse_auto: $("s-ab-auto").checked, sync_seconds: Number($("s-sync").value) || 60,
    own_ips: $("s-own").value.split(",").map((x) => x.trim()).filter(Boolean), forward: fwBody() };
  if ($("s-vt").value.trim()) body.virustotal_api_key = $("s-vt").value.trim();
  if ($("s-mb").value.trim()) body.malwarebazaar_auth_key = $("s-mb").value.trim();
  if ($("s-ab").value.trim()) body.abuseipdb_api_key = $("s-ab").value.trim();
  if ($("s-gn").value.trim()) body.greynoise_api_key = $("s-gn").value.trim();
  saveSettings(body);
});
$("status-refresh").addEventListener("click", () => loadVmStatus(true));
$("scan-now").addEventListener("click", async () => {
  $("scan-now").disabled = true;
  try { await postJSON("/api/scan", {}); $("samples-note").textContent = "Scanning on the VMs…"; } catch (e) { $("samples-note").textContent = e.message; }
  setTimeout(() => { $("scan-now").disabled = false; loadSamples(); }, 20000);
});

// ---- uploads to VirusTotal / MalwareBazaar ---------------------------------------------------
async function postJSON(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "X-HP-Token": token, "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
  return j;
}
function uploadMenu(smp, msg) {
  const d = el("details", "upload");
  d.append(el("summary", "", "Upload…"));
  d.append(el("p", "note", "Sends the file itself, not just its hash. VirusTotal shares uploads with its paying customers " +
    "and MalwareBazaar publishes them, so the attacker can learn the sample was caught. Hash checks share nothing."));
  for (const [svc, name] of [["vt", "VirusTotal"], ["mb", "MalwareBazaar"]]) {
    const done = (smp.submitted || {})[svc];
    const b = el("button", "small", (done ? "Sent to " : "Send to ") + name);
    b.type = "button";
    if (done) b.title = "Uploaded " + fmtTime(done);
    b.addEventListener("click", async () => {
      if (!confirm(`Upload this sample to ${name}?\n\nThe file becomes available to ${name} users. This can't be undone.`)) return;
      b.disabled = true; msg.textContent = `Uploading to ${name}…`;
      try {
        const r = await postJSON("/api/submit", { sha: smp.sha, where: smp.where, service: svc });
        msg.textContent = r.note + " ";
        const a = el("a", "", "Open on " + name);
        a.href = r.link; a.target = "_blank"; a.rel = "noopener noreferrer";
        msg.append(a);
        b.textContent = "Sent to " + name;
        (smp.submitted = smp.submitted || {})[svc] = Date.now();
      } catch (err) { msg.textContent = err.message; }
      b.disabled = false;
    });
    d.append(b);
  }
  return d;
}

// ---- weekly report ---------------------------------------------------------------------------
let reportWeek = "";
// Small multiples, one per measure, each on its own zero-based scale (never two scales on one chart).
function trendCharts(trend, current) {
  const grid = el("div", "trends");
  for (const [key, label] of [["sessions", "Sessions"], ["ips", "Source IPs"], ["logged_in", "Logged in"], ["agents", "Likely AI agents"]]) {
    const cell = el("div", "trend");
    const cur = trend.find((w) => w.week === current) || trend[trend.length - 1];
    const head = el("div", "th");
    head.append(el("span", "note", label), el("span", "v", fmtN(cur[key])));
    const W = 240, H = 56, gap = 4, bw = (W - gap * (trend.length - 1)) / trend.length;
    const max = Math.max(1, ...trend.map((w) => w[key]));
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `${label} per week, last ${trend.length} weeks` });
    trend.forEach((w, i) => {
      const h = Math.max(w[key] ? 2 : 0, (w[key] / max) * (H - 2)), x = i * (bw + gap);
      if (h) root.append(svg("path", { d: topRounded(x, H - h, bw, h, Math.min(4, bw / 2)),
        fill: w.week === current ? "var(--accent)" : "var(--score-0)" }));
      const hit = svg("rect", { x: x - gap / 2, y: 0, width: bw + gap, height: H, class: "hit" });
      attachTip(hit, () => `${w.week}: ${fmtN(w[key])} ${label.toLowerCase()}`);
      root.append(hit);
    });
    root.append(svg("line", { x1: 0, x2: W, y1: H - 0.5, y2: H - 0.5, class: "gridline" }));
    const foot = el("div", "tf");
    foot.append(el("span", "note", trend[0].week), el("span", "note", trend[trend.length - 1].week));
    cell.append(head, root, foot);
    grid.append(cell);
  }
  return grid;
}
async function loadReport() {
  $("report-note").textContent = "Building…";
  let r;
  try { r = await (await fetch("/api/report?week=" + encodeURIComponent(reportWeek))).json(); }
  catch (e) { $("report-note").textContent = "Dashboard server not answering."; return; }
  reportWeek = r.week;
  const sel = $("report-week");
  clear(sel);
  for (const w of r.weeks) sel.append(new Option(w + (w === r.weeks[0] ? " (this week)" : ""), w));
  sel.value = r.week;
  $("report-dl").href = "/api/report.html?week=" + encodeURIComponent(r.week);
  const d = (ms) => new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  $("report-title").textContent = `Weekly report, ${r.week}`;
  $("report-note").textContent = `${d(r.from)} to ${d(r.to - 1)}${r.complete ? "" : ", still in progress"}. ` +
    "Your own IPs are left out. Each finished week is also saved every Monday to dashboard/data/reports.";
  const t = r.totals, box = $("report-kpis");
  clear(box);
  for (const [v, l] of [[t.sessions, "Sessions"], [t.ips, "Source IPs"], [t.new_ips, "Never seen before"], [t.countries, "Countries"],
    [t.logged_in, "Logged in"], [t.ran_commands, "Ran commands"], [t.samples, "New samples"], [t.resets, "Container resets"]]) {
    const f = el("div", "fig"); f.append(el("div", "v", fmtN(v)), el("div", "l", l)); box.append(f);
  }
  const body = $("report-body");
  clear(body);
  const hl = el("ul", "reasons");
  for (const h of r.highlights) hl.append(el("li", "", h));
  body.append(section("This week", hl));
  if (r.trend && r.trend.length) body.append(section("Last eight weeks", trendCharts(r.trend, r.week)));
  const tbl =(title, head, rows, rowFn) => {
    if (!rows.length) return;
    const wrap = el("div", "tablewrap"), tb = el("table", "grid"), hr = el("tr");
    for (const h of head) hr.append(el("th", "", h));
    tb.append(hr);
    for (const x of rows) { const tr = el("tr"); for (const c of rowFn(x)) tr.append(c); tb.append(tr); }
    wrap.append(tb);
    body.append(section(title, wrap));
  };
  const td = (txt, cls) => el("td", cls || "", txt);
  tbl("AI agents and tripwires", ["Session", "Score", "Estimate", "Tripwires"], r.agents, (a) => {
    const c = el("td"), b = el("button", "link mono", a.id); b.type = "button";
    b.addEventListener("click", () => openSession(a.id));
    c.append(b, el("div", "note", `${a.kind} from ${a.ip}, ${fmtTime(a.start, true)}`));
    return [c, td(String(a.score), "num"), td(a.cls), td(a.trips.join("; ") || "none")];
  });
  tbl("New malware samples", ["File", "YARA", "VirusTotal"], r.samples, (x) => {
    const c = el("td"); c.append(el("div", "mono", x.name || "(no name)"), el("div", "note", x.magic), el("div", "note mono", x.sha));
    return [c, td(x.yara.join(", ") || "none"), td((x.vt !== null ? `${x.vt} engines` : "not checked") + (x.family ? `, ${x.family}` : ""))];
  });
  tbl("Command campaigns", ["Campaign", "This week", "All time", "First step"], r.campaigns, (c) =>
    [td(c.id + (c.new ? " (new)" : ""), "mono"), td(fmtN(c.sessions), "num"), td(fmtN(c.total), "num"), td(c.first_step, "mono")]);
  tbl("MITRE ATT&CK techniques", ["Technique", "Sessions"], r.techniques || [], ([k, v]) => {
    const c = el("td"), b = el("button", "link mono", k); b.type = "button";
    b.addEventListener("click", () => listSessions(k.split(" ")[0]));
    c.append(b);
    return [c, td(fmtN(v), "num")];
  });
  tbl("Network IDS alerts", ["Rule", "Alerts"], r.ids || [], ([k, v]) => [td(k, "mono"), td(fmtN(v), "num")]);
  const two = el("div", "rtwo");
  body.append(two);
  for (const [title, key, label] of [["Countries", "countries", "Country"], ["Networks", "networks", "Network"],
    ["Actor estimates", "classes", "Estimate"], ["Protocols", "kinds", "Protocol"]]) {
    const before = body.lastChild;
    tbl(title, [label, "Count"], r[key], ([k, v]) => [td(k), td(fmtN(v), "num")]);
    if (body.lastChild !== before) two.append(body.lastChild);
  }
  for (const [title, key, label] of [["Top credentials tried", "credentials", "User / password"], ["Top commands", "commands", "Command"],
    ["Top web paths", "paths", "Path"], ["Decoy service actions", "decoys", "Action"]])
    tbl(title, [label, "Count"], r[key], ([k, v]) => [td(k, "mono"), td(fmtN(v), "num")]);
  tbl("Container resets", ["When", "Why", "Changed"], r.resets, (x) =>
    [td(fmtTime(x.t, true)), td(x.reason === "persistence" ? "early, after persistence" : x.reason), td(x.paths.join(", "), "mono")]);
}
$("report-week").addEventListener("change", (ev) => { reportWeek = ev.target.value; loadReport(); });

// ---- samples view ---------------------------------------------------------------------------
let samplesData = null;
async function loadSamples() {
  $("samples-note").textContent = "Loading…";
  try {
    samplesData = await (await fetch("/api/samples")).json();
    renderSamples();
  } catch (e) { $("samples-note").textContent = "Dashboard server not answering."; }
}
function verdictCell(r) {
  const td = el("td", "verdicts");
  for (const y of r.yara || []) {
    const c = el("span", "flag yara", y.rule.replace(/_/g, " "));
    c.title = "YARA rule " + y.rule + (y.desc ? ": " + y.desc : "");
    td.append(c);
  }
  if (r.lookup) for (const l of lookupLines(r.lookup)) td.append(el("div", "note", l));
  const sub = Object.keys(r.submitted || {});
  if (sub.length) td.append(el("div", "note", "Uploaded to " + sub.map((k) => k === "vt" ? "VirusTotal" : "MalwareBazaar").join(" and ")));
  if (!td.childNodes.length) td.append(el("span", "note", r.scanned ? "No YARA rule matched" : "Not scanned yet"));
  return td;
}
function renderSamples() {
  const d = samplesData, body = $("samples-table").tBodies[0];
  clear(body);
  const own = $("own").checked;
  const rows = d.samples.filter((r) => own || !r.own_only);
  for (const r of rows) {
    const tr = el("tr");
    const file = el("td", "file");
    file.append(el("div", "mono", r.names[0] || "(no name)"));
    for (const n of r.names.slice(1, 4)) file.append(el("div", "note mono", n));
    file.append(el("div", "note", [r.magic || "type unknown", r.how].filter(Boolean).join(", ")));
    const sha = el("div", "note mono sha", r.sha);
    sha.title = "SHA-256";
    file.append(sha);
    file.append(sampleTools({ sha: r.sha, where: r.where, lookup: r.lookup, submitted: r.submitted }));
    const from = el("td", "from");
    for (const ss of r.sessions.slice(0, 4)) {
      const b = el("button", "link mono", `${ss.ip} (${kindLabel(ss.kind)})`);
      b.type = "button";
      b.addEventListener("click", () => openSession(ss.id));
      from.append(b, el("br"));
    }
    if (r.sessions.length > 4) from.append(el("span", "note", `+${r.sessions.length - 4} more sessions`));
    if (!r.sessions.length) from.append(el("span", "note", "no session"));
    if (r.own_only) from.append(el("div", "note", "your own test"));
    tr.append(el("td", "t", fmtTime(r.last)), file, el("td", "num", fmtBytes(r.size)), from, verdictCell(r));
    body.append(tr);
  }
  if (!rows.length) {
    const tr = el("tr"), td = el("td", "empty", "No samples captured yet.");
    td.colSpan = 5; tr.append(td); body.append(tr);
  }
  const sc = d.scans || {}, parts = [];
  for (const [k, v] of Object.entries(sc))
    parts.push(`${k === "front" ? "Front VM" : "Backend VM"} scanned ${fmtAgo(v.t)}` + (v.yara === false ? " (yara not installed)" : "")
      + (v.error ? ` (problem: ${v.error.split("\n")[0]})` : ""));
  $("samples-note").textContent = `${fmtN(rows.length)} samples. ${fmtN(d.rules)} YARA rules. ` +
    (d.scanning ? "Scanning now…" : parts.join("; ") || "Not scanned yet.");
  $("samples-foot").textContent = `Rules live in ${d.rules_dir}. Add any .yar files there; every scan sends the whole set. ` +
    "Scans run on the VMs every 15 minutes, so samples never leave them.";
  renderDropped(d.dropped);
}
const DROPPED_WHY = { near_duplicate: "only numbers changed", version_cap: "over 5 versions", other: "other" };
function renderDropped(dr) {
  const box = $("dropped"), body = $("dropped-table").tBodies[0];
  box.hidden = !dr || !dr.total;
  if (box.hidden) return;
  clear(body);
  $("dropped-sum").textContent = `Versions not stored: ${fmtN(dr.total)} ` + (dr.total === 1 ? "version" : "versions") +
    ` of ${fmtN(dr.path_count)} ` + (dr.path_count === 1 ? "file" : "files");
  for (const g of dr.paths) {
    const why = el("td", "why");
    for (const [k, n] of Object.entries(g.why)) why.append(el("div", "", `${fmtN(n)} × ${DROPPED_WHY[k] || k}`));
    const last = el("td", "file");
    const sha = el("div", "note mono sha", g.sha);
    sha.title = "SHA-256 of the newest version that was not stored";
    last.append(sha);
    if (g.size != null) last.append(el("div", "note", fmtBytes(g.size)));
    const tr = el("tr");
    tr.append(el("td", "t", fmtTime(g.last)), el("td", "mono", g.path), el("td", "num", fmtN(g.count)), why, last);
    body.append(tr);
  }
  $("dropped-foot").textContent = dr.path_count > dr.paths.length
    ? `Showing the ${fmtN(dr.paths.length)} most recent of ${fmtN(dr.path_count)} files.` : "";
}

// ---- AI-written web pages ---------------------------------------------------------------------
// Paths come from attackers and page text from a model prompted with them: text nodes only.
let llmData = null;
const LLM_SHOW = 300;
async function loadLlm(force) {
  $("llm-note").textContent = force ? "Fetching the saved pages from the front VM…" : "Loading…";
  $("llm-refresh").disabled = true;
  try {
    llmData = await (await fetch("/api/llm-pages?own=" + ($("own").checked ? 1 : 0) + (force ? "&force=1" : ""))).json();
    renderLlm();
  } catch (e) { $("llm-note").textContent = "Dashboard server not answering."; }
  $("llm-refresh").disabled = false;
}
// Rendered in a sandboxed frame: the server sends it with a CSP that allows no scripts, forms or outside loads.
function llmPreviewTool(p) {
  const box = el("div", "llm-preview");
  const b = el("button", "small", "Preview");
  b.type = "button";
  b.setAttribute("aria-expanded", "false");
  let frame = null;
  b.addEventListener("click", () => {
    if (!frame) {
      frame = el("iframe", "llm-frame");
      frame.setAttribute("sandbox", "");
      frame.setAttribute("referrerpolicy", "no-referrer");
      frame.title = `Preview of ${p.method} ${p.path}`;
      frame.src = "/api/llm-preview?key=" + encodeURIComponent(p.method + " " + p.path);
      box.append(frame);
    } else frame.hidden = !frame.hidden;
    const open = !frame.hidden;
    b.textContent = open ? "Hide preview" : "Preview";
    b.setAttribute("aria-expanded", String(open));
  });
  box.prepend(b);
  return box;
}
function renderLlm() {
  const d = llmData, body = $("llm-table").tBodies[0];
  if (!d) return;
  clear(body);
  const f = $("llm-filter").value.trim().toLowerCase();
  const rows = d.pages.filter((p) => !f || (p.method + " " + p.path + " " + p.model).toLowerCase().includes(f));
  for (const p of rows.slice(0, LLM_SHOW)) {
    const req = el("td", "file");
    const det = el("details", "llm-page");
    det.append(el("summary", "mono", `${p.method} ${p.path}`));
    det.append(el("pre", "llm-body", p.body + (p.size > p.body.length ? `\n… (${fmtBytes(p.size - p.body.length)} more)` : "")));
    req.append(det);
    if ((p.ctype || "").startsWith("text/html")) req.append(llmPreviewTool(p));
    if (p.asked) {
      const line = el("div", "note");
      const b = el("button", "link mono", p.asked.ip);
      b.type = "button";
      b.addEventListener("click", () => openSession(p.asked.id));
      line.append(document.createTextNode("First asked for by "), b, document.createTextNode(", " + fmtTime(p.asked.t)));
      req.append(line);
    }
    const ans = el("td", "");
    ans.append(el("div", "", p.status === 200 ? "Page" : "404 (" + (p.status || "?") + ")"));
    ans.append(el("div", "note", `${p.ctype || "?"}, ${fmtBytes(p.size)}`));
    const served = el("td", "num", fmtN(p.served));
    if (p.served) served.append(el("div", "note", `${fmtN(p.visitors)} ${p.visitors === 1 ? "visitor" : "visitors"}, last ${fmtAgo(p.last)}`));
    const tr = el("tr");
    tr.append(el("td", "t", p.created ? fmtTime(p.created) : "–"), req, ans, served, el("td", "mono note", p.model));
    body.append(tr);
  }
  if (!rows.length) {
    const tr = el("tr"), td = el("td", "empty", f ? "No page matches the filter." : "No AI-written pages yet.");
    td.colSpan = 5; tr.append(td); body.append(tr);
  }
  const ok = d.pages.filter((p) => p.status === 200).length;
  const today = d.usage.length ? d.usage[0] : null;
  $("llm-note").textContent = `${fmtN(d.pages.length)} saved pages: ${fmtN(ok)} served as pages, ${fmtN(d.pages.length - ok)} answered with a 404. ` +
    (today ? `AI calls on ${today[0]}: ${fmtN(today[1])}. ` : "") +
    (d.fetched ? `Fetched ${fmtAgo(d.fetched)}.` : "Not fetched yet.") + (d.error ? ` Problem: ${d.error}` : "");
  $("llm-foot").textContent = (rows.length > LLM_SHOW ? `Showing the newest ${fmtN(LLM_SHOW)} of ${fmtN(rows.length)}; filter to find others. ` : "") +
    "Served counts come from the web logs the dashboard has. Click a path to read the page. The text was written for an attacker's request: never follow links or run anything in it.";
}
$("llm-filter").addEventListener("input", () => renderLlm());
$("llm-refresh").addEventListener("click", () => loadLlm(true));

// ---- IP reputation ----------------------------------------------------------------------------
function repLines(r) {
  const out = [];
  const a = r.abuse;
  if (!a) out.push("AbuseIPDB: add a free key in Settings to see abuse reports.");
  else if (a.error) out.push("AbuseIPDB: " + a.error);
  else out.push(`AbuseIPDB: ${a.score}% abuse confidence, ${fmtN(a.reports)} reports from ${fmtN(a.reporters)} users` +
    (a.usage ? `; ${a.usage}` : "") + (a.tor ? "; Tor exit node" : "") + (a.last ? `; last reported ${new Date(a.last).toLocaleDateString()}` : ""));
  const g = r.gn;
  if (g) {
    if (g.error) out.push("GreyNoise: " + g.error);
    else if (!g.found) out.push("GreyNoise: not seen scanning the internet (targeted, new or quiet)");
    else out.push(`GreyNoise: ${g.class || "unknown"}` + (g.noise ? ", internet-wide scanner" : "") +
      (g.riot ? ", known business service" : "") + (g.name && g.name !== "unknown" ? `, ${g.name}` : "") +
      (g.last ? `, last seen ${g.last}` : ""));
  }
  out.push("Checked " + fmtAgo(r.t));
  return out;
}
function repSection(s) {
  const lines = el("div", "lookup");
  const show = (r) => { clear(lines); for (const l of repLines(r)) lines.append(el("div", "note", l)); };
  if (s.iprep) show(s.iprep);
  const b = el("button", "small", s.iprep ? "Check again" : "Check IP reputation");
  b.type = "button";
  const msg = el("span", "note");
  b.addEventListener("click", async () => {
    b.disabled = true; msg.textContent = "Asking AbuseIPDB / GreyNoise…";
    try { show(await postJSON("/api/iprep", { ip: s.ip })); msg.textContent = ""; b.textContent = "Check again"; }
    catch (err) { msg.textContent = err.message; }
    b.disabled = false;
  });
  const tools = el("div", "sampletools");
  tools.append(b, msg);
  return section("IP reputation", lines, tools);
}

// ---- session replay -------------------------------------------------------------------------
// A small terminal emulator: enough of VT100 for shells (cursor moves, erase, wrap). Colours are dropped.
class Term {
  constructor(cols, rows) { this.cols = cols; this.rows = rows; this.reset(); }
  reset() { this.lines = [[]]; this.x = 0; this.y = 0; this.top = 0; this.mode = 0; this.esc = ""; this.ins = false; }
  line(y) { while (this.lines.length <= y) this.lines.push([]); return this.lines[y]; }
  lf() { this.y++; this.line(this.y); if (this.y - this.top >= this.rows) this.top = this.y - this.rows + 1; }
  put(ch) {
    if (this.x >= this.cols) { this.x = 0; this.lf(); }
    const l = this.line(this.y);
    while (l.length < this.x) l.push(" ");
    if (this.ins) { l.splice(this.x++, 0, ch); if (l.length > this.cols) l.length = this.cols; }
    else l[this.x++] = ch;
  }
  csi(p, f) {
    const n = p.replace(/[?>=!]/g, "").split(";").map((v) => parseInt(v, 10));
    const a = isNaN(n[0]) ? 0 : n[0], a1 = a || 1;
    const l = () => this.line(this.y);
    switch (f) {
      case "A": this.y = Math.max(this.top, this.y - a1); break;
      case "B": this.y = Math.min(this.top + this.rows - 1, this.y + a1); l(); break;
      case "C": this.x = Math.min(this.cols - 1, this.x + a1); break;
      case "D": this.x = Math.max(0, this.x - a1); break;
      case "G": this.x = Math.min(this.cols - 1, a1 - 1); break;
      case "H": case "f":
        this.y = this.top + Math.min(this.rows - 1, a1 - 1); this.x = Math.min(this.cols - 1, (n[1] || 1) - 1); l(); break;
      case "J":
        if (a >= 2) { for (let y = this.top; y < this.lines.length; y++) this.lines[y] = []; }
        else if (a === 0) { l().length = Math.min(l().length, this.x); this.lines.length = this.y + 1; }
        break;
      case "K":
        if (a === 0) l().length = Math.min(l().length, this.x);
        else if (a === 1) { const r = l(); for (let i = 0; i <= this.x && i < r.length; i++) r[i] = " "; }
        else this.lines[this.y] = [];
        break;
      case "P": l().splice(this.x, a1); break;
      case "@": { const r = l(); while (r.length < this.x) r.push(" "); r.splice(this.x, 0, ...Array(a1).fill(" ")); break; }
      case "h": case "l": if (!p.startsWith("?") && n.includes(4)) this.ins = f === "h"; break;  // insert mode (IRM)
      default: break;  // colours, other modes, scroll regions: ignored
    }
  }
  write(text) {
    for (const ch of text) {
      const c = ch.codePointAt(0);
      if (this.mode === 1) { this.mode = ch === "[" ? 2 : ch === "]" ? 3 : "()*+#%".includes(ch) ? 4 : 0; this.esc = ""; continue; }
      if (this.mode === 4) { this.mode = 0; continue; }  // charset / line-size selector: one more byte
      if (this.mode === 2) {
        if (c >= 0x40 && c <= 0x7e) { this.csi(this.esc, ch); this.mode = 0; }
        else if (this.esc.length < 40) this.esc += ch; else this.mode = 0;
        continue;
      }
      if (this.mode === 3) { if (c === 7) this.mode = 0; else if (c === 27) this.mode = 1; continue; }
      if (c === 27) this.mode = 1;
      else if (ch === "\r") this.x = 0;
      else if (ch === "\n") { this.lf(); this.x = 0; }  // bots on exec channels send bare \n (no pty to add \r)
      else if (c === 8) this.x = Math.max(0, this.x - 1);
      else if (ch === "\t") this.x = Math.min(this.cols - 1, (Math.floor(this.x / 8) + 1) * 8);
      else if (c >= 32 && c !== 127) this.put(ch);
    }
    if (this.lines.length > 6000) {
      const cut = this.lines.length - 5000;
      this.lines.splice(0, cut); this.y -= cut; this.top = Math.max(0, this.top - cut);
    }
  }
  text() { return this.lines.map((l) => l.join("").replace(/\s+$/, "")).join("\n"); }
}
function replayPlayer(id, kind) {
  const box = el("div", "replay");
  const start = el("button", "small", kind === "tty" ? "Load the recording" : "Replay the typed commands");
  start.type = "button";
  const note = el("p", "note", kind === "tty"
    ? "Cowrie recorded everything the attacker saw. It plays back here as plain text, at real speed or faster."
    : "No terminal recording for this session, so only the typed commands are replayed, without their output.");
  box.append(note, start);
  start.addEventListener("click", async () => {
    start.disabled = true; start.textContent = "Fetching from the VM…";
    const r = await fetch("/api/replay?id=" + encodeURIComponent(id));
    const rec = await r.json().catch(() => ({ error: "bad response" }));
    if (!r.ok || !rec.frames || !rec.frames.length) {
      start.textContent = rec.error || "Nothing to replay"; return;
    }
    start.remove();
    if (rec.synthetic && kind === "tty") note.textContent = "The recording could not be read" + (rec.error ? ` (${rec.error})` : "") + ", so only the typed commands are replayed.";
    mountPlayer(box, rec);
  });
  return box;
}
function mountPlayer(box, rec) {
  const term = new Term(rec.cols, rec.rows);
  const screen = el("pre", "term");
  screen.style.height = `calc(${rec.rows} * 1.35em + 20px)`;
  screen.style.maxWidth = `calc(${rec.cols}ch + 28px)`;
  screen.tabIndex = 0;
  screen.setAttribute("aria-label", "Terminal replay");
  const bar = el("div", "rbar");
  const play = el("button", "small", "Play"); play.type = "button";
  const speed = el("select"); speed.setAttribute("aria-label", "Speed");
  for (const v of [1, 2, 4, 8, 32]) speed.append(new Option(v + "×", v));
  const skipL = el("label", "check"), skip = el("input"); skip.type = "checkbox"; skip.checked = true;
  skipL.append(skip, document.createTextNode(" Shorten pauses over 2 s"));
  const pos = el("input"); pos.type = "range"; pos.min = 0; pos.max = 1000; pos.value = 0; pos.setAttribute("aria-label", "Position");
  const clock = el("span", "note mono");
  bar.append(play, speed, skipL, pos, clock);
  box.append(bar, screen);

  let vt = [], total = 0, idx = 0, now = 0, playing = false, last = 0;
  const timeline = () => {
    vt = []; let t = 0, prev = 0;
    for (const [ft] of rec.frames) { const g = ft - prev; t += skip.checked ? Math.min(g, 2000) : g; prev = ft; vt.push(t); }
    total = Math.max(1, t);
  };
  const fmtClock = (ms) => { const s = Math.floor(ms / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
  const paint = () => {
    screen.textContent = term.text();
    screen.scrollTop = screen.scrollHeight;
    pos.value = Math.round(now / total * 1000);
    clock.textContent = `${fmtClock(now)} / ${fmtClock(total)}`;
  };
  const advance = () => {
    let changed = false;
    while (idx < rec.frames.length && vt[idx] <= now) { term.write(rec.frames[idx][1]); idx++; changed = true; }
    return changed;
  };
  const seek = (v) => { now = Math.max(0, Math.min(total, v)); term.reset(); idx = 0; advance(); paint(); };
  const loop = (ts) => {
    if (!playing || !box.isConnected) return;
    now += (ts - last) * Number(speed.value); last = ts;
    if (now >= total) { now = total; playing = false; play.textContent = "Play again"; }
    advance(); paint();
    if (playing) requestAnimationFrame(loop);
  };
  play.addEventListener("click", () => {
    if (playing) { playing = false; play.textContent = "Play"; return; }
    if (now >= total) seek(0);
    playing = true; play.textContent = "Pause"; last = performance.now(); requestAnimationFrame(loop);
  });
  skip.addEventListener("change", () => { const f = now / total; timeline(); seek(f * total); });
  pos.addEventListener("input", () => seek(pos.value / 1000 * total));
  timeline(); seek(0);
  play.click();
}

$("drawer").addEventListener("close", () => { tip.hidden = true; document.body.append(tip); });
$("drawer").addEventListener("click", (ev) => { if (ev.target === $("drawer")) $("drawer").close(); });
$("d-close").addEventListener("click", () => $("drawer").close());

// ---- live hits ---------------------------------------------------------------------------
// New events arrive in batches (one per log sync). They are replayed with their real spacing,
// squeezed into a few seconds, so the map and ticker show a stream instead of a burst.
const live = { since: null, queue: [], playing: false, mapReady: false, target: null, seen: [], squeeze: 1, k: 1 };
const KIND_TAG = { web: "WEB", ssh: "SSH", telnet: "TEL", redis: "RDS", docker: "DKR", elastic: "ES", mysql: "SQL", ollama: "LLM", k8s: "K8S", rdp: "RDP", smb: "SMB",
  mcp: "MCP", a2a: "A2A", agentdocs: "DOC" };
const TICKER_ROWS = 7;

function hitClass(h) {
  if (h.type === "command" || h.type === "file" || h.type === "canary") return "cmd";
  if (h.type === "login" && h.ok) return "loginok";
  return h.kind === "web" ? "web" : h.kind === "telnet" ? "telnet" : h.kind === "ssh" ? "ssh" : "svc";
}
function hitOutcome(h) {
  if (h.type === "login") return h.ok ? ["let in", "good"] : ["refused", ""];
  if (h.type === "canary") return ["canary", "bad"];
  if (h.type === "command") return [h.kind === "ssh" || h.kind === "telnet" ? "shell" : "decoy", "bad"];
  if (h.type === "file") return ["download", "bad"];
  if (h.kind === "web") return [h.status ? String(h.status) : "", ""];
  return ["", ""];
}
function tickerRow(h, animate) {
  const li = el("li", hitClass(h) + (animate ? " new" : ""));
  const [oc, ocCls] = hitOutcome(h);
  li.append(
    el("span", "tm", new Date(h.t).toLocaleTimeString([], { hour12: false })),
    el("span", "kd", KIND_TAG[h.kind] || String(h.kind || "").toUpperCase().slice(0, 4)),
    el("span", "cc", h.cc || ""),
    el("span", "ip", h.ip),
    el("span", "wh", h.what || ""),
    el("span", "oc " + ocCls, oc),
  );
  li.title = `${h.ip}${h.country ? " (" + h.country + ")" : ""}\n${h.what || ""}`;
  return li;
}
function pushTicker(h, animate) {
  const box = $("ticker");
  box.prepend(tickerRow(h, animate));
  while (box.children.length > TICKER_ROWS) box.lastChild.remove();
}
function drawHit(h) {
  const layer = $("live-layer");
  if (!live.mapReady || h.x == null || document.hidden) return;
  const cls = hitClass(h), big = cls === "cmd" || cls === "loginok", k = live.k || 1;
  const g = svg("g", { class: "hit " + cls });
  g.append(svg("circle", { cx: h.x, cy: h.y, r: (big ? 6 : 4.5) / k, class: "ping" }));
  g.append(svg("circle", { cx: h.x, cy: h.y, r: (big ? 3.4 : 2.6) / k, class: "core" }));
  layer.append(g);
  const t = live.target;
  if (t && Math.hypot(t[0] - h.x, t[1] - h.y) > 4 / k) {
    const dist = Math.hypot(t[0] - h.x, t[1] - h.y), lift = Math.max(28 / k, Math.min(160 / k, dist * 0.35));
    const cx = (h.x + t[0]) / 2, cy = (h.y + t[1]) / 2 - lift;
    const arc = svg("path", { d: `M${h.x},${h.y} Q${cx},${cy} ${t[0]},${t[1]}`, class: "arc" });
    g.append(arc);
    const len = Math.ceil(arc.getTotalLength());
    arc.style.strokeDasharray = `${len} ${len}`;
    arc.style.setProperty("--len", String(len));
    setTimeout(() => {
      if (g.isConnected) g.append(svg("circle", { cx: t[0], cy: t[1], r: (big ? 5 : 3.5) / k, class: "impact" }));
    }, 1050);
  }
  setTimeout(() => g.remove(), 7200);
  const hitsNow = layer.querySelectorAll(".hit");
  for (let i = 0; i < hitsNow.length - 150; i++) hitsNow[i].remove();
}
function drawTarget() {
  const layer = $("live-layer");
  if (!live.target || layer.querySelector(".target")) return;
  const [x, y] = live.target;
  const k = live.k || 1;
  layer.prepend(svg("circle", { cx: x, cy: y, r: 3 / k, class: "target" }));
  layer.prepend(svg("circle", { cx: x, cy: y, r: 4 / k, class: "target-ring" }));
}
function playQueue() {
  if (live.playing) return;
  live.playing = true;
  const step = () => {
    const h = live.queue.shift();
    if (!h) { live.playing = false; return; }
    pushTicker(h, true);
    drawHit(h);
    const next = live.queue[0];
    const gap = next ? Math.max(70, Math.min(1500, (next.t - h.t) / live.squeeze)) : 0;
    setTimeout(step, gap);
  };
  step();
}
function renderRate() {
  const now = Date.now();
  live.seen = live.seen.filter((t) => t > now - 60 * 60_000);
  const recent = live.seen.filter((t) => t > now - 5 * 60_000).length;
  $("live-rate").textContent = recent
    ? `${fmtN(Math.round(recent / 5 * 10) / 10)} a minute over the last 5 minutes`
    : "Quiet for the last 5 minutes";
  $("live-led").className = "live-led" + (recent ? " on" : "");
}
async function pollLive() {
  try {
    const own = $("own").checked ? 1 : 0;
    const r = await (await fetch(`/api/live?since=${live.since ?? 0}&own=${own}`)).json();
    live.target = r.target;
    if (live.mapReady) drawTarget();
    const hits = r.hits || [];
    for (const h of hits) live.seen.push(h.t);
    if (live.since === null) {
      for (const h of hits.slice(-TICKER_ROWS)) pushTicker(h, false);  // backlog: shown without animation
    } else if (hits.length && !rp.on) {   // during a map replay new hits wait for the next poll after it
      const span = hits[hits.length - 1].t - hits[0].t;
      live.squeeze = Math.max(1, span / 12000);                       // play a batch over at most ~12 s
      live.queue.push(...hits.slice(-80));
      if (live.queue.length > 120) live.queue.splice(0, live.queue.length - 120);
      playQueue();
    }
    live.since = Math.max(live.since ?? 0, r.newest || 0);
    renderRate();
  } catch (e) {
    $("live-led").className = "live-led";
  }
}

// ---- map replay --------------------------------------------------------------------------
// Plays the last 24 hours of hits through the same arcs and ticker as the live view, squeezed
// into 30 s to 3 min. Busy stretches are sampled on the server (at most 2,500 hits).
const rp = { on: false, playing: false, hits: [], i: 0, t0: 0, t1: 0, clock: 0, last: 0, tick: 0, saved: [] };
const RP_DRAW_PER_FRAME = 10;

function rpLabel() {
  const d = new Date(rp.clock);
  $("rp-clock").textContent = d.toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" }) + " " +
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  $("rp-pos").value = String(Math.round((rp.clock - rp.t0) / Math.max(1, rp.t1 - rp.t0) * 1000));
}
function rpClearLayer() {
  $("live-layer").replaceChildren();
  drawTarget();
}
function rpSetPlaying(on) {
  rp.playing = on;
  $("rp-play").textContent = on ? "Pause" : (rp.clock >= rp.t1 ? "Play again" : "Play");
  if (on) { rp.last = performance.now(); requestAnimationFrame(rpFrame); }
}
function rpFrame(now) {
  if (!rp.playing || !rp.on) return;
  const dt = Math.min(250, now - rp.last);
  rp.last = now;
  rp.clock = Math.min(rp.t1, rp.clock + dt * (rp.t1 - rp.t0) / Number($("rp-speed").value));
  let drawn = 0;
  while (rp.i < rp.hits.length && rp.hits[rp.i].t <= rp.clock) {
    const h = rp.hits[rp.i++];
    if (drawn++ < RP_DRAW_PER_FRAME) drawHit(h);
    if (now - rp.tick > 140) { rp.tick = now; pushTicker(h, true); }
  }
  rpLabel();
  if (rp.clock >= rp.t1) { rpSetPlaying(false); return; }
  requestAnimationFrame(rpFrame);
}
function rpSeek(v) {
  rp.clock = rp.t0 + v / 1000 * (rp.t1 - rp.t0);
  rp.i = rp.hits.findIndex((h) => h.t > rp.clock);
  if (rp.i < 0) rp.i = rp.hits.length;
  rpClearLayer();
  rpLabel();
}
async function rpStart() {
  const btn = $("rp-start");
  btn.disabled = true;
  let r;
  try {
    r = await (await fetch(`/api/map-replay?own=${$("own").checked ? 1 : 0}`)).json();
  } catch (e) {
    btn.disabled = false;
    return;
  }
  btn.disabled = false;
  $("rp-bar").hidden = false;
  if (r.target) live.target = r.target;
  if (!rp.on) rp.saved = [...$("ticker").children];
  Object.assign(rp, { on: true, hits: r.hits || [], i: 0, t0: r.from, t1: r.to, clock: r.from, tick: 0 });
  $("ticker").replaceChildren();
  rpClearLayer();
  $("rp-note").textContent = !rp.hits.length ? "Nothing happened in the last 24 hours."
    : rp.hits.length < r.total
      ? `Showing ${fmtN(rp.hits.length)} of ${fmtN(r.total)} events, sampled evenly over the day. Commands, downloads, tripwires and accepted logins get most of the room.`
      : `${fmtN(r.total)} events.`;
  rpLabel();
  rpSetPlaying(rp.hits.length > 0);
}
function rpStop() {
  rp.on = false;
  rp.playing = false;
  $("rp-bar").hidden = true;
  rpClearLayer();
  $("ticker").replaceChildren(...rp.saved);
  rp.saved = [];
  $("rp-start").focus();
}
$("rp-start").addEventListener("click", rpStart);
$("rp-stop").addEventListener("click", rpStop);
$("rp-play").addEventListener("click", () => {
  if (rp.clock >= rp.t1) rpSeek(0);
  rpSetPlaying(!rp.playing);
});
$("rp-pos").addEventListener("input", (ev) => rpSeek(Number(ev.target.value)));

// ---- loading -----------------------------------------------------------------------------
function renderStatus() {
  const st = meta.status, led = $("led"), btn = $("sync");
  led.className = "led " + (st.error ? "err" : st.running ? "busy" : st.last_ok ? "ok" : "");
  btn.classList.toggle("err", !!st.error);
  $("syncstate").textContent = st.error ? "Sync failed" : st.running ? "Syncing…" : "Synced " + fmtAgo(st.last_ok);
  btn.title = st.error ? "Sync problem: " + st.error + "\nClick to retry."
    : "Logs are pulled from the honeypot over SSH. Click to sync now."
      + (st.backend_error ? "\nReal-shell backend not reachable: " + st.backend_error : "");
  if (!st.error && st.backend_error) $("syncstate").textContent += " (backend failed)";
}
async function load() {
  try {
    meta = await (await fetch("/api/meta")).json();
    token = meta.token;
    renderStatus();
    data = await (await fetch(`/api/data?range=${encodeURIComponent(state.range)}&own=${$("own").checked ? 1 : 0}`)).json();
    $("host").textContent = `${meta.host}, since ${fmtTime(data.meta.from)}`;
    $("host").title = ($("own").checked ? "Including" : "Hiding") + ` your own IP (${data.meta.own_ips.join(", ") || "none set"})`;
    $("count-sessions").textContent = fmtN(data.truncated ? data.kpi.sessions || data.sessions.length : data.sessions.length);
    renderFigures(data.kpi);
    renderFeed();
    renderClasses();
    renderFunnel();
    renderAgents();
    renderDecoySvc();
    renderSessions();
    if (state.view === "overview") renderActivity();
    if (state.view === "intel") renderIntel();
    if (state.view === "stats") loadStats();
    await renderMap();
    $("attribution").textContent = data.geo.attribution + (data.geo.version ? " (" + data.geo.version + ")" : "") +
      ". Land outline from Natural Earth (public domain).";
  } catch (e) {
    $("led").className = "led err";
    $("sync").classList.add("err");
    $("syncstate").textContent = "Dashboard offline";
    $("sync").title = "The local dashboard server is not answering. Start server.py again.";
  }
}
function init() {
  const fc = $("f-class");
  fc.append(new Option("All actor types", ""));
  for (const k in CLASS_LABEL) fc.append(new Option(CLASS_LABEL[k], k));

  for (const b of $("range").querySelectorAll("button")) {
    b.setAttribute("aria-checked", String(b.dataset.range === state.range));
    b.addEventListener("click", () => {
      state.range = b.dataset.range;
      for (const o of $("range").querySelectorAll("button")) o.setAttribute("aria-checked", String(o === b));
      state.shown = 100;
      load();
    });
  }
  for (const b of $("funnel-kind").querySelectorAll("button"))
    b.addEventListener("click", () => { state.funnel = b.dataset.kind; if (data) renderFunnel(); });
  for (const b of document.querySelectorAll(".views button")) b.addEventListener("click", () => go(b.dataset.view));
  for (const b of document.querySelectorAll("[data-goto]")) b.addEventListener("click", () => go(b.dataset.goto));

  $("own").addEventListener("change", () => { state.shown = 100; load(); if (samplesData) renderSamples(); if (state.view === "llm") loadLlm(false); });
  for (const id of ["f-class", "f-kind", "f-sort"]) $(id).addEventListener("change", () => { state.shown = 100; renderSessions(); });
  $("f-text").addEventListener("input", () => { state.shown = 100; renderSessions(); });
  $("intel-filter").addEventListener("input", () => renderIntel());
  $("more").addEventListener("click", () => { state.shown += 200; renderSessions(); });
  $("sync").addEventListener("click", async () => {
    $("syncstate").textContent = "Syncing…";
    $("led").className = "led busy";
    await fetch("/api/sync", { method: "POST", headers: { "X-HP-Token": token } });
    setTimeout(load, 4000);
  });
  window.addEventListener("hashchange", applyView);
  let rt = null;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(() => { if (data && state.view === "overview") renderActivity(); if (state.view === "stats") renderStats(); }, 150);
  });
  initStats();
  applyView();
  load();
  timer = setInterval(() => { if (!$("drawer").open) load(); }, 30000);
  $("own").addEventListener("change", () => {
    live.since = null; live.queue = []; live.seen = []; clear($("ticker")); pollLive();
  });
  pollLive();
  setInterval(pollLive, 4000);
  setTimeout(() => { if (state.view !== "status") loadVmStatus(false); }, 3000);
}
init();
