"use strict";
// Statistics tab. Loaded before app.js and uses its helpers ($, el, svg, attachTip, ...) only when called.

const ST = { data: null, metric: "sessions", hidden: new Set(), heat: "all", breakdown: "class", mover: "credentials", csv: {}, seq: 0 };
const ST_METRICS = [
  ["sessions", "Sessions", "started in the period"],
  ["ips", "Source IPs", "distinct addresses"],
  ["login_attempts", "Login attempts", "passwords tried"],
  ["logins_ok", "SSH logins", "sessions that got a shell"],
  ["commands", "Commands", "typed after logging in"],
  ["decoy_actions", "Decoy actions", "requests to the fake services"],
  ["ids_alerts", "IDS alerts", "Suricata, all sources"],
  ["samples", "Files captured", "saved to the quarantine"],
  ["agents", "Likely AI agents", "score 60+ or a tripwire"],
];
const ST_PAL = ["#3987e5", "#c98500", "#1f9e8a", "#e0662f", "#a173e6", "#d55181"], ST_OTHER = "#56626f";
const ST_GROUPS = [["web", "Web", "var(--series-web)"], ["ssh", "SSH / Telnet", "var(--series-ssh)"], ["svc", "Decoy services", "var(--series-svc)"]];
const ST_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const ST_MOVERS = [["credentials", "Credentials"], ["commands", "Commands"], ["paths", "Web paths"], ["techniques", "ATT&CK techniques"],
  ["ids", "IDS signatures"], ["cves", "CVEs"], ["countries", "Countries"], ["networks", "Networks"]];
const ST_RANGE_NAME = { "24h": "24 hours", "7d": "7 days", "30d": "30 days", all: "all time" };

function stStepName(step) { return step === 604800000 ? "week" : stepName(step); }
function stPrevName() { return "previous " + ST_RANGE_NAME[ST.data.range]; }
function stDelta(cur, prev) {
  if (prev === null || prev === undefined) return null;
  if (!prev) return cur ? { txt: "new", dir: 1 } : { txt: "no change", dir: 0 };
  const p = Math.round((cur - prev) * 100 / prev);
  return { txt: (p > 0 ? "+" : "") + p + "%", dir: Math.sign(p) };
}
function stDeltaEl(cur, prev, cls) {
  const d = stDelta(cur, prev);
  if (!d) return el("span", "st-delta none", "");
  const s = el("span", "st-delta " + (cls || "") + (d.dir > 0 ? " up" : d.dir < 0 ? " down" : ""), (d.dir > 0 ? "▲ " : d.dir < 0 ? "▼ " : "") + d.txt);
  s.title = `${fmtN(cur)} now, ${fmtN(prev)} in the ${stPrevName()}`;
  return s;
}
// Sequential shading: one hue (the accent), stronger with more. sqrt keeps small counts visible.
function stShade(v, max) {
  if (!v) return "";
  const a = 0.14 + 0.86 * Math.sqrt(v / Math.max(1, max));
  return `rgba(106, 168, 240, ${a.toFixed(3)})`;
}

// ---- CSV -------------------------------------------------------------------------------------
function stCsvCell(v) {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;          // attacker text must not become a spreadsheet formula
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function stCsv(name, rows) {
  const text = rows.map((r) => r.map(stCsvCell).join(",")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv;charset=utf-8" }));
  a.download = `hotpot-${name}-${ST.data.range}.csv`;
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function stIso(t) { return new Date(t).toISOString().replace(".000Z", "Z"); }

// ---- loading ---------------------------------------------------------------------------------
async function loadStats() {
  const seq = ++ST.seq;
  const busy = $("st-busy");
  if (busy) busy.hidden = false;
  try {
    const d = await (await fetch(`/api/stats?range=${encodeURIComponent(state.range)}&own=${$("own").checked ? 1 : 0}`)).json();
    if (seq !== ST.seq) return;
    ST.data = d;
    renderStats();
  } catch (e) {
    if (seq === ST.seq) { clear($("st-highlights")); $("st-highlights").append(el("li", "", "Could not load statistics from the local server.")); }
  } finally {
    if (busy && seq === ST.seq) busy.hidden = true;
  }
}
function renderStats() {
  if (!ST.data || state.view !== "stats") return;
  const d = ST.data;
  $("st-period").textContent = `${fmtTime(d.from)} to ${fmtTime(d.to)}` +
    (d.compare ? `, compared with the ${stPrevName()}` : d.range === "all" ? "" : ", no earlier data to compare with");
  const hl = $("st-highlights");
  clear(hl);
  for (const h of d.highlights) hl.append(el("li", "", h));
  stCards();
  stMain();
  stHeat();
  stFunnels();
  stBreakdown();
  stDists();
  stMatrix();
  stMovers();
  stTables();
}

// ---- metric cards ----------------------------------------------------------------------------
function stSpark(vals) {
  const W = 120, H = 30, max = Math.max(1, ...vals), n = vals.length;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "st-spark", "aria-hidden": "true", preserveAspectRatio: "none" });
  if (n < 2) return root;
  const pts = vals.map((v, i) => `${(i * W / (n - 1)).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`);
  root.append(svg("polygon", { points: `0,${H} ${pts.join(" ")} ${W},${H}`, class: "area" }));
  root.append(svg("polyline", { points: pts.join(" "), class: "line" }));
  return root;
}
function stCards() {
  const d = ST.data, box = $("st-cards");
  clear(box);
  for (const [k, label, detail] of ST_METRICS) {
    const cur = d.totals[k], prev = d.compare ? d.prev_totals[k] : null;
    const card = el("div", "st-card" + (ST.metric === k ? " on" : ""));
    card.setAttribute("role", "radio");
    card.setAttribute("aria-checked", String(ST.metric === k));
    const top = el("div", "st-cardtop");
    top.append(el("div", "v", fmtN(cur)), stDeltaEl(cur, prev));
    card.append(top, el("div", "l", label), el("div", "d", k === "ips" ? `${fmtN(d.totals.new_ips)} new, ${fmtN(d.totals.returning_ips)} returning` : detail),
      stSpark(d.series[k]));
    card.title = `Show ${label.toLowerCase()} over time`;
    activate(card, () => { ST.metric = k; stCards(); stMain(); });
    box.append(card);
  }
}

// ---- stacked time chart (main chart and breakdown) -------------------------------------------
function stLegend(box, items, chartId, redraw) {
  clear(box);
  if (items.length < 2) return;
  for (const it of items) {
    const key = chartId + ":" + it.key;
    const b = el("button", "st-leg" + (ST.hidden.has(key) ? " off" : ""));
    b.type = "button";
    b.setAttribute("aria-pressed", String(!ST.hidden.has(key)));
    b.title = (ST.hidden.has(key) ? "Show " : "Hide ") + it.label;
    const sw = el("span", "sw");
    sw.style.background = it.color;
    b.append(sw, document.createTextNode(it.label));
    b.addEventListener("click", () => {
      if (ST.hidden.has(key)) ST.hidden.delete(key);
      else if (items.filter((i) => !ST.hidden.has(chartId + ":" + i.key)).length > 1) ST.hidden.add(key);
      redraw();
    });
    box.append(b);
  }
  if (items.some((it) => it.prev)) {
    const p = el("span", "st-leg static");
    p.append(el("span", "sw dash"), document.createTextNode(stPrevName() + " (total)"));
    box.append(p);
  }
}
function stStack(box, o) {
  // o: {id, times, step, series: [{key, label, color, values}], prev: values|null, unit, H}
  clear(box);
  const vis = o.series.filter((s) => !ST.hidden.has(o.id + ":" + s.key));
  const n = o.times.length;
  const sums = o.times.map((_, i) => vis.reduce((a, s) => a + s.values[i], 0));
  const peak = Math.max(1, ...sums, ...(o.prev || [0]));
  if (!sums.some(Boolean) && !(o.prev || []).some(Boolean)) { box.append(el("div", "empty", "Nothing in this period.")); return; }
  const W = Math.max(420, box.clientWidth || 860), H = o.H || 260, L = 44, R = 8, T = 10, B = 26;
  const iw = W - L - R, ih = H - T - B;
  const st = niceStep(peak, 4), max = Math.ceil(peak / st) * st;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `${o.unit} per ${stStepName(o.step)}` });
  for (let v = 0; v <= max; v += st) {
    const y = T + ih - (v / max) * ih;
    root.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "gridline" : "baseline" }));
    root.append(svgText({ x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" }, fmtN(v)));
  }
  const band = iw / n, bw = Math.max(2, Math.min(28, band - 3));
  const every = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(iw / 90))));
  let prevLabelT = null;
  const cross = svg("line", { y1: T, y2: T + ih, class: "st-cross", visibility: "hidden" });
  o.times.forEach((t, i) => {
    const x = L + i * band + (band - bw) / 2;
    let y = T + ih;
    const segs = vis.map((s) => [s.values[i], s.color]).filter((s) => s[0] > 0);
    segs.forEach(([v, color], j) => {
      const gap = j > 0 ? 2 : 0;
      const h = Math.max(1.5, (v / max) * ih - gap);
      y -= h + gap;
      const node = j === segs.length - 1 ? svg("path", { d: topRounded(x, y, bw, h, 4) }) : svg("rect", { x, y, width: bw, height: h });
      node.setAttribute("fill", color);
      root.append(node);
    });
    if (i % every === 0) {
      root.append(svgText({ x: L + i * band + band / 2, y: H - 8, "text-anchor": "middle", class: "axis" }, tickLabel(t, o.step, prevLabelT)));
      prevLabelT = t;
    }
  });
  if (o.prev) {
    const pts = o.prev.map((v, i) => `${(L + i * band + band / 2).toFixed(1)},${(T + ih - (v / max) * ih).toFixed(1)}`);
    root.append(svg("polyline", { points: pts.join(" "), class: "st-prevline" }));
  }
  root.append(cross);
  o.times.forEach((t, i) => {
    const hit = svg("rect", { x: L + i * band, y: T, width: band, height: ih, class: "hit" });
    hit.addEventListener("mouseenter", () => { const cx = L + i * band + band / 2; cross.setAttribute("x1", cx); cross.setAttribute("x2", cx); cross.setAttribute("visibility", "visible"); });
    hit.addEventListener("mouseleave", () => cross.setAttribute("visibility", "hidden"));
    attachTip(hit, () => {
      const lines = [`${fmtTime(t)}, one ${stStepName(o.step)}`];
      for (const s of vis.slice().reverse()) lines.push(`${s.label}: ${fmtN(s.values[i])}`);
      if (vis.length > 1) lines.push(`Total: ${fmtN(sums[i])}`);
      if (o.prev) lines.push(`Same time, ${stPrevName()}: ${fmtN(o.prev[i])}`);
      return lines.join("\n");
    });
    root.append(hit);
  });
  box.append(root);
}

function stMainSeries() {
  const d = ST.data, k = ST.metric;
  if (k === "sessions") return ST_GROUPS.map(([g, label, color]) => ({ key: g, label, color, values: d.series[g] }));
  if (k === "ips") return [{ key: "new", label: "New IPs", color: ST_PAL[0], values: d.series.new_ips },
    { key: "ret", label: "Returning IPs", color: ST_PAL[1], values: d.series.returning_ips }];
  const m = ST_METRICS.find((x) => x[0] === k);
  return [{ key: k, label: m[1], color: "var(--accent)", values: d.series[k] }];
}
function stMain() {
  const d = ST.data, k = ST.metric, m = ST_METRICS.find((x) => x[0] === k);
  const series = stMainSeries();
  const prev = d.compare ? d.prev_series[k] : null;
  $("st-main-title").textContent = `${m[1]} per ${stStepName(d.step)}`;
  const redraw = () => { stLegend($("st-main-legend"), series.map((s) => ({ ...s, prev: !!prev })), "main", redraw); stStack($("st-main"), { id: "main", times: d.times, step: d.step, series, prev, unit: m[1] }); };
  if (series.length < 2 && prev) {
    const lg = $("st-main-legend");
    clear(lg);
    const a = el("span", "st-leg static"), sw = el("span", "sw");
    sw.style.background = series[0].color;
    a.append(sw, document.createTextNode("This period"));
    const p = el("span", "st-leg static");
    p.append(el("span", "sw dash"), document.createTextNode(stPrevName()));
    lg.append(a, p);
    stStack($("st-main"), { id: "main", times: d.times, step: d.step, series, prev, unit: m[1] });
  } else redraw();
  ST.csv.main = () => stCsv("over-time-" + k, [["bucket_start_utc", ...series.map((s) => s.label), ...(prev ? ["previous_period_total"] : [])],
    ...d.times.map((t, i) => [stIso(t), ...series.map((s) => s.values[i]), ...(prev ? [prev[i]] : [])])]);
}

// ---- heatmap ---------------------------------------------------------------------------------
function stHeat() {
  const d = ST.data, grid = d.heat[ST.heat], box = $("st-heat");
  clear(box);
  const max = Math.max(0, ...grid.flat());
  if (!max) { box.append(el("div", "empty", "Nothing in this period.")); return; }
  const tbl = el("div", "st-heatgrid");
  tbl.append(el("div", "st-hh"));
  for (let h = 0; h < 24; h++) tbl.append(el("div", "st-hh", h % 3 === 0 ? String(h).padStart(2, "0") : ""));
  tbl.append(el("div", "st-hh", "total"));
  grid.forEach((row, wd) => {
    tbl.append(el("div", "st-hd", ST_DAYS[wd]));
    row.forEach((v, h) => {
      const c = el("div", "st-cell");
      const bg = stShade(v, max);
      if (bg) c.style.background = bg;
      attachTip(c, () => `${ST_DAYS[wd]} ${String(h).padStart(2, "0")}:00-${String(h + 1).padStart(2, "0")}:00 UTC\n${fmtN(v)} session${v === 1 ? "" : "s"}`);
      tbl.append(c);
    });
    tbl.append(el("div", "st-rt", fmtN(row.reduce((a, b) => a + b, 0))));
  });
  box.append(tbl);
  const key = el("div", "st-scale");
  key.append(el("span", "", "0"));
  for (const f of [0.05, 0.2, 0.45, 0.75, 1]) { const s = el("span", "st-sw"); s.style.background = stShade(f * max, max); key.append(s); }
  key.append(el("span", "", fmtN(max) + " sessions an hour"));
  box.append(key);
  ST.csv.heat = () => stCsv("weekday-hour-" + ST.heat, [["weekday", ...Array.from({ length: 24 }, (_, h) => `${h}:00`)],
    ...grid.map((row, wd) => [ST_DAYS[wd], ...row])]);
}

// ---- funnels ---------------------------------------------------------------------------------
function stFunnels() {
  const d = ST.data, box = $("st-funnels");
  clear(box);
  const rows = [];
  for (const [g, label, color] of ST_GROUPS) {
    const counts = d.funnels.cur[g], pc = d.compare ? d.funnels.prev[g] : null, stages = d.stages[g];
    const reach = counts.map((_, i) => counts.slice(i).reduce((a, b) => a + b, 0));
    const preach = pc ? pc.map((_, i) => pc.slice(i).reduce((a, b) => a + b, 0)) : null;
    const col = el("div", "st-fun");
    col.append(el("h3", "", `${label} (${fmtN(reach[0])})`));
    stages.forEach((name, i) => {
      const r = el("div", "st-funrow");
      const conv = i === 0 ? null : reach[i - 1] ? Math.round(reach[i] * 100 / reach[i - 1]) : 0;
      const pconv = !preach || i === 0 ? null : preach[i - 1] ? Math.round(preach[i] * 100 / preach[i - 1]) : null;
      const head = el("div", "st-funhead");
      head.append(el("span", "n", name), el("span", "c", fmtN(reach[i]) + (conv === null ? "" : `  ${conv}%`)));
      const track = el("div", "st-track"), bar = el("div", "st-bar");
      bar.style.width = (reach[0] ? Math.max(reach[i] ? 1 : 0, reach[i] * 100 / reach[0]) : 0) + "%";
      bar.style.background = color;
      track.append(bar);
      r.append(head, track);
      attachTip(r, () => [`${name}: ${fmtN(reach[i])} sessions got at least this far`,
        conv === null ? "" : `${conv}% of those at the step before`,
        pconv === null ? "" : `${stPrevName()}: ${pconv}% (${fmtN(preach[i])} sessions)`].filter(Boolean).join("\n"));
      col.append(r);
      rows.push([label, name, reach[i], conv === null ? "" : conv, preach ? preach[i] : "", pconv === null ? "" : pconv]);
    });
    box.append(col);
  }
  ST.csv.funnels = () => stCsv("funnels", [["protocol", "stage", "sessions_reached", "conversion_pct", "previous_reached", "previous_conversion_pct"], ...rows]);
}

// ---- breakdown over time ---------------------------------------------------------------------
function stBreakSeries() {
  const d = ST.data;
  if (ST.breakdown === "class")
    return Object.keys(CLASS_LABEL).map((k) => ({ key: k, label: CLASS_LABEL[k], color: `var(--c-${k})`, values: d.by_class[k] || d.times.map(() => 0) }))
      .filter((s) => s.values.some(Boolean));
  const src = ST.breakdown === "country" ? d.by_country : d.by_net;
  return Object.keys(src).map((k, i) => ({ key: k, label: k, color: k === "Other" ? ST_OTHER : ST_PAL[i % ST_PAL.length], values: src[k] }))
    .filter((s) => s.values.some(Boolean));
}
function stOpenSessions(kind, key) {
  if (kind === "class") { listSessions("", ""); $("f-class").value = key; renderSessions(); return; }
  if (key === "Other" || key === "Unknown") return;
  if (kind === "net") { const m = /\(AS(\d+)\)$/.exec(key); listSessions(m ? "AS" + m[1] : key); return; }
  listSessions(key);
}
function stBreakdown() {
  const d = ST.data, id = "br-" + ST.breakdown;
  const series = stBreakSeries();
  const redraw = () => {
    stLegend($("st-break-legend"), series, id, redraw);
    stStack($("st-break"), { id, times: d.times, step: d.step, series, prev: null, unit: "Sessions", H: 230 });
  };
  redraw();
  const share = $("st-share");
  clear(share);
  const total = series.reduce((a, s) => a + s.values.reduce((x, y) => x + y, 0), 0) || 1;
  for (const s of series) {
    const v = s.values.reduce((x, y) => x + y, 0);
    const row = el("div", "st-sharerow");
    const sw = el("span", "sw");
    sw.style.background = s.color;
    const name = el("span", "n", s.label);
    name.title = s.label;
    const bar = el("div", "st-track"), fill = el("div", "st-bar");
    fill.style.width = (v * 100 / total) + "%";
    fill.style.background = s.color;
    bar.append(fill);
    row.append(sw, name, el("span", "c", `${fmtN(v)}  ${Math.round(v * 100 / total)}%`), bar);
    if (s.key !== "Other" && s.key !== "Unknown") {
      row.classList.add("link");
      row.title = `List sessions: ${s.label}`;
      activate(row, () => stOpenSessions(ST.breakdown, s.key));
    }
    share.append(row);
  }
  ST.csv.breakdown = () => stCsv("breakdown-" + ST.breakdown, [["bucket_start_utc", ...series.map((s) => s.label)],
    ...d.times.map((t, i) => [stIso(t), ...series.map((s) => s.values[i])])]);
}

// ---- distributions ---------------------------------------------------------------------------
function stHist(box, title, bins, series, note) {
  const wrap = el("div", "st-hist");
  const head = el("div", "st-histhead");
  head.append(el("h3", "", title));
  const lg = el("div", "legend");
  if (series.length > 1) for (const s of series) { const it = el("span"), sw = el("span", "sw"); sw.style.background = s.color; it.append(sw, document.createTextNode(s.label)); lg.append(it); }
  head.append(lg);
  wrap.append(head);
  const chart = el("div", "chart");
  wrap.append(chart);
  if (note) wrap.append(el("div", "st-note", note));
  box.append(wrap);
  const sums = bins.map((_, i) => series.reduce((a, s) => a + s.values[i], 0));
  const total = sums.reduce((a, b) => a + b, 0);
  if (!total) { chart.append(el("div", "empty", "Nothing in this period.")); return; }
  const W = Math.max(300, chart.clientWidth || 500), H = 190, L = 40, R = 6, T = 8, B = 24;
  const iw = W - L - R, ih = H - T - B, peak = Math.max(...sums);
  const st = niceStep(peak, 4), max = Math.ceil(peak / st) * st;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title });
  for (let v = 0; v <= max; v += st) {
    const y = T + ih - (v / max) * ih;
    root.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "gridline" : "baseline" }));
    root.append(svgText({ x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" }, fmtN(v)));
  }
  const band = iw / bins.length, bw = Math.min(56, band - 8);
  bins.forEach((b, i) => {
    const x = L + i * band + (band - bw) / 2;
    let y = T + ih;
    const segs = series.map((s) => [s.values[i], s.color]).filter((s) => s[0] > 0);
    segs.forEach(([v, color], j) => {
      const gap = j > 0 ? 2 : 0, h = Math.max(1.5, (v / max) * ih - gap);
      y -= h + gap;
      const node = j === segs.length - 1 ? svg("path", { d: topRounded(x, y, bw, h, 4) }) : svg("rect", { x, y, width: bw, height: h });
      node.setAttribute("fill", color);
      root.append(node);
    });
    root.append(svgText({ x: L + i * band + band / 2, y: H - 7, "text-anchor": "middle", class: "axis" }, b));
    const hit = svg("rect", { x: L + i * band, y: T, width: band, height: ih, class: "hit" });
    attachTip(hit, () => [`${title}: ${b}`, `${fmtN(sums[i])} sessions (${Math.round(sums[i] * 100 / total)}%)`,
      ...(series.length > 1 ? series.filter((s) => s.values[i]).map((s) => `${s.label}: ${fmtN(s.values[i])}`) : [])].join("\n"));
    root.append(hit);
  });
  chart.append(root);
}
function stDists() {
  const d = ST.data.dist, box = $("st-dists");
  clear(box);
  stHist(box, "Session length", d.duration.bins,
    ST_GROUPS.map(([g, label, color]) => ({ label, color, values: d.duration.groups[g] })));
  stHist(box, "Commands per SSH login", d.commands.bins, [{ label: "Sessions", color: "var(--series-ssh)", values: d.commands.counts }],
    "Only sessions that logged in.");
  stHist(box, "Typing rhythm (median gap between actions)", d.gaps.bins,
    Object.keys(CLASS_LABEL).filter((k) => d.gaps.classes[k] && d.gaps.classes[k].some(Boolean))
      .map((k) => ({ label: CLASS_LABEL[k], color: `var(--c-${k})`, values: d.gaps.classes[k] })),
    "Sessions with at least 3 actions. Scripts sit left, people and agents further right.");
  stHist(box, "AI-agent score", d.score.bins, [{ label: "Sessions", color: "var(--c-agent_suspected)", values: d.score.counts }]);
  ST.csv.dists = () => {
    const rows = [["chart", "bin", "series", "sessions"]];
    d.duration.bins.forEach((b, i) => ST_GROUPS.forEach(([g, label]) => rows.push(["session length", b, label, d.duration.groups[g][i]])));
    d.commands.bins.forEach((b, i) => rows.push(["commands per login", b, "", d.commands.counts[i]]));
    d.gaps.bins.forEach((b, i) => Object.keys(d.gaps.classes).forEach((k) => rows.push(["median gap", b, CLASS_LABEL[k] || k, d.gaps.classes[k][i]])));
    d.score.bins.forEach((b, i) => rows.push(["agent score", b, "", d.score.counts[i]]));
    stCsv("distributions", rows);
  };
}

// ---- ATT&CK matrix ---------------------------------------------------------------------------
function stMatrix() {
  const d = ST.data, box = $("st-matrix");
  clear(box);
  if (!d.matrix.length) { box.append(el("div", "empty", "No techniques tagged in this period.")); return; }
  const max = Math.max(1, ...d.matrix.flatMap((m) => m.techniques.map((t) => t.sessions)));
  for (const m of d.matrix) {
    const col = el("div", "st-tac");
    const h = el("div", "st-tachead");
    h.append(el("span", "n", m.tactic), el("span", "c", fmtN(m.sessions)));
    h.title = `${m.tactic}: ${fmtN(m.sessions)} sessions used at least one technique`;
    col.append(h);
    for (const t of m.techniques) {
      const c = el("div", "st-tech" + (t.sessions ? "" : " gone"));
      const bg = stShade(t.sessions, max);
      if (bg) c.style.background = bg;
      if (t.sessions / max > 0.45) c.classList.add("dark");
      const top = el("div", "st-techtop");
      top.append(el("span", "id", t.id), el("span", "c", fmtN(t.sessions)));
      c.append(top, el("div", "n", t.name));
      if (d.compare) c.append(stDeltaEl(t.sessions, t.prev));
      attachTip(c, () => `${t.id} ${t.name}\n${fmtN(t.sessions)} sessions` + (d.compare ? `\n${stPrevName()}: ${fmtN(t.prev)}` : "") + "\nClick to list the sessions");
      activate(c, () => listSessions(t.id));
      col.append(c);
    }
    box.append(col);
  }
  ST.csv.matrix = () => stCsv("attack", [["tactic", "technique", "name", "sessions", "previous"],
    ...d.matrix.flatMap((m) => m.techniques.map((t) => [m.tactic, t.id, t.name, t.sessions, t.prev === null ? "" : t.prev]))]);
}

// ---- movers ----------------------------------------------------------------------------------
function stMoverKey(dim, k) {
  if (dim === "techniques") return k.split(" ")[0];
  if (dim === "countries") return k === "Unknown" ? null : k;
  if (dim === "networks") { const m = /\(AS(\d+)\)$/.exec(k); return m ? "AS" + m[1] : null; }
  return null;
}
function stMoverTable(title, rows, dim, mode) {
  const wrap = el("div", "st-mov");
  wrap.append(el("h3", "", title));
  if (!rows.length) { wrap.append(el("div", "empty", mode === "top" ? "Nothing in this period." : "None.")); return wrap; }
  const max = Math.max(1, ...rows.map((r) => Math.max(r.cur, r.prev || 0)));
  const mono = ["credentials", "commands", "paths"].includes(dim);
  for (const r of rows) {
    const row = el("div", "st-movrow");
    const name = el("span", "n" + (mono ? " mono" : ""), r.k);
    name.title = r.k;
    const nums = el("span", "c", mode === "top" || mode === "new" ? fmtN(r.cur) : `${fmtN(r.prev)} → ${fmtN(r.cur)}`);
    const track = el("div", "st-track"), fill = el("div", "st-bar");
    fill.style.width = (r.cur * 100 / max) + "%";
    track.append(fill);
    row.append(name, nums);
    if (mode === "top" && r.prev !== null) row.append(stDeltaEl(r.cur, r.prev, "small"));
    row.append(track);
    const q = stMoverKey(dim, r.k);
    if (q) { row.classList.add("link"); row.title = "List sessions: " + r.k; activate(row, () => listSessions(q)); }
    wrap.append(row);
  }
  return wrap;
}
function stMovers() {
  const d = ST.data, dim = ST.mover, m = d.movers[dim], box = $("st-movers");
  clear(box);
  box.append(stMoverTable("Most sessions", m.top.slice(0, 15), dim, "top"));
  if (d.compare) {
    box.append(stMoverTable("Rising", m.up.slice(0, 10), dim, "up"));
    box.append(stMoverTable("Falling", m.down.slice(0, 10), dim, "down"));
    box.append(stMoverTable("New this period", m.new.slice(0, 10), dim, "new"));
  } else {
    const n = el("div", "st-mov");
    n.append(el("div", "empty", d.range === "all" ? "Pick 24 h, 7 days or 30 days to compare with the period before." : "There is no data from the period before this one yet."));
    box.append(n);
  }
  const label = ST_MOVERS.find((x) => x[0] === dim)[1];
  ST.csv.movers = () => stCsv("changes-" + dim, [[label, "sessions", "previous_sessions", "list"],
    ...m.top.map((r) => [r.k, r.cur, r.prev === null ? "" : r.prev, "top"]),
    ...m.up.map((r) => [r.k, r.cur, r.prev, "rising"]), ...m.down.map((r) => [r.k, r.cur, r.prev, "falling"]),
    ...m.new.map((r) => [r.k, r.cur, r.prev, "new"])]);
}

// ---- tables ----------------------------------------------------------------------------------
function stTable(box, head, rows) {
  clear(box);
  if (!rows.length) { box.append(el("div", "empty", "Nothing in this period.")); return; }
  const t = el("table", "st-table"), tr = el("tr");
  head.forEach((h, i) => tr.append(el("th", i ? "num" : "", h)));
  const thead = el("thead");
  thead.append(tr);
  const tb = el("tbody");
  for (const r of rows) {
    const row = el("tr");
    r.cells.forEach((c, i) => {
      const td = el("td", i ? "num" : "");
      if (c instanceof Node) td.append(c); else td.textContent = c;
      row.append(td);
    });
    if (r.go) { row.classList.add("link"); activate(row, r.go); }
    tb.append(row);
  }
  t.append(thead, tb);
  box.append(t);
}
function stTables() {
  const d = ST.data, total = d.totals.sessions || 1;
  const ch = (cur, prev) => d.compare ? [stDeltaEl(cur, prev, "small")] : [];
  const head = (first) => [first, "Sessions", "Share", "IPs", ...(d.compare ? ["Change"] : [])];
  stTable($("st-countries"), head("Country"), d.countries.map((c) => ({
    cells: [c.name, fmtN(c.sessions), Math.round(c.sessions * 100 / total) + "%", fmtN(c.ips), ...ch(c.sessions, c.prev)],
    go: c.name === "Unknown" ? null : () => listSessions(c.name),
  })));
  const kinds = d.kinds.filter((k) => k.sessions || k.prev);
  stTable($("st-kinds"), head("Service"), kinds.map((k) => ({
    cells: [d.kind_names[k.kind] || k.kind, fmtN(k.sessions), Math.round(k.sessions * 100 / total) + "%", fmtN(k.ips), ...ch(k.sessions, k.prev)],
    go: () => listSessions("", k.kind),
  })));
  ST.csv.countries = () => stCsv("countries", [["country", "sessions", "ips", "previous_sessions"], ...d.countries.map((c) => [c.name, c.sessions, c.ips, c.prev === null ? "" : c.prev])]);
  ST.csv.kinds = () => stCsv("services", [["service", "sessions", "ips", "previous_sessions"], ...kinds.map((k) => [d.kind_names[k.kind] || k.kind, k.sessions, k.ips, k.prev === null ? "" : k.prev])]);
}

// ---- wiring (called from app.js init) --------------------------------------------------------
function initStats() {
  const seg = (id, attr, set) => {
    const box = $(id);
    for (const b of box.querySelectorAll("button")) b.addEventListener("click", () => {
      for (const o of box.querySelectorAll("button")) o.setAttribute("aria-checked", String(o === b));
      set(b.dataset[attr]);
    });
  };
  seg("st-heat-kind", "kind", (v) => { ST.heat = v; if (ST.data) stHeat(); });
  seg("st-break-kind", "kind", (v) => { ST.breakdown = v; if (ST.data) stBreakdown(); });
  const mv = $("st-mover-kind");
  for (const [k, label] of ST_MOVERS) {
    const b = el("button", "", label);
    b.type = "button";
    b.setAttribute("role", "radio");
    b.dataset.kind = k;
    b.setAttribute("aria-checked", String(k === ST.mover));
    mv.append(b);
  }
  seg("st-mover-kind", "kind", (v) => { ST.mover = v; if (ST.data) stMovers(); });
  for (const b of document.querySelectorAll("#view-stats [data-csv]")) {
    b.title = "Download this panel as CSV";
    b.addEventListener("click", () => { const f = ST.csv[b.dataset.csv]; if (f) f(); });
  }
}
