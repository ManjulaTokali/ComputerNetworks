"use strict";
const $ = (s) => document.querySelector(s);
const COLORS = {TCP: "#2f6fde", UDP: "#0e9f8e", ICMP: "#d99a00", ARP: "#8b5cf6", Other: "#7a8794"};
let selected = null, charts = {}, capturing = false, debounce = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const post = (path, body) => api(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})});

function human(n) {
  if (n < 1024) return Math.round(n * 10) / 10 + " B";
  const units = ["KB", "MB", "GB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < 2);
  return n.toFixed(1) + " " + units[i];
}
function message(text, ok) {
  const m = $("#msg");
  m.textContent = text || ""; m.hidden = !text; m.className = "msg" + (ok ? " ok" : "");
}
function filterParams() {
  const p = new URLSearchParams();
  const proto = $("#f-proto").value, src = $("#f-src").value.trim(), dst = $("#f-dst").value.trim();
  if (proto) p.set("proto", proto);
  if (src) p.set("src", src);
  if (dst) p.set("dst", dst);
  return p;
}
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function initCharts() {
  if (typeof Chart === "undefined") { $("#chart-note").hidden = false; return; }
  const base = {maintainAspectRatio: false, animation: false};
  charts.proto = new Chart($("#c-proto"), {type: "doughnut",
    data: {labels: [], datasets: [{data: [], backgroundColor: []}]},
    options: {...base, plugins: {legend: {position: "bottom"}}}});
  charts.time = new Chart($("#c-time"), {type: "line",
    data: {labels: [], datasets: [{label: "Packets", data: [], borderColor: "#2f6fde", backgroundColor: "rgba(47,111,222,.15)", fill: true, tension: .25, pointRadius: 0}]},
    options: {...base, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, ticks: {precision: 0}}}}});
  charts.bytes = new Chart($("#c-bytes"), {type: "bar",
    data: {labels: [], datasets: [{label: "Bytes", data: [], backgroundColor: "#0e9f8e"}]},
    options: {...base, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true}}}});
}

function renderStats(s) {
  $("#s-total").textContent = s.total.toLocaleString();
  $("#s-tcp").textContent = s.tcp.toLocaleString();
  $("#s-udp").textContent = s.udp.toLocaleString();
  $("#s-icmp").textContent = s.icmp.toLocaleString();
  $("#s-bytes").textContent = human(s.bytes);
  $("#s-avg").textContent = human(s.avg_size);
  if (!charts.proto) return;
  const names = Object.keys(s.protocols);
  charts.proto.data.labels = names;
  charts.proto.data.datasets[0].data = names.map((n) => s.protocols[n]);
  charts.proto.data.datasets[0].backgroundColor = names.map((n) => COLORS[n] || COLORS.Other);
  const t = s.timeline, note = t.labels.length ? "(per " + t.bucket + " s)" : "";
  charts.time.data.labels = charts.bytes.data.labels = t.labels;
  charts.time.data.datasets[0].data = t.packets;
  charts.bytes.data.datasets[0].data = t.bytes;
  $("#bucket").textContent = $("#bucket2").textContent = note;
  Object.values(charts).forEach((c) => c.update("none"));
}

function renderTable(res) {
  const body = $("#rows");
  body.replaceChildren();
  if (!res.packets.length) {
    const tr = el("tr"), td = el("td", res.total ? "No packets match these filters." : "No packets yet. Start a capture or upload a PCAP file.", "empty");
    td.colSpan = 7; tr.appendChild(td); body.appendChild(tr);
  }
  for (const p of res.packets) {
    const tr = el("tr");
    tr.dataset.no = p.no;
    if (p.no === selected) tr.className = "sel";
    tr.append(el("td", p.no), el("td", p.time), el("td", p.src || "-"), el("td", p.dst || "-"));
    const proto = el("td"); proto.appendChild(el("span", p.proto, "badge " + p.proto)); tr.appendChild(proto);
    tr.append(el("td", p.sport === null ? "-" : p.sport + " > " + p.dport), el("td", p.size + " B"));
    tr.addEventListener("click", () => selectPacket(p.no));
    body.appendChild(tr);
  }
  $("#count").textContent = "Showing " + res.packets.length.toLocaleString() + " of " + res.matched.toLocaleString() + " matching (" + res.total.toLocaleString() + " total)";
}

function renderStatus(s) {
  capturing = s.capturing;
  const pill = $("#status");
  pill.textContent = s.capturing ? "Capturing live" : (s.source === "idle" ? "Idle" : s.source === "live" ? "Stopped" : s.source);
  pill.classList.toggle("live", s.capturing);
  $("#btn-start").disabled = s.capturing;
  $("#btn-stop").disabled = !s.capturing;
  $("#file").disabled = s.capturing;
  $("#upload-label").classList.toggle("disabled", s.capturing);
}

async function refresh() {
  try {
    const q = filterParams(); q.set("limit", 500);
    const [status, stats, pk] = await Promise.all([api("/api/status"), api("/api/stats"), api("/api/packets?" + q)]);
    renderStatus(status); renderStats(stats); renderTable(pk);
    $("#export").href = "/api/export.csv?" + filterParams();
  } catch (e) { message(e.message); }
}

async function selectPacket(no) {
  selected = no;
  document.querySelectorAll("#rows tr").forEach((tr) => tr.classList.toggle("sel", Number(tr.dataset.no) === no));
  const box = $("#detail");
  try {
    const p = await api("/api/packets/" + no);
    box.replaceChildren(el("h2", "Packet #" + p.no), el("p", p.time + " | " + p.size + " bytes | " + p.proto + (p.info ? " | " + p.info : ""), "sub"));
    for (const layer of p.details.layers) {
      box.appendChild(el("h3", layer.name));
      const dl = el("dl");
      for (const [k, v] of layer.fields) dl.append(el("dt", k), el("dd", v));
      box.appendChild(dl);
    }
    box.append(el("h3", "Raw bytes"), el("pre", p.details.hex));
  } catch (e) { box.replaceChildren(el("p", e.message, "empty")); }
}

async function action(fn, okText) {
  try { const r = await fn(); message(okText ? okText(r) : "", true); }
  catch (e) { message(e.message); }
  refresh();
}

async function init() {
  initCharts();
  try {
    const {interfaces} = await api("/api/interfaces");
    for (const i of interfaces) { const o = el("option", i.name); o.value = i.value; $("#iface").appendChild(o); }
  } catch (e) { /* default interface only */ }
  $("#btn-start").onclick = () => action(() => post("/api/capture/start", {interface: $("#iface").value}));
  $("#btn-stop").onclick = () => action(() => post("/api/capture/stop"));
  $("#btn-clear").onclick = () => action(async () => { await post("/api/clear"); selected = null; $("#detail").replaceChildren(el("p", "Select a packet to see its layers and raw bytes.", "empty")); });
  $("#file").onchange = (ev) => {
    const f = ev.target.files[0];
    if (!f) return;
    const fd = new FormData(); fd.append("file", f);
    action(() => api("/api/upload", {method: "POST", body: fd}),
      (r) => "Loaded " + r.loaded.toLocaleString() + " packets" + (r.truncated ? " (file was larger than the packet limit, so only the first ones were kept)" : "") + ".");
    ev.target.value = "";
  };
  for (const id of ["#f-proto", "#f-src", "#f-dst"]) {
    $(id).addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(refresh, 250); });
  }
  refresh();
  setInterval(refresh, 1500);
}
init();
