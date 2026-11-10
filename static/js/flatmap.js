/* Flat 2D "normal map" view: same live data as the globe (nodes, attack arcs, global sightings, satellites, aircraft, quakes) on an equirectangular
   world map with a real-time day/night terminator. Activated by the "Flat map" view button (body.view-flat). */
(() => {
"use strict";
const V = window.VIRUS, S = V.S, DEG = Math.PI / 180;
const cv = document.getElementById("flat"), ctx = cv.getContext("2d");
const img = new Image(); img.src = "/static/textures/earth_atmos_2048.jpg";
const night = document.createElement("canvas"); night.width = 360; night.height = 180; const nctx = night.getContext("2d");
let lastNight = 0, box = { x: 0, y: 0, w: 1, h: 1 };
function size() { const dpr = Math.min(devicePixelRatio, 2); cv.width = innerWidth * dpr; cv.height = innerHeight * dpr; cv.style.width = innerWidth + "px"; cv.style.height = innerHeight + "px"; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = innerWidth, h = innerHeight, s = Math.max(w / 2, h);      // "cover" the viewport with a 2:1 map
  box = { w: s * 2, h: s, x: (w - s * 2) / 2, y: (h - s) / 2 }; }
addEventListener("resize", size); size();
const X = (lon) => box.x + ((lon + 180) / 360) * box.w, Y = (lat) => box.y + ((90 - lat) / 180) * box.h;

function drawNight() {
  const s = V.sunPos(), sl = s.lat * DEG, id = nctx.createImageData(360, 180);
  for (let j = 0; j < 180; j++) for (let i = 0; i < 360; i++) {
    const lat = (90 - j - 0.5) * DEG, dl = (i - 180 + 0.5 - s.lon) * DEG;
    const ndl = Math.sin(lat) * Math.sin(sl) + Math.cos(lat) * Math.cos(sl) * Math.cos(dl);
    const a = 1 - Math.min(1, Math.max(0, (ndl + 0.1) / 0.3)), k = (j * 360 + i) * 4;
    id.data[k] = 0; id.data[k + 1] = 4; id.data[k + 2] = 18; id.data[k + 3] = Math.round(a * 190);
  }
  nctx.putImageData(id, 0, 0);
}
const SEVC = { critical: "#ff3860", high: "#ffb020", medium: "#27d7ff", low: "#00ff9c", info: "#6f9a8c" };
function arc(a, b, col, alpha) {
  const x1 = X(a.lon), y1 = Y(a.lat), x2 = X(b.lon), y2 = Y(b.lat), mx = (x1 + x2) / 2, my = (y1 + y2) / 2 - Math.hypot(x2 - x1, y2 - y1) * 0.22;
  ctx.strokeStyle = col; ctx.globalAlpha = alpha; ctx.lineWidth = 1.4; ctx.beginPath(); ctx.moveTo(x1, y1); ctx.quadraticCurveTo(mx, my, x2, y2); ctx.stroke(); ctx.globalAlpha = 1;
}
function draw(now) {
  requestAnimationFrame(draw);
  if (V.layers.view !== "flat") return;
  const w = innerWidth, h = innerHeight; ctx.fillStyle = "#02060a"; ctx.fillRect(0, 0, w, h);
  if (img.complete && img.naturalWidth) ctx.drawImage(img, box.x, box.y, box.w, box.h);
  if (V.layers.daynight) { if (now - lastNight > 30000 || !lastNight) { drawNight(); lastNight = now; } ctx.imageSmoothingEnabled = true; ctx.drawImage(night, box.x, box.y, box.w, box.h);
    const s = V.sunPos(); ctx.fillStyle = "#ffd54a"; ctx.beginPath(); ctx.arc(X(s.lon), Y(s.lat), 6, 0, 7); ctx.fill(); }
  ctx.strokeStyle = "rgba(39,215,255,.12)"; ctx.lineWidth = 1; for (let lo = -150; lo <= 180; lo += 30) { ctx.beginPath(); ctx.moveTo(X(lo), box.y); ctx.lineTo(X(lo), box.y + box.h); ctx.stroke(); }
  for (let la = -60; la <= 60; la += 30) { ctx.beginPath(); ctx.moveTo(box.x, Y(la)); ctx.lineTo(box.x + box.w, Y(la)); ctx.stroke(); }
  if (V.layers.flows) (S.flows || []).forEach((f) => arc({ lat: f.from_xy[0], lon: f.from_xy[1] }, { lat: f.to_xy[0], lon: f.to_xy[1] }, f.layer === "L3" ? "#4d7cff" : "#c084fc", 0.55));
  if (V.layers.quakes) (V.data.quakes || []).forEach((q) => { const r = 2 + q.mag * 1.6, k = ((((now * 0.0008 + q.lon) % 1) + 1) % 1);
    ctx.strokeStyle = q.mag >= 5 ? "#ff8a30" : "#ffd54a"; ctx.globalAlpha = 1 - k; ctx.beginPath(); ctx.arc(X(q.lon), Y(q.lat), r + k * 10, 0, 7); ctx.stroke(); ctx.globalAlpha = 1;
    ctx.fillStyle = q.mag >= 5 ? "#ff8a30" : "#ffd54a"; ctx.beginPath(); ctx.arc(X(q.lon), Y(q.lat), r * 0.45, 0, 7); ctx.fill(); });
  if (V.layers.aircraft) { ctx.fillStyle = "rgba(220,240,255,.85)"; (V.data.planes || []).forEach((p) => { ctx.save(); ctx.translate(X(p.lon), Y(p.lat)); ctx.rotate(p.h * DEG); ctx.fillRect(-1, -3, 2, 6); ctx.fillRect(-3, -0.5, 6, 1.5); ctx.restore(); }); }
  if (V.layers.sats) (V.data.sats || []).forEach((s) => { const iss = /ZARYA|^ISS/i.test(s.n); ctx.fillStyle = iss ? "#27d7ff" : s.g === "gps-ops" ? "#ffd54a" : "rgba(157,180,255,.9)";
    ctx.beginPath(); ctx.arc(X(s.lon), Y(s.lat), iss ? 4 : 1.8, 0, 7); ctx.fill(); if (iss) { ctx.font = "11px monospace"; ctx.fillText("ISS", X(s.lon) + 7, Y(s.lat) + 4); } });
  if (V.layers.sightings) (S.gevents || []).slice(-300).forEach((e) => { if (!e.src || e.src.lat == null) return; const age = (Date.now() / 1000 - e.epoch);
    ctx.fillStyle = e.severity === "high" || e.severity === "critical" ? "#ffb020" : "#c084fc"; ctx.globalAlpha = Math.max(0.25, 1 - age / 900); ctx.beginPath(); ctx.arc(X(e.src.lon), Y(e.src.lat), 2.6, 0, 7); ctx.fill(); ctx.globalAlpha = 1; });
  const nodes = Object.values(S.nodes);
  (S.events || []).slice(-15).forEach((e) => { const n = S.nodes[e.target.id], age = Date.now() / 1000 - e.epoch; if (n && e.src && e.src.lat != null && age < 20) arc({ lat: e.src.lat, lon: e.src.lon }, n, SEVC[e.severity] || "#27d7ff", 1 - age / 20); });
  nodes.forEach((n) => { const c = V.COL[n.status] ? "#" + V.COL[n.status].toString(16).padStart(6, "0") : "#00ff9c", x = X(n.lon), y = Y(n.lat), k = (now * 0.0015) % 1;
    ctx.strokeStyle = c; ctx.globalAlpha = 1 - k; ctx.beginPath(); ctx.arc(x, y, 6 + k * 14, 0, 7); ctx.stroke(); ctx.globalAlpha = 1; ctx.fillStyle = c; ctx.fillRect(x - 5, y - 5, 10, 10);
    ctx.fillStyle = "#bff7ea"; ctx.font = "600 11px monospace"; ctx.fillText(n.name, x + 9, y + 4); });
}
requestAnimationFrame(draw);
})();
