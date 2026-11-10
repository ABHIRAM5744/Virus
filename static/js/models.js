/* 3D models + REAL-TIME world objects on the globe.
   - node models: procedural low-poly data-centre / server rack / honeypot, lit by the real sun direction, LEDs follow node status
   - satellites: real TLEs (Celestrak) propagated in the browser with SGP4 (satellite.js) -> true current position of the ISS, GPS, weather, Starlink sample
   - aircraft: real ADS-B (OpenSky), dead-reckoned between polls, instanced 3D airliner models
   - earthquakes: real USGS M2.5+ (24h) as pulsing beacons sized by magnitude
   Orbit altitude is visually compressed (otherwise GPS at 20,200 km would be outside the camera). */
(() => {
"use strict";
const V = window.VIRUS, T = V.THREE, R = V.R, esc = V.esc;
V.data = { sats: [], planes: [], quakes: [], iss: null };
const DEG = Math.PI / 180;

/* ------------------------------------------------------------ lights (the real sun) */
const amb = new T.AmbientLight(0x9bb2d6, 1.15), sunLight = new T.DirectionalLight(0xfff2dd, 1.25);
V.scene.add(amb, sunLight, sunLight.target);
V.hooks.push(() => {
  if (!V.sun) return;
  const d = V.ll(V.sun.lat, V.sun.lon, 1).applyQuaternion(V.globe.quaternion);
  sunLight.position.copy(d.multiplyScalar(40));
});

/* ------------------------------------------------------------ helpers */
const std = (c, o = {}) => new T.MeshStandardMaterial(Object.assign({ color: c, metalness: 0.55, roughness: 0.42 }, o));
const box = (w, h, d, mat, x = 0, y = 0, z = 0) => { const m = new T.Mesh(new T.BoxGeometry(w, h, d), mat); m.position.set(x, y, z); return m; };
const cyl = (rt, rb, h, mat, seg = 16) => new T.Mesh(new T.CylinderGeometry(rt, rb, h, seg), mat);
function merge(parts) {            // parts: [{geo, matrix}] -> one non-indexed BufferGeometry (for instancing)
  const pos = [], nor = [];
  parts.forEach(({ geo, matrix }) => {
    const g = geo.index ? geo.toNonIndexed() : geo.clone(); g.applyMatrix4(matrix);
    pos.push(...g.attributes.position.array); nor.push(...g.attributes.normal.array);
  });
  const g = new T.BufferGeometry();
  g.setAttribute("position", new T.Float32BufferAttribute(pos, 3)); g.setAttribute("normal", new T.Float32BufferAttribute(nor, 3)); return g;
}
const M = (x = 0, y = 0, z = 0, rx = 0, ry = 0, rz = 0) => new T.Matrix4().compose(new T.Vector3(x, y, z), new T.Quaternion().setFromEuler(new T.Euler(rx, ry, rz)), new T.Vector3(1, 1, 1));

/* ------------------------------------------------------------ node models (Y = up, base at y=0) */
const hull = std(0x3a5568, { metalness: 0.6, roughness: 0.4 }), trim = std(0x8aa5b8, { metalness: 0.8, roughness: 0.3 });
function led(color) { return new T.MeshBasicMaterial({ color }); }
function nodeModel(n, p, up) {
  const g = new T.Group(), leds = [];
  const L = (w, h, d, x, y, z) => { const m = box(w, h, d, led(V.COL[n.status] || V.COL.ok), x, y, z); leds.push(m); g.add(m); return m; };
  if (n.kind === "honeypot") {                      // glowing honey-jar: cage + core
    const cage = new T.Mesh(new T.IcosahedronGeometry(0.17, 1), new T.MeshBasicMaterial({ color: 0xffb020, wireframe: true, transparent: true, opacity: 0.9 }));
    const core = new T.Mesh(new T.SphereGeometry(0.075, 16, 16), led(0xffcf5a)); cage.position.y = core.position.y = 0.22;
    g.add(cage, core, cyl(0.12, 0.16, 0.06, hull)); leds.push(core);
    g.userData.spin = cage;
  } else if (n.kind === "asset") {                  // server rack + dish
    g.add(box(0.2, 0.34, 0.2, hull, 0, 0.17, 0));
    for (let i = 0; i < 4; i++) { g.add(box(0.205, 0.008, 0.205, trim, 0, 0.06 + i * 0.075, 0)); L(0.03, 0.02, 0.01, 0.06, 0.1 + i * 0.075, 0.103); }
    const mast = cyl(0.006, 0.006, 0.2, trim, 6); mast.position.set(0.07, 0.44, 0); g.add(mast);
    const dish = new T.Mesh(new T.SphereGeometry(0.06, 16, 8, 0, Math.PI * 2, 0, Math.PI / 2.4), std(0xcfd8de, { side: T.DoubleSide, metalness: 0.2 }));
    dish.position.set(0.07, 0.54, 0); dish.rotation.x = Math.PI / 3; g.add(dish);
  } else {                                          // host / HQ: data-centre block with towers
    g.add(box(0.46, 0.14, 0.3, hull, 0, 0.07, 0));
    g.add(box(0.18, 0.3, 0.18, hull, -0.12, 0.29, 0), box(0.14, 0.22, 0.14, hull, 0.13, 0.25, 0.02));
    [[-0.12, 0.45], [0.13, 0.37]].forEach(([x, y]) => { const m = cyl(0.005, 0.005, 0.12, trim, 6); m.position.set(x, y + 0.06, 0); g.add(m); L(0.02, 0.02, 0.02, x, y + 0.13, 0); });
    for (let i = 0; i < 5; i++) L(0.012, 0.012, 0.01, -0.12 + (i - 2) * 0.03, 0.12 + (i % 2) * 0.07, 0.092);
    L(0.4, 0.012, 0.012, 0, 0.145, 0.15);
  }
  g.position.copy(p); g.quaternion.setFromUnitVectors(new T.Vector3(0, 1, 0), up);
  g.scale.setScalar(1.9);
  g.userData.paint = (c) => leds.forEach((m) => m.material.color.setHex(n.kind === "honeypot" ? 0xffb020 : c));
  g.userData.paint(V.COL[n.status] || V.COL.ok);
  return g;
}
V.nodeModel = nodeModel;
V.hooks.push((now) => { for (const id in V.nodeObjs) { const m = V.nodeObjs[id].model; if (m && m.userData.spin) m.userData.spin.rotation.y = now * 0.0006; } });

/* ------------------------------------------------------------ satellites (real TLE -> SGP4 in the browser) */
const satGroup = new T.Group(); V.globe.add(satGroup);
const SATCOL = { stations: 0x27d7ff, "gps-ops": 0xffd54a, weather: 0x62e88a, science: 0xffffff, starlink: 0x9db4ff };
let sats = [], issTrack = null;
function altR(hKm) { return R + 0.26 + Math.min(2.3, (hKm / 6371) * R * 0.45); }
function issModel(scale = 1) {
  const g = new T.Group(), panel = std(0x1b3a8a, { metalness: 0.3, roughness: 0.5, emissive: 0x0a1a44 });
  g.add(box(0.5, 0.02, 0.02, trim));
  [-0.19, -0.1, 0.1, 0.19].forEach((x) => g.add(box(0.07, 0.003, 0.2, panel, x, 0, 0), box(0.07, 0.003, 0.2, panel, x, 0, 0)));
  g.add(cyl(0.025, 0.025, 0.2, std(0xdadada), 10)); g.children[g.children.length - 1].rotation.z = Math.PI / 2; g.children[g.children.length - 1].position.z = 0.0;
  g.add(box(0.03, 0.03, 0.12, std(0xe6e6e6), 0, 0, 0)); g.scale.setScalar(scale * 0.55); return g;
}
function smallSat(col) {
  const g = new T.Group(); g.add(box(0.035, 0.035, 0.035, std(0xcfcfcf)));
  g.add(box(0.12, 0.002, 0.04, std(col, { emissive: col, emissiveIntensity: 0.35, metalness: 0.2 })));
  return g;
}
function label(text, col = "#bff7ea") {
  const c = document.createElement("canvas"); c.width = 256; c.height = 48; const x = c.getContext("2d");
  x.font = "600 22px ui-monospace,Menlo,monospace"; x.fillStyle = col; x.textAlign = "center"; x.fillText(text, 128, 30);
  const s = new T.Sprite(new T.SpriteMaterial({ map: new T.CanvasTexture(c), transparent: true, depthWrite: false })); s.scale.set(1.4, 0.26, 1); return s;
}
function buildSats(list) {
  while (satGroup.children.length) satGroup.remove(satGroup.children[0]);
  sats = [];
  if (!window.satellite) return;
  list.forEach((s) => {
    let rec; try { rec = satellite.twoline2satrec(s.l1, s.l2); } catch (e) { return; }
    const isISS = /ISS \(ZARYA\)|^ISS$/i.test(s.n), big = s.g === "stations";
    const obj = isISS ? issModel(1.0) : big ? issModel(0.5) : smallSat(SATCOL[s.g] || 0xffffff); if (!isISS && !big) obj.scale.setScalar(0.7);
    const o = { n: s.n, g: s.g, rec, obj, iss: isISS, lbl: null };
    if (isISS || (big && /TIANHE|CSS|TIANGONG/i.test(s.n))) { o.lbl = label(isISS ? "ISS" : "Tiangong", "#27d7ff"); satGroup.add(o.lbl); }
    satGroup.add(obj); sats.push(o);
  });
}
const up0 = new T.Vector3(0, 1, 0);
function stepSats(now) {
  const d = new Date(), gm = satellite.gstime(d); V.data.sats = [];
  for (const s of sats) {
    const pv = satellite.propagate(s.rec, d); if (!pv.position) { s.obj.visible = false; continue; }
    const geo = satellite.eciToGeodetic(pv.position, gm), lat = geo.latitude / DEG, lon = geo.longitude / DEG, h = geo.height;
    const p = V.ll(lat, lon, altR(h)); s.obj.position.copy(p); s.obj.visible = true;
    s.obj.quaternion.setFromUnitVectors(up0, p.clone().normalize());
    if (s.lbl) { s.lbl.position.copy(p.clone().multiplyScalar(1.07)); }
    const v = pv.velocity ? Math.hypot(pv.velocity.x, pv.velocity.y, pv.velocity.z) : 0;
    V.data.sats.push({ n: s.n, g: s.g, lat, lon, h, v });
    if (s.iss) V.data.iss = { lat, lon, h, v };
  }
}
function drawIssTrack() {
  if (issTrack) { satGroup.remove(issTrack); issTrack.geometry.dispose(); issTrack = null; }
  const s = sats.find((x) => x.iss); if (!s) return;
  const pts = [], t0 = Date.now();
  for (let m = -10; m <= 95; m += 1.5) {
    const d = new Date(t0 + m * 60000), pv = satellite.propagate(s.rec, d); if (!pv.position) continue;
    const g = satellite.eciToGeodetic(pv.position, satellite.gstime(d)); pts.push(V.ll(g.latitude / DEG, g.longitude / DEG, altR(g.height)));
  }
  issTrack = new T.Line(new T.BufferGeometry().setFromPoints(pts), new T.LineBasicMaterial({ color: 0x27d7ff, transparent: true, opacity: 0.55 }));
  satGroup.add(issTrack);
}
async function loadSats() {
  try {
    const j = await (await fetch("/api/live/satellites")).json(); if (j.error) throw new Error(j.error);
    buildSats(j.sats || []); drawIssTrack(); status("sats", true, `${sats.length} satellites · ${j.source}${(j.errors || []).length ? " (" + j.errors[0] + ")" : ""}`);
  } catch (e) { status("sats", false, String(e.message || e)); }
}

/* ------------------------------------------------------------ aircraft (OpenSky ADS-B, instanced airliner) */
const planeGeo = merge([
  { geo: new T.CylinderGeometry(0.012, 0.012, 0.15, 8), matrix: M(0, 0, 0, Math.PI / 2, 0, 0) },
  { geo: new T.ConeGeometry(0.012, 0.04, 8), matrix: M(0, 0, 0.095, Math.PI / 2, 0, 0) },
  { geo: new T.BoxGeometry(0.17, 0.004, 0.04), matrix: M(0, 0, -0.005) },
  { geo: new T.BoxGeometry(0.06, 0.004, 0.025), matrix: M(0, 0, -0.065) },
  { geo: new T.BoxGeometry(0.004, 0.03, 0.025), matrix: M(0, 0.014, -0.068) },
]);
const PS = new T.Vector3(0.55, 0.55, 0.55), MAXP = 1600, planeMesh = new T.InstancedMesh(planeGeo, std(0xe8f4ff, { metalness: 0.3, roughness: 0.5, emissive: 0x335577, emissiveIntensity: 0.6 }), MAXP);
planeMesh.count = 0; planeMesh.frustumCulled = false; V.globe.add(planeMesh);
let planes = [], planeT = 0;
const _m = new T.Matrix4(), _x = new T.Vector3(), _f = new T.Vector3(), _u = new T.Vector3(), _n = new T.Vector3(), _e = new T.Vector3(), _p = new T.Vector3();
function stepPlanes(dt) {
  planeT += dt; let n = 0; V.data.planes = [];
  for (const a of planes) {
    const hd = a.hdg * DEG, v = a.vel * Math.min(planeT, 120);          // dead-reckon up to 2 min between polls
    const lat = a.lat + (v * Math.cos(hd)) / 111320, lon = a.lon + (v * Math.sin(hd)) / (111320 * Math.max(0.2, Math.cos(a.lat * DEG)));
    _p.copy(V.ll(lat, lon, R * 1.004 + Math.min(0.06, a.alt / 12000 * 0.05))); _u.copy(_p).normalize();
    _n.copy(V.ll(lat + 0.02, lon, 1)).sub(V.ll(lat, lon, 1)).normalize(); _e.copy(V.ll(lat, lon + 0.02, 1)).sub(V.ll(lat, lon, 1)).normalize();
    _f.copy(_n).multiplyScalar(Math.cos(hd)).addScaledVector(_e, Math.sin(hd)).normalize(); _x.crossVectors(_u, _f).normalize();
    _m.makeBasis(_x, _u, _f).scale(PS).setPosition(_p); planeMesh.setMatrixAt(n++, _m);
    if (n % 3 === 0) V.data.planes.push({ lat, lon, h: a.hdg });
    if (n >= MAXP) break;
  }
  planeMesh.count = n; planeMesh.instanceMatrix.needsUpdate = true; V.data.planeCount = n;
}
async function loadPlanes() {
  if (!V.layers.aircraft) return;
  try {
    const j = await (await fetch("/api/live/aircraft")).json(); if (j.error) throw new Error(j.error);
    planes = (j.planes || []).map((s) => ({ lat: s[2], lon: s[3], alt: s[4], hdg: s[5], vel: s[6] })); planeT = 0;
    status("aircraft", true, `${planes.length} aircraft · ${j.source}`);
  } catch (e) { status("aircraft", false, String(e.message || e)); }
}

/* ------------------------------------------------------------ earthquakes (USGS) */
const qGroup = new T.Group(); V.globe.add(qGroup); let quakeObjs = [];
const qcol = (m) => (m >= 6 ? 0xff3860 : m >= 5 ? 0xff8a30 : m >= 4 ? 0xffd54a : 0x62e88a);
async function loadQuakes() {
  try {
    const j = await (await fetch("/api/live/quakes")).json(); if (j.error) throw new Error(j.error);
    while (qGroup.children.length) { const c = qGroup.children[0]; qGroup.remove(c); }
    quakeObjs = []; const rows = (j.quakes || []).filter((q) => q.mag != null).sort((a, b) => b.mag - a.mag).slice(0, 220); V.data.quakes = rows;
    rows.forEach((q) => {
      const p = V.ll(q.lat, q.lon, R * 1.003), up = p.clone().normalize(), col = qcol(q.mag), h = 0.08 + q.mag * 0.07;
      const beam = new T.Mesh(new T.CylinderGeometry(0.012, 0.012, h, 6), new T.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.9 }));
      beam.position.copy(p.clone().addScaledVector(up, h / 2)); beam.quaternion.setFromUnitVectors(up0, up);
      const ring = new T.Mesh(new T.RingGeometry(0.05, 0.065, 28), new T.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.8, side: T.DoubleSide, depthWrite: false }));
      ring.position.copy(p); ring.quaternion.setFromUnitVectors(new T.Vector3(0, 0, 1), up); qGroup.add(beam, ring);
      quakeObjs.push({ ring, mag: q.mag, fresh: Date.now() - q.time < 3600e3, off: Math.random() * 3 });
    });
    status("quakes", true, `${rows.length} quakes M2.5+ · ${j.source}`);
  } catch (e) { status("quakes", false, String(e.message || e)); }
}

/* ------------------------------------------------------------ status line + layer visibility */
const st = {};
function status(k, ok, msg) { st[k] = { ok, msg }; renderStatus(); }
function renderStatus() {
  const e = document.getElementById("live-status"); if (!e) return;
  const rows = [["sats", "Satellites"], ["aircraft", "Aircraft"], ["quakes", "Quakes"]].filter(([k]) => st[k]);
  const iss = V.data.iss ? `<div class="ok">ISS now: ${V.data.iss.lat.toFixed(1)}°, ${V.data.iss.lon.toFixed(1)}° · ${Math.round(V.data.iss.h)} km · ${V.data.iss.v.toFixed(2)} km/s</div>` : "";
  const q = V.data.quakes[0] ? `<div>Strongest 24h: M${V.data.quakes[0].mag} ${esc(V.data.quakes[0].place || "")}</div>` : "";
  e.innerHTML = iss + q + rows.map(([k, n]) => `<div class="${st[k].ok ? "ok" : "bad"}" title="${esc(st[k].msg)}">${n}: ${esc(st[k].ok ? st[k].msg : "unavailable - " + st[k].msg)}</div>`).join("");
}
function applyLayers() {
  satGroup.visible = V.layers.sats && V.layers.view !== "flat"; planeMesh.visible = V.layers.aircraft && V.layers.view !== "flat"; qGroup.visible = V.layers.quakes && V.layers.view !== "flat";
  amb.visible = sunLight.visible = V.layers.view !== "flat";
  document.querySelectorAll("[data-layer]").forEach((b) => b.classList.toggle("on", !!V.layers[b.dataset.layer]));
}
V.onLayer((k, v) => { applyLayers(); if (k === "aircraft" && v) loadPlanes(); if (k === "sats" && v && !sats.length) loadSats(); });
document.addEventListener("click", (e) => { const b = e.target.closest("[data-layer]"); if (b) V.setLayer(b.dataset.layer, !V.layers[b.dataset.layer]); });

let lastSat = 0, lastTxt = 0;
V.hooks.push((now, dt) => {
  if (window.satellite && sats.length && now - lastSat > 250) { lastSat = now; stepSats(now); }
  if (planes.length && V.layers.aircraft) stepPlanes(dt || 0.016);
  for (const q of quakeObjs) { const k = ((now * 0.001 * (q.fresh ? 1.4 : 0.5) + q.off) % 1); q.ring.scale.setScalar(1 + k * (1 + q.mag * 0.5)); q.ring.material.opacity = 0.85 * (1 - k); }
  if (now - lastTxt > 1000) { lastTxt = now; renderStatus(); }
});
applyLayers();
loadSats(); loadQuakes(); loadPlanes();
setInterval(loadQuakes, 180000); setInterval(loadPlanes, 45000); setInterval(loadSats, 6 * 3600e3); setInterval(() => sats.length && drawIssTrack(), 600000);
})();
