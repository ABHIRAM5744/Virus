/* VIRUS Voice SOC - front end: Three.js globe + voice pipeline + SOC panels */
(() => {
"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const R = 5;
const COL = { ok: 0x00ff9c, warn: 0xffb020, compromised: 0xff3860, isolated: 0x6b8cff };
const SEVCOL = { critical: 0xff3860, high: 0xffb020, medium: 0x27d7ff, low: 0x00ff9c, info: 0x6f9a8c };
const LANGS = [["auto", "Auto-detect"], ["en-IN", "English"], ["hi-IN", "हिन्दी Hindi"], ["hi-en", "Hinglish"], ["ta-IN", "தமிழ் Tamil"],
  ["te-IN", "తెలుగు Telugu"], ["kn-IN", "ಕನ್ನಡ Kannada"], ["ml-IN", "മലയാളം Malayalam"], ["mr-IN", "मराठी Marathi"],
  ["bn-IN", "বাংলা Bengali"], ["gu-IN", "ગુજરાતી Gujarati"], ["pa-IN", "ਪੰਜਾਬੀ Punjabi"]];
const STATUS_LABEL = { ok: "OK", warn: "WARNING", compromised: "CRITICAL", isolated: "CONTAINED" };
const SPEECH_LANG = (l) => ({ "hi-en": "hi-IN", auto: "en-IN" }[l] || l);

/* ------------------------------------------------------------------ state */
const S = { gevents: [], flows: [], flowsMeta: {}, scope: "all", nodes: {}, events: [], stats: null, pending: null, selNode: null, selEvent: null, filter: "all",
  busy: false, level: 0, lastNarrate: 0, spokeAt: 0 };

/* ------------------------------------------------------------------ three.js scene */
const canvas = $("#scene");
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
const scene = new THREE.Scene();
scene.background = new THREE.Color(0x02060a);
scene.fog = new THREE.FogExp2(0x02060a, 0.012);
const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 400);
camera.position.set(0, 0, 19);
let camZ = 19;

const globe = new THREE.Group();
scene.add(globe);

const ll = (lat, lon, r = R) => {
  const phi = (90 - lat) * Math.PI / 180, th = (lon + 180) * Math.PI / 180;
  return new THREE.Vector3(-r * Math.sin(phi) * Math.cos(th), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(th));
};

// depth-only occluder so far-side dots/arcs are hidden but the inner core stays visible
const occ = new THREE.Mesh(new THREE.SphereGeometry(R * 0.995, 48, 48), new THREE.MeshBasicMaterial({ colorWrite: false }));
occ.renderOrder = 1; globe.add(occ);

// tactical-mode surface (dots + graticule); hidden in the realistic view
const tactical = new THREE.Group(); globe.add(tactical);
// dotted surface
{
  const N = 3600, pos = new Float32Array(N * 3), g = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), t = g * i;
    pos.set([Math.cos(t) * r * R, y * R, Math.sin(t) * r * R], i * 3);
  }
  const geo = new THREE.BufferGeometry(); geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  tactical.add(new THREE.Points(geo, new THREE.PointsMaterial({ color: 0x1fb8a0, size: 0.045, transparent: true, opacity: 0.85 })));
}
// graticule
{
  const m = new THREE.LineBasicMaterial({ color: 0x0f5a66, transparent: true, opacity: 0.45 });
  for (let lat = -60; lat <= 60; lat += 30) {
    const pts = []; for (let lon = 0; lon <= 360; lon += 6) pts.push(ll(lat, lon - 180, R * 1.001));
    tactical.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), m));
  }
  for (let lon = -180; lon < 180; lon += 30) {
    const pts = []; for (let lat = -90; lat <= 90; lat += 6) pts.push(ll(lat, lon, R * 1.001));
    tactical.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), m));
  }
}
// atmosphere
const atmo = new THREE.Mesh(new THREE.SphereGeometry(R * 1.14, 64, 64), new THREE.ShaderMaterial({
  uniforms: { col: { value: new THREE.Color(0.1, 0.85, 1.0) } },
  vertexShader: "varying vec3 vN;void main(){vN=normalize(normalMatrix*normal);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}",
  fragmentShader: "uniform vec3 col;varying vec3 vN;void main(){float i=pow(max(.0,.74-dot(vN,vec3(0.,0.,1.))),3.);gl_FragColor=vec4(col,1.)*i;}",
  blending: THREE.AdditiveBlending, side: THREE.BackSide, transparent: true, depthWrite: false }));
scene.add(atmo);

// AI core (pulses with voice level)
const core = new THREE.Group(); scene.add(core);
const coreWire = new THREE.Mesh(new THREE.IcosahedronGeometry(1.7, 2), new THREE.MeshBasicMaterial({ color: 0x27d7ff, wireframe: true, transparent: true, opacity: 0.55 }));
const coreSolid = new THREE.Mesh(new THREE.SphereGeometry(0.9, 24, 24), new THREE.MeshBasicMaterial({ color: 0x00ff9c, transparent: true, opacity: 0.35 }));
coreWire.renderOrder = 0; coreSolid.renderOrder = 0; core.add(coreWire, coreSolid);

// starfield
{
  const N = 1400, p = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) { const v = new THREE.Vector3().randomDirection().multiplyScalar(60 + Math.random() * 120); p.set([v.x, v.y, v.z], i * 3); }
  const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(p, 3));
  scene.add(new THREE.Points(g, new THREE.PointsMaterial({ color: 0x7fe9ff, size: 0.35, transparent: true, opacity: 0.55, sizeAttenuation: true })));
}

/* nodes */
const nodeObjs = {};
function labelSprite(text) {
  const c = document.createElement("canvas"); c.width = 256; c.height = 64;
  const x = c.getContext("2d"); x.font = "600 26px ui-monospace,Menlo,monospace"; x.fillStyle = "#bff7ea"; x.textAlign = "center"; x.fillText(text, 128, 40);
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(c), transparent: true, depthWrite: false }));
  s.scale.set(1.7, 0.42, 1); return s;
}
function buildNode(n) {
  const p = ll(n.lat, n.lon, R * 1.005), up = p.clone().normalize();
  const grp = new THREE.Group();
  const dot = new THREE.Mesh(new THREE.SphereGeometry(0.12, 16, 16), new THREE.MeshBasicMaterial({ color: COL[n.status] || COL.ok }));
  dot.position.copy(p); dot.userData.nodeId = n.id;
  const ring = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.235, 40), new THREE.MeshBasicMaterial({ color: COL.ok, transparent: true, opacity: 0.8, side: THREE.DoubleSide, depthWrite: false }));
  ring.position.copy(p); ring.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), up);
  const beam = new THREE.Line(new THREE.BufferGeometry().setFromPoints([p, p.clone().multiplyScalar(1.12)]), new THREE.LineBasicMaterial({ color: COL.ok, transparent: true, opacity: 0.8 }));
  const label = labelSprite(n.name); label.position.copy(p.clone().multiplyScalar(1.2));
  grp.add(dot, ring, beam, label); globe.add(grp);
  const model = window.VIRUS && window.VIRUS.nodeModel ? window.VIRUS.nodeModel(n, p, up) : null;
  if (model) { grp.add(model); dot.material.transparent = true; dot.material.opacity = 0; dot.scale.setScalar(1.8); }
  nodeObjs[n.id] = { grp, dot, ring, beam, label, pos: p, up, data: n, model };
}
function paintNode(n) {
  const o = nodeObjs[n.id]; if (!o) return; o.data = n;
  const c = COL[n.status] || COL.ok;
  o.dot.material.color.setHex(c); o.ring.material.color.setHex(c); o.beam.material.color.setHex(c);
  if (o.model && o.model.userData.paint) o.model.userData.paint(c);
}

/* attack arcs + shockwaves */
const arcs = [], waves = [];
function addArc(ev) {
  const o = nodeObjs[ev.target.id], src = ev.src; if (!o || !src || src.lat == null) return false;
  const far = ll(src.lat, src.lon, R * 1.005), out = ev.direction === "out";
  const a = out ? o.pos : far, b = out ? far : o.pos;
  const mid = a.clone().add(b).multiplyScalar(0.5).setLength(R + a.distanceTo(b) * 0.42 + 0.3);
  const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
  const col = SEVCOL[ev.severity] || SEVCOL.medium;
  const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(56)); geo.setDrawRange(0, 0);
  const line = new THREE.Line(geo, new THREE.LineBasicMaterial({ color: col, transparent: true, opacity: 0.95 }));
  const head = new THREE.Mesh(new THREE.SphereGeometry(0.09, 10, 10), new THREE.MeshBasicMaterial({ color: 0xffffff }));
  const origin = new THREE.Mesh(new THREE.SphereGeometry(0.1, 10, 10), new THREE.MeshBasicMaterial({ color: col, transparent: true }));
  origin.position.copy(far); globe.add(line, head, origin);
  arcs.push({ line, head, origin, curve, t: 0, done: 0, col, target: out ? null : ev.target.id, sev: ev.severity });
  return true;
}
function addWave(id, col, big) {
  const o = nodeObjs[id]; if (!o) return;
  const m = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.26, 48), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthWrite: false }));
  m.position.copy(o.pos); m.quaternion.copy(o.ring.quaternion); globe.add(m);
  waves.push({ m, t: 0, big });
}

/* global layer: attacks seen elsewhere on the internet. Drawn where they ORIGINATE (never as arcs to our node). */
const spots = [], gpulses = [], flowObjs = [];
const gGroup = new THREE.Group(), fGroup = new THREE.Group(); globe.add(gGroup, fGroup);
const GCOL = { critical: 0xff3860, high: 0xffb020, medium: 0xc084fc, low: 0x6f9a8c };
function addSighting(e) {
  const s = e.src; if (!s || s.lat == null) return;
  const p = ll(s.lat, s.lon, R * 1.004), col = GCOL[e.severity] || GCOL.medium;
  const dot = new THREE.Mesh(new THREE.SphereGeometry(0.045, 8, 8), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.95 }));
  dot.position.copy(p); gGroup.add(dot); spots.push({ dot, born: performance.now() });
  const m = new THREE.Mesh(new THREE.RingGeometry(0.06, 0.085, 28), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthWrite: false }));
  m.position.copy(p); m.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), p.clone().normalize()); gGroup.add(m); gpulses.push({ m, t: 0 });
  while (spots.length > 500) { const o = spots.shift(); gGroup.remove(o.dot); o.dot.geometry.dispose(); }
}
function setFlows(flows) {
  while (flowObjs.length) { const o = flowObjs.pop(); fGroup.remove(o.line, o.head); o.line.geometry.dispose(); }
  const mx = Math.max(1, ...flows.map((f) => f.pct));
  flows.forEach((f) => {
    const a = ll(f.from_xy[0], f.from_xy[1], R * 1.005), b = ll(f.to_xy[0], f.to_xy[1], R * 1.005);
    if (a.distanceTo(b) < 0.05) return;
    const mid = a.clone().add(b).multiplyScalar(0.5).setLength(R + a.distanceTo(b) * 0.38 + 0.2), curve = new THREE.QuadraticBezierCurve3(a, mid, b);
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(48)), new THREE.LineBasicMaterial({ color: f.layer === "L3" ? 0x4d7cff : 0xc084fc, transparent: true, opacity: 0.25 + 0.5 * f.pct / mx }));
    const head = new THREE.Mesh(new THREE.SphereGeometry(0.05, 8, 8), new THREE.MeshBasicMaterial({ color: 0xffffff }));
    fGroup.add(line, head); flowObjs.push({ line, head, curve, off: Math.random() });
  });
}

/* interaction */
const rayc = new THREE.Raycaster(), mouse = new THREE.Vector2();
let drag = null, lastInput = 0, focusQ = null;
canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, moved: 0 }; focusQ = null; canvas.setPointerCapture(e.pointerId); });
canvas.addEventListener("pointermove", (e) => {
  if (!drag) return;
  const dx = e.clientX - drag.x, dy = e.clientY - drag.y; drag.x = e.clientX; drag.y = e.clientY; drag.moved += Math.abs(dx) + Math.abs(dy);
  globe.rotateOnWorldAxis(new THREE.Vector3(0, 1, 0), dx * 0.005); globe.rotateOnWorldAxis(new THREE.Vector3(1, 0, 0), dy * 0.005); lastInput = performance.now();
});
canvas.addEventListener("pointerup", (e) => {
  const was = drag; drag = null; lastInput = performance.now();
  if (!was || was.moved > 6) return;
  const r = canvas.getBoundingClientRect(); mouse.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
  rayc.setFromCamera(mouse, camera);
  const hit = rayc.intersectObjects(Object.values(nodeObjs).map((o) => o.dot), false)[0];
  if (hit) selectNode(hit.object.userData.nodeId, false);
});
canvas.addEventListener("wheel", (e) => { e.preventDefault(); camZ = Math.min(30, Math.max(11, camZ + e.deltaY * 0.01)); }, { passive: false });
function resize() { const w = innerWidth, h = innerHeight; renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix(); }
addEventListener("resize", resize); resize();

function focusNode(id) {
  const o = nodeObjs[id]; if (!o) return;
  focusQ = new THREE.Quaternion().setFromUnitVectors(o.up.clone(), new THREE.Vector3(0, 0, 1)); selectNode(id, true);
}

const hooks = [];
function focusLL(lat, lon) { focusQ = new THREE.Quaternion().setFromUnitVectors(ll(lat, lon, 1).normalize(), new THREE.Vector3(0, 0, 1)); }

window.VIRUS = { gGroup, fGroup, THREE, scene, globe, camera, renderer, ll, R, S, atmo, tactical, core, occ, starsOf: () => scene, hooks, focusLL, esc, $, addSighting, nodeObjs,
  setCamZ: (z) => { camZ = z; }, api: (...a) => api(...a), COL, SEVCOL };

/* ------------------------------------------------------------------ render loop */
const ring = $("#ring"), rctx = ring.getContext("2d");
let t0 = performance.now(), smooth = 0;
function drawRing(t) {
  const w = ring.width, c = w / 2; rctx.clearRect(0, 0, w, w);
  const n = 56, base = 54, col = recState ? "255,56,96" : S.busy ? "255,176,32" : "0,255,156";
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2 - Math.PI / 2, wob = 0.5 + 0.5 * Math.sin(t * 0.004 + i * 0.7);
    const len = 4 + (S.level * 46 + 3) * (0.55 + 0.45 * wob);
    rctx.strokeStyle = `rgba(${col},${0.35 + S.level})`; rctx.lineWidth = 2.2; rctx.beginPath();
    rctx.moveTo(c + Math.cos(a) * base, c + Math.sin(a) * base); rctx.lineTo(c + Math.cos(a) * (base + len), c + Math.sin(a) * (base + len)); rctx.stroke();
  }
}
function frame(now) {
  requestAnimationFrame(frame);
  const dt = Math.min(0.05, (now - t0) / 1000); t0 = now;
  smooth += (S.level - smooth) * 0.25;
  // camera / globe motion
  camera.position.z += (camZ - camera.position.z) * 0.08;
  if (focusQ) { globe.quaternion.slerp(focusQ, 0.07); if (globe.quaternion.angleTo(focusQ) < 0.01) focusQ = null; }
  else if ($("#t-rot").checked && !drag && now - lastInput > 3500) globe.rotateOnWorldAxis(new THREE.Vector3(0, 1, 0), 0.0016);
  // core
  const risk = (S.stats?.risk ?? 10) / 100, pulse = 1 + smooth * 1.2 + Math.sin(now * 0.002) * 0.04;
  core.scale.setScalar(pulse); coreWire.rotation.y += dt * (0.3 + smooth * 3); coreWire.rotation.x += dt * 0.15;
  const cc = new THREE.Color().setHSL(0.42 - risk * 0.42, 1, 0.5);
  coreSolid.material.color.copy(cc); coreSolid.material.opacity = 0.25 + smooth * 0.5; coreWire.material.opacity = 0.4 + smooth * 0.5;
  // nodes
  for (const id in nodeObjs) {
    const o = nodeObjs[id], st = o.data.status, sp = st === "compromised" ? 6 : st === "warn" ? 3 : 1.4;
    const k = (now * 0.001 * sp) % 1; o.ring.scale.setScalar(1 + k * (st === "compromised" ? 1.8 : 0.9)); o.ring.material.opacity = 0.9 * (1 - k);
    o.dot.scale.setScalar(S.selNode === id ? 1.8 : 1);
  }
  // arcs
  for (let i = arcs.length - 1; i >= 0; i--) {
    const a = arcs[i];
    if (a.t < 1) {
      a.t = Math.min(1, a.t + dt * 0.55); a.head.position.copy(a.curve.getPoint(a.t)); a.line.geometry.setDrawRange(0, Math.max(2, Math.floor(a.t * 57)));
      if (a.t >= 1) { if (a.target) addWave(a.target, a.col, a.sev === "critical"); a.head.visible = false; }
    } else {
      a.done += dt; const f = Math.max(0, 1 - a.done / 2.2); a.line.material.opacity = f; a.origin.material.opacity = f;
      if (a.done > 2.2) { globe.remove(a.line, a.head, a.origin); a.line.geometry.dispose(); arcs.splice(i, 1); }
    }
  }
  for (let i = waves.length - 1; i >= 0; i--) {
    const w = waves[i]; w.t += dt; const k = w.t / (w.big ? 1.6 : 1.1);
    w.m.scale.setScalar(1 + k * (w.big ? 9 : 5)); w.m.material.opacity = Math.max(0, 0.9 * (1 - k));
    if (k >= 1) { globe.remove(w.m); w.m.geometry.dispose(); waves.splice(i, 1); }
  }
  for (let i = gpulses.length - 1; i >= 0; i--) {
    const g = gpulses[i]; g.t += dt; const k = g.t / 1.6; g.m.scale.setScalar(1 + k * 5); g.m.material.opacity = Math.max(0, 0.9 * (1 - k));
    if (k >= 1) { gGroup.remove(g.m); g.m.geometry.dispose(); gpulses.splice(i, 1); }
  }
  for (const o of spots) { const age = (now - o.born) / 1000; o.dot.material.opacity = Math.max(0.18, 0.95 - age / 400); }
  for (const f of flowObjs) f.head.position.copy(f.curve.getPoint((now * 0.00015 + f.off) % 1));
  for (const h of hooks) { try { h(now, dt); } catch (e) { console.error(e); } }
  drawRing(now);
  renderer.render(scene, camera);
}
requestAnimationFrame(frame);

/* ------------------------------------------------------------------ UI: feed, nodes, panels */
const api = async (url, body, method) => {
  const r = await fetch(url, body ? { method: method || "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
  return r.json();
};
const setStatus = (t) => { $("#status").textContent = t; };
const lang = () => $("#lang").value;

function renderStats() {
  const s = S.stats; if (!s) return;
  $("#risk-val").textContent = s.risk + "%";
  const f = $("#risk-fill"); f.style.width = s.risk + "%";
  f.style.background = s.risk > 66 ? "#ff3860" : s.risk > 38 ? "#ffb020" : "#00ff9c"; f.style.color = f.style.background;
  $("#s-total").textContent = s.total; $("#s-blocked").textContent = `${s.sources_ok}/${s.sources_total}`; $("#s-comp").textContent = s.critical_nodes; $("#s-iso").textContent = s.blocked_ips.length;
  $("#g-total").textContent = (s.global_total || 0).toLocaleString(); $("#g-1h").textContent = (s.global_1h || 0).toLocaleString();
  const tops = s.top_origins || [], mx = Math.max(1, ...tops.map((t) => t[1]));
  $("#g-top").innerHTML = tops.map(([c, n]) => `<div class="bar"><span>${esc(c)}</span><i style="width:${Math.round(100 * n / mx)}%"></i><b>${n}</b></div>`).join("") || '<span class="muted">waiting for global feeds…</span>';
  const fm = S.flowsMeta || {};
  $("#g-flows").innerHTML = (S.flows || []).slice(0, 5).map((f) => `<div class="fl"><span>${esc(f.from_name)} → ${esc(f.to_name)}</span><b>${f.pct.toFixed(1)}%</b><small>${esc(f.layer)}</small></div>`).join("")
    || '<span class="muted">Cloudflare Radar flows need CLOUDFLARE_API_TOKEN (free) - see README</span>';
  $("#g-flows-note").textContent = (S.flows || []).length ? `${fm.source} · ${fm.window} · aggregate share, not single attacks` : "";
}
function allEvents() {
  const loc = S.scope === "global" ? [] : S.events.map((e) => e), glo = S.scope === "local" ? [] : S.gevents;
  return loc.concat(glo).sort((a, b) => b.epoch - a.epoch);
}
function renderFeed() {
  const feed = $("#feed"), list = allEvents().filter((e) => S.filter === "all" || e.severity === S.filter).slice(0, 80);
  feed.innerHTML = list.map((e) => { const g = e.scope === "global"; return `<div class="ev sev-${e.severity} ${g ? "glob" : ""} ${S.selEvent === e.id ? "sel" : ""}" data-id="${e.id}">
    <div class="t"><span>${esc(e.ts.slice(11, 19))} · ${esc(e.severity.toUpperCase())}${g ? " · GLOBAL" : ""}</span><span>${esc(e.mitre ? e.mitre.id : "")}</span></div>
    <div class="ti">${esc(e.title)}</div><div class="m"><span class="sr">${esc(e.source)}</span> · ${g ? "seen in " + esc((e.src && (e.src.country || e.src.city)) || "?") : esc(e.target.name) + (e.src ? (e.direction === "out" ? " → " : " ← ") + esc(e.src.city) : "")}</div></div>`; }).join("");
  $("#count").textContent = `${S.events.length} local · ${S.gevents.length} global`;
}
$("#feed").addEventListener("click", (e) => {
  const el = e.target.closest(".ev"); if (!el) return;
  S.selEvent = el.dataset.id;
  const ev = S.events.find((x) => x.id === S.selEvent) || S.gevents.find((x) => x.id === S.selEvent), glob = ev && ev.scope === "global";
  $("#btn-council").disabled = !ev || glob;
  if (ev) { if (glob) { if (ev.src && ev.src.lat != null) focusLL(ev.src.lat, ev.src.lon); } else focusNode(ev.target.id); $("#ev-detail").classList.remove("muted");
    $("#ev-detail").innerHTML = `<b>${esc(ev.title)}</b><br>${esc(ev.detail)}<br><span class="muted">${esc(ev.source)}${ev.mitre ? " · " + esc(ev.mitre.id) + " " + esc(ev.mitre.name) : ""}${ev.src && ev.src.ip ? " · " + esc(ev.src.ip) : ""}${ev.tags.length ? " · " + esc(ev.tags.join(", ")) : ""}${glob ? " · global intel: not an attack on your nodes" : ""}</span>`; }
  renderFeed();
});
function renderChips() {
  $("#sev-chips").innerHTML = ["all", "critical", "high", "medium", "low"].map((s) => `<button data-s="${s}" class="${S.filter === s ? "on" : ""}">${s}</button>`).join("")
    + `<span class="sp"></span>` + ["all", "local", "global"].map((s) => `<button data-sc="${s}" class="${S.scope === s ? "on" : ""}">${s}</button>`).join("");
}
$("#sev-chips").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; if (b.dataset.sc) S.scope = b.dataset.sc; else S.filter = b.dataset.s; renderChips(); renderFeed(); });

const META_LABEL = { public_ip: "Public IP", ip: "IP", url: "URL", connections: "Connections", unique_remote_ips: "Remote hosts", listening_ports: "Listening", top_processes: "Top procs",
  http_status: "HTTP", latency_ms: "Latency ms", tls_days_left: "TLS days left", missing_security_headers: "Missing hdrs", ports: "Ports", location_source: "Geo via" };
function selectNode(id, fromFocus) {
  S.selNode = id; const n = S.nodes[id]; if (!n) return;
  if (!fromFocus) focusQ = new THREE.Quaternion().setFromUnitVectors(nodeObjs[id].up.clone(), new THREE.Vector3(0, 0, 1));
  const evs = S.events.filter((e) => e.target.id === id && e.severity !== "info").slice(-3).reverse();
  const meta = Object.entries(n.meta || {}).filter(([k, v]) => META_LABEL[k] && v != null && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `<span>${META_LABEL[k]}</span><div class="l">${esc(Array.isArray(v) ? v.join(", ") : v)}</div>`).join("");
  $("#node-body").classList.remove("muted");
  $("#node-body").innerHTML = `<div class="kv"><span>Name</span><b>${esc(n.name)}</b><span>Type</span>${esc(n.kind)}<span>Location</span>${esc(n.city)}
    <span>Status</span><i class="st st-${n.status}">${STATUS_LABEL[n.status] || esc(n.status)}</i>${meta}<span>Recent</span><div class="l">${evs.map((e) => esc(e.title)).join("<br>") || "none"}</div></div>
    <div class="row"><button class="btn" data-a="ack_node">Acknowledge</button>${n.kind === "asset" ? '<button class="btn" data-a="run_scan">Scan ports</button>' : ""}</div>
    <div id="scan-out" class="hint"></div>`;
}
$("#node-body").addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-a]"); if (!b || !S.selNode) return;
  if (b.dataset.a === "run_scan") $("#scan-out").textContent = "Scanning…";
  const r = await api("/api/action", { type: b.dataset.a, node: S.selNode });
  const res = r.results?.[0];
  if (res?.type === "run_scan") $("#scan-out").textContent = res.ok ? `Open: ${res.result.open_ports.join(", ") || "none"} · risky exposed: ${Object.values(res.result.exposed_risky_services).join(", ") || "none"}` : (res.error || res.result?.error || "scan failed");
});
function renderPending() {
  const p = S.pending, card = $("#pending-card"); card.hidden = !p; if (!p) return;
  $("#pending-body").innerHTML = `<div><b style="color:var(--r)">${esc(p.severity.toUpperCase())}</b> ${esc(p.title)}</div>
    <div class="muted">Proposed: block ${esc(p.ip)} (${esc(p.city)}) ${p.direction === "out" ? "- outbound C2 traffic" : "- inbound attacker"}</div>`;
}
$("#p-yes").onclick = () => api("/api/action", { type: "confirm_pending" });
$("#p-no").onclick = () => api("/api/action", { type: "deny_pending" });

$("#btn-council").onclick = async () => {
  if (!S.selEvent) return; const box = $("#council"); box.classList.remove("muted"); box.innerHTML = "Convening Groq · Gemini · Claude…";
  const r = await api("/api/council", { event_id: S.selEvent });
  if (r.error) { box.textContent = r.error; return; }
  box.innerHTML = r.votes.map((v) => `<div class="vote"><b>${esc(v.provider)}</b><div>${v.error ? `<span class="muted">${esc(v.error)}</span>` : `<span class="v">${esc(v.verdict)}</span> ${v.confidence}% · ${v.ms}ms<br>${esc(v.reason)}`}</div></div>`).join("")
    + (r.consensus ? `<div class="consensus">CONSENSUS: ${esc(r.consensus.toUpperCase())}</div>` : "");
};

/* report */
let repMd = "";
const md2html = (m) => esc(m).replace(/^## (.*)$/gm, "<h2>$1</h2>").replace(/^[-*] (.*)$/gm, "<li>$1</li>").replace(/\*\*(.*?)\*\*/g, "<b>$1</b>")
  .replace(/(<li>.*<\/li>\n?)+/g, (b) => `<ul>${b}</ul>`).replace(/\n{2,}/g, "<br>");
async function openReport() {
  $("#modal").hidden = false; $("#rep-body").textContent = "Claude is writing the report…"; $("#rep-prov").textContent = "";
  const l = lang(); const r = await api("/api/report", { lang: ["auto"].includes(l) ? "en-IN" : l });
  repMd = r.markdown || ""; $("#rep-body").innerHTML = md2html(repMd); $("#rep-prov").textContent = "via " + (r.provider || "?");
}
$("#btn-report").onclick = openReport; $("#rep-close").onclick = () => { $("#modal").hidden = true; };
$("#rep-dl").onclick = () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([repMd], { type: "text/markdown" })); a.download = "incident-report.md"; a.click(); };
$("#rep-speak").onclick = async () => {
  const m = repMd.match(/Executive Summary[^\n]*\n+([\s\S]*?)(\n##|$)/i); const txt = (m ? m[1] : repMd).replace(/[#*\-_`]/g, "").trim().slice(0, 600);
  const l = lang(); const r = await api("/api/tts", { text: txt, lang: l === "auto" ? "en-IN" : l }); playResult(r, txt, l);
};

/* ------------------------------------------------------------------ conversation bubbles */
function bubble(kind, text, meta) {
  const d = document.createElement("div"); d.className = "b " + kind; d.textContent = text;
  if (meta) { const s = document.createElement("small"); s.textContent = meta; d.appendChild(s); }
  const c = $("#convo"); c.appendChild(d); while (c.children.length > 5) c.firstChild.remove(); c.scrollTop = c.scrollHeight;
}

/* ------------------------------------------------------------------ audio playback + level */
let actx, analyser, player = new Audio(), playSrc = null, levelTimer = null;
function ensureAudio() {
  if (!actx) actx = new (window.AudioContext || window.webkitAudioContext)();
  if (actx.state === "suspended") actx.resume();
  if (!playSrc) { playSrc = actx.createMediaElementSource(player); analyser = actx.createAnalyser(); analyser.fftSize = 512; playSrc.connect(analyser); analyser.connect(actx.destination); }
}
function pumpLevel(an) {
  clearInterval(levelTimer); const buf = new Uint8Array(an.fftSize);
  levelTimer = setInterval(() => { an.getByteTimeDomainData(buf); let s = 0; for (const v of buf) { const x = (v - 128) / 128; s += x * x; } S.level = Math.min(1, Math.sqrt(s / buf.length) * 3.2); }, 40);
}
function stopSpeaking() { player.pause(); speechSynthesis?.cancel?.(); S.level = 0; clearInterval(levelTimer); }
function playResult(r, fallbackText, l) {
  return new Promise((res) => {
    stopSpeaking();
    if (r && r.audio_b64) {
      ensureAudio(); player.src = `data:${r.audio_mime};base64,${r.audio_b64}`;
      player.onended = () => { S.level = 0; clearInterval(levelTimer); setStatus("Ready"); res(); };
      player.play().then(() => { pumpLevel(analyser); setStatus("Speaking"); }).catch(() => res());
    } else if ("speechSynthesis" in window && fallbackText) {
      const u = new SpeechSynthesisUtterance(fallbackText); u.lang = SPEECH_LANG(l || "en-IN");
      u.onstart = () => { setStatus("Speaking (browser voice)"); const iv = setInterval(() => { S.level = 0.25 + Math.random() * 0.35; }, 90); u.onend = () => { clearInterval(iv); S.level = 0; setStatus("Ready"); res(); }; };
      speechSynthesis.speak(u);
    } else res();
  });
}

/* ------------------------------------------------------------------ microphone -> WAV -> /api/voice */
let rec = null, recState = false, micStream = null, vad = null;
function encodeWav(f32, sr) {
  const buf = new ArrayBuffer(44 + f32.length * 2), v = new DataView(buf), w = (o, s) => [...s].forEach((c, i) => v.setUint8(o + i, c.charCodeAt(0)));
  w(0, "RIFF"); v.setUint32(4, 36 + f32.length * 2, true); w(8, "WAVEfmt "); v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, sr, true); v.setUint32(28, sr * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true); w(36, "data"); v.setUint32(40, f32.length * 2, true);
  for (let i = 0; i < f32.length; i++) v.setInt16(44 + i * 2, Math.max(-1, Math.min(1, f32[i])) * 0x7fff, true);
  return new Blob([buf], { type: "audio/wav" });
}
async function toWav16k(blob) {
  const ab = await blob.arrayBuffer(), c = new (window.AudioContext || window.webkitAudioContext)();
  const dec = await c.decodeAudioData(ab); c.close();
  const off = new OfflineAudioContext(1, Math.max(1, Math.ceil(dec.duration * 16000)), 16000), src = off.createBufferSource();
  src.buffer = dec; src.connect(off.destination); src.start(); const out = await off.startRendering();
  return encodeWav(out.getChannelData(0), 16000);
}
async function startRec() {
  stopSpeaking();
  try { micStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } }); }
  catch (e) { setStatus("Microphone blocked - allow it, or type instead"); return; }
  ensureAudio();
  const chunks = []; rec = new MediaRecorder(micStream); rec.ondataavailable = (e) => e.data.size && chunks.push(e.data);
  const src = actx.createMediaStreamSource(micStream), an = actx.createAnalyser(); an.fftSize = 512; src.connect(an);
  const buf = new Uint8Array(an.fftSize); let spoke = 0, quiet = 0, started = performance.now();
  rec.onstop = async () => {
    clearInterval(vad); src.disconnect(); micStream.getTracks().forEach((t) => t.stop()); recState = false; $("#mic").classList.remove("rec"); S.level = 0;
    if (!spoke) { setStatus("Didn't hear speech - tap the mic and try again"); return; }
    await sendVoice(new Blob(chunks, { type: rec.mimeType }));
  };
  rec.start(); recState = true; $("#mic").classList.add("rec"); setStatus("Listening… (stops automatically when you finish)");
  vad = setInterval(() => {
    an.getByteTimeDomainData(buf); let s = 0; for (const v of buf) { const x = (v - 128) / 128; s += x * x; } const rms = Math.sqrt(s / buf.length); S.level = Math.min(1, rms * 5);
    const el = performance.now() - started;
    if (rms > 0.025) { spoke += 0.1; quiet = 0; } else if (spoke > 0.3) quiet += 0.1;
    if ((spoke > 0.3 && quiet > 1.4) || el > 25000 || (!spoke && el > 9000)) stopRec();
  }, 100);
}
function stopRec() { if (rec && rec.state !== "inactive") rec.stop(); }
async function sendVoice(blob) {
  S.busy = true; $("#mic").classList.add("busy"); setStatus("Transcribing with Gnani Prisma…");
  try {
    const wav = await toWav16k(blob), fd = new FormData(); fd.append("audio", wav, "speech.wav"); fd.append("lang", lang());
    const r = await (await fetch("/api/voice", { method: "POST", body: fd })).json();
    if (r.error) { bubble("a", r.error); setStatus(r.empty ? "Ready" : "Error"); return; }
    await handleReply(r);
  } catch (e) { bubble("a", "Voice pipeline error: " + e.message); setStatus("Error"); }
  finally { S.busy = false; $("#mic").classList.remove("busy"); }
}
async function sendText(text) {
  S.busy = true; $("#mic").classList.add("busy"); setStatus("Thinking…");
  try { await handleReply(await api("/api/chat", { text, lang: lang() })); }
  catch (e) { bubble("a", "Error: " + e.message); } finally { S.busy = false; $("#mic").classList.remove("busy"); }
}
async function handleReply(r) {
  if (r.error) { bubble("a", r.error); return; }
  bubble("u", r.transcript, r.detected_lang ? "detected " + r.detected_lang : "");
  const t = r.timings || {}, meta = [t.stt != null && `STT ${t.stt}s`, `LLM ${t.llm}s (${r.provider})`, `TTS ${t.tts}s`].filter(Boolean).join(" · ");
  bubble("a", r.reply, meta + (r.tts_error ? " · TTS fallback: browser voice" : ""));
  (r.client_actions || []).forEach(clientAction);
  const rep = (r.results || []).find((x) => x.type === "run_scan" && x.ok && x.result);
  if (rep) bubble("a", `Scan ${rep.result.host}: open ${(rep.result.open_ports || []).join(", ") || "none"} · risky exposed: ${Object.values(rep.result.exposed_risky_services || {}).join(", ") || "none"}`);
  playResult(r, r.reply, r.lang); // not awaited: speech must never block the next command
}
function clientAction(a) {
  if (a.type === "focus_node") focusNode(a.node);
  else if (a.type === "filter_severity") { S.filter = ["info", "low", "medium", "high", "critical"].includes(a.level) ? a.level : "all"; renderChips(); renderFeed(); }
  else if (a.type === "open_report") openReport();
  else if (a.type === "set_view" && window.VIRUS.setLayer) window.VIRUS.setLayer("view", ["realistic", "tactical", "flat"].includes(a.view) ? a.view : "realistic");
  else if (a.type === "toggle_layer" && window.VIRUS.setLayer) window.VIRUS.setLayer(a.layer, a.on !== false);
  else if (a.type === "toggle_rotation") $("#t-rot").checked = !$("#t-rot").checked;
}
$("#mic").onclick = () => { if (S.busy) return; recState ? stopRec() : startRec(); };
addEventListener("keydown", (e) => { if (e.code === "Space" && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); if (!S.busy) recState ? stopRec() : startRec(); } });
$("#txt-form").addEventListener("submit", (e) => { e.preventDefault(); const v = $("#txt").value.trim(); if (v && !S.busy) { $("#txt").value = ""; sendText(v); } });
[["Status report", "Give me a status report"], ["Biggest threat?", "What is the biggest threat right now?"], ["Block attacker", "Block the attacker"],
 ["Look up top attacker", "Look up the most recent attacker IP and tell me what it is"], ["Scan my assets", "Run a scan on my monitored asset"],
 ["What is this machine doing?", "What is this machine connecting to right now?"], ["हिंदी में बताओ", "हिंदी में बताओ अभी क्या हो रहा है"],
 ["Hinglish", "Bhai abhi sabse dangerous alert kaunsa hai?"], ["Incident report", "Generate the incident report"]]
  .forEach(([l, q]) => { const b = document.createElement("button"); b.textContent = l; b.onclick = () => !S.busy && sendText(q); $("#quick").appendChild(b); });

/* ------------------------------------------------------------------ live stream */
async function maybeNarrate(ev) {
  if (!$("#t-voice").checked || S.busy || recState || !["critical", "high"].includes(ev.severity) || Date.now() - S.lastNarrate < 30000) return;
  await new Promise((r) => setTimeout(r, 500));
  if (ev.severity !== "critical" && !(S.pending && S.pending.event_id === ev.id)) return;
  S.lastNarrate = Date.now(); S.busy = true;
  try { const l = lang(), r = await api("/api/narrate", { event_id: ev.id, lang: l === "auto" ? "en-IN" : l }); S.busy = false; if (r.reply) { bubble("a", "ALERT · " + r.reply, "via " + r.provider); playResult(r, r.reply, r.lang); } }
  catch (e) { /* ignore */ } finally { S.busy = false; }
}
function connect() {
  const es = new EventSource("/api/stream");
  es.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.kind === "event") { S.events.push(d.event); S.events = S.events.slice(-250); if (!addArc(d.event)) addWave(d.event.target.id, SEVCOL[d.event.severity], d.event.severity === "critical"); renderFeed(); maybeNarrate(d.event); }
    else if (d.kind === "global") { d.items.forEach((g) => { S.gevents.push(g); addSighting(g); }); S.gevents = S.gevents.slice(-400); renderFeed(); }
    else if (d.kind === "flows") { S.flows = d.flows; S.flowsMeta = d.meta; setFlows(d.flows); renderStats(); }
    else if (d.kind === "node") { S.nodes[d.node.id] = d.node; if (!nodeObjs[d.node.id]) buildNode(d.node); paintNode(d.node); if (S.selNode === d.node.id) selectNode(d.node.id, true); }
    else if (d.kind === "stats") { S.stats = d.stats; renderStats(); }
    else if (d.kind === "pending") { S.pending = d.pending; renderPending(); }
  };
  es.onerror = () => setStatus("Reconnecting to telemetry…");
}
async function health() {
  try {
    const h = await api("/api/health"); const set = (id, on, st) => { const e = $("#p-" + id); if (!e) return; const bad = st && (st.rejected || st.last_error);
      e.className = "pill " + (on ? (bad ? "bad" : "on") : ""); e.title = !on ? "no key in .env" : st?.rejected ? "key rejected: " + st.rejected : st?.last_error || ("model: " + (st?.model || "discovering…") + (st?.available_models != null ? " · " + st.available_models + " available" : "")); };
    set("gnani", h.gnani); for (const k of ["groq", "gemini", "claude", "openrouter"]) set(k, h.llm[k], (h.llm_status || {})[k]);
    $("#srcs").innerHTML = (h.sources || []).map((s) => `<span class="src ${s.ok ? "ok" : s.ok === false ? "bad" : s.needs_key ? "key" : ""}" title="${esc(s.last_error || (s.items + " items"))}">${esc(s.name)}${s.needs_key ? " · needs KEY" : ""}</span>`).join("")
      + `<span class="src" title="IPs in live blocklists used for correlation">intel ${h.intel_ips.toLocaleString()} IPs</span>`
      + `<span class="src ${h.firewall_enforcing ? "ok" : ""}" title="${h.firewall_enforcing ? "firewall rules are applied" : "block = dry-run (set ENABLE_FIREWALL=1)"}">firewall ${h.firewall_enforcing ? "ON" : "dry-run"}</span>`;
  } catch (e) { /* ignore */ }
}
async function init() {
  $("#lang").innerHTML = LANGS.map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
  renderChips();
  const st = await api("/api/state"); st.nodes.forEach((n) => { S.nodes[n.id] = n; buildNode(n); paintNode(n); });
  S.gevents = st.global_events || []; S.gevents.forEach(addSighting); S.flows = st.flows || []; S.flowsMeta = st.flows_meta || {}; if (S.flows.length) setFlows(S.flows);
  S.events = st.events; S.stats = st.stats; S.pending = st.pending; renderStats(); renderFeed(); renderPending();
  connect(); health(); setInterval(health, 8000);
  setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString([], { hour12: false }); }, 1000);
  bubble("a", "VIRUS online with live data. Tap the mic or press space and speak in any Indian language. Feeds take a few seconds to fill.");
}
init();
})();
