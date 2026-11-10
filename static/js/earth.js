/* Realistic Earth: NASA-derived day / night-lights / specular / cloud textures, a REAL-TIME day-night terminator (sun position from the
   UTC clock), ocean sun-glint, cloud layer and atmospheric rim. View modes: realistic | tactical (original wireframe HUD) | flat 2D map. */
(() => {
"use strict";
const V = window.VIRUS, T = V.THREE, R = V.R;

const LS = {
  get(k, d) { try { const v = localStorage.getItem("virus." + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem("virus." + k, JSON.stringify(v)); } catch (e) { /* ignore */ } },
};
const layers = Object.assign({ view: "realistic", clouds: true, daynight: true, atmosphere: true, sats: true, aircraft: true, quakes: true, sightings: true, flows: true, arcs: true }, LS.get("layers", {}));
const listeners = [];
V.layers = layers; V.LS = LS;
V.onLayer = (fn) => listeners.push(fn);
V.setLayer = (k, v) => { layers[k] = v; LS.set("layers", layers); apply(); listeners.forEach((f) => { try { f(k, v); } catch (e) { console.error(e); } }); };

/* ---------------------------------------------------------------- sun position (Earth-fixed sub-solar point from UTC)  */
function sunPos(d = new Date()) {
  const n = d.getTime() / 86400000 + 2440587.5 - 2451545.0, rad = Math.PI / 180;
  const L = (280.460 + 0.9856474 * n) % 360, g = ((357.528 + 0.9856003 * n) % 360) * rad;
  const lam = (L + 1.915 * Math.sin(g) + 0.020 * Math.sin(2 * g)) * rad, eps = (23.439 - 0.0000004 * n) * rad;
  const dec = Math.asin(Math.sin(eps) * Math.sin(lam)), ra = Math.atan2(Math.cos(eps) * Math.sin(lam), Math.cos(lam));
  const gmst = ((((18.697374558 + 24.06570982441908 * n) % 24) + 24) % 24) * 15 * rad;
  let lon = ra - gmst; lon = Math.atan2(Math.sin(lon), Math.cos(lon));
  return { lat: dec / rad, lon: lon / rad };
}
V.sunPos = sunPos;

/* ---------------------------------------------------------------- earth + clouds */
const loader = new T.TextureLoader(), aniso = Math.min(8, V.renderer.capabilities.getMaxAnisotropy());
const tex = (f) => { const t = loader.load("/static/textures/" + f); t.anisotropy = aniso; return t; };
const sunDir = new T.Vector3(1, 0, 0), camObj = new T.Vector3(0, 0, 19);
const earthMat = new T.ShaderMaterial({
  uniforms: { dayMap: { value: tex("earth_atmos_2048.jpg") }, nightMap: { value: tex("earth_lights_2048.png") }, specMap: { value: tex("earth_specular_2048.jpg") },
    sunDir: { value: sunDir }, camObj: { value: camObj }, flatMode: { value: 0 } },
  vertexShader: "varying vec2 vUv;varying vec3 vN;varying vec3 vP;void main(){vUv=uv;vN=normalize(position);vP=position;gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}",
  fragmentShader: `uniform sampler2D dayMap,nightMap,specMap;uniform vec3 sunDir,camObj;uniform float flatMode;varying vec2 vUv;varying vec3 vN;varying vec3 vP;
  void main(){
    vec3 N=normalize(vN),V=normalize(camObj-vP);
    float ndl=mix(dot(N,sunDir),1.0,flatMode);
    vec3 day=texture2D(dayMap,vUv).rgb,night=texture2D(nightMap,vUv).rgb;float sp=texture2D(specMap,vUv).r;
    float dayF=smoothstep(-0.10,0.20,ndl);
    vec3 col=day*(0.045+1.1*max(ndl,0.0));
    float tw=smoothstep(-0.02,0.10,ndl)*(1.0-smoothstep(0.10,0.34,ndl));
    col+=vec3(1.0,0.42,0.12)*tw*0.16*day;
    vec3 H=normalize(normalize(sunDir)+V);
    col+=vec3(1.0,0.95,0.85)*pow(max(dot(N,H),0.0),70.0)*sp*smoothstep(0.0,0.2,ndl)*1.4*(1.0-flatMode);
    col+=night*(1.0-dayF)*vec3(1.5,1.2,0.8)*(1.0-flatMode);
    float rim=pow(1.0-max(dot(N,V),0.0),3.0);
    col+=vec3(0.22,0.5,1.0)*rim*(0.18+0.82*dayF)*0.75;
    gl_FragColor=vec4(col,1.0);
  }`,
});
const earth = new T.Mesh(new T.SphereGeometry(R, 96, 96), earthMat);
V.globe.add(earth);

const cloudMat = new T.ShaderMaterial({
  uniforms: { map: { value: tex("earth_clouds_1024.png") }, sunDir: { value: sunDir }, flatMode: { value: 0 } },
  vertexShader: "varying vec2 vUv;varying vec3 vN;void main(){vUv=uv;vN=normalize(position);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}",
  fragmentShader: "uniform sampler2D map;uniform vec3 sunDir;uniform float flatMode;varying vec2 vUv;varying vec3 vN;void main(){float a=texture2D(map,vUv).a;float l=mix(dot(normalize(vN),sunDir),1.0,flatMode);vec3 c=vec3(1.0)*(0.035+0.965*smoothstep(-0.12,0.35,l));gl_FragColor=vec4(c,a*0.78);}",
  transparent: true, depthWrite: false,
});
const clouds = new T.Mesh(new T.SphereGeometry(R * 1.011, 64, 64), cloudMat);
V.globe.add(clouds);

/* sky: far-field stars (denser than the tactical set) */
const stars = (() => {
  const N = 3500, p = new Float32Array(N * 3), c = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) {
    const v = new T.Vector3().randomDirection().multiplyScalar(150 + Math.random() * 60); p.set([v.x, v.y, v.z], i * 3);
    const k = 0.55 + Math.random() * 0.45, w = Math.random(); c.set([k * (0.8 + 0.2 * w), k * 0.9, k * (1 - 0.2 * w)], i * 3);
  }
  const g = new T.BufferGeometry(); g.setAttribute("position", new T.BufferAttribute(p, 3)); g.setAttribute("color", new T.BufferAttribute(c, 3));
  const m = new T.Points(g, new T.PointsMaterial({ size: 0.55, vertexColors: true, transparent: true, opacity: 0.9, sizeAttenuation: false, depthWrite: false }));
  V.scene.add(m); return m;
})();

/* ---------------------------------------------------------------- mode application */
const bg = new T.Color(0x02060a), bgReal = new T.Color(0x000207);
function apply() {
  const real = layers.view === "realistic", flat = layers.view === "flat";
  document.body.classList.toggle("view-flat", flat);
  document.body.dataset.view = layers.view;
  earth.visible = real; clouds.visible = real && layers.clouds; stars.visible = real;
  V.tactical.visible = !real; V.core.visible = !real;
  V.atmo.visible = !flat && (real ? layers.atmosphere : true);
  V.atmo.material.uniforms.col.value.set(real ? 0x4f8dff : 0x1ad9ff);
  V.scene.background = real ? bgReal : bg;
  earthMat.uniforms.flatMode.value = layers.daynight ? 0 : 1; cloudMat.uniforms.flatMode.value = layers.daynight ? 0 : 1;
  V.gGroup.visible = layers.sightings; V.fGroup.visible = layers.flows;
  document.querySelectorAll("[data-view]").forEach((b) => b.classList.toggle("on", b.dataset.view === layers.view));
}

let lastSun = 0;
V.hooks.push((now) => {
  if (now - lastSun > 1000) {            // the sun moves 15 deg/hour: once a second is plenty
    lastSun = now; const s = sunPos(); sunDir.copy(V.ll(s.lat, s.lon, 1)); V.sun = s;
  }
  V.globe.worldToLocal(camObj.copy(V.camera.position));
  clouds.rotation.y += 0.00006;          // clouds drift slightly relative to the ground
});

/* view buttons */
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-view]"); if (!b) return;
  V.setLayer("view", b.dataset.view);
});
apply();
})();
