/* Toolbox: live security tools (/api/tool) with optional AI explanation (/api/tool/explain). */
(() => {
"use strict";
const V = window.VIRUS, $ = V.$, esc = V.esc;
const TOOLS = [
  ["ip", "IP intel", "8.8.8.8", "Geo, ASN, live threat-list hits, open ports (Shodan InternetDB)"],
  ["dns", "DNS + mail", "example.com", "A/AAAA/MX/NS/TXT/CAA over DoH, SPF + DMARC check"],
  ["whois", "WHOIS / RDAP", "example.com", "Registrar, age, expiry (new domains are suspicious)"],
  ["tls", "TLS cert", "example.com", "Issuer, expiry, protocol, cipher"],
  ["headers", "HTTP headers", "https://example.com", "Security-header grade A-F, redirect chain"],
  ["cve", "CVE lookup", "CVE-2024-3094", "NVD details + CISA 'known exploited' flag (or type a keyword)"],
  ["url", "URL check", "http://login-paypa1.example/verify", "Phishing heuristics + live URLhaus/OpenPhish match"],
  ["hash", "Hash lookup", "44d88612fea8a8f36de82e1278abb02f", "Identify hash type, malware reputation"],
  ["subnet", "Subnet calc", "10.0.0.0/24", "Range, hosts, mask"],
];
let cur = "ip", last = null;
const el = $("#toolbox");
$("#tb-tabs").innerHTML = TOOLS.map(([k, n]) => `<button data-tool="${k}" class="${k === cur ? "on" : ""}">${n}</button>`).join("");
function pick(k) { cur = k; const t = TOOLS.find((x) => x[0] === k); $("#tb-in").placeholder = t[2]; $("#tb-desc").textContent = t[3];
  $("#tb-tabs").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.tool === k)); }
pick(cur);
$("#tb-tabs").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) pick(b.dataset.tool); });
$("#btn-toolbox").onclick = () => { el.hidden = !el.hidden; if (!el.hidden) $("#tb-in").focus(); };
$("#tb-close").onclick = () => { el.hidden = true; };
function render(v, d = 0) {
  if (v === null || v === undefined) return '<span class="muted">-</span>';
  if (Array.isArray(v)) return v.length ? (typeof v[0] === "object" ? v.map((x) => `<div class="sub-row">${render(x, d + 1)}</div>`).join("") : esc(v.join(", "))) : '<span class="muted">none</span>';
  if (typeof v === "object") return `<div class="kv2">${Object.entries(v).map(([k, x]) => `<span>${esc(k.replace(/_/g, " "))}</span><div>${render(x, d + 1)}</div>`).join("")}</div>`;
  return esc(v);
}
async function run() {
  const q = $("#tb-in").value.trim() || $("#tb-in").placeholder; $("#tb-out").innerHTML = '<span class="muted">running…</span>'; $("#tb-ai").hidden = true; $("#tb-ai-out").textContent = "";
  const r = await V.api("/api/tool", { tool: cur, input: q }).catch((e) => ({ ok: false, error: String(e) }));
  last = { tool: cur, input: q, result: r.result };
  if (!r.ok) { $("#tb-out").innerHTML = `<div class="bad">${esc(r.error || "failed")}</div>`; return; }
  const v = r.result.verdict ? `<div class="verdict">${esc(r.result.verdict)}</div>` : "";
  $("#tb-out").innerHTML = v + render(r.result) + `<small class="muted">${r.ms} ms · live lookup</small>`; $("#tb-ai").hidden = false;
}
$("#tb-form").addEventListener("submit", (e) => { e.preventDefault(); run(); });
$("#tb-ai").onclick = async () => {
  if (!last) return; $("#tb-ai-out").textContent = "asking the AI…";
  const r = await V.api("/api/tool/explain", last).catch((e) => ({ error: String(e) }));
  $("#tb-ai-out").textContent = r.text ? r.text + `\n— ${r.provider}` : r.error || "AI unavailable";
};
$("#btn-snap").onclick = () => { try { V.renderer.render(V.scene, V.camera); const a = document.createElement("a"); a.download = "virus-globe.png"; a.href = V.renderer.domElement.toDataURL("image/png"); a.click(); } catch (e) { /* ignore */ } };
})();
