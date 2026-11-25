"use strict";
// HealthSafe portals: patient, doctor, hospital, admin. One page; the URL path picks the portal. No external libraries.

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (x, d = 3) => (x === null || x === undefined || Number.isNaN(x)) ? "–" : Number(x).toFixed(d);
const when = (t) => t ? new Date(t * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "–";
const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const C = { rose: "#f0507f", violet: "#6a5cff", mint: "#12a27a", amber: "#e08a00", red: "#d93a49", sky: "#3a8dff", muted: "#6e6b92", grid: "rgba(110,100,190,.12)" };

const PORTAL = location.pathname.replace(/\//g, "") || "patient";
let ME = null, CTX = null, SEC = null, POLL = null;

// ------------------------------------------------------------------ portal definitions
const ICON = {
  home: '<path d="M3 11 12 4l9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  heart: '<path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M15 8l2 2"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  steth: '<path d="M6 3v6a4 4 0 0 0 8 0V3M10 13v3a5 5 0 0 0 10 0v-2"/><circle cx="20" cy="12" r="2"/>',
  users: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M16 3.5a4 4 0 0 1 0 9M22 21a7 7 0 0 0-4-6.3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  nodes: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M10.5 13 6.5 17M13.5 13l4 4"/>',
  chain: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  audit: '<path d="M9 3h6l5 5v13H4V3h5zM14 3v5h5M8 13h8M8 17h5"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="M12 8v5M12 16h.01"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
};
const PORTALS = {
  patient: { name: "Patient portal", badge: "Patient", img: "patient.svg", tagline: "Your health. Your say.",
    blurb: "See your heart-rate readings and choose which hospitals can open your record.",
    hint: "Sign in with your patient account.",
    nav: [["p-home", "My health", "heart", null], ["p-consent", "Sharing", "key", "Who can see your record"], ["p-history", "Activity", "clock", "Activity on your record"]] },
  doctor: { name: "Clinician portal", badge: "Clinician", img: "doctor.svg", tagline: "Your patients' records, when they've said yes.",
    blurb: "Open the records your patients have shared with your hospital.",
    hint: "Sign in with your hospital staff account.",
    nav: [["d-request", "Open a record", "steth", "Open a record"], ["d-patients", "Patients", "users", "Patients"], ["d-history", "My requests", "clock", "Your requests"]] },
  hospital: { name: "Hospital portal", badge: "Hospital", img: "hospital.svg", tagline: "Your hospital at a glance.",
    blurb: "Patients who share their records with you, your staff, and every request they make.",
    hint: "Sign in with your hospital records-office account.",
    nav: [["h-home", "Dashboard", "home", "Hospital dashboard"], ["h-patients", "Patients", "users", "Patients & access"], ["h-log", "Access log", "list", "Access log"], ["h-staff", "Staff", "steth", "Staff accounts"]] },
  admin: { name: "Admin portal", badge: "Administrator", img: "admin.svg", tagline: "Run the consortium.",
    blurb: "Load datasets, manage nodes and accounts, inspect the ledger, and attack the baseline.",
    hint: "Sign in with the consortium administrator account.",
    nav: [["a-home", "Dashboard", "home", "Consortium overview"], ["a-requests", "Access requests", "key", "Access requests & decisions"], ["a-dataset", "Dataset", "db", "Dataset"], ["a-nodes", "Nodes & consensus", "nodes", "Validator nodes"],
      ["a-ledger", "Ledger", "chain", "Ledger"], ["a-audit", "Audit & contracts", "audit", "Audit & smart contracts"], ["a-users", "Accounts", "user", "Portal accounts"],
      ["a-lab", "Attack lab", "shield", "Attack & benchmark lab"], ["a-figures", "Experiments", "chart", "Paper experiments"]] },
};
const P = PORTALS[PORTAL] || PORTALS.patient;

// ------------------------------------------------------------------ plumbing
async function api(method, path, body) {
  const headers = { "X-HealthSafe": "1" };                     // CSRF guard: the server refuses state changes without it
  if (body) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, credentials: "same-origin", headers, body: body ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await r.json(); } catch (_) { /* non-JSON */ }
  const detail = data && data.detail ? (Array.isArray(data.detail) ? data.detail.map((d) => d.msg || String(d)).join("; ") : String(data.detail)) : null;
  if (r.status === 401 && !path.startsWith("/api/auth/")) {
    showLogin(detail && detail !== "sign in first" ? `Signed out: ${esc(detail)}.` : "Your session ended. Please sign in again.");
    throw new Error("signed out");
  }
  if (!r.ok) { const e = new Error(detail || `${r.status} ${r.statusText}`); e.status = r.status; throw e; }
  return data;
}
function toast(msg, err = false) {                               // slides in, then out (styles.css)
  const t = $("#toast"); t.textContent = msg.charAt(0).toUpperCase() + msg.slice(1); t.className = "toast" + (err ? " err" : "");
  void t.offsetWidth; t.classList.add("show");
  clearTimeout(toast._h); clearTimeout(toast._h2);
  toast._h = setTimeout(() => { t.classList.remove("show"); toast._h2 = setTimeout(() => t.classList.add("hidden"), 350); }, err ? 6000 : 3000);
}
function reveal(el) {                                            // show a fresh result, replaying its entrance animation
  el.className = "result"; void el.offsetWidth; el.classList.add("reveal");
}
document.addEventListener("pointerdown", (e) => {                // ripple from the pointer on every clickable control
  const b = e.target.closest(".btn, .chip, .tab, .shortcut, .node button, .src-card");
  if (!b || b.disabled || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const r = b.getBoundingClientRect(), d = Math.max(r.width, r.height) * 2.2, w = document.createElement("span");
  w.className = "ripple"; w.style.cssText = `width:${d}px;height:${d}px;left:${e.clientX - r.left - d / 2}px;top:${e.clientY - r.top - d / 2}px`;
  b.appendChild(w); w.addEventListener("animationend", () => w.remove());
});
async function busy(btn, fn, onError) {
  if (btn.dataset.busy) return;                                  // ignore clicks while a call is in flight
  btn.dataset.busy = "1"; const label = btn.innerHTML; btn.disabled = true; btn.textContent = "Working…"; btn.classList.add("is-busy");
  try { return await fn(); }
  catch (e) { if (e.message !== "signed out") { toast(e.message, true); if (onError) onError(e); } }
  finally { delete btn.dataset.busy; btn.disabled = false; btn.innerHTML = label; btn.classList.remove("is-busy"); }
}
const pill = (ok, yes, no) => `<span class="pill ${ok ? "ok" : "bad"}">${esc(ok ? yes : no)}</span>`;
const greeting = () => { const h = new Date().getHours(); return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening"; };
const firstName = (n) => (n || "").replace(/^Dr\.\s*/, "").split(/[ ,]/)[0];
function dur(seconds) {                                          // "23 h 58 min", "4 min", "< 1 min"
  const m = Math.floor(seconds / 60);
  if (m < 1) return "< 1 min";
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (h < 48) return `${h} h${m % 60 ? ` ${m % 60} min` : ""}`;
  return `${d} days${h % 24 ? ` ${h % 24} h` : ""}`;
}
function avatar(u, cls = "") {                                   // initials on a role-coloured tile (no photos)
  const ini = (u.name || u.username || "?").split(/\s+/).filter((w) => /^[A-Za-z]/.test(w)).slice(0, 2).map((w) => w[0]).join("").toUpperCase();
  return `<span class="avatar ini r-${esc(u.role || "patient")}${u.staff_role === "nurse" ? " r-nurse" : ""} ${cls}" aria-hidden="true">${esc(ini)}</span>`;
}
function statCards(rows) {
  return rows.map(([k, v, s, ic, glyph, alert]) => `<div class="stat${alert ? " alert" : ""}"><span class="ic i-${ic}" aria-hidden="true">${glyph}</span>` +
    `<div><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div></div>`).join("");
}
function emptyRow(n, msg) { return `<tr><td colspan="${n}" class="muted">${esc(msg)}</td></tr>`; }
const hospName = (h) => (CTX && CTX.hospital_names[h]) || h;
function intIn(sel, lo, hi, def) {                               // read a whole number, clamp it, and show the value actually used
  const el = $(sel); let v = Math.round(Number(el.value));
  if (el.value.trim() === "" || !Number.isFinite(v)) v = def;
  v = Math.min(hi, Math.max(lo, v)); el.value = v; return v;
}

// ------------------------------------------------------------------ SVG line chart (sized to its container)
let chartSeq = 0;
function lineChart(el, series, { yLabel = "bpm", xLabel = "time step", clip = false, minSpan = 0, missingLabel = null } = {}) {
  const W = Math.max(320, Math.round(el.clientWidth || 800)), H = W < 520 ? 200 : 240, L = 54, R = 12, T = 14, B = 34;
  const all = series.flatMap((s) => s.values.filter((v) => v !== null && v !== undefined && Number.isFinite(v)));
  if (!all.length) { el.innerHTML = '<div class="note">No values to plot.</div>'; return; }
  let lo = Math.min(...all), hi = Math.max(...all), clipped = 0;
  if (clip) {                                                    // timing spikes (GC, scheduler) would flatten the rest
    const srt = [...all].sort((a, b) => a - b), p = srt[Math.floor(0.98 * (srt.length - 1))];
    clipped = all.filter((v) => v > p).length; if (clipped) hi = p;
  }
  if (hi - lo < minSpan) { const mid = (hi + lo) / 2; lo = mid - minSpan / 2; hi = mid + minSpan / 2; }   // ±1 bpm must not look like a spike
  const mag = Math.max(Math.abs(hi), Math.abs(lo), 1e-9);
  if (hi - lo < mag * 1e-3) { const p = mag * 0.05 || 1; lo -= p; hi += p; }
  const pad = (hi - lo) * 0.08; lo -= pad; hi += pad;
  if (Math.min(...all) >= 0 && lo < 0) lo = 0;
  const n = Math.max(...series.map((s) => s.values.length));
  const X = (i) => L + (n <= 1 ? 0 : (i / (n - 1)) * (W - L - R)), Y = (v) => T + (1 - (Math.min(v, hi) - lo) / (hi - lo)) * (H - T - B);
  const id = `cg${++chartSeq}`, step = (hi - lo) / 4;
  const dp = Math.min(6, Math.max(0, Math.ceil(-Math.log10(step)) + 1));
  let defs = "", g = "", missing = 0;
  for (let k = 0; k <= 4; k++) {
    const v = lo + k * step, y = Y(v);
    g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="${C.grid}" stroke-dasharray="${k ? "3 5" : ""}"/>` +
      `<text x="${L - 8}" y="${y + 4}" font-size="11" text-anchor="end" fill="${C.muted}">${v.toFixed(dp)}</text>`;
  }
  for (let k = 0; k <= 4; k++) {                                // x ticks
    const i = Math.round(k * (n - 1) / 4);
    g += `<text x="${X(i)}" y="${H - B + 22}" font-size="10" text-anchor="middle" fill="${C.muted}">${i + 1}</text>`;
  }
  series.forEach((s, si) => {
    let d = "", pen = false, segs = [], cur = [];
    s.values.forEach((v, i) => {
      if (v === null || v === undefined || !Number.isFinite(v)) { pen = false; if (cur.length) segs.push(cur); cur = []; return; }
      d += `${pen ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`; pen = true; cur.push([X(i), Y(v)]);
    });
    if (cur.length) segs.push(cur);
    if (s.area) {
      defs += `<linearGradient id="${id}a${si}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${s.color}" stop-opacity=".32"/><stop offset="1" stop-color="${s.color}" stop-opacity="0"/></linearGradient>`;
      for (const sg of segs) if (sg.length > 1) g += `<path class="fade" d="M${sg.map((p) => p.map((q) => q.toFixed(1)).join(",")).join("L")}L${sg[sg.length - 1][0].toFixed(1)},${H - B}L${sg[0][0].toFixed(1)},${H - B}Z" fill="url(#${id}a${si})"/>`;
    }
    g += `<path ${s.dash ? 'class="fade"' : 'class="draw" pathLength="1"'} d="${d}" fill="none" stroke="${s.color}" stroke-width="${s.width || 2}" stroke-linejoin="round" stroke-linecap="round" ${s.dash ? 'stroke-dasharray="5 4"' : ""}/>`;
    if (s.markMissing) s.values.forEach((v, i) => { if (v === null) { missing++; g += `<circle cx="${X(i)}" cy="${H - B + 6}" r="3" fill="${C.red}"/>`; } });
  });
  g += `<text x="${(W + L) / 2}" y="${H - 1}" font-size="11" text-anchor="middle" fill="${C.muted}">${esc(xLabel)}</text>`;
  g += `<text x="12" y="${(H - B) / 2}" font-size="11" text-anchor="middle" fill="${C.muted}" transform="rotate(-90 12 ${(H - B) / 2})">${esc(yLabel)}</text>`;
  const legend = series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.name)}</span>`);
  if (missing && missingLabel) legend.push(`<span><i class="dot" style="background:${C.red}"></i>${esc(missingLabel)}</span>`);
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="height:${H}px" role="img" aria-label="${esc(series.map((s) => s.name).join(", "))} chart"><defs>${defs}</defs>${g}</svg>` +
    `<div class="legend">${legend.join("")}</div>` +
    (clipped ? `<div class="note">${clipped} outlier${clipped > 1 ? "s" : ""} above the 98th percentile drawn at the top edge.</div>` : "");
}

// ------------------------------------------------------------------ login
async function showLogin(msg, isError = true) {
  ME = null; clearInterval(POLL);
  $("#appView").classList.add("hidden"); $("#loginView").classList.remove("hidden");
  document.title = `${P.name} · HealthSafe`;
  $("#loginImg").src = `/static/art/${P.img}`; $("#loginBadge").textContent = P.badge;
  $("#loginTagline").textContent = P.tagline; $("#loginBlurb").textContent = P.blurb;
  $("#loginEyebrow").textContent = P.name; $("#loginHint").textContent = P.hint;
  $("#otherPortals").innerHTML = "Other portals: " + Object.entries(PORTALS).filter(([k]) => k !== PORTAL)
    .map(([k, v]) => `<a href="/${k}">${esc(v.name.replace(" portal", ""))}</a>`).join(" · ");
  const err = $("#loginErr");
  if (msg) { err.innerHTML = msg; err.classList.toggle("info", !isError); err.classList.remove("hidden"); } else err.classList.add("hidden");
  try {
    const st = await (await fetch("/api/status")).json();
    $("#demoUsers").innerHTML = (st.demo_users[PORTAL] || []).map((u) => `<button type="button" class="chip" data-user="${esc(u)}">${esc(u)}</button>`).join("");
  } catch (_) { $("#demoUsers").innerHTML = '<span class="muted">Server offline.</span>'; }
  $("#loginUser").focus();
}

async function doLogin(e) {
  e.preventDefault();
  const btn = $("#loginBtn"), err = $("#loginErr");
  btn.disabled = true; err.classList.add("hidden");
  try {
    await api("POST", "/api/auth/login", { username: $("#loginUser").value, password: $("#loginPass").value, portal: PORTAL });
    $("#loginPass").value = ""; await enterApp();
  } catch (ex) {
    err.textContent = ex.message.charAt(0).toUpperCase() + ex.message.slice(1) + "."; err.classList.remove("info"); err.classList.remove("hidden");
    $("#loginPass").value = ""; $("#loginPass").focus();
  } finally { btn.disabled = false; }
}

async function logout() {
  try { await api("POST", "/api/auth/logout"); } catch (_) { /* already out */ }
  location.replace(location.pathname);                         // a fresh page: nothing from this user stays on screen
}

// ------------------------------------------------------------------ app shell
async function enterApp() {
  ME = await api("GET", "/api/auth/me");
  if (ME.role !== PORTAL) {                                      // keep the other portal's session: just point the user there
    const other = PORTALS[ME.role];
    return showLogin(`You're signed in to the <b>${esc(other.name)}</b> as ${esc(ME.name)}. <a href="/${esc(ME.role)}">Go there</a>, or sign in here with a ${esc(P.badge.toLowerCase())} account.`, false);
  }
  $("#loginView").classList.add("hidden"); $("#appView").classList.remove("hidden");
  document.title = `${P.name} · HealthSafe`;
  $("#portalName").textContent = P.name;
  $("#baselineCard").classList.toggle("hidden", PORTAL !== "admin");   // ledger, nodes and the paper's flaws: admin only
  $("#topPills").classList.toggle("hidden", PORTAL !== "admin");
  renderUserCard();
  $("#nav").innerHTML = P.nav.map(([k, label, ic]) => `<button class="tab" data-sec="${k}" role="tab" aria-selected="false" aria-controls="sec-${k}"><svg viewBox="0 0 24 24" aria-hidden="true">${ICON[ic]}</svg><span>${esc(label)}</span></button>`).join("");
  $$("#nav .tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.sec, true)));
  await refreshCtx();
  const want = location.hash.slice(1);
  show(P.nav.some(([k]) => k === want) ? want : P.nav[0][0]);
  clearInterval(POLL); POLL = setInterval(tick, 15000);         // keep pills (and read-only views) current
}

function renderUserCard() {
  const sub = PORTAL === "patient" ? (ME.label ? `Patient ${ME.label}` : "Record not available yet")
    : PORTAL === "doctor" ? `${ME.specialty} · ${ME.hospital_name}` : PORTAL === "hospital" ? ME.hospital_name : "Consortium administrator";
  $("#userCard").innerHTML = `${avatar(ME)}<div><div class="uc-name">${esc(ME.name)}</div><div class="uc-sub">${esc(sub)}</div></div>`;
}

async function refreshCtx() {
  let ctx;
  try { ctx = await api("GET", "/api/context"); } catch (e) {
    if (e.status === 503) { loading(true, "The system is still being built…"); setTimeout(refreshCtx, 1000); }
    return;
  }
  loading(false);
  const changed = CTX && CTX.dataset_id !== ctx.dataset_id; CTX = ctx;
  const hosp = CTX.hospitals.map((h) => `<option value="${esc(h)}">${esc(CTX.hospital_names[h])}</option>`).join("");
  { const keep = $("#polEntity").value; $("#polEntity").innerHTML = hosp; if (keep) $("#polEntity").value = keep; }
  if (changed) await datasetChanged();
  if (!CTX.nodes) return;                                        // only the admin's context carries nodes, ledger and dataset
  const nd = CTX.nodes, src = $("#srcPill"), no = $("#nodesPill"), ch = $("#chainPill");
  src.textContent = CTX.source === "wildppg" ? "WildPPG recordings" : "Synthetic sensors"; src.style.setProperty("--dot", C.violet);
  no.textContent = nd.alive < nd.quorum ? `No quorum: ${nd.alive}/${nd.n} nodes alive` : `${nd.alive}/${nd.n} nodes alive`;
  no.style.setProperty("--dot", nd.alive < nd.quorum ? C.red : C.mint);
  ch.textContent = CTX.chain_valid ? "Chain valid" : "Chain broken"; ch.style.setProperty("--dot", CTX.chain_valid ? C.mint : C.red);
}

async function datasetChanged() {                               // the admin loaded a new dataset: new ledger, new pseudonyms
  $("#dsBannerText").textContent = PORTAL === "admin" ? "A new dataset was loaded: the ledger, pseudonyms and consent were rebuilt."
    : "HealthSafe was updated. Reload to see the latest information.";
  $("#dsBanner").classList.remove("hidden");
  try { ME = await api("GET", "/api/auth/me"); renderUserCard(); } catch (_) { return; }
  clearDecision("The patient list changed. Choose a patient and try again.");
  if (SEC) (LOADERS[SEC] || (() => {}))();
}

function tick() {
  if (document.hidden || !ME) return;
  refreshCtx();
  if (PORTAL === "hospital" && SEC) (LOADERS[SEC] || (() => {}))();   // read-only views refresh themselves
}
function loading(on, text) { $("#loading").classList.toggle("hidden", !on); if (text) $("#loadingText").textContent = text; }

function show(sec, push = false) {
  if (!P.nav.some(([k]) => k === sec)) sec = P.nav[0][0];
  SEC = sec;
  if (push && location.hash.slice(1) !== sec) history.pushState(null, "", "#" + sec); else history.replaceState(null, "", "#" + sec);
  $$("#nav .tab").forEach((t) => { const on = t.dataset.sec === sec; t.classList.toggle("active", on); t.setAttribute("aria-selected", on); });
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `sec-${sec}`));
  const [, label, , title] = P.nav.find(([k]) => k === sec);
  $("#viewEyebrow").textContent = `${P.name} · ${label}`;
  $("#viewTitle").textContent = title || `${greeting()}, ${firstName(ME.name)} 👋`;
  refreshCtx();
  (LOADERS[sec] || (() => {}))();
}

// ------------------------------------------------------------------ plain-language labels (patient, clinician, hospital)
const RES = { EHR: "health record", audit_logs: "access history" };
const ACT = { read: "View", write: "Edit" };
const WHO = { doctor: "Doctors", nurse: "Nurses", auditor: "Auditors" };
const permText = (p) => `${ACT[p.access] || p.access} ${RES[p.resource] || p.resource} · ${WHO[p.role] || p.role}`;
function permStatus(p) {
  if (p.status === "active") return `<span class="pill ok">active · ${esc(dur(p.expires - Date.now() / 1000))} left</span>`;
  if (p.status === "replaced") return '<span class="pill soft-grey">replaced</span>';
  return `<span class="pill bad">${esc(p.status)}</span>`;
}
function outcomePill(o) {
  return { granted: '<span class="pill ok">granted</span>', denied: '<span class="pill bad">denied</span>' }[o] ||
    '<span class="pill warnc">not completed</span>';
}

// ------------------------------------------------------------------ patient
function ledgerNote(l) {                                         // admin only: where a change landed on the ledger
  if (!l) return "";
  if (l.block === null || l.block === undefined) return `<span class="pill bad">Not saved to the ledger: ${esc(l.error || "no quorum")}</span>`;
  const rej = l.rounds.filter((r) => !r.committed).length;
  return `Saved to the ledger in block #${l.block}` + (rej ? `, after ${rej} round(s) rejected from a compromised leader` : "") + ".";
}

function patientMissing() {
  const missing = !!ME.record_missing;
  $$(".p-needs-record").forEach((el) => el.classList.toggle("hidden", missing));
  $$(".p-no-record").forEach((el) => el.classList.toggle("hidden", !missing));
  if (missing) for (const id of ["#pStats", "#pVitals", "#pAccess", "#pPolicies", "#pHist"]) $(id).innerHTML = "";
  return missing;
}

async function patientData() {
  if (patientMissing()) return null;
  try { return await api("GET", "/api/patient"); } catch (e) {
    if (e.message !== "signed out") { ME = await api("GET", "/api/auth/me").catch(() => ME); renderUserCard(); if (!patientMissing()) toast(e.message, true); }
    return null;
  }
}

async function loadPatientHome() {
  $("#pHello").textContent = ME.name;
  const v = await patientData(); if (!v) return;
  const q = v.vitals.hr.filter((x) => x === null).length, ok = v.vitals.hr.filter((x) => x !== null);
  const mean = ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : null, access = v.hospitals.filter((h) => h.has_access).map((h) => h.hospital);
  $("#pStats").innerHTML = statCards([
    ["Average heart rate", mean === null ? "–" : `${mean.toFixed(0)} bpm`, `${ok.length} readings`, "rose", "&#9829;"],
    ["Unreliable readings", q, "left out of your chart", "violet", "&#9888;", q > 10],
    ["Hospitals with access", access.length, access.length ? access.map(hospName).join(", ") : "nobody right now", "sky", "&#9919;"],
    ["Active permissions", v.permissions.filter((p) => p.status === "active").length, `${v.permissions.length} given in total`, "mint", "&#10010;"],
  ]);
  const series = [{ name: "Heart rate", color: C.rose, values: v.vitals.hr, markMissing: true, area: true }];
  if (v.vitals.reference) series.push({ name: "Reference (ECG)", color: C.violet, values: v.vitals.reference, dash: true, width: 1.6 });
  lineChart($("#pVitals"), series, { xLabel: "reading", minSpan: 20, missingLabel: "unreliable reading" });
  $("#pVitalsNote").textContent = `${v.vitals.hr.length} readings.` + (v.vitals.reference ? " The dashed line is an ECG reference taken at the same time." : "");
}

async function loadPatientConsent() {
  const v = await patientData(); if (!v) return;
  $("#pAccess").innerHTML = "<tr><th scope='col'>Hospital</th><th scope='col'>Access</th><th scope='col'>Permission</th><th scope='col'>Time left</th><th></th></tr>" +
    v.hospitals.map((h) => `<tr><td><b>${esc(hospName(h.hospital))}</b></td><td>${pill(h.has_access, "can see your record", "no access")}</td>` +
      `<td>${h.current ? esc(permText(h.current)) : '<span class="muted">–</span>'}</td><td>${h.current ? esc(dur(h.current.expires - Date.now() / 1000)) : '<span class="muted">–</span>'}</td>` +
      `<td>${h.current ? `<button class="btn danger" data-withdraw="${esc(h.hospital)}">Withdraw</button>` : ""}</td></tr>`).join("");
  $("#pPolicies").innerHTML = "<tr><th scope='col'>Hospital</th><th scope='col'>Permission</th><th scope='col'>Status</th></tr>" +
    (v.permissions.length ? v.permissions.map((p) => `<tr class="${p.status === "active" ? "" : "dim"}"><td>${esc(hospName(p.hospital))}</td>` +
      `<td>${esc(permText(p))}</td><td>${permStatus(p)}</td></tr>`).join("") : emptyRow(3, "You haven't given any permissions."));
}

async function patientAction(btn, path, body, okMsg, confirmText) {
  if (confirmText && !confirm(confirmText)) return;
  await busy(btn, async () => { await api("POST", `/api/patient/${path}`, body); toast(okMsg); await loadPatientConsent(); });
}

async function loadPatientHistory() {
  if (patientMissing()) return;
  let h; try { h = await api("GET", "/api/patient/history"); } catch (e) { return; }
  const cls = { you: "soft", granted: "ok", denied: "bad", unavailable: "warnc" };
  const tag = { you: "you", granted: "allowed", denied: "declined", unavailable: "not completed" };
  $("#pHistNote").textContent = `${h.total} event${h.total === 1 ? "" : "s"}`;
  $("#pHist").innerHTML = "<tr><th scope='col'>When</th><th scope='col'>What happened</th><th></th></tr>" +
    (h.events.length ? h.events.map((e) => `<tr><td class="nowrap">${when(e.t)}</td><td>${esc(e.text)}</td><td><span class="pill ${cls[e.kind]}">${tag[e.kind]}</span></td></tr>`).join("")
      : emptyRow(3, "Nothing yet."));
}

// ------------------------------------------------------------------ doctor
let DPATS = [];
async function loadDoctorPatients(selectOnly = false) {
  try { DPATS = await api("GET", "/api/doctor/patients"); } catch (e) { return; }
  const keep = $("#dPatient").value;
  $("#dPatient").innerHTML = DPATS.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}${p.access ? "" : " (no access)"}</option>`).join("");
  if (DPATS.some((p) => p.id === keep)) $("#dPatient").value = keep;
  $("#dAsWho").innerHTML = `Signed in as <b>${esc(ME.name)}</b>, ${esc(ME.hospital_name)}.`;
  if (selectOnly) return;
  $("#dPatients").innerHTML = "<tr><th scope='col'>Patient</th><th scope='col' class='num'>Readings</th><th scope='col'>Health record</th><th></th></tr>" +
    DPATS.map((p) => `<tr><td><b>${esc(p.label)}</b></td><td class="num">${p.n_records}</td><td>${pill(p.access, "you can open it", "not shared with you")}</td>` +
      `<td><button class="btn" data-req="${esc(p.id)}">Open</button></td></tr>`).join("");
}

function clearDecision(msg) {
  $("#dResult").className = "result empty"; $("#dResult").textContent = msg;
  $("#dChart").innerHTML = '<div class="note">No record open.</div>'; $("#dChartNote").textContent = "";
}

async function doRequest(btn) {
  const body = { pseud: $("#dPatient").value, resource: $("#dRes").value, action: $("#dAct").value };
  await busy(btn, async () => {
    const r = await api("POST", "/api/doctor/request", body);
    const what = `${ACT[r.action].toLowerCase()} ${r.patient}'s ${RES[r.resource]}`;
    const msg = { granted: r.record ? `You can ${what}.` : `You can ${what}. There is nothing to display for this request.`,
      denied: `You don't have access to ${what}.`,
      unavailable: "The request could not be completed right now. Please try again shortly." }[r.status];
    reveal($("#dResult"));
    $("#dResult").innerHTML = `<div class="verdict">${r.status === "granted" ? '<span class="pill ok">ACCESS GRANTED</span>' : r.status === "denied" ? '<span class="pill bad">ACCESS DENIED</span>' : '<span class="pill warnc">TRY AGAIN LATER</span>'}</div>` +
      `<p class="muted">${esc(msg)}</p>`;
    if (r.record) {
      const s = [{ name: "Heart rate", color: C.rose, values: r.record.hr, markMissing: true, area: true }];
      if (r.record.reference) s.push({ name: "Reference (ECG)", color: C.violet, values: r.record.reference, dash: true, width: 1.6 });
      lineChart($("#dChart"), s, { xLabel: "reading", minSpan: 20, missingLabel: "unreliable reading" });
      $("#dChartNote").textContent = `${r.patient} · ${r.record.hr.length} readings.`;
    } else { $("#dChart").innerHTML = '<div class="note">No record open.</div>'; $("#dChartNote").textContent = ""; }
  }, async (e) => {
    if (/unknown patient/.test(e.message)) { await loadDoctorPatients(true); clearDecision("The patient list changed. Choose a patient again."); }
  });
}

function reqRows(rows, withWho) {
  return rows.map((r) => `<tr class="${r.outcome === "granted" ? "" : "flag"}"><td class="nowrap">${when(r.t)}</td>` +
    (withWho ? `<td>${esc(r.by ? r.by.name : "–")} <span class="muted">${esc(r.by ? r.by.role : "")}</span></td>` : "") +
    `<td class="nowrap"><b>${esc(r.patient)}</b></td><td>${esc(ACT[r.action])} ${esc(RES[r.resource])}</td><td>${outcomePill(r.outcome)}</td></tr>`).join("");
}

async function loadDoctorHistory() {
  let rows; try { rows = await api("GET", "/api/doctor/history"); } catch (e) { return; }
  $("#dHist").innerHTML = "<tr><th scope='col'>Time</th><th scope='col'>Patient</th><th scope='col'>Request</th><th scope='col'>Result</th></tr>" +
    (rows.length ? reqRows(rows, false) : emptyRow(4, "No requests yet."));
}

// ------------------------------------------------------------------ hospital
let HV = null;
async function hospitalData() { try { HV = await api("GET", "/api/hospital"); } catch (e) { HV = null; } if (HV) $$(".h-updated").forEach((el) => { el.textContent = `Updated ${new Date().toLocaleTimeString()}`; }); return HV; }

async function loadHospitalHome() {
  const v = await hospitalData(); if (!v) return;
  $("#hName").textContent = v.name; $("#hCode").textContent = "Your hospital";
  const s = v.stats;
  $("#hStats").innerHTML = statCards([
    ["Records you can open", `${s.readable}/${s.patients}`, `${s.sharing} patient${s.sharing === 1 ? "" : "s"} share with you`, "violet", "&#9786;"],
    ["Requests", s.requests, `since ${clock(v.since)}`, "sky", "&#9776;"],
    ["Granted", s.granted, "records opened", "mint", "&#10003;"],
    ["Not granted", s.denied, "denied or not completed", "rose", "&#10007;", s.denied > 0],
  ]);
  $("#hRecent").innerHTML = v.requests.length ? `<table class="tbl"><tr><th scope="col">Time</th><th scope="col">By</th><th scope="col">Patient</th><th scope="col">Result</th></tr>` +
    v.requests.slice(0, 6).map((r) => `<tr><td class="nowrap">${when(r.t)}</td><td>${esc(r.by ? r.by.name : "–")}</td><td>${esc(r.patient)}</td><td>${outcomePill(r.outcome)}</td></tr>`).join("") + "</table>"
    : '<div class="note">No requests yet. They appear here when your staff open records.</div>';
  $("#hStaffMini").innerHTML = v.staff.map((m) => `<div class="staff-row${m.disabled ? " off" : ""}">${avatar(m)}<div><b>${esc(m.name)}</b>${m.disabled ? ' <span class="pill bad">disabled</span>' : ""}<div class="sub">${esc(m.specialty)} · ${esc(m.staff_role)}</div></div></div>`).join("") ||
    '<div class="note">No staff accounts.</div>';
  if (s.sharing === 0) $("#hRecent").insertAdjacentHTML("afterbegin", `<div class="callout">No patient shares their record with ${esc(v.name)} yet.</div>`);
}

async function loadHospitalPatients() {
  const v = await hospitalData(); if (!v) return;
  const none = v.stats.sharing === 0;
  $("#hPatientsNote").innerHTML = none ? `<div class="callout">No patient shares their record with ${esc(v.name)} yet. Patients give access from their own HealthSafe account.</div>` : "";
  const share = { shared: '<span class="pill ok">shared</span>', withdrawn: '<span class="pill bad">withdrawn</span>', "not shared": '<span class="pill soft-grey">not shared</span>' };
  $("#hPatients").innerHTML = "<tr><th scope='col'>Patient</th><th scope='col'>Health record</th><th scope='col'>Sharing</th><th scope='col'>Permissions</th></tr>" +
    v.patients.map((p) => `<tr class="${p.can_view || none ? "" : "flag"}"><td><b>${esc(p.label)}</b></td><td>${pill(p.can_view, "can open", "cannot open")}</td>` +
      `<td>${share[p.sharing]}</td>` +
      `<td>${p.permissions.length ? p.permissions.map((x) => `<div class="pol-line">${esc(permText(x))} ${permStatus(x)}</div>`).join("") : '<span class="muted">none</span>'}</td></tr>`).join("");
}

async function loadHospitalLog() {
  const v = await hospitalData(); if (!v) return;
  $("#hLogNote").textContent = v.stats.requests > v.requests_shown ? `Showing the latest ${v.requests_shown} of ${v.stats.requests} requests.`
    : `${v.stats.requests} request${v.stats.requests === 1 ? "" : "s"} since ${clock(v.since)}.`;
  $("#hLog").innerHTML = "<tr><th scope='col'>Time</th><th scope='col'>Staff</th><th scope='col'>Patient</th><th scope='col'>Request</th><th scope='col'>Result</th></tr>" +
    (v.requests.length ? reqRows(v.requests, true) : emptyRow(5, "No requests yet."));
}

async function loadHospitalStaff() {
  const v = await hospitalData(); if (!v) return;
  $("#hStaff").innerHTML = v.staff.map((m) => `<div class="card staff-card${m.disabled ? " off" : ""}">${avatar(m, "lg")}<h3>${esc(m.name)}</h3>` +
    `<div class="sub">${esc(m.specialty)}</div><div class="row" style="justify-content:center;margin-top:10px"><span class="pill i-violet">${esc(m.staff_role)}</span>` +
    `<span class="pill soft">${v.per_staff[m.username] || 0} requests</span>${m.disabled ? '<span class="pill bad">disabled</span>' : ""}</div><div class="mono muted" style="margin-top:8px">${esc(m.username)}</div></div>`).join("") ||
    '<div class="card note">No staff accounts for this hospital.</div>';
}

// ------------------------------------------------------------------ admin: access requests and the reasons behind them
const PRESETS = {
  valid: { resource: "EHR", action: "read", corrupt: 0, ledger: false },
  corrupt: { resource: "EHR", action: "read", corrupt: 2, ledger: false },
  corrupt3: { resource: "EHR", action: "read", corrupt: 3, ledger: false },
  write: { resource: "EHR", action: "write", corrupt: 0, ledger: false },
  audit: { resource: "audit_logs", action: "read", corrupt: 0, ledger: false },
  ledger: { resource: "EHR", action: "read", corrupt: 0, ledger: true },
};
function piText(p) {
  if (!p) return "none";
  return `⟨${esc(p.entity)}, ${esc(p.role)}, ${esc(p.resource)}, ${esc(p.access)}, ${p.expired ? "expired" : "valid"}⟩`;
}

function decisionHtml(r, fromLedger) {                           // the full step-by-step decision (admin only)
  const tok = r.token, pol = r.policy, led = r.ledger;
  const attempts = tok.attempts.map((a) => `<div class="sub">attempt ${a.attempt}: ${a.corrupted ? "corrupted in transit, " : ""}` +
    `H(s′) ${a.hash_matches ? "= p ✓" : "≠ p ✗"} · token sent in clear <span class="mono">${esc(a.token_sent)}</span></div>`).join("");
  const round = (x) => x.leader === null ? "no leader could be elected: too few nodes alive" :
    `leader node ${x.leader}${x.compromised_leader ? " (compromised)" : ""}: ${x.committed ? `committed in ${fmt(x.latency_ms, 2)} ms, ${x.msgs} messages` : "block rejected by honest validators"}`;
  const committed = led && led.block !== null && led.block !== undefined;
  const steps = tok.skipped ? [
    { cls: "skip", title: "1. Authorisation proof (Algs. 3–4)", body: '<div class="sub">Not run.</div>' },
    { cls: "skip", title: "2. Patient policy (Eqs. 8–10)", body: '<div class="sub">Not run.</div>' },
    { cls: "fail", title: "3. Decision committed through consensus (audit trail)", body: `<div class="sub">${ledgerNote(led)}</div>` },
    { cls: "skip", title: "4. Decrypt and release the record", body: '<div class="sub">Not reached.</div>' },
  ] : [
    { cls: tok.passed ? "pass" : "fail", title: `1. Authorisation proof (Alg. 3, retry up to k = ${tok.k}, Alg. 4)`,
      body: attempts + `<div class="sub">${tok.passed ? "accepted" : "rejected"} in ${fmt(tok.ms, 4)} ms</div>` },
    { cls: pol.passed ? "pass" : "fail", title: "2. Patient policy (Eqs. 8–10)",
      body: `<div class="sub">policy token: ${esc(pol.source)}</div><div class="sub">matched policy: ${piText(pol.matched)}</div>` +
        `<div class="sub">governing policy (Eq. 10, latest t_e): ${piText(pol.governing)}</div>` },
    { cls: committed ? "pass" : "fail", title: "3. Decision committed through consensus (audit trail)",
      body: `<div class="sub">${ledgerNote(led)}</div>` + (led ? led.rounds.map((x) => `<div class="sub">${esc(round(x))}</div>`).join("") : "") },
    { cls: r.record ? "pass" : "skip", title: "4. Decrypt and release the record",
      body: r.record ? `<div class="sub">${r.record.n_ciphertexts} ciphertexts decrypted in ${fmt(r.record.decrypt_ms, 2)} ms</div>`
        : `<div class="sub">${r.tampered_blocks ? "Integrity check failed: the ledger copy was tampered with." : r.granted ? "Granted, but only a health-record read releases data." : "Not reached."}</div>` },
  ];
  return `<div class="verdict">${r.granted ? '<span class="pill ok">ACCESS GRANTED</span>' : '<span class="pill bad">ACCESS DENIED</span>'}` +
    `<span class="muted" style="font-size:13px;font-weight:400">${esc(hospName(r.hospital))} → ${esc(r.patient)}, ${esc(r.action)} ${esc(r.resource)}</span></div>` +
    (r.reason ? `<div class="reason">${esc(r.reason)}</div>` : "") +
    `<ul class="steps">${steps.map((s) => `<li class="${s.cls}"><div class="step-title">${s.title}</div>${s.body}</li>`).join("")}</ul>` +
    (fromLedger && pol.passed ? '<div class="note"><span class="pill warnc">Paper flaw</span> The policy token is stored on the public ledger (Eq. 9), so anyone who reads the ledger can submit it.</div>' : "");
}

async function loadAdminRequests() {
  let rq, ov; try { [rq, ov] = await Promise.all([api("GET", "/api/admin/requests"), api("GET", "/api/admin/overview")]); } catch (e) { return; }
  const keepP = $("#tPatient").value, keepH = $("#tHosp").value;
  $("#tPatient").innerHTML = ov.patients.map((p) => `<option value="${esc(p.pseud)}">${esc(p.label)}</option>`).join("");
  if (ov.patients.some((p) => p.pseud === keepP)) $("#tPatient").value = keepP;
  $("#tHosp").innerHTML = CTX.hospitals.map((h) => `<option value="${esc(h)}">${esc(hospName(h))}</option>`).join("");
  if (keepH) $("#tHosp").value = keepH;
  $("#aReqNote").textContent = rq.total > rq.shown ? `Latest ${rq.shown} of ${rq.total}` : `${rq.total} request${rq.total === 1 ? "" : "s"}`;
  $("#aReqs").innerHTML = "<tr><th scope='col'>Time</th><th scope='col'>Hospital</th><th scope='col'>By</th><th scope='col'>Patient</th><th scope='col'>Request</th>" +
    "<th scope='col'>Checks</th><th scope='col'>Result</th><th scope='col'>Reason</th><th scope='col'>Block</th></tr>" +
    (rq.requests.length ? rq.requests.map((r) => `<tr class="${r.granted ? "" : "flag"}"><td class="nowrap">${when(r.t)}</td><td>${esc(hospName(r.hospital))}</td>` +
      `<td>${esc(r.by ? r.by.name : "–")} <span class="muted">${esc(r.by ? r.by.role : "")}</span></td><td class="nowrap"><b>${esc(r.patient)}</b></td>` +
      `<td>${esc(r.action)} ${esc(r.resource)}${r.ledger_copied ? ' <span class="pill warnc">ledger token</span>' : ""}${r.corrupt_first ? ` <span class="pill soft">${r.corrupt_first} corrupted</span>` : ""}</td>` +
      `<td class="nowrap">${pill(r.token_ok, `token ✓${r.attempts > 1 ? ` (${r.attempts} tries)` : ""}`, "token ✗")} ${pill(r.policy_ok, "policy ✓", "policy ✗")}</td>` +
      `<td>${outcomePill(r.outcome)}</td><td class="why-cell">${esc(r.reason || "All checks passed and the decision was committed.")}</td>` +
      `<td>${r.block === null || r.block === undefined ? "not saved" : "#" + r.block}</td></tr>`).join("") : emptyRow(9, "No requests yet."));
}

async function testRequest(btn) {
  const fromLedger = $("#tLedgerPol").checked;
  const body = { hospital: $("#tHosp").value, pseud: $("#tPatient").value, resource: $("#tRes").value, action: $("#tAct").value,
    corrupt_first: intIn("#tCorrupt", 0, 5, 0), policy_from_ledger: fromLedger };
  $$(".chip[data-preset]").forEach((c) => { c.disabled = true; });
  await busy(btn, async () => {
    const r = await api("POST", "/api/admin/request", body);
    reveal($("#tResult")); $("#tResult").innerHTML = decisionHtml(r, fromLedger);
    loadAdminRequests();
  }, async (e) => { if (/unknown patient/.test(e.message)) loadAdminRequests(); });
  $$(".chip[data-preset]").forEach((c) => { c.disabled = false; });
}

// ------------------------------------------------------------------ admin
let PATIENT_ACCOUNTS = 8;
async function loadAdminHome() {
  let ov; try { ov = await api("GET", "/api/admin/overview"); } catch (e) { return; }
  const nd = ov.nodes;
  $("#aStats").innerHTML = statCards([
    ["Patients", ov.patients.length, ov.config.source === "wildppg" ? "WildPPG participants" : "synthetic wearers", "violet", "&#9786;"],
    ["Blocks", ov.blocks, "after genesis · " + (Object.entries(ov.block_kinds).map(([k, v]) => `${v} ${k}`).join(" · ") || "none"), "sky", "&#9939;"],
    ["Validator nodes", `${nd.alive}/${nd.n}`, `quorum ${nd.quorum}` + (nd.alive < nd.quorum ? " — no quorum" : ""), "mint", "&#9673;", nd.alive < nd.quorum],
    ["Chain", ov.chain_valid ? "Valid" : "Broken", ov.chain_valid ? "every hash link checks" : "tampering detected", "rose", "&#128279;", !ov.chain_valid],
  ]);
  const sc = [["a-requests", "Access requests", "Why each request was granted or refused, and test scenarios.", "sky", "&#9776;"], ["a-dataset", "Dataset", `Loaded: ${ov.config.source}, ${ov.patients.length} patients × ${ov.config.n_steps} readings.`, "violet", "&#8681;"],
    ["a-nodes", "Nodes & consensus", `${nd.alive} of ${nd.n} alive, term ${nd.term}.`, "mint", "&#9673;"],
    ["a-lab", "Attack lab", "Run the seven attacks and the benchmarks.", "rose", "&#9888;"]];
  $("#aShortcuts").innerHTML = sc.map(([k, t, d, ic, g]) => `<button class="card shortcut" data-go="${k}"><span class="ic i-${ic}" aria-hidden="true">${g}</span><div><b>${t}</b><div class="sub">${esc(d)}</div></div><span class="go" aria-hidden="true">&rarr;</span></button>`).join("");
}

async function loadDataset(fillForm = true) {
  let d; try { d = await api("GET", "/api/admin/dataset"); } catch (e) { return; }
  try { PATIENT_ACCOUNTS = ((await (await fetch("/api/status")).json()).demo_users.patient || []).length; } catch (_) { /* keep */ }
  const c = d.current, L = d.limits;
  const wc = $("#dsWildCard"), wr = wc.querySelector("input");
  wr.disabled = !d.wildppg.available; wc.classList.toggle("disabled", !d.wildppg.available);
  $("#dsWildNote").textContent = d.wildppg.available ? `Real body-worn PPG with ECG heart rate as truth. ${d.wildppg.participants.length} participants extracted.`
    : "No extracted WildPPG files found (see data_layer/README.md).";
  $("#dsLimits").textContent = `Limits: patients ${L.n_patients[0]}–${L.n_patients[1]}, readings ${L.n_steps[0]}–${L.n_steps[1]}, nodes ${L.n_nodes[0]}–${L.n_nodes[1]}. ` +
    "Crashed + compromised must fit in the nodes, and more than half the nodes must start alive (otherwise nothing can be committed).";
  if (c) {
    if (fillForm) {
      $$('input[name="dsSource"]').forEach((r) => { r.checked = r.value === c.source; });
      $("#dsPatients").value = c.n_patients; $("#dsSteps").value = c.n_steps; $("#dsNodes").value = c.n_nodes; $("#dsCrashed").value = c.crashed; $("#dsComp").value = c.compromised;
    }
    $("#dsCurrent").innerHTML = `<div class="kv"><span>Source</span><b>${c.source === "wildppg" ? "WildPPG recordings" : "Synthetic sensors"}</b></div>` +
      `<div class="kv"><span>Patients</span><b>${c.patients.length}</b></div><div class="kv"><span>Readings each</span><b>${c.n_steps}</b></div>` +
      `<div class="kv"><span>Validator nodes</span><b>${c.n_nodes} (${c.crashed} crashed, ${c.compromised} compromised at start)</b></div>` +
      `<p class="note">${esc(c.source_desc)}</p>`;
    $("#dsPatientsTbl").innerHTML = "<tr><th scope='col'>#</th><th scope='col'>Record</th><th scope='col'>Pseudonym</th><th scope='col' class='num'>Readings</th><th scope='col'>Ground truth</th><th scope='col'>Patient account</th></tr>" +
      c.patients.map((p, i) => `<tr><td>${i + 1}</td><td><b>${esc(p.label)}</b></td><td class="mono">${esc(p.pseud)}</td><td class="num">${p.n_records}</td>` +
        `<td>${p.has_truth ? '<span class="pill ok">ECG</span>' : '<span class="muted">–</span>'}</td><td class="mono">${i < PATIENT_ACCOUNTS ? `patient${i + 1}` : '<span class="muted">no account</span>'}</td></tr>`).join("");
    $("#dsWarn").textContent = c.patients.length < PATIENT_ACCOUNTS
      ? `Patient accounts patient${c.patients.length + 1}–patient${PATIENT_ACCOUNTS} have no record in this dataset; they see an explanation when they sign in.` : "";
  }
  $("#dsParts").textContent = d.wildppg.available ? `WildPPG participants on disk: ${d.wildppg.participants.join(", ")}.` : "";
}

async function loadDatasetGo(btn) {
  const src = ($$('input[name="dsSource"]').find((r) => r.checked) || {}).value || "synthetic";
  const body = { source: src, n_patients: intIn("#dsPatients", 2, 16, 8), n_steps: intIn("#dsSteps", 20, 400, 100), n_nodes: intIn("#dsNodes", 4, 31, 7),
    crashed: intIn("#dsCrashed", 0, 30, 0), compromised: intIn("#dsComp", 0, 30, 0) };
  if (!confirm(`Load the ${src === "wildppg" ? "WildPPG" : "synthetic"} dataset? This rebuilds the ledger: every patient's consent, policies and the request logs start fresh.`)) return;
  loading(true, `Loading the ${src === "wildppg" ? "WildPPG" : "synthetic"} dataset and rebuilding the ledger…`);
  let ok = false;
  await busy(btn, async () => { await api("POST", "/api/admin/dataset", body); ok = true; toast(`Dataset loaded: ${src}`); });
  loading(false); await refreshCtx(); loadDataset(ok);               // on failure keep what the admin typed
}

async function loadNodes() {
  let led, ov; try { [led, ov] = await Promise.all([api("GET", "/api/admin/ledger"), api("GET", "/api/admin/overview")]); } catch (e) { return; }
  const nd = ov.nodes;
  $("#aNoQuorum").classList.toggle("hidden", nd.alive >= nd.quorum);
  $("#aNoQuorum").querySelector(".why").textContent = `Only ${nd.alive} of ${nd.n} nodes are alive; ${nd.quorum} are needed. Nothing can be written to the ledger, so every record request is refused.`;
  $("#aQuorumLine").textContent = `${nd.alive} of ${nd.n} alive · quorum ${nd.quorum} · term ${nd.term}`;
  $("#aNodes").innerHTML = nd.nodes.map((n) => `<div class="node ${n.alive ? "" : "down"} ${n.compromised ? "evil" : ""}">` +
    `<div class="nid">Node ${n.id}</div><div class="nst">${n.alive ? "alive" : "crashed"}${n.compromised ? " · compromised" : ""}</div>` +
    `<button data-node="${n.id}" data-act="${n.alive ? "crash" : "recover"}" aria-label="${n.alive ? "Crash" : "Recover"} node ${n.id}">${n.alive ? "Crash" : "Recover"}</button>` +
    `<button data-node="${n.id}" data-act="compromise" aria-label="${n.compromised ? "Restore" : "Compromise"} node ${n.id}">${n.compromised ? "Restore" : "Compromise"}</button></div>`).join("");
  $("#aCons").innerHTML = led.consensus.map((c) => {
    const ran = c.rounds.filter((x) => x.leader !== null), rej = ran.filter((x) => !x.committed).length;
    return `<div class="cons-row"><b>${esc(c.why)}</b><span>` + (c.block !== null && c.block !== undefined ? `block #${c.block}` : `<span class="pill bad">${esc(c.error)}</span>`) +
      ` · ${ran.length ? `${ran.length} round(s), ${rej} rejected` : "not run"}</span></div>`; }).join("") || '<div class="note">None yet.</div>';
}

async function loadLedger() {
  let led; try { led = await api("GET", "/api/admin/ledger"); } catch (e) { return; }
  $("#aValid").className = "pill " + (led.valid ? "ok" : "bad"); $("#aValid").textContent = led.valid ? "chain valid" : "chain broken";
  $("#aLedger").innerHTML = "<tr><th scope='col'>#</th><th scope='col'>Kind</th><th scope='col'>Term</th><th scope='col' class='num'>Tx</th><th scope='col' class='num'>Bytes</th><th scope='col'>Hash</th><th scope='col'>Prev</th><th></th></tr>" +
    led.blocks.slice().reverse().map((b) => `<tr class="${b.hash_ok ? "" : "flag"}"><td>${b.index}</td><td>${esc(b.kind)}</td><td>${b.term ?? "–"}</td>` +
      `<td class="num">${b.n_tx}</td><td class="num">${b.bytes}</td><td class="mono">${esc(b.hash)}${b.hash_ok ? "" : " ✗"}</td><td class="mono">${esc(b.prev)}</td>` +
      `<td class="nowrap"><button class="btn" data-block="${b.index}" data-op="view">View</button> ` +
      (b.index > 0 ? (b.tampered ? `<button class="btn" data-block="${b.index}" data-op="restore">Restore</button>` : `<button class="btn danger" data-block="${b.index}" data-op="tamper">Tamper</button>`) : "") +
      `</td></tr>`).join("");
}

let VIEWED = null;
async function viewBlock(i) {
  try {
    const b = await api("GET", `/api/admin/block/${i}`); VIEWED = i;
    const shown = Object.assign({}, b, { timestamp: `${b.timestamp} (${new Date(b.timestamp * 1000).toLocaleString()})` });
    $("#aBlock").innerHTML = `<div class="row head-row"><h3>Block #${b.index} ${b.hash === b.recomputed ? '<span class="pill ok">hash checks</span>' : '<span class="pill bad">hash mismatch: tampered</span>'}</h3>` +
      `<button class="btn" id="aBlockClose">Close</button></div><pre>${esc(JSON.stringify(shown, null, 2))}</pre>`;
  } catch (e) { toast(e.message, true); }
}
async function blockOp(btn) {
  const i = btn.dataset.block, op = btn.dataset.op;
  if (op === "view") return viewBlock(i);
  await busy(btn, async () => {
    await api("POST", `/api/admin/block/${i}/${op}`);
    toast(op === "tamper" ? `Block #${i} tampered: chain verification now fails` : `Block #${i} restored`);
    await loadLedger(); refreshCtx(); if (VIEWED === i) viewBlock(i);
  });
}

async function loadAudit() {
  let au; try { au = await api("GET", "/api/admin/audit"); } catch (e) { return; }
  $("#aAuditNote").innerHTML = `${au.total} events on-chain. Patient identities on the ledger: ` +
    (au.identity_on_ledger ? '<span class="pill bad">found</span>' : '<span class="pill ok">none (pseudonyms only)</span>');
  $("#aAudit").innerHTML = "<tr><th scope='col'>Block</th><th scope='col'>Event</th><th scope='col'>Pseudonym</th></tr>" +
    au.events.map((e) => `<tr><td>${e.block}</td><td>${esc(e.event)}</td><td class="mono">${esc(e.who)}</td></tr>`).join("");
  $("#aContracts").innerHTML = "<tr><th scope='col'>Block</th><th scope='col'>Rule</th><th scope='col'>Pseudonym</th></tr>" +
    (au.contract_events.length ? au.contract_events.map((e) => `<tr><td>${e.block}</td><td>${esc(e.rule)}</td><td class="mono">${esc(e.who)}</td></tr>`).join("") : emptyRow(3, "No events."));
}

async function loadUsers() {
  let us; try { us = await api("GET", "/api/admin/users"); } catch (e) { return; }
  const order = { admin: 0, hospital: 1, doctor: 2, patient: 3 };
  us.sort((a, b) => order[a.role] - order[b.role] || a.username.localeCompare(b.username));
  $("#aUsers").innerHTML = "<tr><th scope='col'>Account</th><th scope='col'>Portal</th><th scope='col'>Linked to</th><th scope='col'>Signed in</th><th scope='col'>Last sign-in</th><th scope='col'>Status</th><th></th></tr>" +
    us.map((u) => `<tr class="${u.disabled ? "flag" : ""}"><td><div class="row" style="gap:10px;flex-wrap:nowrap">${avatar(u, "sm")}<div><b>${esc(u.name)}</b><div class="mono muted">${esc(u.username)}</div></div></div></td>` +
      `<td><span class="pill i-${{ admin: "mint", hospital: "sky", doctor: "violet", patient: "rose" }[u.role]}">${esc(u.role)}</span></td>` +
      `<td>${u.role === "patient" ? `patient #${u.patient_index + 1}` : u.hospital ? `${esc(u.hospital_name)}${u.staff_role ? ` · ${esc(u.staff_role)}` : ""}` : "–"}</td>` +
      `<td>${u.sessions ? `<span class="pill ok">${u.sessions} session${u.sessions > 1 ? "s" : ""}</span>` : '<span class="muted">–</span>'}</td><td class="nowrap">${when(u.last_login)}</td>` +
      `<td>${u.disabled ? '<span class="pill bad">disabled</span>' : '<span class="pill ok">active</span>'}</td>` +
      `<td>${u.role === "admin" ? "" : `<button class="btn ${u.disabled ? "" : "danger"}" data-user="${esc(u.username)}" data-act="${u.disabled ? "enable" : "disable"}">${u.disabled ? "Enable" : "Disable"}</button>`}</td></tr>`).join("");
}

const failed = (sel) => () => { const el = $(sel); el.className = "result empty"; el.textContent = "That run failed; see the message above. Nothing new to show."; };
async function runAttacks(btn) {
  await busy(btn, async () => {
    const r = await api("POST", "/api/lab/attacks", { n: intIn("#lAttN", 10, 1000, 100) });
    reveal($("#lAttacks"));
    $("#lAttacks").innerHTML = `<div class="bigstat"><div><div class="v ${r.fp_rate > 0 ? "badv" : "okv"}">${r.fp_rate}%</div><div class="k">false-positive rate (attacks accepted)</div></div>` +
      `<div><div class="v okv">${r.fn_rate}%</div><div class="k">false-negative rate (${r.legitimate.accepted}/${r.legitimate.attempts} legitimate accepted)</div></div></div>` +
      "<div class='scroll-x'><table class='tbl'><tr><th scope='col'>Attack</th><th scope='col'>Defence in the paper</th><th scope='col' class='num'>Accepted</th><th></th></tr>" +
      r.rows.map((x) => `<tr class="${x.paper_flaw ? "flag" : ""}"><td>${esc(x.attack)}</td><td>${esc(x.defence)}</td><td class="num">${x.accepted} / ${x.attempts}</td>` +
        `<td>${x.paper_flaw ? '<span class="pill bad">succeeds (paper flaw)</span>' : '<span class="pill ok">blocked</span>'}</td></tr>`).join("") + "</table></div>" +
      "<h3 style='margin-top:18px'>Identity leakage: sensitive values visible in plaintext</h3><div class='scroll-x'><table class='tbl'><tr><th scope='col'>Party / view</th><th scope='col'>Leaked</th></tr>" +
      r.leakage.map((x) => `<tr><td>${esc(x.view)}</td><td>${x.leaked.length ? x.leaked.map((l) => `<span class="pill bad">${esc(l)}</span>`).join(" ") : '<span class="pill ok">none</span>'}</td></tr>`).join("") + "</table></div>";
  }, failed("#lAttacks"));
}
async function runVerify(btn) {
  await busy(btn, async () => {
    const r = await api("POST", "/api/lab/bench/verify", { n: intIn("#lVerN", 10, 2000, 500) });
    const el = $("#lVerify"); reveal(el);
    el.innerHTML = `<div class="bigstat"><div><div class="v">${fmt(r.auth.mean, 4)} ms</div><div class="k">proof verification (paper ≈ ${r.paper_auth_ms} ms)</div></div>` +
      `<div><div class="v">${fmt(r.rbac.mean, 4)} ms</div><div class="k">smart-contract RBAC</div></div></div><div class="chart" id="lVerChart"></div>`;
    lineChart($("#lVerChart"), [{ name: "Authorisation proof", color: C.violet, values: r.series.auth, width: 1.4 }, { name: "RBAC", color: C.amber, values: r.series.rbac, width: 1.4 }], { yLabel: "ms", xLabel: "request", clip: true });
  }, failed("#lVerify"));
}
async function runCrypto(btn) {
  await busy(btn, async () => {
    const r = await api("POST", "/api/lab/bench/crypto", { n: intIn("#lCryN", 10, 500, 100) });
    const el = $("#lCrypto"); reveal(el);
    el.innerHTML = "<table class='tbl'><tr><th scope='col'>Scheme</th><th scope='col' class='num'>Enc ms</th><th scope='col' class='num'>Dec ms</th><th scope='col' class='num'>Bytes</th></tr>" +
      r.schemes.map((s) => `<tr><td>${esc(s.scheme)}</td><td class="num">${fmt(s.enc.mean, 4)}</td><td class="num">${fmt(s.dec.mean, 4)}</td><td class="num">${s.bytes}</td></tr>`).join("") +
      "</table><div class='note'>The Kyber-inspired mock is a cost model only: its key can be rebuilt from public data.</div>";
  }, failed("#lCrypto"));
}
async function runCons(btn) {
  const proto = $("#lConsP").value, top = proto === "PBFT" ? 300 : 1000;
  const n = intIn("#lConsN", 4, top, 100), crashed = intIn("#lConsC", 0, n - 1, 0);
  await busy(btn, async () => {
    const r = await api("POST", "/api/lab/bench/consensus", { proto, n, mode: $("#lConsM").value, rounds: 30, crashed });
    const el = $("#lCons"); reveal(el);
    el.innerHTML = r.latency ? `<div class="bigstat"><div><div class="v">${fmt(r.latency.mean, 2)} ms</div><div class="k">latency per block</div></div>` +
      `<div><div class="v">${fmt(r.tps.mean, 0)}</div><div class="k">TPS (20 tx/block)</div></div></div>` +
      `<div class="note">${esc(r.proto)}, ${r.n} nodes: ${r.committed}/${r.rounds} rounds committed · quorum ${r.quorum} · ${fmt(r.msgs, 0)} messages/block</div>`
      : `<span class="pill bad">No commits</span><div class="note">${r.crashed} of ${r.n} nodes crashed; quorum is ${r.quorum}.</div>`;
  }, failed("#lCons"));
}
async function loadFigures() {
  let f; try { f = await api("GET", "/api/lab/figures"); } catch (_) { return; }
  const fig = (x, src) => `<figure><a href="${x.url}" target="_blank" rel="noopener"><img src="${x.url}?t=${Math.round(x.mtime)}" alt="${esc(x.name)}" loading="lazy"></a><figcaption>${esc(src)} · ${esc(x.name)}</figcaption></figure>`;
  $("#lFigs").innerHTML = [...f.base.map((x) => fig(x, "baseline")), ...f.wildppg.map((x) => fig(x, "WildPPG"))].join("") ||
    '<div class="note">No figures yet: run the full experiments.</div>';
}
async function runExperiments(btn) {
  if (!confirm("Run every paper experiment now? It takes about 8 minutes and overwrites the figures in code/v2_components/output.")) return;
  try { await api("POST", "/api/lab/experiments/run"); } catch (e) { toast(e.message, true); return; }
  btn.disabled = true; $("#lExpLog").classList.remove("hidden");
  const poll = async () => {
    let s; try { s = await api("GET", "/api/lab/experiments/status"); } catch (_) { setTimeout(poll, 3000); return; }
    $("#lExpLog").textContent = s.log.join("\n") || "starting…"; $("#lExpLog").scrollTop = 1e9;
    if (s.running) { setTimeout(poll, 3000); return; }
    btn.disabled = false; toast(s.returncode === 0 ? "Experiments finished" : `Experiments ended with code ${s.returncode}`, s.returncode !== 0); loadFigures();
  };
  poll();
}

const LOADERS = {
  "p-home": loadPatientHome, "p-consent": loadPatientConsent, "p-history": loadPatientHistory,
  "d-request": () => loadDoctorPatients(true), "d-patients": () => loadDoctorPatients(false), "d-history": loadDoctorHistory,
  "h-home": loadHospitalHome, "h-patients": loadHospitalPatients, "h-log": loadHospitalLog, "h-staff": loadHospitalStaff,
  "a-home": loadAdminHome, "a-requests": loadAdminRequests, "a-dataset": () => loadDataset(true), "a-nodes": loadNodes, "a-ledger": loadLedger, "a-audit": loadAudit, "a-users": loadUsers,
  "a-figures": loadFigures,
};

// ------------------------------------------------------------------ wiring
function wire() {
  $("#loginForm").addEventListener("submit", doLogin);
  $("#loginUser").addEventListener("input", () => $("#loginErr").classList.add("hidden"));
  $("#demoUsers").addEventListener("click", (e) => { const b = e.target.closest("[data-user]"); if (b) { $("#loginUser").value = b.dataset.user; $("#loginPass").focus(); } });
  $("#logoutBtn").addEventListener("click", logout);
  $("#dsBannerReload").addEventListener("click", () => location.reload());
  window.addEventListener("popstate", () => { if (ME) show(location.hash.slice(1)); });
  window.addEventListener("hashchange", () => { if (ME && location.hash.slice(1) !== SEC) show(location.hash.slice(1)); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && ME) tick(); });
  // patient
  $("#shareBtn").addEventListener("click", (e) => {
    const h = $("#polEntity").value, ttl = Number($("#polTtl").value);
    patientAction(e.currentTarget, "share", { entity: h, role: $("#polRole").value, resource: $("#polRes").value, access: $("#polAccess").value, ttl_s: ttl },
      `${hospName(h)} now has access`);
  });
  $("#pAccess").addEventListener("click", (e) => {
    const b = e.target.closest("[data-withdraw]"); if (!b) return;
    patientAction(b, "withdraw", { hospital: b.dataset.withdraw }, `${hospName(b.dataset.withdraw)}'s access was withdrawn`,
      `Withdraw ${hospName(b.dataset.withdraw)}'s access to your record?`);
  });
  $("#revokeTokBtn").addEventListener("click", (e) => patientAction(e.currentTarget, "revoke-token", null, "You stopped sharing with every hospital",
    "Stop sharing with every hospital? No hospital can open your record until you give access again."));
  // doctor
  $("#dReqBtn").addEventListener("click", (e) => doRequest(e.currentTarget));
  $("#dPatient").addEventListener("change", () => clearDecision("Open this patient's record."));
  $("#dPatients").addEventListener("click", (e) => { const b = e.target.closest("[data-req]"); if (b) { show("d-request", true); $("#dPatient").value = b.dataset.req; clearDecision("Open this patient's record."); } });
  // admin
  $("#tReqBtn").addEventListener("click", (e) => testRequest(e.currentTarget));
  $$(".chip[data-preset]").forEach((c) => c.addEventListener("click", () => {
    if ($("#tReqBtn").dataset.busy) return;
    const p = PRESETS[c.dataset.preset]; $("#tRes").value = p.resource; $("#tAct").value = p.action; $("#tCorrupt").value = p.corrupt; $("#tLedgerPol").checked = p.ledger;
    testRequest($("#tReqBtn"));
  }));
  $("#aShortcuts").addEventListener("click", (e) => { const b = e.target.closest("[data-go]"); if (b) show(b.dataset.go, true); });
  $("#dsLoadBtn").addEventListener("click", (e) => loadDatasetGo(e.currentTarget));
  $("#aNodes").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-node]"); if (!b) return;
    await busy(b, async () => { await api("POST", `/api/admin/node/${b.dataset.node}/${b.dataset.act}`); await loadNodes(); refreshCtx(); });
  });
  $("#aRecoverAll").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    const ov = await api("GET", "/api/admin/overview");
    for (const n of ov.nodes.nodes) if (!n.alive) await api("POST", `/api/admin/node/${n.id}/recover`);
    toast("Every node is back up"); await loadNodes(); refreshCtx();
  }));
  $("#aLedger").addEventListener("click", (e) => { const b = e.target.closest("button[data-block]"); if (b) blockOp(b); });
  $("#aBlock").addEventListener("click", (e) => { if (e.target.id === "aBlockClose") { $("#aBlock").innerHTML = ""; VIEWED = null; } });
  $("#aUsers").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-user]"); if (!b) return;
    if (b.dataset.act === "disable" && !confirm(`Disable ${b.dataset.user}? They are signed out everywhere and cannot sign in until re-enabled.`)) return;
    await busy(b, async () => { await api("POST", `/api/admin/users/${encodeURIComponent(b.dataset.user)}/${b.dataset.act}`); toast(`${b.dataset.user} ${b.dataset.act}d`); await loadUsers(); });
  });
  $("#lAttBtn").addEventListener("click", (e) => runAttacks(e.currentTarget));
  $("#lVerBtn").addEventListener("click", (e) => runVerify(e.currentTarget));
  $("#lCryBtn").addEventListener("click", (e) => runCrypto(e.currentTarget));
  $("#lConsBtn").addEventListener("click", (e) => runCons(e.currentTarget));
  $("#lExpBtn").addEventListener("click", (e) => runExperiments(e.currentTarget));
}

wire();
if (!PORTALS[PORTAL]) location.replace("/");
else enterApp().catch(() => showLogin());
