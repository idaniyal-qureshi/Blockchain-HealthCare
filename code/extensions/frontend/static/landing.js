"use strict";
// Landing page: show whether the server is up (the CSP forbids inline scripts, so this lives in its own file).
fetch("/api/status").then((r) => r.json()).then((s) => {
  const p = document.getElementById("sysPill");
  p.textContent = s.ready ? `System online · ${s.source === "wildppg" ? "WildPPG data" : "synthetic data"}` : (s.error || "System starting…");
  p.style.setProperty("--dot", s.ready ? "#12a27a" : "#e08a00");
}).catch(() => { document.getElementById("sysPill").textContent = "Server offline"; });
