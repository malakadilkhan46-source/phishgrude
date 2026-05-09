// Injects an alert banner when background detects a dangerous/suspicious site.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== "PHISHGUARD_ALERT") return;
  const { result } = msg;
  if (document.getElementById("phishguard-banner")) return;

  const dangerous = result.verdict === "dangerous";
  const bg = dangerous ? "#7f1d1d" : "#78350f";
  const accent = dangerous ? "#fecaca" : "#fde68a";
  const title = dangerous ? "⚠️ PhishGuard: Dangerous site" : "⚠️ PhishGuard: Suspicious site";

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${bg}; color: white; font-family: system-ui, -apple-system, sans-serif;
    padding: 14px 20px; box-shadow: 0 4px 16px rgba(0,0,0,.35);
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
    font-size: 14px; line-height: 1.4;
  `;
  banner.innerHTML = `
    <div>
      <div style="font-weight:700;color:${accent};font-size:15px;margin-bottom:2px">${title}</div>
      <div style="opacity:.95">VirusTotal flagged this URL — Malicious: <b>${result.stats.malicious||0}</b>, Suspicious: <b>${result.stats.suspicious||0}</b>. Proceed with caution.</div>
    </div>
    <button id="phishguard-close" style="background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);color:white;border-radius:6px;padding:6px 12px;cursor:pointer;font-weight:600">Dismiss</button>
  `;
  document.documentElement.appendChild(banner);
  banner.querySelector("#phishguard-close").addEventListener("click", () => banner.remove());
});