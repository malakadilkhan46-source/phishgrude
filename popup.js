const $ = (id) => document.getElementById(id);

function applyVerdict(result) {
  const dot = $("dot");
  const label = $("vlabel");
  dot.className = "dot";
  if (!result) {
    dot.classList.add("v-unknown");
    label.textContent = "No scan yet";
    return;
  }
  const v = result.verdict;
  dot.classList.add(`v-${v}`);
  label.textContent =
    v === "safe" ? "Safe site" :
    v === "suspicious" ? "Suspicious site" :
    v === "dangerous" ? "Dangerous site" : "Unknown";
  $("vurl").textContent = result.url || "";
  $("s-mal").textContent = result.stats?.malicious ?? 0;
  $("s-sus").textContent = result.stats?.suspicious ?? 0;
  $("s-harm").textContent = result.stats?.harmless ?? 0;
}

async function loadCurrent() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  try {
    const u = new URL(tab.url);
    const key = `${u.protocol}//${u.host}${u.pathname}`;
    const { cache = {}, history = [], vtApiKey } = await chrome.storage.local.get(["cache", "history", "vtApiKey"]);
    if (vtApiKey) $("apikey").value = vtApiKey;
    const entry = cache[key];
    applyVerdict(entry?.result || null);
    const list = $("history");
    list.innerHTML = "";
    history.slice(0, 10).forEach((h) => {
      const row = document.createElement("div");
      row.className = "hrow";
      const dot = document.createElement("div");
      dot.className = `dot v-${h.verdict}`;
      const url = document.createElement("div");
      url.className = "url";
      url.textContent = h.url;
      row.append(dot, url);
      list.appendChild(row);
    });
  } catch {}
}

$("save").addEventListener("click", async () => {
  const v = $("apikey").value.trim();
  await chrome.storage.local.set({ vtApiKey: v });
  $("save").textContent = "Saved ✓";
  setTimeout(() => ($("save").textContent = "Save key"), 1500);
});

$("rescan").addEventListener("click", async () => {
  $("vlabel").textContent = "Scanning…";
  $("dot").className = "dot v-unknown";
  await chrome.runtime.sendMessage({ type: "PHISHGUARD_RESCAN" });
  setTimeout(loadCurrent, 1500);
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "PHISHGUARD_RESULT") applyVerdict(msg.result);
});

loadCurrent();