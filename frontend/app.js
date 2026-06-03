// ===== État global =====
let SENDERS = [];
let ACCOUNTS = [];
let PROTECTED = [];
const selected = new Set();
let scanPoll = null, msPoll = null, unsubPoll = null;

const $ = (id) => document.getElementById(id);
const api = async (url, opts) => {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const t = await res.json().catch(() => ({}));
    throw new Error(t.detail || res.statusText);
  }
  return res.json();
};
const acc = () => $("accountFilter").value;

// ===== Utils =====
function fmtSize(b) {
  if (!b) return "—";
  const u = ["o", "Ko", "Mo", "Go"]; let i = 0, n = b;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}
function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "2-digit" });
}
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function toast(msg, kind = "") {
  const t = $("toast"); t.textContent = msg; t.className = `toast ${kind}`;
  setTimeout(() => t.classList.add("hidden"), 5000);
}

// ===== Navigation vues =====
function switchView(view) {
  document.querySelectorAll(".navitem").forEach(t => t.classList.toggle("active", t.dataset.view === view));
  document.querySelectorAll(".view").forEach(v => v.classList.add("hidden"));
  $("view-" + view).classList.remove("hidden");
  if (view === "suspects") loadSuspects();
  if (view === "insights") loadInsights();
  if (view === "rules") loadRules();
}

// ===== Chargement =====
async function loadAccounts() {
  ACCOUNTS = await api("/api/accounts");
  $("accountFilter").innerHTML = '<option value="all">Tous les comptes</option>' +
    ACCOUNTS.map(a => `<option value="${a.id}">${escapeHtml(a.label)}</option>`).join("");
  renderAccountsList();
}
async function loadProtected() {
  const r = await api("/api/rules");
  PROTECTED = r.protected || [];
}
async function loadStats() {
  const s = await api(`/api/stats?account=${acc()}`);
  $("stats").innerHTML = `
    <div class="stat-card clickable" data-stat="all"><div class="v">${s.total || 0}</div><div class="l">Mails analysés</div></div>
    <div class="stat-card promo clickable" data-stat="promo"><div class="v">${s.promo || 0}</div><div class="l">Promos</div></div>
    <div class="stat-card clickable" data-stat="unread"><div class="v">${s.unread || 0}</div><div class="l">Non lus</div></div>
    <div class="stat-card susp clickable" data-stat="suspects"><div class="v">${s.suspicious || 0}</div><div class="l">Suspects</div></div>`;
  const sb = $("suspBadge");
  if (s.suspicious > 0) { sb.textContent = s.suspicious; sb.classList.remove("hidden"); }
  else sb.classList.add("hidden");
}

function onStatClick(stat) {
  if (stat === "suspects") { switchView("suspects"); return; }
  $("promoOnly").checked = stat === "promo";
  $("unreadOnly").checked = stat === "unread";
  if (stat === "all") { $("catFilter").value = ""; $("search").value = ""; }
  renderSenders();
}
async function loadSenders() {
  SENDERS = await api(`/api/senders?account=${acc()}`);
  // catégories disponibles
  const cats = [...new Set(SENDERS.map(s => s.category))].filter(Boolean).sort();
  const cur = $("catFilter").value;
  $("catFilter").innerHTML = '<option value="">Toutes catégories</option>' +
    cats.map(c => `<option value="${c}">${c}</option>`).join("");
  $("catFilter").value = cur;
  selected.clear();
  renderSenders();
}

// ===== Tableau expéditeurs =====
function renderSenders() {
  const q = $("search").value.toLowerCase();
  const cat = $("catFilter").value;
  const promoOnly = $("promoOnly").checked;
  const unreadOnly = $("unreadOnly").checked;
  const sortBy = $("sortBy").value;

  let rows = SENDERS.filter(s => {
    if (cat && s.category !== cat) return false;
    if (promoOnly && !s.promo_count && !s.has_unsub) return false;
    if (unreadOnly && !s.unread_count) return false;
    if (!q) return true;
    return (s.from_email || "").toLowerCase().includes(q) || (s.from_name || "").toLowerCase().includes(q);
  });
  rows.sort((a, b) => (b[sortBy] || 0) - (a[sortBy] || 0));

  $("emptyState").classList.toggle("hidden", rows.length > 0);
  $("sendersBody").innerHTML = rows.map(s => {
    const high = s.count >= 10;
    const susp = s.phishing_score > 0;
    return `<tr data-email="${encodeURIComponent(s.from_email)}">
      <td class="col-chk"><input type="checkbox" class="rowchk" ${selected.has(s.from_email) ? "checked" : ""}/></td>
      <td><div class="sender-cell">
        <span class="em">${escapeHtml(s.from_email || "(inconnu)")}
          ${susp ? '<span class="badge susp">⚠ suspect</span>' : ""}
          <span class="cat-badge">${escapeHtml(s.category || "")}</span></span>
        ${s.from_name ? `<span class="nm">${escapeHtml(s.from_name)}</span>` : ""}
      </div></td>
      <td class="num"><span class="count-pill ${high ? "high" : ""}">${s.count}</span></td>
      <td class="num">${s.unread_count || 0}</td>
      <td>${fmtDate(s.last_ts)}</td>
      <td class="num">${fmtSize(s.total_size)}</td>
      <td>${s.unsubscribed ? '<span class="badge unsubd">désab.</span>' : (s.has_unsub ? '<span class="badge yes">oui</span>' : '<span class="badge no">—</span>')}</td>
      <td><div class="row-actions">
        <button class="icon-btn" data-act="view" title="Voir">👁</button>
        ${s.has_unsub ? '<button class="icon-btn" data-act="unsub" title="Désabonner">🚫</button>' : ""}
        <button class="icon-btn shield ${s.protected ? "on" : ""}" data-act="protect" title="Protéger">🛡</button>
        <button class="icon-btn" data-act="archive" title="Archiver">📦</button>
        <button class="icon-btn danger" data-act="delete" title="Supprimer">🗑</button>
      </div></td>
    </tr>`;
  }).join("");
  updateBulk();
}
function updateBulk() {
  $("selCount").textContent = `${selected.size} sélectionné(s)`;
  $("bulkActions").classList.toggle("hidden", selected.size === 0);
}
const senderByEmail = (e) => SENDERS.find(s => s.from_email === e);

// ===== Actions =====
async function doAction(act_, emails) {
  if (act_ === "delete" && !confirm(`Mettre à la corbeille tous les mails de ${emails.length} expéditeur(s) ?`)) return;
  let ok = 0; const errs = [];
  for (const email of emails) {
    const s = senderByEmail(email);
    if (!s) continue;
    try {
      if (act_ === "unsub") {
        if (!s.list_unsubscribe) { errs.push(email); continue; }
        const r = await api("/api/actions/unsubscribe", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sender: email, list_unsubscribe: s.list_unsubscribe }),
        });
        if (r.ok) ok++;
        else if (r.links && (r.links.https.length || r.links.mailto.length)) {
          window.open(r.links.https[0] || ("mailto:" + r.links.mailto[0]), "_blank"); ok++;
        } else errs.push(email);
      } else {
        await api(`/api/actions/${act_}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sender: email, account_id: acc() }),
        });
        ok++;
      }
    } catch (e) { errs.push(`${email}: ${e.message}`); }
  }
  if (act_ !== "unsub") { await loadStats(); await loadSenders(); }
  else { await loadSenders(); }
  selected.clear();
  const lbl = { delete: "supprimé(s)", archive: "archivé(s)", unsub: "désabonné(s)" }[act_];
  toast(`${ok} expéditeur(s) ${lbl}.` + (errs.length ? ` ${errs.length} échec(s).` : ""), errs.length ? "err" : "ok");
}

async function toggleProtect(email) {
  const i = PROTECTED.indexOf(email);
  if (i >= 0) PROTECTED.splice(i, 1); else PROTECTED.push(email);
  await api("/api/rules/protected", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ protected: PROTECTED }),
  });
  await loadSenders();
}

async function viewSender(email) {
  const msgs = await api(`/api/senders/messages?email=${encodeURIComponent(email)}&account=${acc()}`);
  $("detailTitle").textContent = `${email} · ${msgs.length} message(s)`;
  $("detailBody").innerHTML = msgs.map(m => `
    <div class="msg-row">
      <div class="subj">${m.unread ? "🔵 " : ""}${escapeHtml(m.subject || "(sans objet)")}</div>
      <div class="meta">${fmtDate(m.date_ts)} · ${fmtSize(m.size)} · ${escapeHtml(m.folder)}
        ${m.phishing_score > 0 ? ` · ⚠ ${escapeHtml(m.phishing_reasons || "")}` : ""}</div>
    </div>`).join("") || '<div class="empty">Aucun message.</div>';
  $("detailModal").classList.remove("hidden");
}

// ===== Désabonnement de masse =====
async function unsubAll() {
  if (!confirm("Se désabonner de TOUS les expéditeurs proposant un lien de désabonnement ?")) return;
  try {
    await api("/api/actions/unsubscribe_all", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account: acc() }),
    });
    toast("Désabonnement de masse lancé…", "ok");
    if (unsubPoll) clearInterval(unsubPoll);
    unsubPoll = setInterval(async () => {
      const st = await api("/api/unsubscribe/status");
      $("scanBarLabel").textContent = "Désabonnement…";
      $("scanBar").classList.remove("hidden");
      $("scanText").textContent = `Désabonnement ${st.done}/${st.total}`;
      $("progressFill").style.width = (st.total ? (st.done / st.total * 100) : 0) + "%";
      if (!st.running) {
        clearInterval(unsubPoll); unsubPoll = null;
        setTimeout(() => $("scanBar").classList.add("hidden"), 1200);
        toast(`Désabonnement terminé (${st.done} traités).`, "ok");
        await loadSenders();
      }
    }, 1000);
  } catch (e) { toast(e.message, "err"); }
}

// ===== Scan =====
async function startScan() {
  try {
    await api("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_all: $("scanAll").checked, mode: $("scanMode").value }),
    });
    $("scanBarLabel").textContent = "Scan…";
    $("scanBar").classList.remove("hidden");
    if (scanPoll) clearInterval(scanPoll);
    scanPoll = setInterval(pollScan, 800);
  } catch (e) { toast(e.message, "err"); }
}
async function pollScan() {
  const st = await api("/api/scan/status");
  const pct = st.total ? Math.round(st.done / st.total * 100) : 0;
  $("progressFill").style.width = pct + "%";
  $("scanText").textContent = `${st.current || ""} ${st.done}/${st.total} (${pct}%)`;
  if (!st.running) {
    clearInterval(scanPoll); scanPoll = null;
    setTimeout(() => $("scanBar").classList.add("hidden"), 1200);
    toast(st.log.join("  |  ") || "Scan terminé", "ok");
    await loadStats(); await loadSenders();
  }
}

// ===== Suspects =====
async function loadSuspects() {
  const list = await api(`/api/suspicious?account=${acc()}`);
  $("suspectsList").innerHTML = list.map(s => `
    <div class="suspect-card" data-email="${encodeURIComponent(s.from_email)}">
      <div class="top">
        <span class="em">${escapeHtml(s.from_email)} <span class="nm">${escapeHtml(s.from_name || "")}</span></span>
        <span class="score">${s.phishing_score}/100</span>
      </div>
      <div class="reasons">⚠ ${escapeHtml(s.reasons || "")}</div>
      <div class="subj">Ex. : « ${escapeHtml(s.example_subject || "")} » · ${s.count} mail(s)</div>
      <div class="row-actions" style="margin-top:10px">
        <button class="icon-btn" data-sact="view">👁 Voir</button>
        <button class="icon-btn danger" data-sact="delete">🗑 Supprimer tout</button>
      </div>
    </div>`).join("") || '<div class="empty">Aucun expéditeur suspect détecté. 🎉</div>';
}

// ===== Insights =====
function barChart(el, items, labelKey, valKey, fmt) {
  const max = Math.max(1, ...items.map(i => i[valKey] || 0));
  el.innerHTML = items.map(i => `
    <div class="bar-row">
      <span class="lbl">${escapeHtml(String(i[labelKey] || ""))}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(i[valKey] || 0) / max * 100}%"></div></div>
      <span class="bar-val">${fmt ? fmt(i[valKey]) : (i[valKey] || 0)}</span>
    </div>`).join("") || '<div class="empty">—</div>';
}
async function loadInsights() {
  const d = await api(`/api/insights?account=${acc()}`);
  barChart($("volChart"), d.volume_by_month, "month", "count");
  barChart($("sizeChart"), d.top_size.map(x => ({ lbl: x.from_email, total_size: x.total_size })), "lbl", "total_size", fmtSize);
  barChart($("dormantList"), d.dormant.map(x => ({ lbl: `${x.from_email} (${fmtDate(x.last_ts)})`, count: x.count })), "lbl", "count");
}

// ===== Règles =====
async function loadRules() {
  const r = await api("/api/rules");
  PROTECTED = r.protected || [];
  $("protectedList").value = PROTECTED.join("\n");
  $("rulesList").innerHTML = (r.rules || []).map(rule => `
    <div class="rule-item">
      <span>${escapeHtml(rule.match_type)} = <strong>${escapeHtml(rule.value)}</strong> → ${escapeHtml(rule.action)}${rule.target ? " (" + escapeHtml(rule.target) + ")" : ""}</span>
      <button class="icon-btn danger" data-delrule="${rule.id}">✕</button>
    </div>`).join("") || '<div class="meta" style="color:var(--muted)">Aucune règle.</div>';
  const sch = await api("/api/schedule");
  $("schEnabled").checked = sch.enabled;
  $("schInterval").value = sch.interval_hours;
  $("schScanAll").checked = sch.scan_all;
  $("schApplyRules").checked = sch.apply_rules;
}

// ===== Comptes (modale) =====
function renderAccountsList() {
  $("accountsList").innerHTML = ACCOUNTS.map(a => `
    <div class="account-item">
      <div><strong>${escapeHtml(a.label)}</strong>
        <div class="meta">${escapeHtml(a.email)} · ${a.auth_type === "oauth_ms" ? "OAuth" : a.imap_host}</div></div>
      <button class="icon-btn danger" data-del="${a.id}">Supprimer</button>
    </div>`).join("") || '<div class="meta">Aucun compte.</div>';
}
async function addAccount() {
  const payload = {
    email: $("accEmail").value.trim(), password: $("accPassword").value,
    label: $("accLabel").value.trim(), imap_host: $("accHost").value.trim(),
    imap_port: $("accPort").value ? parseInt($("accPort").value) : null,
    username: $("accUser").value.trim(),
  };
  const msg = $("accMsg"); msg.textContent = "Connexion…"; msg.className = "form-msg";
  try {
    const r = await api("/api/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    msg.textContent = `✓ Ajouté (${r.inbox_count} mails)`; msg.className = "form-msg ok";
    ["accEmail", "accPassword", "accLabel", "accHost", "accPort", "accUser"].forEach(id => $(id).value = "");
    await loadAccounts();
  } catch (e) { msg.textContent = "✗ " + e.message; msg.className = "form-msg err"; }
}
async function testAccount() {
  const payload = {
    email: $("accEmail").value.trim(), password: $("accPassword").value,
    imap_host: $("accHost").value.trim(),
    imap_port: $("accPort").value ? parseInt($("accPort").value) : null,
    username: $("accUser").value.trim(),
  };
  const msg = $("accMsg"); msg.textContent = "Test…"; msg.className = "form-msg";
  try {
    const r = await api("/api/accounts/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (r.ok) { msg.textContent = `✓ OK (${r.inbox_count} mails)`; msg.className = "form-msg ok"; }
    else { msg.textContent = "✗ " + r.error; msg.className = "form-msg err"; }
  } catch (e) { msg.textContent = "✗ " + e.message; msg.className = "form-msg err"; }
}

// ===== OAuth Microsoft =====
async function msConnect() {
  const clientId = $("msClientId").value.trim();
  const email = $("msEmail").value.trim();
  const label = $("msLabel").value.trim();
  const msg = $("msMsg");
  if (!email) { msg.textContent = "✗ Adresse e-mail requise"; msg.className = "form-msg err"; return; }
  msg.textContent = ""; msg.className = "form-msg";
  try {
    const flow = await api("/api/oauth/ms/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_id: clientId }) });
    $("msUserCode").textContent = flow.user_code;
    $("msVerifyLink").href = flow.verification_uri;
    $("msFlow").classList.remove("hidden");
    $("msStatus").textContent = "En attente de connexion…";
    window.open(flow.verification_uri, "_blank");
    if (msPoll) clearInterval(msPoll);
    let busy = false;
    msPoll = setInterval(async () => {
      if (busy) return; busy = true;
      try {
        const r = await api("/api/oauth/ms/poll", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_id: clientId, device_code: flow.device_code, email, label }) });
        if (r.status === "ok") {
          clearInterval(msPoll); msPoll = null;
          $("msFlow").classList.add("hidden");
          msg.textContent = "✓ Compte Microsoft ajouté"; msg.className = "form-msg ok";
          $("msClientId").value = ""; $("msEmail").value = ""; $("msLabel").value = "";
          await loadAccounts(); return;
        } else if (r.status === "error") {
          clearInterval(msPoll); msPoll = null; $("msFlow").classList.add("hidden");
          msg.textContent = "✗ " + (r.description || r.error); msg.className = "form-msg err"; return;
        }
      } catch (e) { clearInterval(msPoll); msPoll = null; msg.textContent = "✗ " + e.message; msg.className = "form-msg err"; }
      finally { busy = false; }
    }, (flow.interval || 5) * 1000);
  } catch (e) { msg.textContent = "✗ " + e.message; msg.className = "form-msg err"; }
}
function switchTab(tab) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
  $("tab-oauth").classList.toggle("hidden", tab !== "oauth");
  $("tab-pwd").classList.toggle("hidden", tab !== "pwd");
}

// ===== Écouteurs =====
function bind() {
  document.querySelectorAll(".navitem").forEach(t => t.onclick = () => switchView(t.dataset.view));
  document.querySelectorAll(".tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  $("stats").addEventListener("click", (e) => {
    const card = e.target.closest(".stat-card"); if (card) onStatClick(card.dataset.stat);
  });
  $("scanBtn").onclick = startScan;
  $("accountsBtn").onclick = () => $("accountsModal").classList.remove("hidden");
  $("closeAccounts").onclick = () => $("accountsModal").classList.add("hidden");
  $("closeDetail").onclick = () => $("detailModal").classList.add("hidden");
  $("addAccBtn").onclick = addAccount;
  $("testAccBtn").onclick = testAccount;
  $("msConnectBtn").onclick = msConnect;
  $("unsubAllBtn").onclick = unsubAll;
  $("exportBtn").onclick = () => window.open(`/api/export?account=${acc()}&format=xlsx`, "_blank");
  $("accountFilter").onchange = async () => { await loadStats(); await loadSenders(); };
  ["search", "catFilter", "promoOnly", "unreadOnly", "sortBy"].forEach(id => {
    $(id)[id === "search" ? "oninput" : "onchange"] = renderSenders;
  });

  $("selectAll").onchange = (e) => {
    document.querySelectorAll("#sendersBody tr").forEach(tr => {
      const email = decodeURIComponent(tr.dataset.email);
      if (e.target.checked) selected.add(email); else selected.delete(email);
    });
    renderSenders();
  };
  $("sendersBody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr"); if (!tr) return;
    const email = decodeURIComponent(tr.dataset.email);
    if (e.target.classList.contains("rowchk")) {
      if (e.target.checked) selected.add(email); else selected.delete(email);
      updateBulk(); return;
    }
    const a = e.target.dataset.act;
    if (a === "view") viewSender(email);
    else if (a === "unsub") doAction("unsub", [email]);
    else if (a === "archive") doAction("archive", [email]);
    else if (a === "delete") doAction("delete", [email]);
    else if (a === "protect") toggleProtect(email);
  });
  document.querySelectorAll("[data-bulk]").forEach(btn => {
    btn.onclick = () => {
      const a = { unsubscribe: "unsub", archive: "archive", delete: "delete" }[btn.dataset.bulk];
      if (selected.size) doAction(a, [...selected]);
    };
  });
  $("suspectsList").addEventListener("click", (e) => {
    const card = e.target.closest(".suspect-card"); if (!card) return;
    const email = decodeURIComponent(card.dataset.email);
    if (e.target.dataset.sact === "view") viewSender(email);
    else if (e.target.dataset.sact === "delete") {
      if (confirm(`Supprimer tous les mails de ${email} ?`))
        api("/api/actions/delete", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sender: email, account_id: acc() }) })
          .then(() => { toast("Supprimé", "ok"); loadSuspects(); loadStats(); });
    }
  });
  $("accountsList").addEventListener("click", async (e) => {
    const id = e.target.dataset.del;
    if (id && confirm("Supprimer ce compte ? (les mails ne sont pas touchés)")) {
      await api(`/api/accounts/${id}`, { method: "DELETE" });
      await loadAccounts(); await loadStats(); await loadSenders();
    }
  });

  // Règles
  $("addRuleBtn").onclick = async () => {
    const payload = {
      match_type: $("ruleMatchType").value, value: $("ruleValue").value.trim(),
      action: $("ruleAction").value, target: $("ruleTarget").value.trim(),
    };
    if (!payload.value) { toast("Valeur requise", "err"); return; }
    await api("/api/rules", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    $("ruleValue").value = ""; $("ruleTarget").value = ""; loadRules();
  };
  $("rulesList").addEventListener("click", async (e) => {
    const id = e.target.dataset.delrule;
    if (id) { await api(`/api/rules/${id}`, { method: "DELETE" }); loadRules(); }
  });
  $("saveProtected").onclick = async () => {
    const list = $("protectedList").value.split("\n").map(x => x.trim()).filter(Boolean);
    await api("/api/rules/protected", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ protected: list }) });
    PROTECTED = list; toast("Protégés enregistrés", "ok"); loadSenders();
  };
  $("applyRulesBtn").onclick = async () => {
    const r = await api("/api/rules/apply", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    toast(`${r.applied} action(s) appliquée(s)`, "ok"); loadStats(); loadSenders();
  };
  $("saveSchedule").onclick = async () => {
    await api("/api/schedule", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: $("schEnabled").checked, interval_hours: parseInt($("schInterval").value) || 24,
        scan_all: $("schScanAll").checked, apply_rules: $("schApplyRules").checked,
      }),
    });
    $("schMsg").textContent = "✓ Enregistré"; $("schMsg").className = "form-msg ok";
  };
}

// ===== Init =====
(async function init() {
  bind();
  await loadAccounts();
  await loadProtected();
  await loadStats();
  await loadSenders();
  if (ACCOUNTS.length === 0) $("accountsModal").classList.remove("hidden");
})();
