"use strict";

/* ---------- utilitaires ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function storageGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function storageSet(k, v) {
  try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* ignoré */ }
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

function modpow(base, exp, mod) {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

function short(s) { return s.length > 22 ? `${s.slice(0, 10)}…${s.slice(-8)}` : s; }

let toastTimer;
function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1600);
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = el("textarea", { class: "offscreen" }); // pas de style inline (CSP)
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast("Copié !");
  } catch {
    toast("Copie impossible : sélectionnez le texte à la main.");
  }
}

function numRow(label, value) {
  return el("div", { class: "num-row" },
    el("span", { class: "label", text: label }),
    el("code", { class: "num", text: value }),
    el("button", { type: "button", class: "copy", text: "Copier", onclick: () => copyText(value) }));
}

/* ---------- état + API ---------- */
const state = {
  token: storageGet("zkp_token"),
  me: null,
  history: { 1: [], 2: [] },
  pending: { 1: null, 2: null },
  proofs: [],
};

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.token) headers["X-Token"] = state.token;
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = {};
  try { data = await res.json(); } catch { /* corps vide */ }
  if (!res.ok) {
    if (res.status === 401 && state.token && path !== "/api/me") logout();
    throw new Error(data.error || `Erreur ${res.status}`);
  }
  return data;
}

/* ---------- connexion ---------- */
function setMsg(node, text, kind = "") {
  node.textContent = text;
  node.className = `msg ${kind}`;
}

async function loadMe() {
  if (!state.token) { renderLoggedOut(); return; }
  try {
    state.me = await api("/api/me");
    renderLoggedIn();
  } catch (e) {
    state.token = null;
    storageSet("zkp_token", null);
    renderLoggedOut();
    setMsg($("#login-msg"), e.message, "bad");
  }
}

function logout() {
  state.token = null;
  state.me = null;
  state.history = { 1: [], 2: [] };
  state.pending = { 1: null, 2: null };
  state.proofs = [];
  storageSet("zkp_token", null);
  renderLoggedOut();
}

$("#register-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const msg = $("#login-msg");
  try {
    const r = await api("/api/register", { method: "POST", body: { name: $("#name").value } });
    state.token = r.token;
    storageSet("zkp_token", r.token);
    setMsg(msg, "");
    await loadMe();
  } catch (e) { setMsg(msg, e.message, "bad"); }
});

$("#token-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  state.token = $("#token-in").value.trim();
  storageSet("zkp_token", state.token);
  await loadMe();
});

$("#logout").addEventListener("click", logout);
$("#show-token").addEventListener("click", () => {
  const box = $("#token-box");
  box.hidden = !box.hidden;
  $("#show-token").textContent = box.hidden ? "Afficher mon jeton" : "Masquer mon jeton";
});
$$("[data-copy-from]").forEach((b) =>
  b.addEventListener("click", () => copyText($("#" + b.dataset.copyFrom).textContent)));

/* ---------- rendu ---------- */
function levelCard(lv) { return $(`.level[data-level="${lv}"]`); }

function renderLoggedOut() {
  $("#login").hidden = false;
  $("#player").hidden = true;
  for (const lv of [1, 2, 3]) {
    const card = levelCard(lv);
    card.classList.remove("solved");
    $(".solved-badge", card).hidden = true;
    $("[data-params]", card).replaceChildren(
      el("div", { class: "locked", text: "Inscrivez-vous pour recevoir vos paramètres personnels." }));
    const v = $("[data-verifier]", card);
    if (v) v.replaceChildren();
    $(".submit-form", card).hidden = true;
    setMsg($(".msg", card), "");
  }
  $$(".needs-login").forEach((b) => (b.hidden = true));
  $("#l3-proofs").replaceChildren();
  renderLeak();
}

function renderLoggedIn() {
  const me = state.me;
  $("#login").hidden = true;
  $("#player").hidden = false;
  $("#me-name").textContent = me.name;
  $("#token-value").textContent = state.token;
  $$(".needs-login").forEach((b) => (b.hidden = false));
  for (const lv of [1, 2, 3]) {
    const card = levelCard(lv);
    const P = me.levels[lv];
    const rows = [
      numRow("p", P.p), numRow("q", P.q), numRow("g", P.g), numRow("y", P.y),
      el("div", { class: "params-actions" },
        el("button", {
          type: "button", class: "copy", text: "Copier en Python",
          onclick: () => {
            let py = `p = ${P.p}\nq = ${P.q}\ng = ${P.g}\ny = ${P.y}\n`;
            if (P.lcg) py += `A = ${P.lcg.A}\nB = ${P.lcg.B}\n`;
            copyText(py);
          },
        })),
    ];
    $("[data-params]", card).replaceChildren(...rows);
    $(".submit-form", card).hidden = false;
    const v = $("[data-verifier]", card);
    if (v) buildVerifier(lv, v);
  }
  renderSolved();
  renderLeak();
  renderProofs();
}

function renderSolved() {
  const me = state.me;
  let pts = 0;
  for (const lv of [1, 2, 3]) {
    const solved = Object.prototype.hasOwnProperty.call(me.solved, String(lv));
    if (solved) pts += me.levels[lv].points;
    const card = levelCard(lv);
    card.classList.toggle("solved", solved);
    $(".solved-badge", card).hidden = !solved;
  }
  $("#me-points").textContent = pts;
}

function renderLeak() {
  const lcg = state.me ? state.me.levels[3].lcg : { A: "…", B: "…" };
  $("#leak").textContent =
`# prover.py : extrait retrouvé dans un commit oublié
from hashlib import sha256

A = ${lcg.A}
B = ${lcg.B}

def next_nonce(r):
    # « Plus rapide que secrets.randbelow, et tout aussi aléatoire, non ? »
    return (A * r + B) % q

def prove(x, r, message):
    t = pow(g, r, p)
    c = int(sha256(f"{g}|{y}|{t}|{message}".encode()).hexdigest(), 16) % q
    s = (r + c * x) % q
    return t, c, s

# r = graine_secrète
# for n in range(...):
#     publier(prove(x, r, f"preuve #{n} pour {pseudo}"))
#     r = next_nonce(r)`;
}

/* ---------- vérifieur interactif (niveaux 1 et 2) ---------- */
function verifyEq(P, t, c, s) {
  const p = BigInt(P.p), g = BigInt(P.g), y = BigInt(P.y);
  return modpow(g, BigInt(s), p) === (BigInt(t) * modpow(y, BigInt(c), p)) % p;
}

function randomChallenge(lv) {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  if (lv === 1) n %= BigInt(state.me.levels[1].q);
  return (n === 0n ? 1n : n).toString();
}

function buildVerifier(lv, mount) {
  const P = state.me.levels[lv];
  const out1 = el("div", { class: "out" });
  const out2 = el("div", { class: "out" });
  const cInput = el("input", { placeholder: "défi c (entier)", inputmode: "numeric" });
  const respondBtn = el("button", { type: "button", text: "Envoyer le défi" });
  const msg = el("p", { class: "msg", role: "status" });
  const tbody = el("tbody");

  const renderHistory = () => {
    const h = state.history[lv];
    const counts = {};
    h.forEach((r) => (counts[r.t] = (counts[r.t] || 0) + 1));
    tbody.replaceChildren(...(h.length ? h.map((r, i) =>
      el("tr", { class: counts[r.t] > 1 && lv === 2 ? "dup" : "" },
        el("td", { text: String(i + 1) }),
        el("td", { class: "mono t", text: short(r.t), title: r.t }),
        el("td", { class: "mono", text: short(r.c), title: r.c }),
        el("td", { class: "mono", text: short(r.s), title: r.s }),
        el("td", { text: r.ok ? "✓" : "✗" })))
      : [el("tr", {}, el("td", { colspan: "5", class: "muted", text: "Aucune transcription pour l'instant." }))]));
  };

  const commit = async () => {
    setMsg(msg, "");
    try {
      const r = await api("/api/commit", { method: "POST", body: { level: lv } });
      state.pending[lv] = r.t;
      out1.replaceChildren(numRow("t", r.t));
      out2.replaceChildren();
      respondBtn.disabled = false;
    } catch (e) { setMsg(msg, e.message, "bad"); }
  };

  const respond = async () => {
    setMsg(msg, "");
    const c = cInput.value.trim() || randomChallenge(lv);
    cInput.value = c;
    try {
      const r = await api("/api/respond", { method: "POST", body: { level: lv, c } });
      const t = state.pending[lv];
      const ok = verifyEq(P, t, r.c, r.s);
      out2.replaceChildren(
        numRow("s", r.s),
        el("div", {
          class: `check ${ok ? "ok" : "bad"}`,
          text: ok ? "gˢ ≡ t·yᶜ (mod p) : preuve acceptée ✓" : "Vérification échouée ✗",
        }));
      state.history[lv].push({ t, c: r.c, s: r.s, ok });
      state.pending[lv] = null;
      respondBtn.disabled = true;
      cInput.value = "";
      renderHistory();
    } catch (e) { setMsg(msg, e.message, "bad"); }
  };

  respondBtn.disabled = !state.pending[lv];
  respondBtn.addEventListener("click", respond);
  if (state.pending[lv]) out1.append(numRow("t", state.pending[lv]));

  mount.replaceChildren(el("div", { class: "verifier" },
    el("div", { class: "step" },
      el("span", { class: "n", text: "1" }),
      el("button", { type: "button", text: "Demander un engagement t", onclick: commit })),
    out1,
    el("div", { class: "step" },
      el("span", { class: "n", text: "2" }),
      cInput,
      el("button", { type: "button", class: "secondary", text: "Aléatoire",
        onclick: () => { cInput.value = randomChallenge(lv); } }),
      respondBtn),
    out2,
    msg,
    el("div", { class: "history-head" },
      el("strong", { text: "Historique des transcriptions" }),
      el("button", {
        type: "button", class: "copy", text: "Copier (Python)",
        onclick: () => copyText("transcripts = [  # (t, c, s)\n" +
          state.history[lv].map((r) => `    (${r.t}, ${r.c}, ${r.s}),`).join("\n") + "\n]\n"),
      })),
    el("div", { class: "table-wrap" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", { text: "#" }), el("th", { text: "t" }), el("th", { text: "c" }),
          el("th", { text: "s" }), el("th", { text: "ok" }))),
        tbody))));
  renderHistory();
}

/* ---------- niveau 3 ---------- */
function renderProofs() {
  const P = state.me.levels[3];
  $("#l3-proofs").replaceChildren(...state.proofs.slice().reverse().map((pr) => {
    const ok = verifyEq(P, pr.t, pr.c, pr.s);
    return el("div", { class: "proof" },
      el("div", { class: "proof-head" },
        el("strong", { text: `Preuve #${pr.index}` }),
        el("span", { class: "muted mono", text: `message = "${pr.message}"` })),
      numRow("t", pr.t), numRow("c", pr.c), numRow("s", pr.s),
      el("div", { class: `check ${ok ? "ok" : "bad"}`, text: ok ? "gˢ ≡ t·yᶜ (mod p) ✓" : "Vérification échouée ✗" }));
  }));
}

$("#l3-get").addEventListener("click", async () => {
  const msg = $(".msg", levelCard(3));
  try {
    const r = await api("/api/l3/proofs", { method: "POST", body: {} });
    state.proofs.push(...r.proofs);
    renderProofs();
    setMsg(msg, "");
  } catch (e) { setMsg(msg, e.message, "bad"); }
});

$("#l3-copy").addEventListener("click", () => {
  copyText("proofs = [  # (index, t, c, s)\n" +
    state.proofs.map((p) => `    (${p.index}, ${p.t}, ${p.c}, ${p.s}),`).join("\n") + "\n]\n");
});

/* ---------- soumission ---------- */
$$(".level").forEach((card) => {
  const lv = Number(card.dataset.level);
  $(".submit-form", card).addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = $(".msg", card);
    const input = $("input[name=x]", ev.target);
    try {
      const r = await api("/api/submit", { method: "POST", body: { level: lv, x: input.value } });
      setMsg(msg, r.message, r.ok ? "ok" : "bad");
      if (r.ok) {
        state.me.solved[lv] = Date.now() / 1000;
        renderSolved();
        loadScoreboard();
      }
    } catch (e) { setMsg(msg, e.message, "bad"); }
  });
});

/* ---------- classement ---------- */
async function loadScoreboard() {
  try {
    const sb = await api("/api/scoreboard");
    const body = $("#score-body");
    if (!sb.players.length) {
      body.replaceChildren(el("tr", {}, el("td", { colspan: "6", class: "muted", text: "Personne n'est encore inscrit." })));
      return;
    }
    body.replaceChildren(...sb.players.map((p, i) => {
      const cells = [1, 2, 3].map((lv) => {
        const td = el("td");
        if (p.solved.includes(lv)) {
          td.append(el("span", { class: "yes", text: "✓" }));
          if (sb.first_blood[lv] === p.name) td.append(el("span", { class: "fb", text: "1er" }));
        } else td.append(el("span", { class: "no", text: "·" }));
        return td;
      });
      return el("tr", { class: state.me && state.me.name === p.name ? "me" : "" },
        el("td", { text: String(i + 1) }),
        el("td", { text: p.name }),
        ...cells,
        el("td", { class: "r mono", text: String(p.points) }));
    }));
  } catch { /* on réessaiera */ }
}

/* ---------- démarrage ---------- */
$("#origin").textContent = location.origin;
loadMe();
loadScoreboard();
setInterval(loadScoreboard, 10000);
