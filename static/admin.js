"use strict";

const $ = (s) => document.querySelector(s);
let token = "";
try { token = sessionStorage.getItem("zkp_admin") || ""; } catch { /* ignoré */ }

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

async function api(path, body) {
  const opts = { method: body ? "POST" : "GET", headers: { "X-Admin-Token": token } };
  if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erreur ${res.status}`);
  return data;
}

function setMsg(text, kind = "") { const m = $("#msg"); m.textContent = text; m.className = `msg ${kind}`; }

async function load() {
  try {
    const st = await api("/api/admin/state");
    try { sessionStorage.setItem("zkp_admin", token); } catch { /* ignoré */ }
    $("#panel").hidden = false;
    setMsg("");
    const sg = st.small_group;
    $("#summary").textContent =
      `${st.players.length} joueur(s). Groupe N1 : p = ${sg.p} (${st.small_bits} bits), q = ${sg.q}, g = ${sg.g}.`;
    $("#rows").replaceChildren(...st.players.map((p) => {
      const solved = Object.keys(p.solved).sort().join(", ") || "-";
      const att = [1, 2, 3].map((l) => p.attempts[l] || 0).join(" / ");
      const keys = el("details", {},
        el("summary", { text: "voir" }),
        ...[1, 2, 3].map((l) => el("div", { class: "mono small", text: `x${l} = ${p.keys[l]}` })),
        el("div", { class: "mono small muted", text: `jeton = ${p.token}` }));
      return el("tr", {},
        el("td", { text: p.name }),
        el("td", { text: solved }),
        el("td", { class: "mono", text: att }),
        el("td", { class: "mono", text: String(p.l3_proofs) }),
        el("td", { class: "keys" }, keys),
        el("td", {}, el("button", {
          type: "button", class: "copy", text: "Supprimer",
          onclick: async () => {
            if (!confirm(`Supprimer ${p.name} ?`)) return;
            try { await api("/api/admin/delete", { name: p.name }); load(); } catch (e) { setMsg(e.message, "bad"); }
          },
        })));
    }));
  } catch (e) {
    $("#panel").hidden = true;
    setMsg(e.message, "bad");
  }
}

$("#auth").addEventListener("submit", (ev) => {
  ev.preventDefault();
  token = $("#adm-token").value.trim();
  load();
});

async function reset(what, question) {
  if (!confirm(question)) return;
  try { await api("/api/admin/reset", { what }); setMsg("Réinitialisé.", "ok"); load(); }
  catch (e) { setMsg(e.message, "bad"); }
}
$("#reset-players").addEventListener("click", () =>
  reset("players", "Effacer tous les joueurs ? Les mêmes pseudos retrouveront les mêmes clés."));
$("#reset-all").addEventListener("click", () =>
  reset("all", "Tout régénérer ? Toutes les clés changent et les joueurs sont effacés."));

if (token) { $("#adm-token").value = token; load(); }  // « Charger » sert aussi à rafraîchir
