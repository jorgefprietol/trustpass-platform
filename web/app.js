"use strict";
let apiKey = "";
let pendingRevocation = null;
const labels = {"facility-access": "Acceso a instalaciones", "professional-certification": "Certificación profesional", "event-pass": "Pase de evento"};
const $ = (id) => document.getElementById(id);
const date = (value) => new Date(value * 1000).toLocaleString("es-EC", {dateStyle: "short", timeStyle: "short"});
function notify(message, error = false) { $("notice").textContent = message; $("notice").classList.toggle("error", error); }
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json", ...(options.headers || {})}});
  if (!response.ok) {
    let detail = "Operación no disponible";
    try { const body = await response.json(); if (typeof body.detail === "string") detail = body.detail; } catch { /* Gateway may return HTML. */ }
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json();
}
function node(tag, text, className) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; }
function clearSession() {
  apiKey = "";
  ["issue-button", "verify-button", "refresh"].forEach(id => { $(id).disabled = true; });
  $("credentials").replaceChildren(); $("events").replaceChildren();
  ["active-count", "revoked-count", "event-count"].forEach(id => { $(id).textContent = "—"; });
}
async function refresh() {
  const [credentials, events] = await Promise.all([api("/api/v1/credentials"), api("/api/v1/events")]);
  $("active-count").textContent = credentials.filter(c => c.status === "active" && c.expires_at > Date.now() / 1000).length;
  $("revoked-count").textContent = credentials.filter(c => c.status === "revoked").length;
  $("event-count").textContent = events.length;
  $("credentials").replaceChildren();
  credentials.forEach(c => {
    const row = node("tr"); const owner = node("td"); owner.append(node("strong", c.subject), node("small", c.id));
    const status = c.status === "revoked" ? "revoked" : c.expires_at <= Date.now() / 1000 ? "expired" : "active";
    const state = node("td"); state.append(node("span", {active: "Activa", revoked: "Revocada", expired: "Vencida"}[status], `badge ${status}`));
    const action = node("td");
    if (c.status === "active") { const button = node("button", "Revocar", "revoke"); button.addEventListener("click", () => { pendingRevocation = c.id; $("revoke-subject").textContent = c.subject; $("revoke-dialog").showModal(); }); action.append(button); }
    else action.textContent = "—";
    row.append(owner, node("td", labels[c.category] || c.category), node("td", date(c.expires_at)), state, action); $("credentials").append(row);
  });
  if (!credentials.length) { const row = node("tr"); const cell = node("td", "Aún no hay credenciales. Emite la primera para comenzar.", "empty"); cell.colSpan = 5; row.append(cell); $("credentials").append(row); }
  $("events").replaceChildren();
  events.forEach(event => { const item = node("li"); const title = node("div"); title.append(node("span", event.event_type === "credential.issued" ? "↗  Credencial emitida" : "⊘  Credencial revocada"), node("small", ` · ${event.credential_id.slice(0, 8)}`)); item.append(title, node("small", date(event.occurred_at))); $("events").append(item); });
  if (!events.length) $("events").append(node("li", "Sin eventos recibidos todavía.", "empty"));
}
$("connect-form").addEventListener("submit", async event => {
  event.preventDefault(); clearSession(); apiKey = $("api-key").value.trim(); $("api-key").value = "";
  try { await refresh(); ["issue-button", "verify-button", "refresh"].forEach(id => { $(id).disabled = false; }); notify("Sesión conectada. Los datos están actualizados."); }
  catch (error) { clearSession(); notify(`No se pudo conectar. ${error.message}`, true); }
});
$("issue-form").addEventListener("submit", async event => {
  event.preventDefault(); $("issue-button").disabled = true;
  try { const result = await api("/api/v1/credentials", {method: "POST", headers: {"Idempotency-Key": crypto.randomUUID()}, body: JSON.stringify({subject: $("subject").value, category: $("category").value, valid_for_seconds: Number($("validity").value)})}); $("credential-token").value = result.token; $("verification-result").textContent = "Credencial emitida. Puedes verificarla ahora."; $("verification-result").className = "verification-result"; notify(`Credencial emitida para ${result.subject}.`); await refresh(); }
  catch (error) { notify(error.message, true); }
  finally { $("issue-button").disabled = false; }
});
$("verify-form").addEventListener("submit", async event => {
  event.preventDefault(); $("verify-button").disabled = true;
  try { const result = await api("/api/v1/verifications", {method: "POST", body: JSON.stringify({token: $("credential-token").value.trim()})}); const messages = {active: "✓ Credencial válida · Firma y registro confirmados", revoked: "⊘ Credencial revocada", expired: "⊘ Credencial vencida", invalid_signature: "⊘ Firma o contenido inválidos", unknown: "⊘ Credencial no encontrada"}; $("verification-result").textContent = messages[result.reason]; $("verification-result").className = `verification-result ${result.valid ? "valid" : "invalid"}`; }
  catch (error) { $("verification-result").textContent = `No se pudo verificar. ${error.message}`; $("verification-result").className = "verification-result invalid"; }
  finally { $("verify-button").disabled = false; }
});
$("refresh").addEventListener("click", () => refresh().then(() => notify("Registro actualizado.")).catch(error => notify(error.message, true)));
$("cancel-revoke").addEventListener("click", () => { pendingRevocation = null; $("revoke-dialog").close(); });
$("confirm-revoke").addEventListener("click", async () => {
  $("confirm-revoke").disabled = true;
  try { await api(`/api/v1/credentials/${pendingRevocation}/revoke`, {method: "POST"}); $("revoke-dialog").close(); pendingRevocation = null; notify("Credencial revocada."); await refresh(); }
  catch (error) { notify(error.message, true); }
  finally { $("confirm-revoke").disabled = false; }
});
