const state = { sequence: 0, configured: false, messages: new Set(), events: new Set(), totalMessages: 0, participants: [] };
const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 2600);
}

function openDialog(id) { const dialog = $(id); if (!dialog.open) dialog.showModal(); }
function closeDialog(id) { const dialog = $(id); if (dialog.open) dialog.close(); }
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => closeDialog(button.dataset.close)));

function timeLabel(value) {
  try { return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  catch { return "now"; }
}

function addMessage(message) {
  if (state.messages.has(message.id)) return;
  state.messages.add(message.id);
  state.totalMessages += 1;
  $("welcomeCard")?.remove();
  const article = document.createElement("article");
  article.className = `message${message.local ? " local" : ""}`;
  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.textContent = (message.nickname || "?").slice(0, 2).toUpperCase();
  const content = document.createElement("div");
  const head = document.createElement("div");
  head.className = "message-head";
  const name = document.createElement("strong"); name.textContent = message.nickname;
  const verified = document.createElement("span"); verified.className = "verified"; verified.textContent = "✓ signed";
  const time = document.createElement("time"); time.textContent = timeLabel(message.created_at);
  const hops = document.createElement("code"); hops.textContent = message.hops ? `${message.hops} hop${message.hops > 1 ? "s" : ""}` : "local";
  const body = document.createElement("p"); body.textContent = message.text;
  head.append(name);
  if (message.private) {
    const badge = document.createElement("span"); badge.className = "private-badge";
    badge.textContent = message.local ? `private to ${message.recipient_nickname || "peer"}` : "private to you";
    head.append(badge);
  }
  head.append(verified, time, hops); content.append(head, body); article.append(avatar, content);
  $("messages").append(article);
  $("messages").scrollTop = $("messages").scrollHeight;
  $("statMessages").textContent = state.totalMessages;
}

function addEvent(event) {
  const eventKey = `${event.sequence}:${event.text}`;
  if (state.events.has(eventKey)) return;
  state.events.add(eventKey);
  const item = document.createElement("div"); item.className = `event ${event.kind}`;
  const text = document.createElement("p"); text.textContent = event.text;
  const time = document.createElement("time"); time.textContent = timeLabel(event.created_at);
  item.append(text, time); $("eventList").prepend(item);
}

function renderPeers(peers) {
  $("peerCount").textContent = peers.length; $("statPeers").textContent = peers.length;
  const list = $("peerList"); list.replaceChildren();
  if (!peers.length) { const empty = document.createElement("div"); empty.className = "empty-peers"; empty.textContent = "No links yet"; list.append(empty); return; }
  peers.forEach((peer) => {
    const item = document.createElement("div"); item.className = "peer";
    const dot = document.createElement("i"); const copy = document.createElement("span");
    const address = document.createElement("strong"); address.textContent = peer.address;
    const direction = document.createElement("small"); direction.textContent = `${peer.direction} link`;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "×"; remove.title = "Disconnect";
    remove.addEventListener("click", async () => { await api(`/api/disconnect/${encodeURIComponent(peer.id)}`, { method: "POST", body: "{}" }); await refresh(); });
    copy.append(address, direction); item.append(dot, copy, remove); list.append(item);
  });
}

function renderParticipants(participants) {
  state.participants = participants;
  const select = $("recipientSelect");
  const selected = select.value;
  select.replaceChildren();
  const broadcast = document.createElement("option");
  broadcast.value = ""; broadcast.textContent = "# room broadcast"; select.append(broadcast);
  participants.forEach((participant) => {
    const option = document.createElement("option"); option.value = participant.id;
    option.textContent = `${participant.nickname} (private, ${participant.hops} hop${participant.hops === 1 ? "" : "s"})`;
    select.append(option);
  });
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
  updatePrivacyMode();
}

function updatePrivacyMode() {
  const privateMode = Boolean($("recipientSelect").value);
  $("privacyMode").textContent = privateMode ? "recipient-only end-to-end encryption" : "shared room encryption";
  $("privacyMode").classList.toggle("private", privateMode);
  $("messageInput").placeholder = privateMode ? "Private message through the mesh..." : "Message #bluetooth...";
}

function applyStatus(status) {
  state.sequence = Math.max(state.sequence, status.sequence || 0);
  state.configured = status.configured;
  $("nicknameLabel").textContent = status.configured ? status.nickname : "not configured";
  $("avatar").textContent = status.configured ? status.nickname.slice(0, 2).toUpperCase() : "?";
  $("fingerprint").textContent = status.fingerprint;
  $("identityDot").classList.toggle("on", status.configured);
  $("statRoom").textContent = status.room_id ? status.room_id.slice(0, 6) : "—";
  $("messageInput").disabled = !status.configured;
  $("sendButton").disabled = !status.configured;
  $("recipientSelect").disabled = !status.configured;
  $("messageInput").placeholder = status.configured ? "Message #bluetooth…" : "Join a room to start chatting…";
  $("radioStatus").textContent = status.bluetooth_error ? "radio unavailable" : "listening";
  $("localAddress").textContent = status.bluetooth_error || `${status.local_address || "Bluetooth"} · ch ${status.channel}`;
  document.querySelector(".radio-icon").classList.toggle("on", !status.bluetooth_error);
  renderPeers(status.peers || []);
  renderParticipants(status.participants || []);
  (status.messages || []).forEach(addMessage); (status.events || []).forEach(addEvent);
  renderKnownDevices(status.paired_devices || []);
}

function renderKnownDevices(devices) {
  const host = $("knownDevices"); host.replaceChildren();
  devices.slice(0, 8).forEach((device) => {
    const button = document.createElement("button"); button.type = "button"; button.className = "device-chip";
    button.textContent = device.address; button.title = device.name;
    button.addEventListener("click", () => { $("addressInput").value = device.address; }); host.append(button);
  });
}

async function refresh() {
  try { applyStatus(await api("/api/status")); }
  catch (error) { $("radioStatus").textContent = "backend offline"; }
}

async function poll() {
  try {
    const update = await api(`/api/updates?after=${state.sequence}`);
    state.sequence = Math.max(state.sequence, update.sequence || 0);
    (update.messages || []).forEach(addMessage); (update.events || []).forEach(addEvent); renderPeers(update.peers || []); renderParticipants(update.participants || []);
  } catch (_) { /* A later poll will retry. */ }
}

$("setupOpen").addEventListener("click", () => openDialog("setupDialog"));
$("connectOpen").addEventListener("click", () => openDialog("connectDialog"));
$("securityInfo").addEventListener("click", () => openDialog("securityDialog"));
$("showRoom").addEventListener("change", (event) => { $("roomInput").type = event.target.checked ? "text" : "password"; });

$("setupForm").addEventListener("submit", async (event) => {
  event.preventDefault(); $("setupError").textContent = "";
  try {
    const result = await api("/api/settings", { method: "POST", body: JSON.stringify({ nickname: $("nicknameInput").value, room_code: $("roomInput").value }) });
    applyStatus(result.status); $("roomInput").value = ""; closeDialog("setupDialog"); toast("Encrypted room ready"); openDialog("connectDialog");
  } catch (error) { $("setupError").textContent = error.message; }
});

$("connectForm").addEventListener("submit", async (event) => {
  event.preventDefault(); $("connectError").textContent = ""; $("connectButton").disabled = true; $("connectButton").textContent = "Connecting…";
  try {
    await api("/api/connect", { method: "POST", body: JSON.stringify({ address: $("addressInput").value, channel: Number($("channelInput").value) }) });
    closeDialog("connectDialog"); toast("Bluetooth link connected"); await refresh();
  } catch (error) { $("connectError").textContent = error.message; }
  finally { $("connectButton").disabled = false; $("connectButton").textContent = "Connect over Bluetooth"; }
});

$("composer").addEventListener("submit", async (event) => {
  event.preventDefault(); const text = $("messageInput").value; if (!text.trim()) return;
  try { const result = await api("/api/messages", { method: "POST", body: JSON.stringify({ text, recipient_id: $("recipientSelect").value || null }) }); addMessage(result.message); $("messageInput").value = ""; resizeComposer(); }
  catch (error) { toast(error.message); }
});

function resizeComposer() { const input = $("messageInput"); input.style.height = "auto"; input.style.height = `${Math.min(input.scrollHeight, 130)}px`; $("charCount").textContent = `${input.value.length} / 2000`; }
$("messageInput").addEventListener("input", resizeComposer);
$("recipientSelect").addEventListener("change", updatePrivacyMode);
$("messageInput").addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("composer").requestSubmit(); } });

$("panicButton").addEventListener("click", async () => {
  if (!confirm("Wipe the room key and all in-memory messages on this laptop?")) return;
  await api("/api/panic", { method: "POST", body: "{}" }); location.reload();
});

refresh().then(() => { if (!state.configured) openDialog("setupDialog"); });
setInterval(poll, 1000);
