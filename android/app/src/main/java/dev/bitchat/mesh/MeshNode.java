package dev.bitchat.mesh;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

final class MeshNode implements BluetoothTransport.Listener {
    static final int MAX_TTL = 7;
    private final Crypto identity;
    private final BluetoothTransport transport;
    private final UiListener ui;
    private final Map<String, Long> seen = new LinkedHashMap<>();
    private final Map<String, Participant> participants = new LinkedHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private volatile SecretKey roomKey;
    private volatile String roomId;
    private volatile String nickname = "anonymous";

    interface UiListener {
        void onStatus(String value);
        void onParticipants(List<Participant> participants);
        void onMessage(ChatMessage message);
        void onLinks(int count);
    }

    MeshNode(Context context, BluetoothAdapter adapter, UiListener ui) throws Exception {
        this.identity = new Crypto(context);
        this.ui = ui;
        this.transport = new BluetoothTransport(adapter, this);
    }

    String fingerprint() { return identity.fingerprint; }

    void start() {
        transport.start();
        scheduler.scheduleAtFixedRate(this::announceQuietly, 4, 12, TimeUnit.SECONDS);
    }

    synchronized void configure(String nickname, String roomCode) throws Exception {
        String clean = nickname.trim();
        if (clean.isEmpty() || clean.length() > 32) throw new IllegalArgumentException("Nickname must be 1-32 characters");
        this.nickname = clean;
        roomKey = Crypto.deriveRoomKey(roomCode);
        roomId = Crypto.roomId(roomKey);
        seen.clear();
        participants.clear();
        ui.onParticipants(new ArrayList<>());
        ui.onStatus("Encrypted room ready: " + roomId);
        announce();
    }

    void connect(BluetoothDevice device, boolean laptop) { transport.connect(device, laptop); }

    void send(String text, String recipientId) throws Exception {
        String clean = text.trim();
        if (clean.isEmpty()) throw new IllegalArgumentException("Message cannot be empty");
        if (clean.length() > 2000) throw new IllegalArgumentException("Message is too long");
        ensureConfigured();
        String id = UUID.randomUUID().toString().replace("-", "");
        JSONObject payload = new JSONObject()
                .put("id", id)
                .put("sender_id", identity.fingerprint)
                .put("nickname", nickname)
                .put("created_at", now())
                .put("text", clean)
                .put("private", recipientId != null);
        JSONObject packet;

        if (recipientId != null) {
            Participant recipient;
            synchronized (this) { recipient = participants.get(recipientId); }
            if (recipient == null) throw new IllegalArgumentException("Recipient is no longer reachable");
            payload.put("recipient_id", recipient.id).put("recipient_nickname", recipient.nickname);
            packet = basePacket("private", id)
                    .put("recipient_id", recipient.id)
                    .put("public_key", identity.publicKeyB64);
            Crypto.Encrypted encrypted = Crypto.encryptPrivate(
                    Crypto.publicKey(recipient.publicKey), payload, aad(packet), identity);
            packet.put("nonce", encrypted.nonce)
                    .put("ciphertext", encrypted.ciphertext)
                    .put("signature", encrypted.signature)
                    .put("wrapped_key", encrypted.wrappedKey);
        } else {
            packet = basePacket("chat", id).put("public_key", identity.publicKeyB64);
            Crypto.Encrypted encrypted = Crypto.encrypt(roomKey, payload, aad(packet), identity);
            packet.put("nonce", encrypted.nonce)
                    .put("ciphertext", encrypted.ciphertext)
                    .put("signature", encrypted.signature);
        }
        remember(id);
        transport.broadcast(packet, null);
        ui.onMessage(new ChatMessage(nickname, clean, true, recipientId != null,
                recipientId == null ? null : payload.getString("recipient_nickname"), 0, payload.getString("created_at")));
    }

    synchronized List<Participant> participantSnapshot() {
        long cutoff = System.currentTimeMillis() - 36_000;
        List<Participant> result = new ArrayList<>();
        for (Participant participant : participants.values()) if (participant.lastSeen >= cutoff) result.add(participant.publicCopy());
        return result;
    }

    private void announceQuietly() { try { if (roomId != null) announce(); } catch (Exception ignored) {} }

    private void announce() throws Exception {
        ensureConfigured();
        String id = UUID.randomUUID().toString().replace("-", "");
        JSONObject signed = new JSONObject()
                .put("id", id)
                .put("room_id", roomId)
                .put("sender_id", identity.fingerprint)
                .put("nickname", nickname)
                .put("public_key", identity.publicKeyB64)
                .put("created_at", now());
        JSONObject packet = new JSONObject(signed.toString())
                .put("v", 1).put("type", "announce").put("ttl", MAX_TTL)
                .put("signature", identity.sign(Crypto.canonical(signed)));
        remember(id);
        transport.broadcast(packet, null);
    }

    @Override public void onPacket(JSONObject packet, BluetoothTransport.Link ingress) {
        try {
            String type = packet.getString("type");
            if ("announce".equals(type)) receiveAnnouncement(packet, ingress);
            else if ("chat".equals(type)) receiveChat(packet, ingress);
            else if ("private".equals(type)) receivePrivate(packet, ingress);
        } catch (Exception error) {
            String detail = error.getMessage();
            ui.onStatus("Rejected invalid packet: " +
                    (detail == null || detail.trim().isEmpty() ? error.getClass().getSimpleName() : detail));
        }
    }

    private void receiveAnnouncement(JSONObject packet, BluetoothTransport.Link ingress) throws Exception {
        validateBase(packet, "announce");
        if (alreadySeen(packet.getString("id")) || !packet.getString("room_id").equals(roomId)) return;
        String sender = packet.getString("sender_id");
        String publicKey = packet.getString("public_key");
        if (!Crypto.fingerprint(publicKey).equals(sender)) throw new SecurityException("Fingerprint mismatch");
        JSONObject signed = new JSONObject()
                .put("id", packet.getString("id"))
                .put("room_id", packet.getString("room_id"))
                .put("sender_id", sender)
                .put("nickname", packet.getString("nickname"))
                .put("public_key", publicKey)
                .put("created_at", packet.getString("created_at"));
        Crypto.verify(Crypto.canonical(signed), packet.getString("signature"), publicKey);
        remember(packet.getString("id"));
        if (!sender.equals(identity.fingerprint)) {
            int hops = MAX_TTL - packet.getInt("ttl") + 1;
            synchronized (this) {
                participants.put(sender, new Participant(sender, packet.getString("nickname"), publicKey, hops, System.currentTimeMillis()));
            }
            ui.onParticipants(participantSnapshot());
        }
        relay(packet, ingress);
    }

    private void receiveChat(JSONObject packet, BluetoothTransport.Link ingress) throws Exception {
        validateBase(packet, "chat");
        String id = packet.getString("id");
        if (alreadySeen(id) || !packet.getString("room_id").equals(roomId)) return;
        JSONObject payload = Crypto.decrypt(roomKey, packet, aad(packet));
        validateSender(packet, payload);
        remember(id);
        ui.onMessage(messageFrom(payload, false, MAX_TTL - packet.getInt("ttl") + 1));
        relay(packet, ingress);
    }

    private void receivePrivate(JSONObject packet, BluetoothTransport.Link ingress) throws Exception {
        validateBase(packet, "private");
        String id = packet.getString("id");
        if (alreadySeen(id) || !packet.getString("room_id").equals(roomId)) return;
        remember(id);
        if (!packet.getString("recipient_id").equals(identity.fingerprint)) {
            relay(packet, ingress);
            return;
        }
        JSONObject payload = identity.decryptPrivate(packet, aad(packet));
        validateSender(packet, payload);
        if (!payload.getString("recipient_id").equals(identity.fingerprint)) throw new SecurityException("Recipient mismatch");
        ui.onMessage(messageFrom(payload, false, MAX_TTL - packet.getInt("ttl") + 1));
    }

    private void validateSender(JSONObject packet, JSONObject payload) throws Exception {
        if (!payload.getString("id").equals(packet.getString("id")) ||
                !payload.getString("sender_id").equals(packet.getString("sender_id"))) {
            throw new SecurityException("Envelope mismatch");
        }
        if (!Crypto.fingerprint(packet.getString("public_key")).equals(packet.getString("sender_id"))) {
            throw new SecurityException("Sender fingerprint mismatch");
        }
    }

    private static ChatMessage messageFrom(JSONObject payload, boolean local, int hops) throws Exception {
        return new ChatMessage(payload.getString("nickname"), payload.getString("text"), local,
                payload.optBoolean("private", false), payload.optString("recipient_nickname", null),
                hops, payload.getString("created_at"));
    }

    private JSONObject basePacket(String type, String id) throws Exception {
        return new JSONObject().put("v", 1).put("type", type).put("id", id)
                .put("room_id", roomId).put("ttl", MAX_TTL).put("sender_id", identity.fingerprint);
    }

    private static byte[] aad(JSONObject packet) throws Exception {
        String value = packet.getInt("v") + "|" + packet.getString("type") + "|" +
                packet.getString("id") + "|" + packet.getString("room_id");
        if ("private".equals(packet.getString("type"))) {
            value += "|" + packet.getString("sender_id") + "|" + packet.getString("recipient_id");
        }
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private void relay(JSONObject packet, BluetoothTransport.Link ingress) throws Exception {
        int ttl = packet.getInt("ttl");
        if (ttl > 1) transport.broadcast(new JSONObject(packet.toString()).put("ttl", ttl - 1), ingress);
    }

    private void validateBase(JSONObject packet, String type) throws Exception {
        if (packet.getInt("v") != 1 || !type.equals(packet.getString("type"))) throw new SecurityException("Protocol mismatch");
        int ttl = packet.getInt("ttl");
        if (ttl < 1 || ttl > MAX_TTL) throw new SecurityException("Invalid TTL");
    }

    private synchronized boolean alreadySeen(String id) { return seen.containsKey(id); }
    private synchronized void remember(String id) {
        seen.put(id, System.currentTimeMillis());
        while (seen.size() > 2000) seen.remove(seen.keySet().iterator().next());
    }
    private void ensureConfigured() { if (roomKey == null) throw new IllegalStateException("Join a room first"); }
    private static String now() { return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(); }

    @Override public void onStatus(String text) { ui.onStatus(text); }
    @Override public void onLinksChanged(int count) { ui.onLinks(count); announceQuietly(); }

    static final class Participant {
        final String id, nickname, publicKey;
        final int hops;
        final long lastSeen;
        Participant(String id, String nickname, String publicKey, int hops, long lastSeen) {
            this.id = id; this.nickname = nickname; this.publicKey = publicKey; this.hops = hops; this.lastSeen = lastSeen;
        }
        Participant publicCopy() { return new Participant(id, nickname, "", hops, lastSeen); }
        @Override public String toString() { return nickname + " - private (" + hops + " hop" + (hops == 1 ? "" : "s") + ")"; }
    }

    static final class ChatMessage {
        final String nickname, text, recipient, createdAt;
        final boolean local, privateMessage;
        final int hops;
        ChatMessage(String nickname, String text, boolean local, boolean privateMessage, String recipient, int hops, String createdAt) {
            this.nickname = nickname; this.text = text; this.local = local; this.privateMessage = privateMessage;
            this.recipient = recipient; this.hops = hops; this.createdAt = createdAt;
        }
    }
}
