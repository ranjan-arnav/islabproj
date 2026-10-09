package dev.bitchat.mesh;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final class Crypto {
    private static final String IDENTITY_PREFS = "bitchat-mesh-identity-v2";
    private static final String PRIVATE_KEY_PREF = "private-key-pkcs8";
    private static final String PUBLIC_KEY_PREF = "public-key-x509";
    private static final byte[] KDF_SALT = "bitchat-web-room-key-v1".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final PSSParameterSpec PSS_SHA256 = new PSSParameterSpec(
            "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 350, 1);

    final PrivateKey privateKey;
    final PublicKey publicKey;
    final String publicKeyB64;
    final String fingerprint;

    Crypto(Context context) throws Exception {
        SharedPreferences preferences = context.getSharedPreferences(IDENTITY_PREFS, Context.MODE_PRIVATE);
        String privateEncoded = preferences.getString(PRIVATE_KEY_PREF, null);
        String publicEncoded = preferences.getString(PUBLIC_KEY_PREF, null);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        if (privateEncoded == null || publicEncoded == null) {
            // A regular JCA key avoids vendor-specific AndroidKeyStore RSA/OAEP
            // failures. MODE_PRIVATE plus allowBackup=false keeps it app-private.
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(3072, RANDOM);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            if (!preferences.edit()
                    .putString(PRIVATE_KEY_PREF, b64(privateKey.getEncoded()))
                    .putString(PUBLIC_KEY_PREF, b64(publicKey.getEncoded()))
                    .commit()) {
                throw new IllegalStateException("Could not save cryptographic identity");
            }
        } else {
            privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(unb64(privateEncoded)));
            publicKey = factory.generatePublic(new X509EncodedKeySpec(unb64(publicEncoded)));
        }
        publicKeyB64 = b64(publicKey.getEncoded());
        fingerprint = hex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded())).substring(0, 16);
    }

    static SecretKey deriveRoomKey(String roomCode) throws Exception {
        if (roomCode.length() < 8) throw new IllegalArgumentException("Room code needs at least 8 characters");
        PBEKeySpec spec = new PBEKeySpec(roomCode.toCharArray(), KDF_SALT, 310_000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    static String roomId(SecretKey key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("room-id:".getBytes(StandardCharsets.UTF_8));
        return hex(digest.digest(key.getEncoded())).substring(0, 16);
    }

    String sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.setParameter(PSS_SHA256);
        signature.initSign(privateKey);
        signature.update(data);
        return b64(signature.sign());
    }

    static void verify(byte[] data, String signatureB64, String publicKeyB64) throws Exception {
        PublicKey key = publicKey(publicKeyB64);
        byte[] encodedSignature = unb64(signatureB64);
        Exception lastProviderError = null;

        // Android vendors differ on whether initVerify resets RSA-PSS parameters.
        // Try both legal initialization orders and both common algorithm aliases,
        // while always requiring the exact SHA-256/MGF1-SHA256/350-byte-salt suite.
        for (String algorithm : new String[]{"SHA256withRSA/PSS", "RSASSA-PSS"}) {
            for (boolean parametersAfterKey : new boolean[]{true, false}) {
                try {
                    Signature verifier = Signature.getInstance(algorithm);
                    if (parametersAfterKey) {
                        verifier.initVerify(key);
                        verifier.setParameter(PSS_SHA256);
                    } else {
                        verifier.setParameter(PSS_SHA256);
                        verifier.initVerify(key);
                    }
                    verifier.update(data);
                    if (verifier.verify(encodedSignature)) return;
                } catch (Exception error) {
                    lastProviderError = error;
                }
            }
        }
        if (lastProviderError != null) {
            throw new SecurityException("RSA-PSS verification failed: " +
                    lastProviderError.getClass().getSimpleName() + ": " + lastProviderError.getMessage(),
                    lastProviderError);
        }
        throw new SecurityException("Invalid RSA-PSS signature");
    }

    static Encrypted encrypt(SecretKey key, JSONObject payload, byte[] aad, Crypto identity) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] plain = canonical(payload);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return new Encrypted(b64(nonce), b64(cipher.doFinal(plain)), identity.sign(plain), null);
    }

    static Encrypted encryptPrivate(PublicKey recipient, JSONObject payload, byte[] aad, Crypto identity) throws Exception {
        byte[] rawKey = new byte[32];
        RANDOM.nextBytes(rawKey);
        SecretKey key = new SecretKeySpec(rawKey, "AES");
        Encrypted encrypted = encrypt(key, payload, aad, identity);
        // PKCS#1 v1.5 is used only to wrap a random 32-byte AES key. It is
        // implemented consistently by Android Conscrypt and Python/OpenSSL.
        Cipher wrap = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        wrap.init(Cipher.ENCRYPT_MODE, recipient);
        return new Encrypted(encrypted.nonce, encrypted.ciphertext, encrypted.signature, b64(wrap.doFinal(rawKey)));
    }

    static JSONObject decrypt(SecretKey key, JSONObject packet, byte[] aad) throws Exception {
        byte[] plain = decryptBytes(key, packet, aad);
        verify(plain, packet.getString("signature"), packet.getString("public_key"));
        return new JSONObject(new String(plain, StandardCharsets.UTF_8));
    }

    JSONObject decryptPrivate(JSONObject packet, byte[] aad) throws Exception {
        byte[] wrapped = unb64(packet.getString("wrapped_key"));
        if (wrapped.length != 384) throw new SecurityException("Invalid RSA-3072 wrapped-key length: " + wrapped.length);
        Cipher unwrap = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        unwrap.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawKey = unwrap.doFinal(wrapped);
        if (rawKey.length != 32) throw new SecurityException("Invalid AES-256 message-key length");
        SecretKey key = new SecretKeySpec(rawKey, "AES");
        return decrypt(key, packet, aad);
    }

    private static byte[] decryptBytes(SecretKey key, JSONObject packet, byte[] aad) throws Exception {
        byte[] nonce = unb64(packet.getString("nonce"));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(unb64(packet.getString("ciphertext")));
    }

    static PublicKey publicKey(String value) throws Exception {
        return java.security.KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.X509EncodedKeySpec(unb64(value)));
    }

    static String fingerprint(String publicKeyB64) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(unb64(publicKeyB64))).substring(0, 16);
    }

    static byte[] canonical(JSONObject object) throws Exception {
        TreeMap<String, Object> sorted = new TreeMap<>();
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            sorted.put(key, object.get(key));
        }
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : sorted.entrySet()) {
            if (!first) out.append(',');
            first = false;
            out.append(JSONObject.quote(entry.getKey())).append(':');
            Object value = entry.getValue();
            if (value == null || value == JSONObject.NULL) out.append("null");
            else if (value instanceof Boolean || value instanceof Number) out.append(value);
            else out.append(JSONObject.quote(String.valueOf(value)));
        }
        return out.append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    static String b64(byte[] value) { return Base64.encodeToString(value, Base64.URL_SAFE | Base64.NO_WRAP); }
    static byte[] unb64(String value) { return Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP); }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }

    static final class Encrypted {
        final String nonce, ciphertext, signature, wrappedKey;
        Encrypted(String nonce, String ciphertext, String signature, String wrappedKey) {
            this.nonce = nonce; this.ciphertext = ciphertext; this.signature = signature; this.wrappedKey = wrappedKey;
        }
    }
}
