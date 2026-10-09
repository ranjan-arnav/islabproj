# Bitchat Mesh for Android

The Android application speaks the same encrypted JSON packet protocol as the Python laptop client. It supports multiple simultaneous Bluetooth Classic RFCOMM links, signed peer discovery, seven-hop forwarding, room broadcasts, and recipient-only private messages.

## Install

1. Copy `bitchat-mesh-debug.apk` to an Android 8.0 or newer phone.
2. Open the file and allow installation from the file-manager source when Android asks.
3. Grant **Nearby devices** permission.
4. Pair the phone with the other phones or laptops in Android Settings before opening links in the app.

## Connect Android to Android

1. Run the app on both phones.
2. Join the same room on both.
3. On one phone, select the paired phone and choose **Android phone**.
4. Tap **Connect**. Only one side should initiate the link.

## Connect Android to the Python laptop

1. Run the Python web app on the laptop and keep its Bluetooth listener on channel 12.
2. Pair the phone and laptop in their operating-system Bluetooth settings.
3. On the phone, select the paired laptop.
4. Choose **Python laptop - channel 12** and tap **Connect**.

The Android device must initiate laptop links because the Python listener uses a fixed RFCOMM channel rather than Android's service UUID.

If a laptop connection fails, confirm that **Python laptop - channel 12** is selected. The app tries both Android raw-channel socket modes. The status line records the underlying Android error if neither mode succeeds; remove and re-pair the laptop and phone before retrying.

After joining the same room, wait up to 12 seconds for signed announcements. The recipient selector changes from only **# room broadcast** to include entries such as **name - private (1 hop)**. Version 1.0.2 includes RSA-PSS provider compatibility for participant discovery on different Android vendors.

## Multi-hop example

```text
Android A  <--Bluetooth-->  Android B  <--Bluetooth-->  Python laptop C
```

After signed announcements propagate, C appears in A's recipient selector with a two-hop label. A private message for C is encrypted to C's public key. B forwards it without decrypting or displaying it.

## Security

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 room-key derivation
- RSA-3072 PKCS#1 v1.5 wrapping for random per-message AES keys, selected for Android/Python provider interoperability
- RSA-PSS/SHA-256 signatures
- App-private RSA identity storage with Android backup disabled
- SHA-256 public-key fingerprints

Relay devices can observe packet timing, size, and sender/recipient fingerprints but cannot read recipient-only message content.
