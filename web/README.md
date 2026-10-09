# bitchat web (Python + Bluetooth)

This directory contains a local web edition of [bitchat](https://github.com/permissionlesstech/bitchat). The browser is the user interface; Python owns the Bluetooth radio because desktop browsers cannot advertise themselves as general-purpose Bluetooth peripherals.

Every laptop runs the same program. Connections use Bluetooth Classic RFCOMM and do not use Wi-Fi, the internet, or a central chat server. A laptop may connect to several peers and relays encrypted packets for peers that are not directly in range.

## What is implemented

- Local Flask web interface at `http://127.0.0.1:5000`
- Bluetooth RFCOMM server and client on channel 12
- Multiple simultaneous laptop links
- Controlled mesh flooding, seven-hop TTL, split-horizon relay, and duplicate suppression
- AES-256-GCM encryption using a key derived from the shared room code
- Recipient-only private messages using per-message AES-256 keys wrapped with RSA-OAEP
- RSA-3072 PSS signatures with SHA-256 and visible public-key fingerprints
- In-memory chat history and panic wipe
- Strict packet sizes, message sizes, schema checks, and authenticated decryption

The cryptographic choices apply the lab manual's AES, SHA hashing, RSA, and digital-signature topics. AES-GCM and RSA-PSS are modern authenticated constructions; they replace insecure textbook RSA signing and unauthenticated AES modes.

## Supported systems

- **Windows 10/11:** supported with Python 3.11 or newer. This is the primary tested platform.
- **Linux:** supported when BlueZ, `bluetoothctl`, and RFCOMM socket support are installed.
- **macOS:** the web UI works, but CPython does not expose the RFCOMM socket transport used by this project. Use Windows or Linux for the Bluetooth nodes.

Bluetooth Classic must be available and enabled. Corporate device policy can disable RFCOMM even when ordinary Bluetooth accessories work.

## Run it on each Windows laptop

1. Install Python 3.11 or newer and enable **Add Python to PATH** during installation.
2. Turn Bluetooth on.
3. In Windows **Settings > Bluetooth & devices**, pair the laptops with each other. Accept the matching PIN on both laptops.
4. Copy this repository to each laptop, open PowerShell in the `web` directory, and run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\run.ps1
   ```

5. Wait for the dependencies to install. Open <http://127.0.0.1:5000> if it does not open automatically.
6. Enter a nickname and the **same room code** on every laptop. Use a long, random code and share it face-to-face.
7. Note each laptop's Bluetooth address shown in the top-right of the chat header.
8. On laptop A, click **Connect a laptop**, enter laptop B's displayed address, keep channel `12`, and connect. Only one side should initiate a given link.
9. For more laptops, create enough links to join the network. You do not need every laptop to connect to every other laptop.
10. To prevent relay laptops from reading a message, choose a named peer in the **send to** selector. Leave `# room broadcast` selected only when everyone in the room should see it.

### Three-laptop example

```text
Laptop A  <--Bluetooth-->  Laptop B  <--Bluetooth-->  Laptop C
```

Connect A to B, then B to C. After C appears in A's **send to** selector, A selects C and sends. The message is encrypted with a fresh AES key, that key is wrapped to C's RSA public key, and B relays the opaque packet without decrypting, displaying, or logging the chat message. The UI on C reports `2 hops`.

For better resilience with four or more laptops, connect each laptop to two nearby peers where possible. Do not create both A-to-B and B-to-A links; that only creates a redundant duplicate connection.

## Linux start-up

Pair the laptops with `bluetoothctl`, then run:

```bash
chmod +x run.sh
./run.sh
```

If the listener reports a permission error, ensure the user can access Bluetooth sockets and that BlueZ is running. Distribution policies differ; do not run the whole web app as root unless your lab environment explicitly requires it.

## How security works

1. **Key derivation:** PBKDF2-HMAC-SHA256 performs 310,000 iterations over the room code and produces a 256-bit AES key. Only a short SHA-256-derived room identifier goes on the wire.
2. **Encryption:** each message uses a fresh 96-bit random nonce and AES-256-GCM. The version, message ID, packet type, and room ID are authenticated as associated data.
3. **Signing:** every installation creates a local RSA-3072 identity. The sender signs the canonical plaintext with RSA-PSS/SHA-256 and includes the public key in the encrypted packet envelope.
4. **Private messages:** a fresh random AES-256 key encrypts each private message. Only the chosen recipient can unwrap that key using its RSA private key; RSA-OAEP with SHA-256 protects the wrapped key.
5. **Verification:** a receiver decrypts the AES-GCM packet, verifies the RSA signature, and confirms that the SHA-256 fingerprint of the supplied public key equals the sender ID.
6. **Relay:** the TTL is intentionally excluded from the authenticated header, so a relay can decrement it without decrypting or re-signing the message. All other protected content remains unchanged.

The room code is a shared secret: anyone who learns it can decrypt room broadcasts. Recipient-only private messages use the selected recipient's RSA key instead. Relay devices can still observe routing metadata such as packet timing, sender and recipient fingerprints, and size, but cannot read the private plaintext. Compare fingerprints in person for identity-sensitive use.

## Test and run manually

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe app.py
```

Useful options:

```powershell
# Change only the local web port; Bluetooth remains on RFCOMM channel 12.
.\.venv\Scripts\python.exe app.py --port 5050
```

The UI intentionally binds to `127.0.0.1`. Do not bind it to `0.0.0.0` on an untrusted network; the local HTTP API has no login because it is designed for same-laptop access.

## Troubleshooting

- **Bluetooth listener failed / address already in use:** another copy is running or channel 12 is occupied. Stop the other process. All peers must use the same RFCOMM channel.
- **Connection refused:** make sure the app is running on the destination laptop, the shown address was entered correctly, and both devices are paired.
- **A connection times out:** remove the OS-level pairing on both laptops, pair again, and retry from only one side.
- **Packets ignored for another room:** re-enter the exact same room code on all laptops; room codes are case-sensitive.
- **Messages reach B but not C:** ensure B has both links visible. Mesh forwarding requires the intermediate app to remain running.

## Scope differences from the native project

This is an educational Python adaptation, not a wire-compatible port of the native Swift/Kotlin apps. It preserves the local mesh-chat concept, encrypted relaying, identity fingerprints, TTL, and IRC-like visual character. It does not implement BLE GATT interoperability, Noise sessions, Nostr, file transfer, voice, store-and-forward persistence, or forward secrecy.
