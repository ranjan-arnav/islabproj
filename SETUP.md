# Bitchat Web Setup Guide

This guide explains how to run the Python web edition of Bitchat and connect two or more laptops over Bluetooth.

## 1. Requirements

Each laptop needs:

- Windows 10 or Windows 11
- Bluetooth Classic support
- Python 3.11 or newer
- A local copy of this repository
- No internet connection after the Python packages have been installed

During Python installation, enable **Add Python to PATH**.

## 2. Pair the laptops

Do this before starting the application:

1. Open **Settings** on both laptops.
2. Go to **Bluetooth & devices**.
3. Turn Bluetooth on.
4. Select **Add device > Bluetooth** on one laptop.
5. Select the other laptop.
6. Confirm the matching PIN on both laptops.
7. Wait until Windows shows the devices as paired.

For multiple laptops, pair every pair that will have a direct connection. For example, an A-B-C chain requires A paired with B and B paired with C.

## 3. Start the application

Open PowerShell in the project directory and run:

```powershell
cd D:\bitchat\web
Set-ExecutionPolicy -Scope Process Bypass
.\run.ps1
```

The first run creates a Python virtual environment and installs the required packages. Later runs reuse that environment.

When the terminal displays the following address, the application is ready:

```text
http://127.0.0.1:5000
```

Open that address in Chrome, Edge, or Firefox. Keep the PowerShell window open while using the application.

Repeat these steps on every laptop.

## 4. Join the encrypted room

On each laptop:

1. Enter a nickname.
2. Enter a room code containing at least eight characters.
3. Select **Derive room key**.

Every participant must enter the exact same room code. Room codes are case-sensitive.

Use a long, random room code and exchange it in person. The application derives an AES-256 key locally and never transmits the room code.

## 5. Connect two laptops

Each running application displays its Bluetooth address in the upper-right corner. It looks similar to:

```text
AA:BB:CC:DD:EE:FF
```

To connect laptop A to laptop B:

1. Keep the application running on both laptops.
2. Copy the Bluetooth address displayed on laptop B.
3. On laptop A, select **Connect a laptop**.
4. Enter laptop B's Bluetooth address.
5. Leave the RFCOMM channel set to `12`.
6. Select **Connect over Bluetooth**.
7. Confirm that the peer appears under **Nearby peers** on both laptops.
8. Wait for the other nickname to appear in the **send to** selector.
9. Choose the nickname for a recipient-only message, or choose `# room broadcast` for a message visible to every room member.
10. Send a test message.

Only one side should initiate a particular connection. Do not connect A to B and B to A simultaneously.

## 6. Connect multiple laptops

Laptops do not all need direct connections. Intermediate laptops relay encrypted packets automatically.

Example with three laptops:

```text
Laptop A  <-- Bluetooth -->  Laptop B  <-- Bluetooth -->  Laptop C
```

Set it up as follows:

1. Connect A to B.
2. Connect B to C.
3. Use the same room code on A, B, and C.
4. Wait until C appears in A's **send to** selector with a two-hop label.
5. Select C and send a private message from A.
6. B relays the encrypted packet to C without decrypting, displaying, or recording the chat message.

The interface on C should report that the message travelled two hops.

For larger groups, connect each laptop to one or two nearby laptops. The application prevents routing loops with message identifiers and stops forwarding after seven hops.

## 7. Security used by the application

- **AES-256-GCM** encrypts messages and detects ciphertext modification.
- **PBKDF2-HMAC-SHA256** derives the AES key from the shared room code.
- **RSA-3072 PSS with SHA-256** signs every message.
- **RSA-3072 PKCS#1 v1.5** wraps each random private AES message key to its selected recipient for consistent Android/Python provider interoperability.
- **SHA-256 fingerprints** identify each installation's public key.
- A fresh random nonce is generated for every encrypted message.

Anyone who knows the room code can read room broadcasts. A message sent to a named recipient uses a separate random AES key that only that recipient can unwrap. Intermediate nodes can observe packet metadata but cannot read the private content. When sender identity matters, compare the displayed fingerprints in person.

## 8. Stop the application

Return to the PowerShell window running the server and press:

```text
Ctrl+C
```

Closing the terminal also stops the local website and Bluetooth listener.

## 9. Run the automated tests

From the `web` directory:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests cover encryption, signature verification, packet framing, API behavior, tamper detection, and three-node mesh relay.

## 10. Troubleshooting

### The page does not open

- Confirm the PowerShell window says `Running on http://127.0.0.1:5000`.
- Open `http://127.0.0.1:5000` manually.
- Ensure another program is not already using port 5000.

### Bluetooth listener failed

- Turn Bluetooth on.
- Confirm the laptop has a Bluetooth adapter.
- Stop other copies of the application.
- Restart Bluetooth from Windows Settings and run the application again.

### Connection timed out or was refused

- Confirm the destination application is running.
- Check the destination Bluetooth address carefully.
- Keep RFCOMM channel `12` on every laptop.
- Remove the Windows pairing on both laptops, pair them again, and retry.
- Initiate the connection from only one side.

### Messages are ignored for another room

Re-enter the exact same room code on every laptop. Capitalization and spaces matter.

### A message reaches B but not C

- Confirm B shows both Bluetooth links.
- Keep B's application and PowerShell window running.
- Confirm all three laptops use the same room code.

### Windows asks about network access

The web interface is local to the laptop and binds to `127.0.0.1`. Bluetooth messages use RFCOMM rather than the local Wi-Fi network. You do not need to expose the Flask development server to public networks.

## 11. Manual start commands

If `run.ps1` cannot be used, run:

```powershell
cd D:\bitchat\web
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Do not run multiple copies of the application on the same laptop because only one process can own Bluetooth RFCOMM channel 12.
