# Network Security Project: Secure E2EE Chat with mTLS & Anti-Replay Defense

This project implements a zero-trust chat application with **End-to-End Encryption (E2EE)** using a hybrid RSA/AES-GCM scheme. It features **Mutual TLS (mTLS)** for strong device authentication, **Anti-Replay defenses** (timestamp window + signature caching), and **AAD Integrity Checks** to bind metadata to ciphertext, preventing tampering. You can find more information about the project in the file `report.pdf` 

# Prerequisites
Python 3 installed. You must also install the required cryptographic libraries listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```
# Setup & Usage

### 1. Generate the PKI
Run the generation script to create the Certificate Authority and keys. This will create a `certs/` directory containing the Root CA, Server, and Client certificates.

```bash
python gen_pki.py
```

### 2. Start the Secure Server
```bash
python server.py
```

### 3. Start the Clients
Open two separate terminal windows (one for Alice, one for Bob).
Terminal 1: Alice
```bash
python client.py
#Select Identity: A
```

Terminal 2: Bob
```bash
python client.py
#Select Identity: B
```

# Security Analysis & Attack Simulations
This architecture is resistant to DoS, Spoofing, and Replay attacks. You can verify the defenses using the included test scripts.

### 1. Test DoS Protection 
Simulates an attack where a 5000-byte payload is sent to crash the server (limit is 4096 bytes).

```bash
python test_bomb.py
```
Expected Result: The attacker sees:
```bash
[SUCCESS] The server closed the connection immediately. 
```
The server logs a security alert and disconnects the socket.

### 2. Test Spoofing (Identity Binding)
Simulates an authenticated user (Alice) trying to send a message claiming to be "Bob".

```bash
python test_spoofing.py
```
Expected Result: The attacker sees 
```bash
[BLOCKED] Server ignored the packet (Silent Drop). (System is Secure). 
```
The server logs [!] Spoofing detected. and silently drops the packet.

### 3. Test Replay Attacks
The client automatically drops replayed messages.
