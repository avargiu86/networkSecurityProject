import socket
import ssl
import threading
import sys
import os
import json
import base64
import time
import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

#Global State
peer_public_keys = {} #Stores public keys of other users (Alice/Bob)
my_private_key: Optional[RSAPrivateKey] = None #My private RSA key for decrypting session keys
my_username = ""

#NETWROK SECURITY: Anti-Replay Cache
#We store hashes of messages received in the last X seconds to prevent duplicates
seen_signatures = set()
REPLAY_WINDOW_SECONDS = 60.0 #Messages older than 60s are discarded
TARGET_SIZE = 4096 #Fixed packet size to prevent traffic analysis

def clear_line():
    sys.stdout.write("\033[K")


def load_private_key(filename):
    """Load the RSA private key from a PEM file."""
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


def load_public_key_from_pem(pem_bytes):
    """Convert PEM certificate bytes into a usable RSA Public Key object."""
    cert = load_pem_x509_certificate(
        pem_bytes.encode('utf-8') if isinstance(pem_bytes, str) else pem_bytes
    )
    return cert.public_key()


def receive_handler(sock):
    """Thread loop to listen for incoming encrypted messages."""
    while True:
        try:
            #Read from socket. Buffer size is 8192 to accommodate padded JSONs
            chunk = sock.recv(8192).decode('utf-8')  # Buffer aumentato
            if not chunk:
                print("\n[!] Disconnected.")
                sys.exit(0)

            try:
                #Parse JSON and hand off to processing logic
                msg_obj = json.loads(chunk)
                process_message(msg_obj)
            except json.JSONDecodeError:
                pass
        except (ConnectionResetError, OSError):
            break


def process_message(msg):
    global peer_public_keys, my_private_key, seen_signatures

    if my_private_key is None: return

    msg_type = msg.get("type")

    if msg_type == "USER_JOINED":
        #Store the new user's public key
        new_user = msg['username']
        if new_user != my_username:
            peer_public_keys[new_user] = load_public_key_from_pem(msg['public_key'])
            print(f"\r[Server] {new_user} è entrato.\nYou: ", end="")

    elif msg_type == "USER_LIST":
        #Bulk update of all online users' public keys
        for u in msg['users']:
            peer_public_keys[u['username']] = load_public_key_from_pem(u['public_key'])
        print(f"\r[Server] Utenti online: {list(peer_public_keys.keys())}\nYou: ", end="")

    elif msg_type == "MESSAGE":
        sender = msg['sender']
        b64_payload = msg['payload']
        keys_map = msg['keys']
        timestamp = msg.get('timestamp', 0)

        #ANTI-REPLAY CHECK (Time Window)
        current_time = time.time()
        #Discard if too old (prevent replay of old captured traffic)
        if current_time - timestamp > REPLAY_WINDOW_SECONDS:
            print(f"\r[!] Message discared: Too old (Replay Attack or Lag).\nYou: ", end="")
            return

        if timestamp > current_time + 5.0:  #5s Tolerance per clock skew
            print(f"\r[!] Message discared : Timestamp in the future.\nYou: ", end="")
            return

        #ANTI-REPLAY CHECK (Signature Cache)
        #Create a unique hash of the encrypted payload + timestamp
        msg_sig = hashlib.sha256(f"{b64_payload}{timestamp}".encode()).hexdigest()
        #Check if we have already seen this specific message signature
        if msg_sig in seen_signatures:
            #Silent drop: it is a duplicate
            return

        seen_signatures.add(msg_sig)

        #DECRYPTION
        #Check if there is an encrypted session key for me
        my_encrypted_key_b64 = keys_map.get(my_username)
        if my_encrypted_key_b64:
            try:
                #Decrypt the AES Session Key using my RSA Private Key
                enc_sym_key = base64.b64decode(my_encrypted_key_b64)
                aes_key = my_private_key.decrypt(
                    enc_sym_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                #Parse the encrypted payload structure
                encrypted_bytes = base64.b64decode(b64_payload)
                nonce = encrypted_bytes[:12] #First 12 bytes are IV
                tag = encrypted_bytes[12:28] #Next 16 bytes are GCM Auth Tag
                ciphertext = encrypted_bytes[28:] #The rest is actual data

                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()

                #INTEGRITY CHECK (AAD-Additional Authenticated Data)
                #We reconstruct the data that MUST match the sender's metadata.
                #Format: "sender:timestamp"
                #If the sender or timestamp in the JSON was tampered with,
                #this AAD check will fail decryption.
                aad_data = f"{sender}:{timestamp}".encode('utf-8')
                decryptor.authenticate_additional_data(aad_data)

                #Finalize decryption (throws InvalidTag if integrity fails)
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                print(f"\r[{sender} [SECURE]]: {plaintext.decode('utf-8')}\nTu: ", end="")

            except (InvalidTag, ValueError):
                # This exception means someone modified the ciphertext OR the metadata (sender/timestamp)
                print(f"\r[!] ALARM: Integrity check failed! Possible metadata tampering.\nYou: ", end="")
        else:
            pass


def main():
    global my_private_key, my_username

    print("--- CHAT E2EE CLIENT (with AAD Integrity & Anti-Replay) ---")
    choice = input("Identity (A/B): ").strip().upper()

    #Identity Setup
    if choice == "A":
        cert, key, cn = "certs/client-alice-cert.pem", "certs/client-alice-key.pem", "client-alice"
    elif choice == "B":
        cert, key, cn = "certs/client-bob-cert.pem", "certs/client-bob-key.pem", "client-bob"
    else:
        print("Invalid identity")
        return

    if not os.path.exists(key):
        print("Missing certificates.")
        return

    my_private_key = load_private_key(key)
    my_username = cn

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("certs/ca-cert.pem")
    context.load_cert_chain(certfile=cert, keyfile=key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssl_sock = context.wrap_socket(sock, server_hostname='localhost')
        ssl_sock.connect(('localhost', 8443))
        threading.Thread(target=receive_handler, args=(ssl_sock,), daemon=True).start()

        print(f"[SUCCESS] Connected as {my_username}.")
        print("You: ", end="")

        while True:
            text = input("")
            if text.lower() == 'exit': break
            if not peer_public_keys:
                print(f"\r[!] No recipient.\nTu: ", end="")
                continue

            #ECNRYPTION AND INTEGRITY
            session_key = os.urandom(32) #AES key
            nonce = os.urandom(12)   #unique IV
            timestamp = time.time()  #current time

            #Create AAD (Additional Authenticated Data)
            #Cryptographically bind the sender identity and time to the ciphertext.
            aad_data = f"{my_username}:{timestamp}".encode('utf-8')

            cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            #Insert AAD into GCM calculation
            encryptor.authenticate_additional_data(aad_data)

            #Encrypt the text
            ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
            tag = encryptor.tag

            #Pack IV + Tag + Ciphertext into one blob
            payload_b64 = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

            #Encrypt the Session Key for every recipient using their RSA Public Key
            keys_map = {}
            for user, pub_key in peer_public_keys.items():
                encrypted_session_key = pub_key.encrypt(
                    session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                keys_map[user] = base64.b64encode(encrypted_session_key).decode('utf-8')

            #Construct the Packet
            packet = {
                "type": "MESSAGE",
                "sender": my_username,
                "timestamp": timestamp,  #Essential for replay check, test: I put timestamp -75, it will give "message too old"
                "payload": payload_b64,
                "keys": keys_map,
                "padding": "" #initially empty
            }

            #TRAFFIC ANALYSIS MITIGATION (Padding)
            #Calculate current size and add spaces to reach TARGET_SIZE
            temp_json = json.dumps(packet)
            current_len = len(temp_json)
            pad_needed = TARGET_SIZE - current_len

            if pad_needed > 0:
                packet["padding"] = " " * pad_needed

            #Final serialization
            final_json = json.dumps(packet)

            sys.stdout.write("\033[F")
            sys.stdout.write(f"\rYou [SECURE]: {text}\nYou: ")
            ssl_sock.send(final_json.encode('utf-8')) #Send over SSL/TLS socket

    except KeyboardInterrupt:
        print("\nUscita...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()