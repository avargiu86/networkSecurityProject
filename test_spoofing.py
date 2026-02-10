import socket, ssl, json, time


def attempt_spoofing():
    """ Simulates a spoofing attack by sending a message as 'Bob' using 'Alice's' authenticated mTLS session.
        Verifies that the server enforces identity binding between the certificate and the payload sender. """

    #Load Alice's legitimate certificates
    #We must authenticate as a valid user (Alice) to pass the mTLS handshake.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("certs/ca-cert.pem")
    context.load_cert_chain(certfile="certs/client-alice-cert.pem", keyfile="certs/client-alice-key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(sock, server_hostname='localhost')

    try:
        conn.connect(('localhost', 8443))
        print("[ATTACKER] Connected with Alice's certificate.")

        #Try to send a malicious packet
        #In the JSON payload, we explicitly claim to be BOB.
        fake_packet = {
            "type": "MESSAGE",
            "sender": "client-bob",
            "payload": "dati_fake",
            "timestamp": time.time()
        }

        print(f"[ATTACK] Sending forged packet: Sender='client-bob'...")
        conn.send(json.dumps(fake_packet).encode('utf-8'))

        #Read the response (or check for disconnection)
        data = conn.recv(1024)
        if not data:
            #If we receive no data, the server closed the socket -> Security Check Passed
            print("[BLOCKED] The server closed the connection. Attack failed (System is Secure).")
        else:
            #If we receive data, the server accepted the fake identity -> Security Check Failed
            print("[VULNERABILITY] The server accepted the message (Attack Successful).")

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    attempt_spoofing()