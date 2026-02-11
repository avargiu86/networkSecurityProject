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
        print("[ATTACKER] Connected to server with Alice's certificate.")

        conn.settimeout(0.5)
        try:
            while True:
                data = conn.recv(4096)
                if not data: break
                print(f"[INFO] Ignoring welcome message: {len(data)} bytes")
        except socket.timeout:
            pass  #empty buffer, we're ready
        conn.settimeout(None)  #Reset the socket

        #Try to send a malicious packet
        #In the JSON payload, we explicitly claim to be Bob.
        fake_packet = {
            "type": "MESSAGE",
            "sender": "client-bob",
            "payload": "dati_fake",
            "timestamp": time.time()
        }

        print(f"[ATTACK] Sending forged packet: Sender='client-bob'...")
        conn.send(json.dumps(fake_packet).encode('utf-8'))

        #timeout for response
        conn.settimeout(2.0)

        try:
            data = conn.recv(1024)
            if not data:
                #If we receive no data, the server closed the socket -> Security Check Passed
                print("[BLOCKED] The server closed the connection! (System is Secure).")
            else:
                # If we receive data, the server accepted the fake identity -> Security Check Failed
                print(f"[VULNERABILITY] The server sent data back: {data}")
        except socket.timeout:
            #If the timeout occurs, it means that the server has ignored the packet (Silent Drop)
            print("[BLOCKED] Server ignored the packet (Silent Drop). System is Secure.")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    attempt_spoofing()