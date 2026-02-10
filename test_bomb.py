import socket, ssl


def test_json_bomb():
    """ Simulates a DoS attack by sending an oversized 5000-byte payload.
        Verifies that the server strictly enforces its 4096-byte limit by checking for an immediate connection reset or closure."""
    
    #SSL Configuration using Alice's legitimate certificates
    #We need valid credentials to pass the mTLS handshake and reach the application layer
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("certs/ca-cert.pem")
    context.load_cert_chain(certfile="certs/client-alice-cert.pem", keyfile="certs/client-alice-key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(sock, server_hostname='localhost')

    try:
        conn.connect(('localhost', 8443))
        print("[ATTACKER] Connected with Alice's certificate. Preparing oversized payload...")

        #Create a 5000-byte payload (The server's strict limit is 4096 bytes)
        #It doesn't need to be valid JSON; the server should block based on raw size.
        oversized_payload = b"A" * 5000

        print(f"[ATTACK] Sending {len(oversized_payload)} bytes of payload...")
        conn.send(oversized_payload)

        #Wait to see if the server kicks us out
        try:
            data = conn.recv(1024)
            if not data:
                print("[SUCCESS] The server closed the connection immediately.")
            else:
                print("[FAILURE] The server responded (it should have dropped us).")
        except (ConnectionResetError, OSError, ssl.SSLError):
            print("[SUCCESS] The server forcibly reset the connection (TCP RST).")

    except (socket.error, ssl.SSLError, OSError) as e:
        print(f"[NET ERROR] Network error (expected or unexpected): {e}")
    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")

    finally:
        conn.close()


if __name__ == "__main__":
    test_json_bomb()