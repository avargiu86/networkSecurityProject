import socket
import ssl
import threading
import json
import time

#SECURITY CONFIGURATION
#Constants for defence against DoS
RATE_LIMIT_WINDOW = 5.0  #Time window in seconds for rate limiting
RATE_LIMIT_COUNT = 10    #Max messages allowed within the time window
MAX_MSG_SIZE = 4096  #Max packet size in bytes (Input Validation)

#Dictionary to store connected clients
clients = {}

def broadcast(message_dict, sender_socket):
    """Forward a JSON dictionary to all connected clients except the sender."""
    data = json.dumps(message_dict).encode('utf-8')
    for sock in list(clients.keys()):
        if sock != sender_socket:
            try:
                sock.sendall(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                remove_client(sock) #If sending fails, assume the client dropped and remove them


def remove_client(conn):
    """Safely removes a client from the active list and closes the socket."""
    if conn in clients:
        print(f"[-] {clients[conn]['name']} disconnected.")
        del clients[conn]
        try:
            conn.close()
        except OSError:
            pass


def handle_client(conn, addr):
    """Main thread function for handling a single client connection.
    Performs authentication, validation, and message relaying."""
    try:
        #mTLS identity extraction
        #Get the peer certificate in binary form and convert to PEM
        der_cert = conn.getpeercert(binary_form=True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert_dict = conn.getpeercert()
        subject = dict(x[0] for x in cert_dict['subject'])
        client_name = subject.get('commonName', str(addr)) #Extract the Common Name (CN) from the certificate subject
    except (ssl.SSLError, ValueError, KeyError) as e:
        print(f"[!] Certificate reading error: {e}")
        return

    print(f"[+] {client_name} connected. Public key distribution...")

    #Register the client and initialize their message history for Rate Limiting
    clients[conn] = {
        "addr": addr,
        "cert_pem": pem_cert,
        "name": client_name,
        "msg_history": []   #Empty list for timestamps
    }

    #New user announcement
    join_msg = {
        "type": "USER_JOINED",
        "username": client_name,
        "public_key": pem_cert
    }
    broadcast(join_msg, conn) #Notify other users that a new client has joined and share their Public Key

    #Send the list of currently connected users to the new client
    existing_users = []
    for s, info in clients.items():
        if s != conn:
            existing_users.append({"username": info['name'], "public_key": info['cert_pem']})

    if existing_users:
        welcome_msg = {"type": "USER_LIST", "users": existing_users}
        try:
            conn.sendall(json.dumps(welcome_msg).encode('utf-8'))
        except OSError:
            remove_client(conn)
            return

    while True:
        try:
            #SECURITY: SIZE CHECK (INPUT VALIDATION)
            #Read MAX_MSG_SIZE + 1 bytes to detect if the packet exceeds the limit
            data = conn.recv(MAX_MSG_SIZE + 1) #We read 1 more byte to see if it goes over
            if not data:
                break

            #TRAFFIC ANALYSIS DEBUG
            print(f"[DEBUG NETWORK] Received {len(data)} bytes")

            #Check if the message exceeds the allowed size
            if len(data) > MAX_MSG_SIZE:
                print(
                    f"[!] SECURITY ALERT: {client_name} sent a packet too large ({len(data)} bytes).")
                print(f"Possible buffer overflow attempt or JSON bomb.")
                remove_client(conn)  #Punitive disconnection
                return  #Exit thread

            try:
                msg_obj = json.loads(data.decode('utf-8'))

                #SECURITY: RATE LIMITING CHECK
                current_time = time.time()
                #Retrieve message history for this client
                history = clients[conn]["msg_history"]

                #Cleanup: Keep only timestamps within the sliding window (last 5 seconds)
                history = [t for t in history if current_time - t < RATE_LIMIT_WINDOW]
                clients[conn]["msg_history"] = history

                #Enforcement: If count exceeds limit, block the user
                if len(history) >= RATE_LIMIT_COUNT:
                    print(f"[!] DoS Attack Detected from {client_name}. Forced disconnection.")
                    remove_client(conn)
                    return

                #Log: Add current timestamp to history
                history.append(current_time)
                clients[conn]["msg_history"] = history

                #SECURITY CHECK: Server-side Spoofing Prevention
                #Identity Binding: Ensure the sender declared in the JSON ('sender')
                #matches the authenticated Common Name from the certificate ('client_name').
                #The actual integrity check will be done by the client with GCM,
                #but this saves bandwidth by avoiding false forwards.
                if msg_obj.get("type") == "MESSAGE":
                    declared_sender = msg_obj.get("sender")
                    if declared_sender != client_name:
                        print(f"[!] Spoofing detected. {client_name} is trying to send as {declared_sender}")
                        continue  #Drop the malicious packet

                    #Extract encrypted payload for display
                    encrypted_payload = msg_obj.get('payload', '')

                    #We truncate it to 50 characters to avoid clogging up the terminal,
                    #but enough to see that it's Base64 "garbage."
                    preview = encrypted_payload[:50] + "..." if len(encrypted_payload) > 50 else encrypted_payload

                    print(f"[Relay] Message from {client_name} forwarded.")
                    print(f" [SERVER SEES]: {preview}")

                    broadcast(msg_obj, conn) #If all checks pass, relay the message to other clients

            except json.JSONDecodeError:
                pass #Ignore malformed JSON packets

        except (ConnectionResetError, OSError, ssl.SSLError):
            break

    remove_client(conn) #Ensure client is removed if the loop exits


def main():
    #Create SSL context for Mutual Authentication mTLS (Client Auth)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED #REQUIRE a certificate from the client (mTLS)
    try:
        #Load the trusted CA to verify client certificates
        context.load_verify_locations(cafile="certs/ca-cert.pem")
        context.load_cert_chain(certfile="certs/server-cert.pem", keyfile="certs/server-key.pem") #Load the Server's own certificate and private key
    except FileNotFoundError:
        print("Certificates not found.")
        return

    #Create a standard TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Allow address reuse to avoid "Address already in use" errors on restart

    try:
        sock.bind(('localhost', 8443))
        sock.listen(5)
    except OSError as e:
        print(f"Error bind: {e}")
        return

    print("Server started successfully. Listening on localhost:8443. Waiting for connections...")

    try: #Connection acceptance loop
        while True:
            newsock = None
            try:
                #Accept raw TCP connection
                newsock, addr = sock.accept()
                #Wrap the socket with SSL/TLS (perform the handshake)
                ssl_conn = context.wrap_socket(newsock, server_side=True)
                #Start a new thread to handle this client
                t = threading.Thread(target=handle_client, args=(ssl_conn, addr), daemon=True)
                t.start()
            except (ssl.SSLError, OSError) as e:
                print(f"Connection error: {e}")
                if newsock: newsock.close()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()