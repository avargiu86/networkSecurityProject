from OpenSSL import crypto
import os
import random


def generate_key_pair(bits=2048):
   """Generate a 2048-bit RSA private key"""
   key = crypto.PKey()
   key.generate_key(crypto.TYPE_RSA, bits)
   return key


def create_cert(cn, issuer_cert=None, issuer_key=None, is_ca=False, is_server=False):
   """Create an X.509 v3 certificate"""
   key = generate_key_pair() #Generate the specific key pair for this certificate

   cert = crypto.X509()
   cert.get_subject().C = "IT"
   cert.get_subject().O = "UniCa NetSec Course"
   cert.get_subject().CN = cn #Common Name: used to identify the user (Alice/Bob) or the server
   cert.set_version(2) # Set version 3 to support extensions
   cert.set_serial_number(random.randint(1000, 1000000)) #Random serial to avoid collision

   #Validity period: from now until 1 year (365 days)
   cert.gmtime_adj_notBefore(0)
   cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

   # Signature Management (Chain of Trust)
   if is_ca: #If it is a CA, it self-signs (Root of Trust)
       issuer = cert.get_subject()
       signing_key = key
   else: #If it is a user/server certificate, the Issuer is the CA that signs it
       issuer = issuer_cert.get_subject()
       signing_key = issuer_key

   cert.set_issuer(issuer)

   #Configuring extensions
   extensions = []
   if is_ca: #CA:TRUE authorizes this certificate to sign other certificates
       extensions.append(crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"))
       extensions.append(crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"))
   else: #CA:FALSE prevents a user from becoming a CA
       extensions.append(crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"))
       extensions.append(crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"))
       #digitalSignature: to authenticate during the TLS handshake
       #keyEncipherment: allows other clients to use this public key to encrypt the AES session key

   #Unique identifier of the public key
   extensions.append(crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert))


   if is_server:
       #SAN (Subject Alternative Name): Mandatory to avoid SSL errors with localhost/modern IPs
       extensions.append(crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost, IP:127.0.0.1"))

   #Associate the public key with the certificate and sign everything with the Issuer's private key
   cert.add_extensions(extensions)
   cert.set_pubkey(key)
   cert.sign(signing_key, 'sha256')
   return key, cert


def save_file(filename, content, is_key=False):
   """Save keys and certificates to disk in PEM (Base64) format"""
   path = os.path.join("certs", filename)
   mode = crypto.FILETYPE_PEM
   data = crypto.dump_privatekey(mode, content) if is_key else crypto.dump_certificate(mode, content)
   with open(path, "wb") as f:
       f.write(data)


def main():
   if not os.path.exists('certs'):
       os.makedirs('certs')

   print("=== PKI Generation (E2EE Ready) ===")

   #Root CA: key and self-signed certificate.
   ca_key, ca_cert = create_cert("NetSec Root CA", is_ca=True)
   save_file("ca-key.pem", ca_key, is_key=True)
   save_file("ca-cert.pem", ca_cert)

   #Server: Certificate signed by the CA
   server_key, server_cert = create_cert("localhost", issuer_cert=ca_cert, issuer_key=ca_key, is_server=True)
   save_file("server-key.pem", server_key, is_key=True)
   save_file("server-cert.pem", server_cert)

   #Client Alice: Certificate signed by the CA
   alice_key, alice_cert = create_cert("client-alice", issuer_cert=ca_cert, issuer_key=ca_key)
   save_file("client-alice-key.pem", alice_key, is_key=True)
   save_file("client-alice-cert.pem", alice_cert)

   #Client Bob: Certificate signed by the CA
   bob_key, bob_cert = create_cert("client-bob", issuer_cert=ca_cert, issuer_key=ca_key)
   save_file("client-bob-key.pem", bob_key, is_key=True)
   save_file("client-bob-cert.pem", bob_cert)

   #Used for:
   #mTLS authentication to the server
   #E2EE key exchange between clients (thanks to keyEncipherment)

   print("\nPKI Generated. Client certificates now support encryption.")


if __name__ == "__main__":
   main()
