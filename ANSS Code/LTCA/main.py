import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import json
from cryptography.hazmat.primitives import hashes
import hashlib
import base64


def register (json_data):
    data = json.loads(json_data)
    with open('oem_public_key.pem', 'rb') as f:
        oem_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )
    VRegID_signed = base64.b64decode(data["VRegID_signed"])
    # Verify oem signature
    hasher = hashlib.sha256()
    hasher.update(str(data['VRegID']).encode())
    message_digest = hasher.digest()
    try:
        oem_public_key.verify(
            VRegID_signed,
            message_digest,
            ec.ECDSA(hashes.SHA256())
        )
        print("oem signature is verified!")
    except:
        print("oem signature is not verified.")
        exit
    # Verify V LK
    V_LK_bytes = data["LK"].encode()
    V_LK = serialization.load_pem_public_key(
        V_LK_bytes,
        backend=default_backend()
    )
    V_LK_signed = base64.b64decode(data["LK_signed"])
    hasher = hashlib.sha256()
    hasher.update(V_LK_bytes)
    message_digest = hasher.digest()
    try:
        V_LK.verify(
            V_LK_signed,
            message_digest,
            ec.ECDSA(hashes.SHA256())
        )
        print("V_LK signature is verified!")
    except:
        print("V_LK signature is not verified.")
        exit


    # Sign V_LK with LTCA private key
    with open('Long-term_private_key.pem', 'rb') as key_file:  # load long-term private key
        LTCA_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    hasher = hashlib.sha256()
    hasher.update(V_LK_bytes)
    message_digest = hasher.digest()

    LTCA_LK_signed = LTCA_private_key.sign(
        message_digest,
        ec.ECDSA(hashes.SHA256())
    )
    LTCA_LK_signed_base64 = base64.b64encode(LTCA_LK_signed).decode('utf-8')
    data = {
        "LK": data["LK"],
        "RSA_key": data["RSA_key"],
        "LTCA_LK_signed": LTCA_LK_signed_base64
    }
    json_data = json.dumps(data, indent=4)
    # Send LK to RA
    RA_addr = '192.168.81.130'
    RA_port = 8802

    context = ssl._create_unverified_context()

    with socket.create_connection((RA_addr, RA_port)) as sock:
        with context.wrap_socket(sock, server_hostname=RA_addr) as tls_sock:
            # send data
            tls_sock.sendall(json_data.encode())

            # accept response
            response = tls_sock.recv(1024)
            print('Received from RA')

    
    return response

LTCA_addr = '192.168.81.129'
LTCA_port = 8801

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='TLS_cert.pem', keyfile='TLS_private_key.pem')

server_socket.bind((LTCA_addr, LTCA_port))
server_socket.listen(5)

while True:
    # Accept client connection
    client_socket, client_addr = server_socket.accept()
    print(f'Connection from {client_addr}')

    tls_client_socket = context.wrap_socket(client_socket, server_side=True)

    try:
        # get data
        data = tls_client_socket.recv(1024)
        response_from_RA = register(data)

        # send data
        tls_client_socket.send(response_from_RA)

    finally:
        # close TLS connection
        tls_client_socket.shutdown(socket.SHUT_RDWR)
        tls_client_socket.close()

    if not data:
        break