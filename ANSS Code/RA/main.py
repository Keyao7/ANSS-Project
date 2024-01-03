import base64
import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import json
from cryptography.hazmat.primitives.asymmetric import padding

# 从PEM文件读取密钥
with open('symmetric_key.pem', 'rb') as file:
    lines = file.readlines()
    # 假设密钥是文件的第二行
    pem_key = lines[1].strip()

# 解码密钥
key = base64.urlsafe_b64decode(pem_key)

def register (json_data):
    data = json.loads(json_data)
    with open('Long-term_public_key.pem', 'rb') as f:
        LTCA_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )
    V_LK_bytes = data["LK"].encode()
    V_LK = serialization.load_pem_public_key(
        V_LK_bytes,
        backend=default_backend()
    )

    LTCA_LK_signed = base64.b64decode(data["LTCA_LK_signed"])

    hasher = hashlib.sha256()
    hasher.update(V_LK_bytes)
    message_digest = hasher.digest()
    try:
        LTCA_public_key.verify(
            LTCA_LK_signed,
            message_digest,
            ec.ECDSA(hashes.SHA256())
        )
        print("LTCA signature is verified!")
    except:
        print("LTCA signature is not verified.")
        exit
    
    V_RSA_bytes = data["RSA_key"].encode()
    V_RSA = serialization.load_pem_public_key(
        V_RSA_bytes,
        backend=default_backend()
    )
    print(key)
    encrypted_key = V_RSA.encrypt(
        key,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    encrypted_key_base64 = base64.b64encode(encrypted_key).decode('utf-8')
    data = {
        "k_enc": encrypted_key_base64
    }
    json_data = json.dumps(data, indent=4)
    


    return json_data
host_addr = '192.168.81.130'
host_port = 8802

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='TLS_cert.pem', keyfile='TLS_private_key.pem')

server_socket.bind((host_addr, host_port))
server_socket.listen(5)

while True:
    # Accept client connection
    client_socket, client_addr = server_socket.accept()
    print(f'Connection from {client_addr}')

    tls_client_socket = context.wrap_socket(client_socket, server_side=True)

    try:
        # get data
        data = tls_client_socket.recv(1024)
        json_data = register(data)

        # send data
        tls_client_socket.send(json_data.encode())

    finally:
        # close TLS connection
        tls_client_socket.shutdown(socket.SHUT_RDWR)
        tls_client_socket.close()

    if not data:
        break