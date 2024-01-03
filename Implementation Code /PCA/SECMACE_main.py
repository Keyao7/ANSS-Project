import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import json
import base64
import time


def PseudonymRequest (data):
    pack = json.loads(data)

    start_time = time.time()
    
    # verify pseudonyms set's signatures with pseudonym public keys
    Pseudonym_list_decode = pack['Pseudonyms']
    Pseudonym_list = []
    for i in Pseudonym_list_decode:
        Pseudonym_list.append(i.encode())
    Pseudonym_list_bytes = b''.join(Pseudonym_list)
    Pseudonym_pem_list = []
    for i in Pseudonym_list:
        Pseudonym_K = serialization.load_pem_public_key(
        i,
        backend=default_backend()
        )
        Pseudonym_pem_list.append(Pseudonym_K)
    

    signature_list = pack['Signatures']
    for i in range(len(Pseudonym_list)):
        try:
            Pseudonym_pem_list[i].verify(
                base64.b64decode(signature_list[i].encode()),
                Pseudonym_list_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            print("Pseudonym " +str(i)+ " signature is valid!")
        except:
            print("Pseudonym " +str(i)+ " signature is invalid.")
            exit

    return b"Pseudonym_ACK"




# TLS Server
PCA_addr = '192.168.81.131'
PCA_port = 8803

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='TLS_cert.pem', keyfile='TLS_private_key.pem')

server_socket.bind((PCA_addr, PCA_port))
server_socket.listen(5)

while True:
    # Accept client connection
    client_socket, client_addr = server_socket.accept()
    print(f'Connection from {client_addr}')

    tls_client_socket = context.wrap_socket(client_socket, server_side=True)

    try:
        # get data
        data = tls_client_socket.recv(1024)
        result = PseudonymRequest(data)

        # send data
        tls_client_socket.send(result)

    finally:
        # close TLS connection
        tls_client_socket.shutdown(socket.SHUT_RDWR)
        tls_client_socket.close()

    if not data:
        break