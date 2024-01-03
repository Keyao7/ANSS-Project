import json
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
from cryptography.hazmat.primitives import serialization
import time
import socket
import ssl
import base64
from cryptography.hazmat.primitives.asymmetric import padding

# V 


with open('V_public_key.pem', 'rb') as f: # load long-term public key LK
    V_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

with open('V_private_key.pem', 'rb') as key_file:  # load long-term private key Lk
    V_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

V_public_key_bytes = V_public_key.public_bytes( # convert pem to bytes (LK)
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# RSA key
with open('RSA_public_key.pem', 'rb') as f: # 
    RSA_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )
with open('RSA_private_key.pem', 'rb') as key_file:  # 
    RSA_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
RSA_public_key_bytes = RSA_public_key.public_bytes( # convert pem to bytes
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(V_public_key_bytes)
print(RSA_public_key_bytes)




N = random.randint(0,10000) 

t_now = time.time()

# sign LK with Lk
hasher = hashlib.sha256()
hasher.update(V_public_key_bytes)
message_digest = hasher.digest()

LK_signed = V_private_key.sign(
    message_digest,
    ec.ECDSA(hashes.SHA256())
)

# save signature
# with open('signature.bin', 'wb') as f:
#     f.write(LK_signed)

# oem

with open('oem_private_key.pem', 'rb') as key_file: # load oem private key
    oem_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )



VRegID = random.randint(0,10000) # generate VRegID

# sign VRegID with oem private key
hasher = hashlib.sha256()
hasher.update(str(VRegID).encode())
message_digest = hasher.digest()

VRegID_signed = oem_private_key.sign(
    message_digest,
    ec.ECDSA(hashes.SHA256())
)

# convert oem signature to json format
VRegID_signed_base64 = base64.b64encode(VRegID_signed).decode('utf-8')

# convert Lk signature to json format
LK_signed_base64 = base64.b64encode(LK_signed).decode('utf-8')


data = {
    "VRegID": VRegID,
    "VRegID_signed": VRegID_signed_base64,
    "LK": V_public_key_bytes.decode(),
    "RSA_key": RSA_public_key_bytes.decode(),
    "LK_signed": LK_signed_base64,
    "t_now": t_now,
    "N": N
}

json_data = json.dumps(data)

with open('request.json', 'w') as f:
    f.write(json_data)


# Send Registration Request
    
LTCA_addr = '192.168.81.129'
LTCA_port = '8801'

context = ssl._create_unverified_context()

with socket.create_connection((LTCA_addr, LTCA_port)) as sock:
    with context.wrap_socket(sock, server_hostname=LTCA_addr) as tls_sock:
        # send data
        tls_sock.sendall(json_data.encode())

        # accept response
        response = tls_sock.recv(1024)
        json_response = json.loads(response)
        enc_key = base64.b64decode(json_response['k_enc'])
        key_from_RA = RSA_private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        key_from_RA = base64.urlsafe_b64encode(key_from_RA)
        with open('symmetric_key.pem', 'wb') as f:
            f.write(b'-----BEGIN SYMMETRIC KEY-----\n')
            f.write(key_from_RA)
            f.write(b'\n-----END SYMMETRIC KEY-----\n')
        
        print('Received:', response.decode())
