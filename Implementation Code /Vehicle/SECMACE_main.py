from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import random
import time
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import ssl
import socket
import json


# Long-term key
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


N = random.randint(0,10000) 

t_now = time.time()

with open('oem_private_key.pem', 'rb') as key_file: # load oem private key
    oem_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

start_time = time.time()

# sign LK with Lk
hasher = hashlib.sha256()
hasher.update(V_public_key_bytes)
message_digest = hasher.digest()

LK_signed = V_private_key.sign(
    message_digest,
    ec.ECDSA(hashes.SHA256())
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
    "LK_signed": LK_signed_base64,
    "t_now": t_now,
    "N": N
}

json_data = json.dumps(data)

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
        print(response.decode())





# Pseudonym Request 
        

V_Pseudonyms_number = 2 # Pseudonym Number

# load Pseudonym key pairs
V_Pseudonyms_dic = {}
for i in range(V_Pseudonyms_number):
    public_key_file_name = 'V_Pseudonym_public_key_' + str(i+1) + '.pem'
    private_key_file_name =  'V_Pseudonym_private_key_' + str(i+1) + '.pem'

    with open(public_key_file_name, 'rb') as f: 
        V_Pseudonym_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    with open(private_key_file_name, 'rb') as key_file:  
        V_Pseudonym_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    V_Pseudonym_public_key_bytes = V_Pseudonym_public_key.public_bytes( 
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
    
    V_Pseudonyms_dic[i] = (V_Pseudonym_public_key, V_Pseudonym_private_key, V_Pseudonym_public_key_bytes)



Id_req = random.randint(0,10000)
N = random.randint(0,10000)
t_now = time.time()


Pseudonym_list = []
Pseudonym_list_decode = []
for i in V_Pseudonyms_dic.values():
    Pseudonym_list.append(i[2])
    Pseudonym_list_decode.append(i[2].decode())
Pseudonym_list_bytes = b''.join(Pseudonym_list) # combine pseudonym keys

signature_list = []
for i in V_Pseudonyms_dic.values():
    signature = i[1].sign(
        Pseudonym_list_bytes,
        ec.ECDSA(hashes.SHA256())
    ) # sign pseudonyms set with every pseudonym private key
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    signature_list.append(signature_base64)



pseudonym_request_pack = {
    "Id_req":Id_req,
    "Signatures":signature_list,
    "Pseudonyms":Pseudonym_list_decode,
    "N":N,
    "t_now":t_now
}

pseudonym_request_data = json.dumps(pseudonym_request_pack)

# Send Pseudonym Request
        
PCA_addr = '192.168.81.131'
PCA_port = '8803'

context = ssl._create_unverified_context()
with socket.create_connection((PCA_addr, PCA_port)) as sock:
    with context.wrap_socket(sock, server_hostname=PCA_addr) as tls_sock:
        # send data
        tls_sock.sendall(pseudonym_request_data.encode())

        # accept response
        response = tls_sock.recv(1024)
        print(response.decode())

end_time = time.time()

total_time = end_time - start_time
print(f"The code took {total_time} seconds to execute.")
        