from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa

V_Lk = ec.generate_private_key(ec.SECP256R1(), default_backend())
V_LK = V_Lk.public_key()

V_Lk_pem = V_Lk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open('V_private_key.pem', 'wb') as f:
    f.write(V_Lk_pem)

V_LK_pem = V_LK.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('V_public_key.pem', 'wb') as f:
    f.write(V_LK_pem)

# OEM
oem_Lk = ec.generate_private_key(ec.SECP256R1(), default_backend())

oem_Lk_pem = oem_Lk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open('oem_private_key.pem', 'wb') as f:
    f.write(oem_Lk_pem)

oem_LK = oem_Lk.public_key()

oem_LK_pem = oem_LK.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('oem_public_key.pem', 'wb') as f:
    f.write(oem_LK_pem)

# RSA key
RSA_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
RSA_private_key_pem = RSA_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() 
)

RSA_public_key = RSA_private_key.public_key()
RSA_public_key_pem = RSA_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('RSA_private_key.pem', 'wb') as f:
    f.write(RSA_private_key_pem)
with open('RSA_public_key.pem', 'wb') as f:
    f.write(RSA_public_key_pem)


local_file = 'oem_public_key.pem'
remote_user = 'ubuntu'
remote_host = '192.168.81.129'
remote_path = '/home/ubuntu/LTCA'

scp_command = f"scp {local_file} {remote_user}@{remote_host}:{remote_path}"

try:
    subprocess.run(scp_command, check=True, shell=True)
    print("File uploaded successfully")
except subprocess.CalledProcessError:
    print("Error during file upload")