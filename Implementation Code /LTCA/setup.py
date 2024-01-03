from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives import hashes
import subprocess

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

with open('TLS_private_key.pem', 'wb') as f:
    f.write(private_key_pem)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Stockholm"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Stockholm"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VPKI"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"LTCA.com"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # 证书有效期为1年
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(private_key, hashes.SHA256(), default_backend())

cert_pem = cert.public_bytes(serialization.Encoding.PEM)

with open('TLS_cert.pem', 'wb') as f:
    f.write(cert_pem)


Lk = ec.generate_private_key(ec.SECP256R1(), default_backend())
LK = Lk.public_key()

Lk_pem = Lk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open('Long-term_private_key.pem', 'wb') as f:
    f.write(Lk_pem)

LK_pem = LK.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('Long-term_public_key.pem', 'wb') as f:
    f.write(LK_pem)


local_file = 'Long-term_public_key.pem'
remote_user = 'ubuntu'
remote_host = '192.168.81.130'
remote_path = '/home/ubuntu/RA'

scp_command = f"scp {local_file} {remote_user}@{remote_host}:{remote_path}"

try:
    subprocess.run(scp_command, check=True, shell=True)
    print("File uploaded successfully")
except subprocess.CalledProcessError:
    print("Error during file upload")