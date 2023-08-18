from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



# Generate a new RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
    backend=default_backend()
)

# Extract the public key
public_key = private_key.public_key()


##################### EXPORT #####################

# Serialize the public key in PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write the PEM to a file
with open('public_key.pem', 'wb') as f:
    f.write(pem_public_key)


# Serialize the private key in PEM format
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
# Write the PEM private key to a file
with open('private_key.pem', 'wb') as f:
    f.write(pem_private_key)



##################### IMPORT #####################

# Read the PEM key file
with open('private_key.pem', 'rb') as f:
    pem_data = f.read()

# Deserialize the PEM data
priv_key = serialization.load_pem_private_key(
    pem_data,
    password=None,
    backend=default_backend()
)

# Access the RSA components of the key
rsa_private_key = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Print the RSA private key
print(rsa_private_key.decode())
