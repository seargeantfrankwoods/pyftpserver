from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_pair():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def save_keys(private_key_pem, public_key_pem):
    # Save private key to file
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key_pem)
    print("Private key saved to private_key.pem")
    
    # Save public key to file
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key_pem)
    print("Public key saved to public_key.pem")

def main():
    private_key_pem, public_key_pem = generate_key_pair()
    save_keys(private_key_pem, public_key_pem)

if __name__ == "__main__":
    main()
