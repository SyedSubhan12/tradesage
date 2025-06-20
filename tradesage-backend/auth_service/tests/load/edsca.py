#!/usr/bin/env python3
"""
Script to generate ECDSA key pair for JWT signing.
Run this once to create persistent keys for your application.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import os

def generate_ecdsa_keys(private_key_path: str = "jwt_private_key.pem", 
                       public_key_path: str = "jwt_public_key.pem"):
    """Generate ECDSA key pair and save to files."""
    
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key and serialize it
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write private key
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    print(f"Private key written to: {private_key_path}")
    
    # Write public key
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    print(f"Public key written to: {public_key_path}")
    
    # Set appropriate permissions (Unix/Linux/macOS)
    if os.name != 'nt':  # Not Windows
        os.chmod(private_key_path, 0o600)  # Read/write for owner only
        os.chmod(public_key_path, 0o644)   # Read for all, write for owner
        print("File permissions set appropriately")

if __name__ == "__main__":
    generate_ecdsa_keys()
    print("\nKey pair generated successfully!")
    print("Make sure to:")
    print("1. Keep the private key secure and never commit it to version control")
    print("2. Update your application settings to point to these key files")
    print("3. Restart your application to use the new keys")