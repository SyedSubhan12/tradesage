#!/usr/bin/env python3

"""
Generate ECDSA key pair for JWT signing
Uses the ES256 algorithm (ECDSA with P-256 curve and SHA-256)
"""

import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)

def generate_ecdsa_keys(certs_dir: str = "certs"):
    """Generate ECDSA key pair and save to files"""
    # Create directory if it doesn't exist
    os.makedirs(certs_dir, exist_ok=True)
    
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write private key
    private_key_path = os.path.join(certs_dir, "ecdsa-private.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_key_path, 0o600)  # Set secure permissions
    
    # Write public key
    public_key_path = os.path.join(certs_dir, "ecdsa-public.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    os.chmod(public_key_path, 0o644)  # Set secure permissions
    
    print(f"Generated ECDSA key pair:")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key: {public_key_path}")
    print("\nKey permissions set:")
    print(f"  Private key: 600 (rw-------)")
    print(f"  Public key: 644 (rw-r--r--)")

if __name__ == "__main__":
    # Get certificates directory from command line or use default
    certs_dir = sys.argv[1] if len(sys.argv) > 1 else "certs"
    generate_ecdsa_keys(certs_dir) 