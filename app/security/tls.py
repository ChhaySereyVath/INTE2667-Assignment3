"""R01: encryption in transit for the local prototype.

`flask make-cert` creates a self-signed certificate for localhost so `python run.py`
serves HTTPS. In a real deployment the certificate comes from a public authority and
TLS is usually ended at a load balancer; the app's HSTS header and Secure cookies are
the same either way.
"""
import ipaddress
import os
from datetime import timedelta
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.security.shared_security import utcnow

CERT_DIR = Path("certs")
CERT_FILE = "dev-cert.pem"
KEY_FILE = "dev-key.pem"


def make_dev_certificate(directory=CERT_DIR, days=365):
    """Write a P-256 key and a self-signed certificate for localhost and 127.0.0.1."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: it vouches for itself
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = directory / KEY_FILE, directory / CERT_FILE
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)  # R01: only the owner may read the private key
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


@click.command("make-cert")
def make_cert_command():
    """Create certs/dev-cert.pem and certs/dev-key.pem so run.py serves HTTPS."""
    cert_path, key_path = make_dev_certificate()
    click.echo(f"Wrote {cert_path} and {key_path}. They are in .gitignore: never commit them.")