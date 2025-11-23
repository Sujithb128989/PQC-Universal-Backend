"""
channel.py - Secure gRPC channel creation with PQC-enabled TLS

This module provides functionality to create a secure gRPC channel
using post-quantum cryptography (PQC) enabled certificates.
"""

import grpc
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Default certificate paths (can be overridden)
CERT_DIR = "certs"
CLIENT_KEY_PATH = f"{CERT_DIR}/client.key"
CLIENT_CERT_PATH = f"{CERT_DIR}/client.crt"
CA_CERT_PATH = f"{CERT_DIR}/ca.crt"


def create_secure_channel(
    server_address,
    ca_cert_path=CA_CERT_PATH,
    client_cert_path=CLIENT_CERT_PATH,
    client_key_path=CLIENT_KEY_PATH
):
    """
    Creates a secure gRPC channel with the server using PQC-enabled TLS credentials.

    Args:
        server_address: The server address in the format 'host:port'
        ca_cert_path: Path to the CA certificate file (for server verification)
        client_cert_path: Path to the client certificate file
        client_key_path: Path to the client private key file

    Returns:
        grpc.Channel: A secure gRPC channel, or None if certificate loading fails

    Raises:
        FileNotFoundError: If any of the certificate files cannot be found
    """
    try:
        # Read the certificate files
        with open(ca_cert_path, 'rb') as f:
            ca_cert = f.read()
            logger.info(f"Loaded CA certificate from {ca_cert_path}")

        with open(client_cert_path, 'rb') as f:
            client_cert = f.read()
            logger.info(f"Loaded client certificate from {client_cert_path}")

        with open(client_key_path, 'rb') as f:
            client_key = f.read()
            logger.info(f"Loaded client private key from {client_key_path}")

    except FileNotFoundError as e:
        logger.error(f"Certificate file not found: {e}")
        print(f"Error: Certificate file not found: {e}")
        print("Please ensure certificates have been generated and are in the correct location.")
        return None

    except Exception as e:
        logger.error(f"Error reading certificate files: {e}")
        print(f"Error reading certificates: {e}")
        return None

    # Create SSL credentials
    # IMPORTANT: certificate_chain should contain ONLY the client certificate,
    # not concatenated with the CA certificate. The CA certificate goes in
    # root_certificates for server verification.
    credentials = grpc.ssl_channel_credentials(
        root_certificates=ca_cert,      # CA cert for verifying the server
        private_key=client_key,          # Client's private key
        certificate_chain=client_cert    # Client's certificate (not concatenated with CA)
    )

    logger.info(f"Creating secure channel to {server_address}")

    # Create and return the secure channel
    return grpc.secure_channel(server_address, credentials)
