import socket
import struct
import time
import hmac
import hashlib
import secrets
import os
import asyncio
import logging
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from functools import lru_cache

# Security Key for HMAC and AES Encryption (ensure they are securely stored)
SECURITY_KEY = os.getenv("SECURITY_KEY") or os.urandom(32)  # Use environment variable or generate if not set
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY") or os.urandom(32)  # Use environment variable or generate if not set

# IPv7 Constants
IPV7_VERSION = 7
SERVER_HOST = "::"  # Bind to all IPv6 interfaces
SERVER_PORT = 7777
MAX_PACKET_SIZE = 1024  # Prevent oversized packets
RATE_LIMIT = 5  # Max packets per 10 seconds per IP
RATE_WINDOW = 10  # Time window for rate limiting (in seconds)
NONCE_TTL = 60  # Time-to-live for nonces in seconds

# Rate limiter dictionary (IP -> [Timestamps])
rate_limiter = defaultdict(list)

# LRU Nonce cache for replay attack prevention with TTL
nonce_cache = {}

def rotate_keys():
    """Function to rotate keys periodically (in production use secure storage)"""
    global SECURITY_KEY, ENCRYPTION_KEY
    SECURITY_KEY = os.urandom(32)
    ENCRYPTION_KEY = os.urandom(32)

def ipv6_to_ipv7_custom(ipv6_address):
    """Convert an IPv6 address to a custom IPv7-like address format"""
    return f"IPv7-{ipv6_address}-Extended"

def generate_hmac(data):
    """Generate an HMAC for integrity verification"""
    return hmac.new(SECURITY_KEY, data, hashlib.sha256).digest()

def encrypt_data(data):
    """Encrypt data using AES-GCM"""
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(ENCRYPTION_KEY)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce + ciphertext  # Combine nonce with ciphertext

def decrypt_data(encrypted_data):
    """Decrypt data using AES-GCM"""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(ENCRYPTION_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def create_ipv7_packet(src_ip, dest_ip, data):
    """Construct a custom IPv7 packet with HMAC authentication and AES encryption"""
    try:
        if len(data) > MAX_PACKET_SIZE - 100:
            raise ValueError("Data too large")

        version = struct.pack("B", IPV7_VERSION)
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dest_ip_bytes = socket.inet_pton(socket.AF_INET6, dest_ip)
        nonce = secrets.token_bytes(16)  # Unique nonce per packet

        encrypted_payload = encrypt_data(data)
        hmac_signature = generate_hmac(version + src_ip_bytes + dest_ip_bytes + nonce + encrypted_payload)

        return version + src_ip_bytes + dest_ip_bytes + nonce + hmac_signature + encrypted_payload
    except Exception as e:
        logging.error(f"Error creating packet: {e}")
        return None

def parse_ipv7_packet(packet):
    """Parse and verify an IPv7 packet"""
    try:
        if len(packet) < 33 + 16 + 32:
            raise ValueError("Packet too small")

        version = struct.unpack("B", packet[:1])[0]
        src_ip = socket.inet_ntop(socket.AF_INET6, packet[1:17])
        dest_ip = socket.inet_ntop(socket.AF_INET6, packet[17:33])
        nonce = packet[33:49]
        hmac_received = packet[49:81]
        encrypted_data = packet[81:]

        if version != IPV7_VERSION:
            raise ValueError("Invalid IPv7 version")

        # Check if nonce is replayed and cleanup old nonces
        current_time = time.time()
        for key in list(nonce_cache):
            if current_time - nonce_cache[key][1] > NONCE_TTL:
                del nonce_cache[key]  # Remove expired nonces

        if any(entry[0] == nonce for entry in nonce_cache.values()):
            raise ValueError("Replay attack detected")
        nonce_cache[nonce] = (nonce, current_time)

        expected_hmac = generate_hmac(packet[:49] + encrypted_data)
        if not hmac.compare_digest(hmac_received, expected_hmac):
            raise ValueError("Packet HMAC verification failed")

        data = decrypt_data(encrypted_data)
        return version, src_ip, dest_ip, data
    except Exception as e:
        logging.error(f"Error parsing packet: {e}")
        return None, None, None, None

def rate_limit(ip):
    """Sliding window rate limiting to prevent abuse"""
    now = time.time()
    timestamps = rate_limiter[ip]
    rate_limiter[ip] = [t for t in timestamps if now - t < RATE_WINDOW]

    if len(rate_limiter[ip]) >= RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for {ip}")
        return True
    rate_limiter[ip].append(now)
    return False

class IPv7ServerProtocol(asyncio.DatagramProtocol):
    """Protocol for handling IPv7 UDP packets asynchronously"""

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        """Invoked when connection is made (socket created)"""
        self.transport = transport
        logging.info(f"Secure IPv7 Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    def datagram_received(self, data, addr):
        """Invoked when a datagram is received"""
        ip_address = addr[0]
        if rate_limit(ip_address):
            return

        version, src_ip, dest_ip, data = parse_ipv7_packet(data)
        if version == IPV7_VERSION and src_ip and dest_ip:
            logging.info(f"[IPv7] Packet Received - From: {ipv6_to_ipv7_custom(src_ip)} To: {ipv6_to_ipv7_custom(dest_ip)} Data: {data}")
        else:
            logging.error(f"[ERROR] Invalid or Tampered Packet from {ip_address}")

    def error_received(self, exc):
        """Invoked when an error is received"""
        logging.error(f"Error received: {exc}")

    def connection_lost(self, exc):
        """Invoked when the connection is closed"""
        logging.info("Closing IPv7 server connection")

async def ipv7_client(message):
    """Sends a securely signed and encrypted message to the IPv7 server"""
    try:
        client_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        client_socket.bind(("::", 0))

        packet = create_ipv7_packet("::1", "::1", message)
        if packet:
            logging.debug(f"Sending Secure Packet...")
            client_socket.sendto(packet, ("::1", SERVER_PORT))
            logging.info("[IPv7] Secure Packet Sent!")

        client_socket.close()
    except Exception as e:
        logging.error(f"Client Error: {e}")

async def main():
    """Runs both server and client asynchronously"""
    loop = asyncio.get_event_loop()

    # Start server
    listen = loop.create_datagram_endpoint(IPv7ServerProtocol, local_addr=(SERVER_HOST, SERVER_PORT))
    await listen

    # Simulate a client sending a message
    await ipv7_client("Hello, Secure IPv7!")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())



