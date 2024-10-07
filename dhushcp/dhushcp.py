#!/usr/bin/env python3
import subprocess
import os
import sys
import uuid
import math
import struct
import gc
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ==============================
# Configuration Constants
# ==============================
DHCP_OPTION_ID = 224  # Custom DHCP option ID for DHushCP
SESSION_ID_OPTION = 225  # DHCP option for Session ID
DATA_OPTION = 226  # DHCP option for embedding data

DHUSHCP_ID = b'DHushCP-ID'  # Identifier to recognize DHushCP packets

MAX_DHCP_OPTION_DATA = 255  # Maximum data per DHCP option
AES_KEY_SIZE = 32  # 256 bits for AES-256
NONCE_SIZE = 12  # 96 bits for AES-GCM nonce
CHECKSUM_SIZE = 32  # 256 bits for SHA-256 checksum

# ==============================
# Utility Functions
# ==============================

def generate_session_id():
    """Generate a unique session identifier."""
    return uuid.uuid4().bytes  # 16 bytes

def get_wireless_interface():
    """Detect and select the active wireless interface."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.split()[1] for line in lines if "Interface" in line]

        if not interfaces:
            print("No wireless interface found. Exiting.")
            sys.exit(1)

        if len(interfaces) > 1:
            print("Multiple wireless interfaces detected. Please choose one:")
            for idx, iface in enumerate(interfaces):
                print(f"{idx + 1}. {iface}")
            try:
                choice = int(input("Enter the number corresponding to your choice: ")) - 1
                if choice < 0 or choice >= len(interfaces):
                    print("Invalid selection. Exiting.")
                    sys.exit(1)
                selected_interface = interfaces[choice]
            except ValueError:
                print("Invalid input. Please enter a number.")
                sys.exit(1)
        else:
            selected_interface = interfaces[0]
            print(f"Detected wireless interface: {selected_interface}")

        # Check if the interface is UP
        state_check = subprocess.run(['ip', 'link', 'show', selected_interface], capture_output=True, text=True)
        if "state UP" in state_check.stdout:
            return selected_interface
        else:
            print(f"Interface {selected_interface} is DOWN. Please bring it UP before running the script.")
            sys.exit(1)
    except Exception as e:
        print(f"Failed to detect wireless interface: {e}")
        sys.exit(1)

def check_sudo():
    """Ensure the script is run with sudo privileges."""
    if os.geteuid() != 0:
        print("This script requires sudo privileges. Please run it with `sudo`.")
        sys.exit(1)

def generate_ecc_keypair():
    """Generate ECC key pair."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """Deserialize PEM-formatted public key."""
    return serialization.load_pem_public_key(pem_data)

def derive_shared_key(private_key, peer_public_key):
    """Derive shared secret using ECDH and derive AES key using HKDF."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'DHushCP-SharedKey',
    ).derive(shared_secret)
    return derived_key

def encrypt_message(aes_key, plaintext):
    """Encrypt plaintext using AES-GCM and append SHA-256 checksum."""
    # Compute SHA-256 checksum of plaintext
    digest = hashes.Hash(hashes.SHA256())
    digest.update(plaintext.encode())
    checksum = digest.finalize()

    # Encrypt plaintext
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    # Combine nonce, ciphertext, and checksum
    encrypted_package = nonce + ciphertext + checksum
    return encrypted_package

def decrypt_message(aes_key, encrypted_package):
    """Decrypt ciphertext using AES-GCM and verify SHA-256 checksum."""
    try:
        nonce = encrypted_package[:NONCE_SIZE]
        ciphertext = encrypted_package[NONCE_SIZE:-CHECKSUM_SIZE]
        received_checksum = encrypted_package[-CHECKSUM_SIZE:]

        # Decrypt ciphertext
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        plaintext = plaintext_bytes.decode()

        # Verify checksum
        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext.encode())
        calculated_checksum = digest.finalize()

        if calculated_checksum != received_checksum:
            print("[ERROR] Checksum verification failed! Message integrity compromised.")
            return None

        return plaintext
    except InvalidTag:
        print("[ERROR] AES-GCM authentication failed! Message may have been tampered with.")
        return None
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return None

def embed_data_into_dhcp_options(data_bytes):
    """Embed data into DHCP option 226, handling fragmentation if necessary."""
    fragments = []
    max_data_per_option = MAX_DHCP_OPTION_DATA - 2  # 2 bytes for headers
    total_fragments = math.ceil(len(data_bytes) / max_data_per_option)
    for i in range(total_fragments):
        fragment = data_bytes[i*max_data_per_option:(i+1)*max_data_per_option]
        header = struct.pack("!BB", i, total_fragments)  # Sequence number and total fragments
        fragments.append(header + fragment)
    options = []
    for frag in fragments:
        options.append((DATA_OPTION, frag))
    return options

def reassemble_data_from_dhcp_options(options):
    """Reassemble data from DHCP option 226, verifying sequence."""
    fragments = {}
    total_fragments = None
    for opt in options:
        if isinstance(opt, tuple) and opt[0] == DATA_OPTION:
            data = opt[1]
            if len(data) < 2:
                continue
            seq_num, total = struct.unpack("!BB", data[:2])
            fragment = data[2:]
            fragments[seq_num] = fragment
            if total_fragments is None:
                total_fragments = total
            elif total_fragments != total:
                print("[ERROR] Inconsistent total fragments.")
                return None
    if total_fragments is None:
        return None
    if len(fragments) != total_fragments:
        print(f"[ERROR] Expected {total_fragments} fragments, but received {len(fragments)}.")
        return None
    # Reassemble
    assembled = b''.join([fragments[i] for i in range(total_fragments)])
    return assembled

def create_dhcp_discover(session_id, dhushcp_id, data_options=[]):
    """Create a DHCP Discover packet with embedded data."""
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=RandMAC().replace(":", ""), xid=RandInt(), flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            (DHCP_OPTION_ID, dhushcp_id),
            (SESSION_ID_OPTION, session_id),
        ] + data_options + [("end")])
    )

def send_dhcp_discover(packet, iface):
    """Send a DHCP Discover packet."""
    sendp(packet, iface=iface, verbose=False)
    print("[INFO] Sent DHCP Discover packet.")

def listen_dhcp_discover(iface, callback, timeout=120):
    """Listen for DHCP Discover packets."""
    sniff(
        filter="udp and (port 67 or 68)",
        iface=iface,
        prn=callback,
        store=0,
        timeout=timeout
    )

def create_cleanup_packet(session_id, dhushcp_id):
    """Create a final DHCP Discover packet to signal cleanup."""
    return create_dhcp_discover(session_id, dhushcp_id)

def send_cleanup(iface, packet):
    """Send the cleanup DHCP Discover packet."""
    send_dhcp_discover(packet, iface)
    print("[INFO] Sent cleanup DHCP Discover packet.")

# ==============================
# Main Communication Functions
# ==============================

def initiate_key_exchange(iface, session_id, dhushcp_id, private_key):
    """Initiate key exchange by sending public key."""
    public_pem = serialize_public_key(private_key.public_key())
    options = embed_data_into_dhcp_options(public_pem)
    packet = create_dhcp_discover(session_id, dhushcp_id, options)
    send_dhcp_discover(packet, iface)
    print("[INFO] Initiated key exchange by sending public key.")

def respond_key_exchange(iface, session_id, dhushcp_id, private_key, peer_public_pem):
    """Respond to key exchange by sending own public key and derive shared key."""
    peer_public_key = deserialize_public_key(peer_public_pem)
    shared_key = derive_shared_key(private_key, peer_public_key)
    print("[INFO] Derived shared AES key.")

    # Send own public key
    public_pem = serialize_public_key(private_key.public_key())
    options = embed_data_into_dhcp_options(public_pem)
    packet = create_dhcp_discover(session_id, dhushcp_id, options)
    send_dhcp_discover(packet, iface)
    print("[INFO] Responded to key exchange by sending public key.")

    return shared_key

def handle_received_dhcp(packet, iface, private_key, dhushcp_id, session_id, shared_key_holder):
    """Handle received DHCP Discover packets."""
    if DHCP in packet and packet[DHCP].options:
        dhcp_options = packet[DHCP].options
        option_dict = {opt[0]: opt[1] for opt in dhcp_options if isinstance(opt, tuple)}
        
        # Check for DHushCP-ID and Session ID
        if DHCP_OPTION_ID in option_dict and option_dict[DHCP_OPTION_ID] == dhushcp_id and SESSION_ID_OPTION in option_dict:
            received_session_id = option_dict[SESSION_ID_OPTION]
            if received_session_id != session_id:
                return  # Not our session

            # Check if data is present
            data_options = [opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == DATA_OPTION]
            if not data_options:
                return  # No data embedded

            # Reassemble data
            assembled_data = reassemble_data_from_dhcp_options(dhcp_options)
            if not assembled_data:
                return  # Reassembly failed

            # Determine if it's a public key or encrypted message
            try:
                # Attempt to deserialize as public key
                peer_public_key = deserialize_public_key(assembled_data)
                print("[INFO] Received peer's public key.")
                # Derive shared key
                shared_key = derive_shared_key(private_key, peer_public_key)
                shared_key_holder['key'] = shared_key
                print("[INFO] Derived shared AES key.")

                # If initiating, prompt for message after responding with own public key
                if shared_key_holder.get('initiated'):
                    # Initiator has already sent their public key
                    # Now, after receiving the peer's public key, they should be ready to send a message
                    print("[INFO] Key exchange complete. You can now send a message.")
                else:
                    # Respond to key exchange by sending own public key
                    initiate_key_exchange(iface, session_id, dhushcp_id, private_key)

            except Exception:
                # Assume it's an encrypted message
                if shared_key_holder['key'] is None:
                    print("[WARNING] Received encrypted message but shared key is not established.")
                    return
                plaintext = decrypt_message(shared_key_holder['key'], assembled_data)
                if plaintext:
                    print(f"\n[MESSAGE] {plaintext}\n")
                    # Optionally, reply back
                    user_reply = input("Enter your reply (or press Enter to skip): ").strip()
                    if user_reply:
                        encrypted_reply = encrypt_message(shared_key_holder['key'], user_reply)
                        packet_options = embed_data_into_dhcp_options(encrypted_reply)
                        reply_packet = create_dhcp_discover(session_id, dhushcp_id, packet_options)
                        send_dhcp_discover(reply_packet, iface)
                        print("[INFO] Sent encrypted reply.")

def cleanup_process(iface, session_id, dhushcp_id, private_key, public_key, shared_key_holder):
    """Perform cleanup after communication."""
    print("\n[INFO] Initiating cleanup process...")
    confirmation = input("Do you want to perform cleanup? This will delete encryption keys and clear system logs. (y/n): ").strip().lower()
    if confirmation != 'y':
        print("[INFO] Cleanup aborted by user.")
        return

    # Send a final DHCP Discover packet to signal cleanup
    cleanup_packet = create_cleanup_packet(session_id, dhushcp_id)
    send_cleanup(iface, cleanup_packet)

    # Delete encryption keys
    try:
        private_key = None
        public_key = None
        shared_key_holder['key'] = None
        gc.collect()
        print("[INFO] Encryption keys deleted from memory.")
    except Exception as e:
        print(f"[ERROR] Failed to delete encryption keys: {e}")

    # Clear recent system logs
    try:
        print("[INFO] Clearing system logs...")
        log_files = ['/var/log/syslog', '/var/log/messages']
        for log in log_files:
            if os.path.exists(log):
                subprocess.run(['truncate', '-s', '0', log], check=True)
                print(f"[DEBUG] Cleared {log}.")
        print("[INFO] System logs cleared successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to clear system logs: {e}")

    # Clear the terminal
    try:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(".")  # Confirmation dot
    except Exception as e:
        print(f"[ERROR] Failed to clear the terminal: {e}")

def main():
    check_sudo()
    iface = get_wireless_interface()
    session_id = generate_session_id()
    print(f"[INFO] Session ID: {session_id.hex()}")

    private_key, public_key = generate_ecc_keypair()
    print("[INFO] Generated ECC key pair.")

    shared_key_holder = {'key': None, 'initiated': False}  # To hold the derived shared key and initiation status

    # Decide whether to initiate key exchange or wait for it
    choice = input("Do you want to initiate communication? (y/n): ").strip().lower()
    if choice == 'y':
        initiate_key_exchange(iface, session_id, DHUSHCP_ID, private_key)
        shared_key_holder['initiated'] = True

    # Start listening for DHCP Discover packets
    print("[INFO] Listening for DHCP Discover packets...")
    listen_dhcp_discover(iface, lambda pkt: handle_received_dhcp(pkt, iface, private_key, DHUSHCP_ID, session_id, shared_key_holder), timeout=300)

    # If initiated and shared key is established, prompt for message
    if shared_key_holder.get('key') and shared_key_holder.get('initiated'):
        user_message = input("Enter your message to send: ").strip()
        if user_message:
            encrypted_message = encrypt_message(shared_key_holder['key'], user_message)
            packet_options = embed_data_into_dhcp_options(encrypted_message)
            message_packet = create_dhcp_discover(session_id, DHUSHCP_ID, packet_options)
            send_dhcp_discover(message_packet, iface)
            print("[INFO] Sent encrypted message.")

    # Perform cleanup after listening
    cleanup_process(iface, session_id, DHUSHCP_ID, private_key, public_key, shared_key_holder)

    print("[INFO] Session ended.")

if __name__ == "__main__":
    main()