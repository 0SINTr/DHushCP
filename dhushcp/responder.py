#!/usr/bin/env python3
# Copyright 2024-2025 © 0SINTr (https://github.com/0SINTr)
import os
import gc
import sys
import time
import argparse
import threading
import subprocess
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, get_if_hwaddr
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from colorama import Fore, Style

import sys
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.key_binding import KeyBindings
except ImportError:
    print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "The 'prompt_toolkit' library is required for this script to run.")
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Please install it using 'sudo apt install python3-prompt-toolkit'")
    sys.exit(1)

# ==============================
# Configuration Constants
# ==============================
DHCP_OPTION_ID = 224       # Custom DHCP option ID for DHushCP
SESSION_ID_OPTION = 225    # DHCP option for Session ID
DATA_OPTION = 226          # DHCP option for embedding data
DHUSHCP_ID = None          # Will be set in main()

MAX_MESSAGE_LENGTH = 100    # Maximum message length in characters
MAX_DHCP_OPTION_DATA = 255  # Maximum data per DHCP option
AES_KEY_SIZE = 32           # 256 bits for AES-256
NONCE_SIZE = 12             # 96 bits for AES-GCM nonce
CHECKSUM_SIZE = 32          # 256 bits for SHA-256 checksum

# ==============================
# Utility Functions
# ==============================

def get_wireless_interface():
    """Detect and select the active wireless interface."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.split()[1] for line in lines if "Interface" in line]

        if not interfaces:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No wireless interface found. Exiting.")
            sys.exit(1)

        if len(interfaces) > 1:
            print(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Multiple wireless interfaces detected. Please choose one:")
            for idx, iface in enumerate(interfaces):
                print(f"{idx + 1}. {iface}")
            try:
                choice = int(input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the number corresponding to your choice: ")) - 1
                if choice < 0 or choice >= len(interfaces):
                    print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid selection. Exiting.")
                    sys.exit(1)
                selected_interface = interfaces[choice]
            except ValueError:
                print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid input. Please enter a number.")
                sys.exit(1)
        else:
            selected_interface = interfaces[0]
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Detected wireless interface: {selected_interface}")

        # Check if the interface is UP
        state_check = subprocess.run(['ip', 'link', 'show', selected_interface], capture_output=True, text=True)
        if "state UP" in state_check.stdout:
            return selected_interface
        else:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Interface {selected_interface} is DOWN. Please bring it UP before running the script.")
            sys.exit(1)
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to detect wireless interface: {e}")
        sys.exit(1)

def check_sudo():
    """Ensure the script is run with sudo privileges."""
    if os.geteuid() != 0:
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "This script requires sudo privileges. Please run it with `sudo`.")
        sys.exit(1)

def get_limited_input(prompt_message, max_length):
    session = PromptSession()
    bindings = KeyBindings()

    @bindings.add('c-m')  # Enter key
    def _(event):
        buffer = event.app.current_buffer
        if len(buffer.text) > max_length:
            # Prevent the input from being accepted
            event.app.current_buffer.validation_state = False
            event.app.current_buffer.validate_and_handle()
        else:
            buffer.validate_and_handle()

    def bottom_toolbar():
        text_length = len(session.default_buffer.text)
        remaining = max_length - text_length
        return HTML(f'Remaining characters: <b><style bg="ansiyellow">{remaining}</style></b>')

    validator = Validator.from_callable(
        lambda text: len(text) <= max_length,
        error_message=f'Message exceeds maximum length of {max_length} characters.',
        move_cursor_to_end=True)

    try:
        user_input = session.prompt(
            HTML(prompt_message),
            validator=validator,
            validate_while_typing=False,
            key_bindings=bindings,
            bottom_toolbar=bottom_toolbar)
        return user_input
    except ValidationError:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Message exceeds maximum length of {max_length} characters. Please shorten your message.")
        return None

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
            print(Style.BRIGHT + "<SAFETY> Checksum verification failed! Message integrity compromised." + Style.RESET_ALL)
            return None

        return plaintext
    except InvalidTag:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "AES-GCM authentication failed! Message may have been tampered with.")
        return None
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Decryption failed: {e}")
        return None

def embed_data_into_dhcp_option(data_bytes):
    """Embed data into a single DHCP option 226."""
    if len(data_bytes) > MAX_DHCP_OPTION_DATA:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Data exceeds maximum size for a single DHCP option.")
        return None
    return [(DATA_OPTION, data_bytes)]

def reassemble_data_from_dhcp_option(options):
    """Extract data from a single DHCP option 226."""
    for opt in options:
        if isinstance(opt, tuple) and opt[0] == DATA_OPTION:
            return opt[1]
    return None

def create_dhcp_discover(session_id, dhushcp_id, data_options=[]):
    """Create a DHCP Discover packet with embedded data."""
    xid = RandInt()
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=get_if_hwaddr(iface), xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            (DHCP_OPTION_ID, dhushcp_id),
            (SESSION_ID_OPTION, session_id),
        ] + data_options + [("end")])
    )

def send_dhcp_discover(packet, iface):
    """Send a DHCP Discover packet."""
    sendp(packet, iface=iface, verbose=False)
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Sent DHCP Discover packet.")

def listen_dhcp_discover(iface, callback, stop_event):
    """Listen for DHCP Discover packets."""
    sniff(
        filter="udp and (port 67 or 68)",
        iface=iface,
        prn=callback,
        store=0,
        stop_filter=lambda pkt: stop_event.is_set()
    )

# ==============================
# Main Communication Functions
# ==============================

def respond_key_exchange(iface, session_id, dhushcp_id, private_key, peer_public_pem):
    """Respond to key exchange by sending own public key and derive shared key."""
    try:
        peer_public_key = deserialize_public_key(peer_public_pem)
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to deserialize peer's public key: {e}")
        return

    shared_key = derive_shared_key(private_key, peer_public_key)
    shared_key_holder[session_id] = {'key': shared_key}
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Derived shared AES key.")

    # Serialize own public key
    public_pem = serialize_public_key(private_key.public_key())

    # Embed own public key into DHCP Discover options
    options = embed_data_into_dhcp_option(public_pem)

    # Create and send DHCP Discover with own public key
    packet = create_dhcp_discover(session_id, dhushcp_id, options)
    send_dhcp_discover(packet, iface)
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Responded to key exchange by sending public key.")

def handle_received_dhcp(packet):
    """Handle received DHCP Discover packets."""
    global DHUSHCP_ID
    #print(Style.BRIGHT + "[DEBUG] " + Style.RESET_ALL + "Responder received a packet.")
    try:
        if DHCP in packet and packet[DHCP].options:
            dhcp_options = packet[DHCP].options
            option_dict = {opt[0]: opt[1] for opt in dhcp_options if isinstance(opt, tuple)}

            # Ignore packets sent by ourselves
            if Ether in packet:
                src_mac = packet[Ether].src
                if src_mac == own_mac:
                    return

            # Debugging: Print received DHCP options
            #print("[DEBUG] Received DHCP Discover with options:", option_dict)

            # Check for DHushCP-ID and Session ID
            if DHCP_OPTION_ID in option_dict and option_dict[DHCP_OPTION_ID] == DHUSHCP_ID and SESSION_ID_OPTION in option_dict:
                session_id = option_dict[SESSION_ID_OPTION]

                # Check if data is present
                data_options = [opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == DATA_OPTION]
                if not data_options:
                    print("[WARNING] No data embedded in DHCP Discover. Ignoring packet.")
                    return  # No data embedded

                # Reassemble data
                assembled_data = reassemble_data_from_dhcp_option(dhcp_options)
                if not assembled_data:
                    print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Failed to reassemble data from DHCP options.")
                    return  # Reassembly failed

                # Determine if it's a public key or encrypted message
                try:
                    # Attempt to deserialize as public key
                    peer_public_key = deserialize_public_key(assembled_data)
                    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Received peer's public key.")

                    # Check if shared key already exists
                    if session_id in shared_key_holder:
                        #print("[DEBUG] Shared key already established for this session.")
                        return

                    # Derive shared key and respond
                    respond_key_exchange(iface, session_id, DHUSHCP_ID, private_key, assembled_data)
                except Exception as e:
                    # Assume it's an encrypted message
                    #print(f"[DEBUG] Data is not a public key. Attempting to decrypt as message.")
                    if session_id not in shared_key_holder or shared_key_holder[session_id]['key'] is None:
                        print("[WARNING] Received encrypted message but shared key is not established.")
                        return
                    plaintext = decrypt_message(shared_key_holder[session_id]['key'], assembled_data)
                    if plaintext:
                        print(Style.BRIGHT + Fore.GREEN + "\n[MESSAGE RECEIVED] " + Style.RESET_ALL + f"{plaintext}\n")
                        # Prompt user to reply
                        user_reply = get_limited_input("-> Enter your reply (max 100 characters, or press Ctrl+C to exit and cleanup):\n", MAX_MESSAGE_LENGTH)
                        if user_reply is None:
                            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Reply exceeds maximum length of {MAX_MESSAGE_LENGTH} characters. Please shorten your reply.")
                            return               
                        if user_reply:
                            encrypted_reply = encrypt_message(shared_key_holder[session_id]['key'], user_reply)
                            packet_options = embed_data_into_dhcp_option(encrypted_reply)
                            reply_packet = create_dhcp_discover(session_id, DHUSHCP_ID, packet_options)
                            send_dhcp_discover(reply_packet, iface)
                            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Sent encrypted reply.")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Exception in handle_received_dhcp: {e}")

def cleanup_process():
    """Perform cleanup after communication."""
    print("\n[INFO] Initiating cleanup process...")
    confirmation = input("Do you want to perform cleanup? This will delete encryption keys and clear system logs. (y/n): ").strip().lower()
    if confirmation != 'y':
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Cleanup aborted by user.")
        return

    # Delete encryption keys
    try:
        private_key = None
        public_key = None
        shared_key_holder.clear()
        gc.collect()
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Encryption keys deleted from memory.")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to delete encryption keys: {e}")

    # Clear recent system logs
    try:
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Clearing system logs...")
        log_files = ['/var/log/syslog', '/var/log/auth.log']
        for log in log_files:
            if os.path.exists(log):
                subprocess.run(['truncate', '-s', '0', log], check=True)
                #print(f"[DEBUG] Cleared {log}.")
        print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "System logs cleared successfully.")
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to clear system logs: {e}")

    # Clear the terminal
    try:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(".")  # Confirmation dot
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to clear the terminal: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='DHushCP Script')
    parser.add_argument('-i', '--id', type=str, required=True,
                        help='Unique DHushCP ID (shared secret between users)')
    args = parser.parse_args()
    return args

def main():
    global iface, private_key, public_key, shared_key_holder, own_mac, DHUSHCP_ID

    # Parse command-line arguments
    args = parse_arguments()
    DHUSHCP_ID = args.id.encode('utf-8')

    print(Style.BRIGHT + "\n<SAFETY> Use Ctrl+C at any time to initiate cleanup and exit.\n" + Style.RESET_ALL)
    check_sudo()
    iface = get_wireless_interface()
    own_mac = get_if_hwaddr(iface)

    private_key, public_key = generate_ecc_keypair()
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Generated ECC key pair.")
    print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + "Responder is now listening for DHCP Discover packets.")

    shared_key_holder = {}  # To hold the derived shared keys per session_id

    stop_event = threading.Event()

    # Start listening in a separate thread
    listener_thread = threading.Thread(
        target=listen_dhcp_discover,
        args=(iface, handle_received_dhcp, stop_event)
    )
    listener_thread.daemon = True
    listener_thread.start()

    # Keep the script running to listen for incoming messages
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        cleanup_process()
        sys.exit(0)

if __name__ == "__main__":
    main()
