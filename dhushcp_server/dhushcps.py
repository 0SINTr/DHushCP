import subprocess
import os
import sys
from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import math

# Automatically detect the wireless interface
def get_wireless_interface():
    """Automatically detect the active wireless interface name."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.split()[1] for line in lines if "Interface" in line]
        if interfaces:
            print(f"Detected wireless interface: {interfaces[0]}")
            return interfaces[0]
        else:
            print("No wireless interface found.")
            sys.exit(1)
    except Exception as e:
        print(f"Failed to detect wireless interface: {e}")
        sys.exit(1)

# Check if the script is running with sudo privileges
def check_sudo():
    """Check if the script is running with sudo privileges."""
    if os.geteuid() != 0:
        print("This script requires sudo privileges. Please run it with `sudo`.")
        sys.exit(1)

# Release any existing IP on the interface using `ip` command
def check_and_release_ip(interface):
    """Check if the interface has an assigned IP and release it using the `ip` command."""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
        if "inet " in result.stdout:
            print(f"Warning: Interface {interface} has an IP address assigned.")
            print("Releasing the IP address to avoid conflicts...")
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface], capture_output=True, text=True)
            print(f"IP address on {interface} has been released using `ip addr flush`.")
        else:
            print(f"No IP address found on {interface}.")
    except Exception as e:
        print(f"Failed to check or release IP on {interface} using `ip` command: {e}")

# Generate RSA Keys for the Server
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Convert Public Key to PEM format for sharing
server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Placeholder for Client's public key
client_public_key = None

# Function to fragment a message into smaller chunks with sequence numbers and metadata
def fragment_message_with_sequence(message, chunk_size):
    """Fragment a message into smaller chunks with sequence numbers."""
    fragments = []
    total_fragments = math.ceil(len(message) / chunk_size)
    for seq_num, i in enumerate(range(0, len(message), chunk_size)):
        fragment = message[i:i + chunk_size]
        fragments.append((seq_num, total_fragments, fragment))  # (sequence_number, total_fragments, fragment)
    return fragments

# Function to embed message chunks into selected DHCP options
def embed_fragments_into_dhcp_options(fragments, option_list=["43", "60", "77", "125"]):
    """Embed message fragments into selected DHCP options."""
    options = []
    for i, (seq_num, total_fragments, fragment) in enumerate(fragments):
        if i < len(option_list):
            encoded_fragment = bytes([seq_num]) + bytes([total_fragments]) + fragment
            options.append((option_list[i], encoded_fragment))
    return options

# Function to reassemble message from fragmented DHCP options
def reassemble_message_from_options(options):
    """Reassemble message fragments from DHCP options."""
    fragments = {}
    for opt in options:
        if opt[0] in ["43", "60", "77", "125"]:
            seq_num = opt[1][0]  # Sequence number
            total_fragments = opt[1][1]  # Total fragments
            fragment_data = opt[1][2:]  # Fragment data
            fragments[seq_num] = fragment_data
    if len(fragments) == total_fragments:
        return b"".join([fragments[i] for i in sorted(fragments)])
    else:
        return None

# Function to perform cleanup after reading the message
def perform_cleanup():
    """Perform cleanup after reading the message."""
    global server_private_key, client_public_key
    server_private_key = None
    client_public_key = None
    os.system('clear' if os.name == 'posix' else 'cls')
    print(".")  # Confirmation dot

# Check for sudo privileges and detect the interface
check_sudo()
wifi_interface = get_wireless_interface()
check_and_release_ip(wifi_interface)

# Handle DHCP Discover and respond with DHCP Offer containing fragmented Server's Public Key
def handle_discover(packet):
    global client_public_key

    if packet[DHCP] and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        for option in packet[DHCP].options:
            if option[0] == 224 and option[1] == b"DHushCP-ID":
                print("Received valid DHCP Discover from DHushCP client")

                # Reassemble Client's Public Key from Fragments
                client_public_key_pem = reassemble_message_from_options(packet[DHCP].options)
                if client_public_key_pem:
                    client_public_key = serialization.load_pem_public_key(client_public_key_pem)
                    print(f"Received and reassembled Client's Public Key")

                    # Fragment the Server's Public Key and embed in DHCP Offer
                    server_key_fragments = fragment_message_with_sequence(server_public_key_pem, 50)
                    fragmented_options = embed_fragments_into_dhcp_options(server_key_fragments)

                    # Create and send DHCP Offer with the fragmented Server's Public Key
                    offer = (
                        Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                        IP(src="192.168.1.1", dst="255.255.255.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(op=2, yiaddr="192.168.1.10", siaddr="192.168.1.1", chaddr=packet[Ether].chaddr) /
                        DHCP(options=[("message-type", "offer"),
                                      ("server_id", "192.168.1.1"),
                                      (224, b"DHushCP-ID")] + fragmented_options + [("end")])
                    )
                    sendp(offer, iface=wifi_interface)
                    print("Sent DHCP Offer with fragmented Server's Public Key")
                break
        else:
            print("Received DHCP Discover without matching custom option, ignoring...")

# Handle DHCP Request and respond with DHCP Ack containing encrypted message
def handle_request(packet):
    global client_public_key

    if packet[DHCP] and packet[DHCP].options[0][1] == 3:  # DHCP Request
        encrypted_message = reassemble_message_from_options(packet[DHCP].options)
        if encrypted_message:
            # Decrypt the message using the Server's Private Key
            decrypted_message = server_private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Received and decrypted message from Client: {decrypted_message.decode()}")

            # Prompt the user to enter a response message for the client
            user_response = input("Enter the message to send back to the client: ")

            # Encrypt response message using Client's Public Key
            encrypted_response = client_public_key.encrypt(
                user_response.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Fragment the encrypted message and embed in DHCP Ack
            response_fragments = fragment_message_with_sequence(encrypted_response, 251)
            fragmented_options = embed_fragments_into_dhcp_options(response_fragments)

            # Create and send DHCP Ack with the encrypted response message
            ack = (
                Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                IP(src="192.168.1.1", dst=packet[IP].dst) /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr="192.168.1.1", chaddr=packet[Ether].chaddr) /
                DHCP(options=[("message-type", "ack"),
                              ("server_id", "192.168.1.1"),
                              (224, b"DHushCP-ID")] + fragmented_options + [("end")])
            )
            sendp(ack, iface=wifi_interface)
            print("Sent DHCP Ack with encrypted message")

# Handle DHCP Release and perform cleanup
def handle_release(packet):
    if packet[DHCP] and packet[DHCP].options[0][1] == 7:  # DHCP Release
        print("Received DHCP Release from client, performing cleanup...")
        perform_cleanup()
        sys.exit()

# Sniff for DHCP Discover, Request, and Release packets
sniff(filter="udp and (port 67 or 68)", prn=handle_discover, iface=wifi_interface, timeout=60)
sniff(filter="udp and (port 67 or 68)", prn=handle_request, iface=wifi_interface, timeout=60)
sniff(filter="udp and (port 67 or 68)", prn=handle_release, iface=wifi_interface, timeout=60)
