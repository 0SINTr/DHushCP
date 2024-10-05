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

# Generate RSA Keys for the Client
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

# Convert Public Key to PEM format for sharing
client_public_key_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

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

# Function to get complete message input from the user, with byte-based limit handling
def get_complete_message(prompt, max_bytes=735):
    """Get a complete message input from the user with byte-based limit handling."""
    print(f"{prompt} (Type 'END' on a new line to finish. Maximum {max_bytes} bytes or 500 characters recommended.)")
    user_message = ""
    while True:
        line = input("> ")
        if line.strip().upper() == "END":
            break
        if len((user_message + line + " ").encode('utf-8')) > max_bytes:
            print(f"Byte limit of {max_bytes} exceeded! Message truncated.")
            while len(user_message.encode('utf-8')) > max_bytes:
                user_message = user_message[:-1]  # Remove characters until it fits
            break
        user_message += line + " "
    return user_message.strip()

# Function to wait for a strict Enter confirmation
def wait_for_enter(prompt="Press Enter to confirm you read the message..."):
    """Wait for a strict Enter confirmation to proceed."""
    while True:
        user_input = input(prompt)
        if user_input == "":  # Enter was pressed without any other input
            break
        print("Please press only Enter to confirm.")
        continue

# Function to perform cleanup after reading the message
def perform_cleanup():
    """Perform cleanup after reading the message."""
    global client_private_key, server_public_key
    client_private_key = None
    server_public_key = None
    os.system('clear' if os.name == 'posix' else 'cls')
    print(".")  # Confirmation dot

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

# Placeholder for Server's public key
server_public_key = None

# Check and release IP on the wireless interface
check_sudo()
wifi_interface = get_wireless_interface()
check_and_release_ip(wifi_interface)

# Create and send a DHCP Discover packet with the fragmented Client's Public Key
client_mac = get_if_hwaddr(wifi_interface)
public_key_fragments = fragment_message_with_sequence(client_public_key_pem, 50)
fragmented_options = embed_fragments_into_dhcp_options(public_key_fragments)

discover = (
    Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=client_mac) /
    DHCP(options=[("message-type", "discover"), ("param_req_list", [224]), (224, b"DHushCP-ID")] + fragmented_options + [("end")])
)

print("Sending DHCP Discover packet with fragmented Client's Public Key")
sendp(discover, iface=wifi_interface)

# Listen for DHCP Offer and respond with DHCP Request (unicast)
def handle_offer(packet):
    global server_public_key

    if packet[DHCP] and packet[DHCP].options[0][1] == 2:  # DHCP Offer
        for option in packet[DHCP].options:
            if option[0] == 224 and option[1] == b"DHushCP-ID":
                print("Received valid DHCP Offer from DHushCP server")

                # Reassemble and process the server's public key
                server_public_key_pem = reassemble_message_from_options(packet[DHCP].options)
                if server_public_key_pem:
                    server_public_key = serialization.load_pem_public_key(server_public_key_pem)
                    print(f"Received and reassembled Server's Public Key")

                    # Prompt the user to enter a message for the server
                    user_message = get_complete_message("Enter the message to send to the server")

                    # Check the byte length of the input message
                    message_byte_length = len(user_message.encode('utf-8'))
                    if message_byte_length > 735:
                        print(f"Message is too long! The input is {message_byte_length} bytes, but the maximum is 735 bytes.")
                        sys.exit(1)

                    print(f"Message accepted. Length in bytes: {message_byte_length} (Max: 735 bytes)")

                    # Encrypt message using Server's Public Key
                    encrypted_message = server_public_key.encrypt(
                        user_message.encode(),
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                    # Fragment the encrypted message and send in DHCP Request
                    encrypted_fragments = fragment_message_with_sequence(encrypted_message, 251)
                    fragmented_options = embed_fragments_into_dhcp_options(encrypted_fragments)

                    # Create and send DHCP Request packet with fragmented encrypted message
                    request = (
                        Ether(src=client_mac, dst=packet[Ether].src) /
                        IP(src="0.0.0.0", dst=packet[IP].src) /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=packet[Ether].chaddr) /
                        DHCP(options=[("message-type", "request"),
                                      ("server_id", packet[IP].src),
                                      ("requested_addr", packet[BOOTP].yiaddr)] +
                                      fragmented_options + [("end")])
                    )

                    print("Sending DHCP Request with encrypted message")
                    sendp(request, iface=wifi_interface)
                    break  # Stop further packet processing if the correct offer is found

# Listen for DHCP Offer and handle accordingly
sniff(filter="udp and (port 67 or 68)", prn=handle_offer, iface=wifi_interface, timeout=60)
