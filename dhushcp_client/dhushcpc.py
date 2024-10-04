from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os
import sys
import math

# Custom DHCP option to uniquely identify DHushCP communication
custom_option_value = b"DHushCP-ID"

# Function to fragment a message into smaller chunks with sequence numbers and metadata
def fragment_message_with_sequence(message, chunk_size):
    fragments = []
    total_fragments = math.ceil(len(message) / chunk_size)
    for seq_num, i in enumerate(range(0, len(message), chunk_size)):
        fragment = message[i:i + chunk_size]
        fragments.append((seq_num, total_fragments, fragment))  # (sequence_number, total_fragments, fragment)
    return fragments

# Function to embed message chunks into selected DHCP options
def embed_fragments_into_dhcp_options(fragments, option_list=["43", "60", "77", "125"]):
    options = []
    for i, (seq_num, total_fragments, fragment) in enumerate(fragments):
        if i < len(option_list):
            encoded_fragment = bytes([seq_num]) + bytes([total_fragments]) + fragment
            options.append((option_list[i], encoded_fragment))
    return options

# Generate RSA Keys for the Client
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

# Convert Public Key to PEM format for sharing
client_public_key_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Fragment the public key into 50-byte chunks
public_key_fragments = fragment_message_with_sequence(client_public_key_pem, 50)
fragmented_options = embed_fragments_into_dhcp_options(public_key_fragments)

# Create and send a DHCP Discover packet with the fragmented Client's Public Key
client_mac = get_if_hwaddr("wlan0")
discover = (
    Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=client_mac) /
    DHCP(options=[("message-type", "discover"), ("param_req_list", [224]), (224, custom_option_value)] + fragmented_options + [("end")])
)

print("Sending DHCP Discover packet with fragmented Client's Public Key")
sendp(discover, iface="wlan0")

# Placeholder for Server's public key
server_public_key = None

# Listen for DHCP Offer and respond with DHCP Request (unicast)
def handle_offer(packet):
    global server_public_key

    # Check if the packet is a DHCP Offer and contains the correct custom option
    if packet[DHCP] and packet[DHCP].options[0][1] == 2:  # DHCP Offer
        # Look for our custom option (224)
        for option in packet[DHCP].options:
            if option[0] == 224 and option[1] == custom_option_value:
                print("Received valid DHCP Offer from DHushCP server")

                # Reassemble and process the server's public key
                server_public_key_pem = reassemble_message_from_options(packet[DHCP].options)
                if server_public_key_pem:
                    server_public_key = serialization.load_pem_public_key(server_public_key_pem)
                    print(f"Received and reassembled Server's Public Key")

                    # Prompt the user to enter a message for the server
                    user_message = input("Enter the message to send to the server: ").encode()

                    # Encrypt message using Server's Public Key
                    encrypted_message = server_public_key.encrypt(
                        user_message,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                    # Ensure the message can fit into the selected DHCP options
                    max_fragment_size = 251  # Max payload size per fragment (255 bytes - 4 bytes metadata)
                    if len(encrypted_message) > len(["43", "60", "77", "125"]) * max_fragment_size:
                        print("Message is too long to fit in the DHCP options. Please enter a shorter message.")
                        sys.exit(1)

                    # Fragment the encrypted message and send in DHCP Request
                    encrypted_fragments = fragment_message_with_sequence(encrypted_message, max_fragment_size)
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
                    sendp(request, iface="wlan0")
                    break  # Stop further packet processing if the correct offer is found
        else:
            print("Received DHCP Offer without matching custom option, ignoring...")

# Function to reassemble message from fragmented DHCP options
def reassemble_message_from_options(options):
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
    global client_private_key, server_public_key
    client_private_key = None
    server_public_key = None
    os.system('clear' if os.name == 'posix' else 'cls')
    print(".")  # Confirmation dot

# Handle DHCP Ack (Receive and decrypt the server's response)
def handle_ack(packet):
    if packet[DHCP] and packet[DHCP].options[0][1] == 5:  # DHCP Ack
        encrypted_message = reassemble_message_from_options(packet[DHCP].options)
        if encrypted_message:
            # Decrypt the message using Client's Private Key
            decrypted_message = client_private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Received and decrypted message from Server: {decrypted_message.decode()}")

            # Wait for user to confirm they read the message
            input("Press Enter to confirm you read the message...")

            # Send DHCP Release
            release = (
                Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=client_mac) /
                DHCP(options=[("message-type", "release"), ("server_id", packet[IP].src), ("end")])
            )
            sendp(release, iface="wlan0")
            print("Sent DHCP Release")

            # Cleanup and Exit
            perform_cleanup()
            sys.exit()

# Listen for DHCP Offer and Ack packets
sniff(filter="udp and (port 67 or 68)", prn=handle_offer, iface="wlan0", timeout=60)
sniff(filter="udp and (port 67 or 68)", prn=handle_ack, iface="wlan0", timeout=60)
