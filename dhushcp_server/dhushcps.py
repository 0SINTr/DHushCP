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

# Generate RSA Keys for the Server
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Convert Public Key to PEM format for sharing
server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

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
    global server_private_key, client_public_key
    server_private_key = None
    client_public_key = None
    os.system('clear' if os.name == 'posix' else 'cls')
    print(".")  # Confirmation dot

# Placeholder for Client's public key
client_public_key = None

# Handle DHCP Discover and respond with DHCP Offer containing fragmented Server's Public Key
def handle_discover(packet):
    global client_public_key

    if packet[DHCP] and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        # Look for the custom option to verify it's from the DHushCP client
        for option in packet[DHCP].options:
            if option[0] == 224 and option[1] == custom_option_value:
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
                                      (224, custom_option_value)] + fragmented_options + [("end")])
                    )
                    sendp(offer, iface="wlan0")
                    print("Sent DHCP Offer with fragmented Server's Public Key")
                break
        else:
            print("Received DHCP Discover without matching custom option, ignoring...")

# Handle DHCP Request and respond with DHCP Ack containing encrypted message
def handle_request(packet):
    global client_public_key

    if packet[DHCP] and packet[DHCP].options[0][1] == 3:  # DHCP Request
        # Reassemble encrypted message from DHCP options
        encrypted_message = reassemble_message_from_options(packet[DHCP].options)
        if encrypted_message:
            # Decrypt the message using Server's Private Key
            decrypted_message = server_private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Received and decrypted message from Client: {decrypted_message.decode()}")

            # Prompt the user to enter a response message for the client
            user_response = input("Enter the message to send back to the client: ").encode()

            # Encrypt message using Client's Public Key
            encrypted_response = client_public_key.encrypt(
                user_response,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Ensure the message can fit into the selected DHCP options
            max_fragment_size = 251  # Max payload size per fragment (255 bytes - 4 bytes metadata)
            if len(encrypted_response) > len(["43", "60", "77", "125"]) * max_fragment_size:
                print("Message is too long to fit in the DHCP options. Please enter a shorter message.")
                sys.exit(1)

            # Fragment the encrypted response message and embed into DHCP Ack
            response_fragments = fragment_message_with_sequence(encrypted_response, max_fragment_size)
            fragmented_options = embed_fragments_into_dhcp_options(response_fragments)

            # Create and send DHCP Ack packet with fragmented encrypted response message
            ack = (
                Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                IP(src="192.168.1.1", dst=packet[IP].dst) /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr="192.168.1.1", chaddr=packet[Ether].chaddr) /
                DHCP(options=[("message-type", "ack"),
                              ("server_id", "192.168.1.1"),
                              (224, custom_option_value)] + fragmented_options + [("end")])
            )
            sendp(ack, iface="wlan0")
            print("Sent DHCP Ack with encrypted message")

# Handle DHCP Release and perform cleanup
def handle_release(packet):
    if packet[DHCP] and packet[DHCP].options[0][1] == 7:  # DHCP Release
        print("Received DHCP Release from client, performing cleanup...")
        perform_cleanup()
        sys.exit()

# Sniff for DHCP Discover, Request, and Release packets
sniff(filter="udp and (port 67 or 68)", prn=handle_discover, iface="wlan0", timeout=60)
sniff(filter="udp and (port 67 or 68)", prn=handle_request, iface="wlan0", timeout=60)
sniff(filter="udp and (port 67 or 68)", prn=handle_release, iface="wlan0", timeout=60)
