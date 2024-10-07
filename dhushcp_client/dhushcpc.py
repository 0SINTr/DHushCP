# CLIENT CODE:
# Copyright (C) 2024-2025 0SINTr (https://github.com/0SINTr)

import subprocess
import os
import sys
from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import math
import uuid

# ==============================
# Utility Functions
# ==============================

def generate_session_id():
    """Generate a unique session identifier."""
    return str(uuid.uuid4()).encode('utf-8')  # Bytes for embedding

def get_wireless_interface():
    """Detect and select the active wireless interface."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.split()[1] for line in lines if "Interface" in line]

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
                print(f"Selected interface: {selected_interface}")
            except ValueError:
                print("Invalid input. Please enter a number.")
                sys.exit(1)
        elif interfaces:
            selected_interface = interfaces[0]
            print(f"Detected wireless interface: {selected_interface}")
        else:
            print("No wireless interface found.")
            sys.exit(1)

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

def check_and_release_ip(interface):
    """Release any existing IP address on the interface to avoid conflicts."""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
        if "inet " in result.stdout:
            print(f"Warning: Interface {interface} has an IP address assigned.")
            print("Releasing the IP address to avoid conflicts...")
            subprocess.run(['ip', 'addr', 'flush', 'dev', interface], capture_output=True, text=True)
            # Verify if IP was successfully flushed
            verify = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
            if "inet " not in verify.stdout:
                print(f"IP address on {interface} has been successfully released using `ip addr flush`.")
            else:
                print(f"Failed to release IP address on {interface}. Please check manually.")
        else:
            print(f"No IP address found on {interface}.")
    except Exception as e:
        print(f"Failed to check or release IP on {interface} using `ip` command: {e}")

def generate_checksum(data):
    """Generate SHA-256 checksum for data validation."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    checksum = digest.finalize()
    print("[DEBUG] Generated checksum.")
    return checksum

def fragment_message_with_sequence(message, chunk_size=60):
    """
    Fragment a message into smaller chunks with sequence numbers and metadata.

    Args:
        message (bytes): The message to fragment.
        chunk_size (int): The size of each chunk.

    Returns:
        list of tuples: Each tuple contains (sequence_number, total_fragments, fragment).
    """
    fragments = []
    total_fragments = math.ceil(len(message) / chunk_size)
    print(f"[DEBUG] Fragmenting message into {total_fragments} fragments.")
    for seq_num, i in enumerate(range(0, len(message), chunk_size)):
        fragment = message[i:i + chunk_size]
        fragments.append((seq_num, total_fragments, fragment))
    return fragments

def embed_fragments_into_dhcp_options(fragments, option_list=[150, 151, 152, 153]):
    """
    Embed message fragments into selected DHCP options.

    Args:
        fragments (list of tuples): Each tuple contains (sequence_number, total_fragments, fragment).
        option_list (list of int): DHCP option numbers to use for embedding.

    Returns:
        list of tuples: Each tuple contains (option_number, embedded_data).
    """
    options = []
    print(f"[DEBUG] Embedding fragments into DHCP options {option_list}.")
    for i, (seq_num, total_fragments, fragment) in enumerate(fragments):
        if i < len(option_list):
            encoded_fragment = bytes([seq_num]) + bytes([total_fragments]) + fragment
            options.append((option_list[i], encoded_fragment))
            print(f"[DEBUG] Embedded fragment {seq_num + 1}/{total_fragments} into option {option_list[i]}.")
    return options

def get_complete_message(prompt, max_bytes=700):
    """
    Prompt the user to input a complete message with real-time byte count.
    Type 'END' on a new line to finish.

    Args:
        prompt (str): The message prompt to display.
        max_bytes (int): Maximum allowed bytes for the message.

    Returns:
        str: The complete user message.
    """
    print(f"{prompt} (Type 'END' on a new line to finish. Maximum {max_bytes} bytes or 500 characters recommended.)")
    user_message = ""
    while True:
        # Display real-time byte count
        line = input(f"[{len(user_message.encode('utf-8'))}/{max_bytes} bytes] > ")
        if line.strip().upper() == "END":
            break
        if len((user_message + line + " ").encode('utf-8')) > max_bytes:
            print(f"Byte limit of {max_bytes} exceeded! Message truncated.")
            # Efficient truncation to fit max_bytes
            while len(user_message.encode('utf-8')) + len(line.encode('utf-8')) + 1 > max_bytes:
                user_message = user_message[:-1]
            # Slice the line to fit the remaining bytes
            remaining_bytes = max_bytes - len(user_message.encode('utf-8')) - 1
            truncated_line = line.encode('utf-8')[:remaining_bytes].decode('utf-8', errors='ignore')
            user_message += truncated_line + " "
            break
        user_message += line + " "
    return user_message.strip()

def wait_for_enter(prompt="Press Enter to confirm you read the message..."):
    """Wait for the user to press Enter to confirm."""
    while True:
        user_input = input(prompt)
        if user_input == "":
            break
        print("Please press only Enter to confirm.")

def perform_cleanup():
    """Perform cleanup after sending the message."""
    global client_private_key, server_public_key

    # Send DHCP Release packet
    try:
        release_packet = (
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=client_mac.replace(":", ""), xid=RandInt(), flags=0x8000) /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", server_ip),
                ("end")
            ])
        )
        sendp(release_packet, iface=wifi_interface, verbose=False)
        print("DHCP Release packet sent successfully.")
    except Exception as e:
        print(f"Failed to send DHCP Release packet: {e}")

    # Clear RSA keys from memory
    try:
        del client_private_key
        del server_public_key
        print("[DEBUG] Cleared RSA keys from memory.")
    except Exception as e:
        print(f"Error deleting RSA keys: {e}")

    # Clear DHCP logs to remove any traces (Not Recommended)
    try:
        print("Attempting to clear system logs to remove DHCP traces...")
        if os.path.exists('/var/log/syslog'):
            subprocess.run(['truncate', '-s', '0', '/var/log/syslog'], check=True)
            print("[DEBUG] Cleared /var/log/syslog.")
        if os.path.exists('/var/log/messages'):
            subprocess.run(['truncate', '-s', '0', '/var/log/messages'], check=True)
            print("[DEBUG] Cleared /var/log/messages.")
        print("System logs cleared successfully.")
    except Exception as e:
        print(f"Failed to clear logs: {e}")

    # Clear the terminal
    os.system('clear' if os.name == 'posix' else 'cls')
    print(".")  # Confirmation dot

def reassemble_message_from_options(options):
    """
    Reassemble the message from fragmented DHCP options with checksum verification.

    Args:
        options (list): List of DHCP options.

    Returns:
        bytes or None: The reassembled message if checksum is valid, else None.
    """
    fragments = {}
    total_fragments = None
    print("[DEBUG] Reassembling message from DHCP options...")
    for opt in options:
        if isinstance(opt, tuple) and opt[0] in [150, 151, 152, 153]:
            if isinstance(opt[1], bytes) and len(opt[1]) >= 2:
                seq_num = opt[1][0]
                total = opt[1][1]
                fragment_data = opt[1][2:]
                fragments[seq_num] = fragment_data
                print(f"[DEBUG] Received fragment {seq_num + 1}/{total} from option {opt[0]}")
                if total_fragments is None:
                    total_fragments = total
                elif total_fragments != total:
                    print("Inconsistent total fragments count.")
                    return None
    if total_fragments is None:
        print("No fragments found in options.")
        return None
    if len(fragments) == total_fragments:
        try:
            assembled_data = b"".join([fragments[i] for i in sorted(fragments)])
            print("[DEBUG] Successfully assembled data from fragments.")
        except KeyError as e:
            print(f"Missing fragment: {e}")
            return None

        # Validate checksum if the last 32 bytes represent a checksum
        if len(assembled_data) < 32:
            print("Assembled data is too short to contain a checksum.")
            return None
        reassembled_message, checksum = assembled_data[:-32], assembled_data[-32:]
        if generate_checksum(reassembled_message) == checksum:
            print("[DEBUG] Checksum verification passed.")
            return reassembled_message
        else:
            print("Checksum verification failed! Message integrity compromised.")
            return None
    else:
        print(f"Expected {total_fragments} fragments, but received {len(fragments)}.")
        return None

# ==============================
# Main Execution Flow
# ==============================

# Placeholder for Server's public key and IP address
server_public_key = None
server_ip = None
server_mac = None
session_id = None

def main():
    global server_public_key, server_ip, session_id, client_private_key, server_ip, client_mac, wifi_interface

    # Initial setup
    check_sudo()
    wifi_interface = get_wireless_interface()
    check_and_release_ip(wifi_interface)

    # Generate RSA Keys for the Client
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_public_key = client_private_key.public_key()
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate a unique session identifier
    session_id = generate_session_id()

    # Get client's MAC address
    client_mac = get_if_hwaddr(wifi_interface)
    print(f"[DEBUG] Client MAC address: {client_mac}")

    # Prepare the DHCP Discover packet with fragmented Client's Public Key, DHushCP-ID, and Session ID
    dhushcp_id = b"DHushCP-ID"  # Custom identifier for DHushCP

    # Append checksum to the public key
    checksum = generate_checksum(client_public_key_pem)
    public_key_with_checksum = client_public_key_pem + checksum

    # Fragment the public key
    public_key_fragments = fragment_message_with_sequence(public_key_with_checksum, chunk_size=60)

    # Embed fragments into DHCP options 150, 151, 152, 153
    fragmented_options = embed_fragments_into_dhcp_options(public_key_fragments, option_list=[150, 151, 152, 153])

    # Debug: Print embedded options
    print("[DEBUG] Embedded DHCP options with public key fragments:")
    for opt in fragmented_options:
        print(f"Option {opt[0]}: {opt[1]}")

    # Create DHCP Discover packet
    discover = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=client_mac.replace(":", ""), xid=RandInt(), flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [224, 225]),  # Requesting custom options 224 and 225
            (224, dhushcp_id),
            (225, session_id),  # Embed the unique session ID
        ] + fragmented_options + [("end")])
    )

    # Debug: Print the DHCP Discover packet details
    print("[DEBUG] DHCP Discover Packet:")
    discover.show()

    print("Sending DHCP Discover packet with fragmented Client's Public Key, DHushCP-ID, and Session ID")
    sendp(discover, iface=wifi_interface, verbose=False)
    print("DHCP Discover packet sent successfully")

    # Listen for DHCP Offer from the server
    def handle_offer(packet):
        global server_public_key, server_ip

        if packet.haslayer(DHCP):
            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt[0], int)}
            msg_type = dhcp_options.get(53)
            print("[DEBUG] Received DHCP Message Type:", msg_type)

            # DHCP Offer has a message type value of 2
            if msg_type == 2 and dhcp_options.get(224) == dhushcp_id and dhcp_options.get(225) == session_id:
                print("Received valid DHCP Offer from server with matching Session ID")

                # Extract server's IP address
                server_ip = packet[IP].src
                print(f"[DEBUG] Server IP address: {server_ip}")

                # Reassemble and process the server's public key
                server_public_key_pem = reassemble_message_from_options(packet[DHCP].options)
                if server_public_key_pem:
                    try:
                        # Load the server's public key
                        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
                        print(f"Received and reassembled Server's Public Key from IP: {server_ip}")
                    except Exception as e:
                        print(f"Error reassembling Server's Public Key: {e}")
                        return False  # Continue sniffing if reassembly fails

                    # Prompt the client user to input a message
                    user_message = get_complete_message("Enter the message to send to the server")

                    # Check the byte length of the input message
                    message_byte_length = len(user_message.encode('utf-8'))
                    if message_byte_length > 700:
                        print(f"Message is too long! The input is {message_byte_length} bytes, but the maximum is 700 bytes.")
                        sys.exit(1)

                    print(f"Message accepted. Length in bytes: {message_byte_length} (Max: 700 bytes)")

                    # Encrypt the message using Server's Public Key
                    try:
                        encrypted_message = server_public_key.encrypt(
                            user_message.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print("[DEBUG] Encrypted the message using Server's Public Key.")
                    except Exception as e:
                        print(f"Error during encryption: {e}")
                        sys.exit(1)

                    # Generate checksum for the encrypted message
                    checksum = generate_checksum(encrypted_message)
                    encrypted_message_with_checksum = encrypted_message + checksum

                    # Fragment the encrypted message and embed in DHCP Request
                    encrypted_fragments = fragment_message_with_sequence(encrypted_message_with_checksum, chunk_size=251)
                    fragmented_options = embed_fragments_into_dhcp_options(encrypted_fragments, option_list=[150, 151, 152, 153])

                    # Debug: Print embedded options for DHCP Request
                    print("[DEBUG] Embedded DHCP options with encrypted message fragments:")
                    for opt in fragmented_options:
                        print(f"Option {opt[0]}: {opt[1]}")

                    # Create DHCP Request packet with encrypted message and session ID
                    request = (
                        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                        IP(src="0.0.0.0", dst="255.255.255.255") /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=client_mac.replace(":", ""), xid=RandInt(), flags=0x8000) /
                        DHCP(options=[
                            ("message-type", "request"),
                            ("param_req_list", [224, 225]),
                            ("server_id", server_ip),
                            (224, dhushcp_id),
                            (225, session_id)  # Embed the unique session ID
                        ] + fragmented_options + [("end")])
                    )

                    # Debug: Print the DHCP Request packet details
                    print("[DEBUG] DHCP Request Packet:")
                    request.show()

                    print("Sending DHCP Request packet with encrypted message and Session ID")
                    sendp(request, iface=wifi_interface, verbose=False)
                    print("DHCP Request packet sent successfully")

                    return False  # Continue sniffing for DHCP Ack

        return False  # Continue sniffing

    print("Listening for DHCP Offer packets...")
    # Sniff for DHCP Offer packets and handle accordingly
    sniff(
        filter="udp and (port 67 or 68)",
        prn=handle_offer,
        iface=wifi_interface,
        stop_filter=lambda x: False,  # Continue sniffing
        timeout=120
    )

    # Listen for DHCP Ack from the server
    def handle_ack(packet):
        if packet.haslayer(DHCP):
            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt[0], int)}
            msg_type = dhcp_options.get(53)
            print("[DEBUG] Received DHCP Message Type:", msg_type)

            # DHCP Ack has a message type value of 5
            if msg_type == 5 and dhcp_options.get(224) == dhushcp_id and dhcp_options.get(225) == session_id:
                print("Received valid DHCP Ack from server with matching Session ID")

                # Reassemble and decrypt the server's reply
                encrypted_reply_with_checksum = reassemble_message_from_options(packet[DHCP].options)
                if encrypted_reply_with_checksum:
                    try:
                        # Separate the message and checksum
                        encrypted_reply = encrypted_reply_with_checksum[:-32]
                        checksum_received = encrypted_reply_with_checksum[-32:]
                        # Verify checksum
                        if generate_checksum(encrypted_reply) != checksum_received:
                            print("Checksum verification failed! Message integrity compromised.")
                            return False

                        # Decrypt the reply using Client's Private Key
                        decrypted_reply = client_private_key.decrypt(
                            encrypted_reply,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"Received and decrypted reply from Server: {decrypted_reply.decode()}")
                    except Exception as e:
                        print(f"Error during decryption of server's reply: {e}")
                        return False

                    # Prompt the client user to confirm reading the message
                    wait_for_enter()

                    # Send DHCP Release packet and perform cleanup
                    perform_cleanup()

                    return True  # Stop sniffing

        return False  # Continue sniffing

    print("Listening for DHCP Ack packets...")
    # Sniff for DHCP Ack packets and handle accordingly
    sniff(
        filter="udp and (port 67 or 68)",
        prn=handle_ack,
        iface=wifi_interface,
        stop_filter=handle_ack,
        timeout=120
    )

if __name__ == "__main__":
    main()
