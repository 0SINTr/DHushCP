# SERVER CODE:
# Copyright (C) 2024-2025 0SINTr (https://github.com/0SINTr)

import subprocess
import os
import sys
from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import math

# ==============================
# Utility Functions
# ==============================

def generate_session_id():
    """Generate a unique session identifier."""
    return str(uuid.uuid4()).encode('utf-8')  # Bytes for embedding

def get_wireless_interface():
    """Detect and select the active wireless interface."""
    try:
        print("[DEBUG] Detecting wireless interfaces...")
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
        print(f"[DEBUG] Checking if interface {selected_interface} is UP...")
        state_check = subprocess.run(['ip', 'link', 'show', selected_interface], capture_output=True, text=True)
        if "state UP" in state_check.stdout:
            print(f"Interface {selected_interface} is UP.")
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
    else:
        print("[DEBUG] Script is running with sudo privileges.")

def check_and_release_ip(interface):
    """Release any existing IP address on the interface to avoid conflicts."""
    try:
        print(f"[DEBUG] Checking existing IP addresses on {interface}...")
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
        if "inet " in result.stdout:
            print(f"Warning: Interface {interface} has an IP address assigned.")
            print("Releasing the IP address to avoid conflicts...")
            subprocess.run(['ip', 'addr', 'flush', 'dev', interface], capture_output=True, text=True)
            # Verify if IP was successfully flushed
            print("[DEBUG] Verifying IP release...")
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

def perform_cleanup(server_ip, server_mac, wifi_interface):
    """Perform cleanup after reading the message."""
    global server_private_key, client_public_key

    print("[DEBUG] Starting cleanup process...")
    # Send DHCP Release packet
    try:
        if server_ip:
            print("[DEBUG] Preparing DHCP Release packet...")
            release_packet = (
                Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=server_mac.replace(":", ""), xid=RandInt(), flags=0x8000) /
                DHCP(options=[
                    ("message-type", "release"),
                    ("server_id", server_ip),
                    ("end")
                ])
            )
            sendp(release_packet, iface=wifi_interface, verbose=False)
            print("DHCP Release packet sent successfully.")
        else:
            print("Skipping DHCP Release as server IP is not available.")
    except Exception as e:
        print(f"Failed to send DHCP Release packet: {e}")

    # Clear RSA keys from memory
    try:
        del server_private_key
        del client_public_key
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
    global server_public_key, server_ip, session_id, server_private_key, client_public_key, server_ip, client_mac, wifi_interface

    # Initial setup
    check_sudo()
    wifi_interface = get_wireless_interface()
    check_and_release_ip(wifi_interface)

    # Generate RSA Keys for the Server
    print("[DEBUG] Generating RSA key pair for the server...")
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_public_key = server_private_key.public_key()
    server_public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("[DEBUG] RSA key pair generated.")

    # Placeholder for server's IP address
    server_ip = "192.168.68.1"  # Replace with your server's actual IP

    # Get server's MAC address
    server_mac = get_if_hwaddr(wifi_interface)
    print(f"[DEBUG] Server MAC address: {server_mac}")

    # Listen for DHCP Discover packets first
    def handle_discover(packet):
        global client_public_key, client_ip, session_id

        if packet.haslayer(DHCP):
            print("[DEBUG] DHCP Packet Received.")
            for opt in packet[DHCP].options:
                print(f"Option: {opt}")

            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt[0], int)}

            msg_type = dhcp_options.get(53)
            print(f"[DEBUG] Received DHCP Message Type: {msg_type}")

            # DHCP Discover has a message type value of 1
            if msg_type == 1 and dhcp_options.get(224) == b"DHushCP-ID":
                print("[DEBUG] DHCP Discover with DHushCP-ID detected.")
                session_id = dhcp_options.get(225)
                if session_id is None:
                    print("Session ID (option 225) not found in DHCP Discover. Ignoring packet.")
                    return  # Continue sniffing

                print(f"[DEBUG] Session ID: {session_id}")

                # Extract client's MAC address
                client_mac = packet[Ether].src
                print(f"[DEBUG] Client MAC address: {client_mac}")

                # Reassemble and process the client's public key
                client_public_key_pem = reassemble_message_from_options(packet[DHCP].options)
                if client_public_key_pem:
                    try:
                        # Load the client's public key
                        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
                        client_ip = packet[IP].src  # Capture client's IP address for future use
                        print(f"[DEBUG] Received and reassembled Client's Public Key from IP: {client_ip}")
                    except Exception as e:
                        print(f"Error reassembling Client's Public Key: {e}")
                        return  # Continue sniffing if reassembly fails

                    # Create and send a DHCP Offer packet with the server's public key and session ID
                    server_public_key_with_checksum = server_public_key_pem + generate_checksum(server_public_key_pem)
                    server_public_key_fragments = fragment_message_with_sequence(server_public_key_with_checksum, chunk_size=50)
                    server_fragmented_options = embed_fragments_into_dhcp_options(server_public_key_fragments, option_list=[150, 151, 152, 153])

                    offer = (
                        Ether(src=server_mac, dst=client_mac) /
                        IP(src=server_ip, dst="255.255.255.255") /  # Broadcast to client
                        UDP(sport=67, dport=68) /
                        BOOTP(op=2, yiaddr=server_ip, siaddr=server_ip, chaddr=client_mac.replace(":", ""), xid=packet[BOOTP].xid, flags=0x8000) /
                        DHCP(options=[
                            ("message-type", "offer"),
                            ("param_req_list", [224, 225]),  # Requesting custom options 224 and 225
                            (224, b"DHushCP-ID"),
                            (225, session_id),  # Embed the received session ID
                        ] + server_fragmented_options + [("end")])
                    )

                    print("[DEBUG] Sending DHCP Offer packet with fragmented Server's Public Key and Session ID.")
                    sendp(offer, iface=wifi_interface, verbose=False)
                    print("DHCP Offer sent successfully.")
                else:
                    print("Failed to reassemble Client's Public Key. Ignoring packet.")

    print("Listening for DHCP Discover packets...")
    # Sniff for DHCP Discover packets and handle accordingly
    sniff(
        filter="udp and (port 67 or 68)",
        prn=handle_discover,
        iface=wifi_interface,
        store=0,
        timeout=120
    )

    # After sending DHCP Offer, listen for DHCP Request packets
    def handle_request(packet):
        global client_public_key, client_ip, session_id

        if packet.haslayer(DHCP):
            print("[DEBUG] DHCP Packet Received.")
            for opt in packet[DHCP].options:
                print(f"Option: {opt}")

            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt[0], int)}

            msg_type = dhcp_options.get(53)
            print(f"[DEBUG] Received DHCP Message Type: {msg_type}")

            # DHCP Request has a message type value of 3
            if msg_type == 3 and dhcp_options.get(224) == b"DHushCP-ID" and dhcp_options.get(225) == session_id:
                print("[DEBUG] DHCP Request with DHushCP-ID and matching Session ID detected.")

                # Reassemble and decrypt the client's message
                encrypted_message_with_checksum = reassemble_message_from_options(packet[DHCP].options)
                if encrypted_message_with_checksum:
                    try:
                        # Separate message and checksum
                        encrypted_message = encrypted_message_with_checksum[:-32]
                        checksum = encrypted_message_with_checksum[-32:]
                        # Verify checksum
                        if generate_checksum(encrypted_message) != checksum:
                            print("Checksum verification failed! Message integrity compromised.")
                            return  # Continue sniffing

                        # Decrypt the message using server's private key
                        decrypted_message = server_private_key.decrypt(
                            encrypted_message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"Received and decrypted message from Client: {decrypted_message.decode()}")
                    except Exception as e:
                        print(f"Error during decryption of client's message: {e}")
                        return  # Continue sniffing if decryption fails

                    # Prompt the server user to confirm reading the message
                    wait_for_enter()

                    # Prompt the server user to enter a reply message
                    user_reply = get_complete_message("Enter the reply message to send to the client")

                    # Check the byte length of the input message
                    message_byte_length = len(user_reply.encode('utf-8'))
                    if message_byte_length > 700:
                        print(f"Reply message is too long! The input is {message_byte_length} bytes, but the maximum is 700 bytes.")
                        sys.exit(1)

                    print(f"Reply message accepted. Length in bytes: {message_byte_length} (Max: 700 bytes)")

                    # Encrypt reply using Client's Public Key
                    try:
                        encrypted_reply = client_public_key.encrypt(
                            user_reply.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print("[DEBUG] Encrypted the reply message.")
                    except Exception as e:
                        print(f"Error during encryption: {e}")
                        sys.exit(1)

                    # Generate checksum for the encrypted reply
                    checksum = generate_checksum(encrypted_reply)
                    encrypted_reply_with_checksum = encrypted_reply + checksum

                    # Fragment the encrypted reply and embed in DHCP Ack
                    encrypted_fragments = fragment_message_with_sequence(encrypted_reply_with_checksum, chunk_size=251)
                    fragmented_options = embed_fragments_into_dhcp_options(encrypted_fragments, option_list=[150, 151, 152, 153])

                    # Create DHCP Ack packet with encrypted reply and session ID
                    ack = (
                        Ether(src=server_mac, dst=packet[Ether].src) /
                        IP(src=server_ip, dst="255.255.255.255") /
                        UDP(sport=67, dport=68) /
                        BOOTP(op=2, yiaddr=server_ip, siaddr=server_ip, chaddr=packet[BOOTP].chaddr, xid=packet[BOOTP].xid, flags=0x8000) /
                        DHCP(options=[
                            ("message-type", "ack"),
                            ("param_req_list", [224, 225]),
                            ("server_id", server_ip),
                            (224, b"DHushCP-ID"),
                            (225, session_id)  # Include the received session ID in the ACK
                        ] + fragmented_options + [("end")])
                    )

                    print("[DEBUG] Sending DHCP Ack packet with encrypted reply message and Session ID.")
                    sendp(ack, iface=wifi_interface, verbose=False)
                    print("Reply message sent successfully.")

    print("Listening for DHCP Request packets...")
    # Sniff for DHCP Request packets and handle accordingly
    sniff(
        filter="udp and (port 67 or 68)",
        prn=handle_request,
        iface=wifi_interface,
        store=0,
        timeout=120
    )

    # After sending DHCP Ack, listen for DHCP Release packets
    def handle_release(packet):
        if packet.haslayer(DHCP):
            print("[DEBUG] DHCP Packet Received.")
            for opt in packet[DHCP].options:
                print(f"Option: {opt}")

            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt[0], int)}

            msg_type = dhcp_options.get(53)
            print(f"[DEBUG] Received DHCP Message Type: {msg_type}")

            # DHCP Release has a message type value of 7
            if msg_type == 7 and dhcp_options.get(225) == session_id:
                print("[DEBUG] Received DHCP Release with matching Session ID.")
                perform_cleanup(server_ip, server_mac, wifi_interface)
                return True  # Stop sniffing
            else:
                print(f"[DEBUG] Received DHCP Message Type {msg_type} does not match 'release' or Session ID mismatch.")

        return False  # Continue sniffing

    print("Listening for DHCP Release packets...")
    # Sniff for DHCP Release packets and handle accordingly
    sniff(
        filter="udp and (port 67 or 68)",
        prn=handle_release,
        iface=wifi_interface,
        store=0,
        stop_filter=handle_release,
        timeout=120
    )

if __name__ == "__main__":
    main()
