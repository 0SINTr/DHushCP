# 🛡️ DHushCP: Secure Covert Communication via DHCP 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
[![Last Commit](https://img.shields.io/github/last-commit/0SINTr/DHushCP)](https://github.com/0SINTr/DHushCP/commits/main/)

## 📖 Table of Contents

- [🛡️ DHushCP: Secure Covert Communication via DHCP](#🛡️-dhushcp-secure-covert-communication-via-dhcp)
  - [🔍 Overview](#-overview)
  - [🚀 Features](#-features)
  - [📈 Advantages](#-advantages)
  - [🔄 Communication Flow](#-communication-flow)
  - [🕵️ Example Use Case for DHushCP](#%EF%B8%8F-example-use-case-for-dhushcp)
  - [🧮 Available Message Space Calculation](#-available-message-space-calculation)
  - [🖥️ System Requirements](#%EF%B8%8F-system-requirements)
  - [🛠️ Installation & Setup](#%EF%B8%8F-installation--setup)
  - [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  - [📜 License](#-license)

## 🔍 Overview

**DHushCP** is a tool designed to facilitate **secure covert communication** between two parties - a client and server - using standard **DHCP (Dynamic Host Configuration Protocol)** packets. **DHushCP** utilizes principles of **network steganography** by embedding encrypted messages within protocol fields that are not commonly inspected. By inserting cryptographic elements within unused DHCP options, **DHushCP** enables hidden message exchanges over existing network infrastructures without raising suspicion.

## 🚀 Features

- **End-to-End Encryption:** Utilizes RSA asymmetric encryption to secure messages between client and server.
- **Session Management:** Generates unique session IDs to maintain communication integrity and prevent message mixing.
- **Message Fragmentation:** Efficiently fragments messages to fit within DHCP option constraints, ensuring seamless transmission.
- **Automated Cleanup:** Automatically handles session termination and cleans up sensitive data upon completion.
- **User-Friendly Interface:** Interactive prompts guide users through message input and confirmation steps.
- **Checksum Verification:** Implements SHA-256 checksums to ensure data integrity and authenticity.

## 📈 Advantages

- **Stealthy Communication:** Leverages the common DHCP protocol to facilitate hidden message exchanges, reducing the likelihood of detection.
- **No Additional Infrastructure:** Operates outside existing network setups without the need for specialized hardware or software.
- **Flexible Integration:** Easily integrates into various network environments, making it adaptable for different use cases.
- **User Control:** Empowers users with interactive prompts, ensuring that communication is deliberate and controlled.
- **Robust Security:** Combines multiple security mechanisms to safeguard data against interception and unauthorized access.

## 🔄 Communication Flow

1. **Initial Exchange:**
   - **Client:**
     - Generates a unique session ID.
     - Detects and selects the active wireless interface.
     - Releases any existing IP address on the interface.
     - Generates RSA key pair (public/private keys).
     - Fragments and embeds its public key, DHushCP-ID (option 224), and session ID (option 225) into the DHCP Discover packet.
     - Sends the DHCP Discover packet and waits for a legitimate DHCP Offer from the server.
   
   - **Server:**
     - Listens for DHCP Discover packets with option 224 set to DHushCP-ID.
     - Upon receiving a valid DHCP Discover (option 224 set to DHushCP-ID), extracts the session ID from option 225.
     - Extracts and reassembles the client's public RSA key from the DHCP options.
     - Generates its own RSA key pair.
     - Fragments and embeds its public key, DHushCP-ID, and the extracted session ID into the DHCP Offer packet.
     - Sends the DHCP Offer packet back to the client and waits for a legitimate DHCP Request.

2. **Message Transmission:**
   - **Client:**
     - Receives the DHCP Offer from the server.
     - Extracts and reassembles the server's public RSA key from DHCP options.
     - Prompts the user to input a message.
     - Encrypts the message using the server's public RSA key.
     - Generates a checksum for the encrypted message.
     - Fragments and embeds the encrypted message with the checksum and session ID into the DHCP Request packet.
     - Sends the DHCP Request packet and waits for a DHCP Ack from the server.
   
   - **Server:**
     - Receives and validates the DHCP Request packet by checking options 224 and 225.
     - Reassembles and decrypts the client's message using its own private RSA key.
     - Displays the decrypted message to the server user.
     - Prompts the server user to press Enter to confirm reading the message.
     - Prompts the server user to input a reply.
     - Encrypts the reply using the client's public RSA key.
     - Generates a checksum for the encrypted reply.
     - Fragments and embeds the encrypted reply with the checksum and session ID into the DHCP Ack packet.
     - Sends a DHCP Ack packet back to the client.
     - Waits for a DHCP Release packet from the client.

3. **Finalization:**
   - **Client:**
     - Receives the DHCP Ack from the server.
     - Reassembles and decrypts the server's reply using its private RSA key.
     - Displays the message to the user.
     - Waits for the user to press Enter to confirm reading the message.
     - Sends a DHCP Release packet and performs cleanup (deleting RSA keys, clearing logs, clearing the screen etc.).
   
   - **Server:**
     - Receives the DHCP Release packet.
     - Automatically performs cleanup by taking the same steps as the client and terminates the session.

## 🕵️ **Example Use Case for DHushCP**

#### **Scenario: Covert Communication in a Public Space**

Imagine a scenario where two individuals (Alice and Bob) need to communicate covertly while being in a public space, such as a coffee shop. They both arrive separately and sit at different tables, appearing to be independent customers. They do not connect to the public Wi-Fi network, but their laptops are within wireless range of each other.

#### **Problem**
Alice and Bob need to exchange a short message without creating any obvious network link or visible ad-hoc connection that could attract attention. Using traditional messaging apps or establishing a direct Wi-Fi connection could be easily detected by anyone monitoring the network.

#### **Solution: Using DHushCP for Covert Communication**

1. **Step 1: Bob Starts the DHushCP Server**
   - Bob runs the **DHushCP** server on his laptop.
   - His server listens for DHCP Discover packets that contain a special identifier (custom DHCP option 224) set by **DHushCP**.
   - This ensures that his server only responds to legitimate **DHushCP** client packets and ignores other DHCP traffic.

2. **Step 2: Alice Starts the DHushCP Client**
   - Alice runs the **DHushCP** client on her laptop.
   - Her client sends a DHCP Discover packet that contains her public RSA key, embedded and fragmented into multiple DHCP options, along with the DHushCP-ID (option 224) and a unique session ID (option 225).
   - This packet is **broadcast** in the local wireless network range.

3. **Step 3: Server Responds to Client's DHCP Discover**
   - Upon receiving Alice's DHCP Discover packet, Bob’s server verifies the DHushCP-ID and session ID.
   - The server then sends back a DHCP Offer packet containing its own public RSA key, embedded and fragmented across multiple DHCP options, along with the same session ID.

4. **Step 4: Key Exchange and Secure Message Transmission**
   - Once Alice receives the DHCP Offer from Bob, both have securely exchanged public keys.
   - Alice inputs a short covert message (e.g., **"Meet at the corner at 2 PM"**) and her client encrypts the message using Bob’s public key.
   - The encrypted message is fragmented into multiple DHCP options and sent to Bob in a DHCP Request packet.

5. **Step 5: Server Receives and Decrypts the Message**
   - Bob’s server receives the DHCP Request, reassembles the fragments, and decrypts the message using his private RSA key.
   - The decrypted message is displayed on his terminal.
   - Bob then inputs a covert response (e.g., **"Understood. See you there."**) and encrypts it using Alice’s public key.
   - The encrypted reply is fragmented into multiple DHCP options and sent to Alice in a DHCP Ack packet.

6. **Step 6: Client Receives and Decrypts the Reply**
   - Alice’s client receives the DHCP Ack, reassembles the fragments, and decrypts the reply using her private RSA key.
   - The decrypted reply message is displayed to her.
   - Both Alice and Bob perform cleanup by deleting the exchanged RSA keys and clearing any sensitive logs or data from their terminals.

#### ⚠️ **One-Time Message Exchange Design**
- **DHushCP is designed for short-form, one-time message exchanges**. It supports a single message from the client to the server, followed by a response from the server back to the client.
- After each message exchange, the session is terminated, and the RSA keys are securely deleted. If further communication is needed, the process should be restarted from scratch, with **new RSA key pairs** being generated.
- This approach maximizes security by ensuring that each communication session is unique and does not reuse any cryptographic keys.

#### **Why This Setup Is Effective**
- The entire exchange happens within **standard DHCP packets**, blending into regular network traffic.
- There is **no visible Wi-Fi connection** or direct link between Alice and Bob.
- After the communication ends, both laptops securely delete the exchanged RSA keys and clear the terminal, leaving no traces behind.
- This approach is useful in scenarios where Alice and Bob want to avoid suspicion and keep their presence discreet while exchanging critical information.

### 🧮 **Available Message Space Calculation**

- **Total Usable Space Across 4 DHCP Options:** 1,004 bytes
- **RSA Encryption Overhead (4 blocks):** 1,024 bytes
- **Plaintext Capacity (4 blocks × 190 bytes):** 760 bytes
- **Checksum Size:** 32 bytes
- **Available Message Space:** 760 bytes - 32 bytes = **728 bytes**

As a result, the current limit for messages is **500 characters**.

## 🖥️ System Requirements

- **Operating System:** Linux-based systems (e.g., Ubuntu, Debian, Fedora)
- **Python Version:** Python 3.8 or higher
- **Dependencies:**
  - `scapy` for packet crafting and sniffing
  - `cryptography` for RSA encryption and checksum generation
- **Privileges:** Root or sudo access to send and receive DHCP packets
- **Network Interface:** Active wireless interface in UP state

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/DHushCP.git
   cd DHushCP
   ```

2. **Install Dependencies:** Ensure you have Python 3.8 or higher installed. Then, install the required Python packages:
   ```bash
   sudo apt install python3-scapy
   sudo apt install python3-cryptography
   ```

3. **Configure Wireless Interface:**

Ensure that your wireless interface is active and in the UP state.
The scripts will automatically detect and prompt you to select the active interface if multiple are detected.

4. **Run the Scripts:** Both client and server scripts require root privileges to send and sniff DHCP packets. You can run the scripts using `sudo`:

**Server:**
`sudo python3 server.py`

**Client:**
`sudo python3 client.py`

Follow the on-screen prompts to initiate and manage the communication session.

## ⚠️ Disclaimer
**DHushCP** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **DHushCP** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
No license is provided for this software, therefore the work is under exclusive copyright by default. Read more about what this means [here](https://choosealicense.com/no-permission/).