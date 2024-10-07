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

- **End-to-End Encryption:** Utilizes Elliptic Curve Cryptography (ECC) for secure message exchange between Initiator and Responder.
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
   - **Initiator:**
     - Generates a unique session ID.
     - Detects and selects the active wireless interface.
     - Generates an ECC key pair (private/public keys).
     - Generates RSA key pair (public/private keys).
     - Embeds its public key, DHushCP-ID (option 224), and session ID (option 225) into the DHCP Discover packet.
     - Sends the DHCP Discover packet and waits for the Responder's public key.
   
   - **Responder:**
     - Listens for DHCP Discover packets with option 224 set to DHushCP-ID.
     - Upon receiving a valid DHCP Discover (option 224 set to DHushCP-ID), extracts the session ID from option 225.
     - Extracts and reassembles the Initiator's public ECC key from the correct DHCP option.
     - Generates its own ECC key pair.
     - Embeds its public key, DHushCP-ID, and the extracted session ID into a DHCP Discover packet.
     - Sends the DHCP Discover packet back to the Initiator.

2. **Message Transmission:**
   - **Initiator:**
     - Receives the Responder's public key from the DHCP Discover packet.
     - Derives the shared AES key using its private ECC key and the Responder's public ECC key.
     - Prompts the user to input a message.
     - Encrypts the message using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted message with the checksum and session ID into a DHCP Discover packet.
     - Fragments and embeds the encrypted message with the checksum and session ID into the DHCP Request packet.
     - Sends the DHCP Discover packet containing the encrypted message.
   
   - **Responder:**
     - Receives the encrypted DHCP Discover packet from the Initiator.
     - Reassembles and decrypts the message using the shared AES key.
     - Displays the decrypted message to the Responder user.
     - Prompts the Responder user to input a reply.
     - Encrypts the reply using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted reply with the checksum and session ID into a DHCP Discover packet.
     - Generates a checksum for the encrypted reply.
     - Fragments and embeds the encrypted reply with the checksum and session ID into the DHCP Ack packet.
     - Sends the DHCP Discover packet containing the encrypted reply.

3. **Finalization:**
   - **Initiator:**
     - Receives the encrypted DHCP Discover packet containing the Responder's reply.
     - Decrypts the reply using the shared AES key.
     - Displays the decrypted reply message to the Initiator user.
     - Upon request, performs cleanup by deleting encryption keys, clearing system logs, and resetting the terminal.
   
   - **Responder:**
     - Receives the DHCP Discover sent by the Initiator.
     - Upon request, performs cleanup by deleting encryption keys, clearing system logs, and resetting the terminal.

## 🕵️ **Example Use Case for DHushCP**

#### **Scenario: Covert Communication in a Public Space**

Imagine a scenario where two individuals (Alice and Bob) need to communicate covertly while being in a public space, such as a coffee shop. They both arrive separately and sit at different tables, appearing to be independent customers. They do not connect to the public Wi-Fi network, but their laptops are within wireless range of each other.

#### **Problem**
Alice and Bob need to exchange a short message without creating any obvious network link or visible ad-hoc connection that could attract attention. Using traditional messaging apps or establishing a direct Wi-Fi connection could be easily detected by anyone monitoring the network.

#### **Solution: Using DHushCP for Covert Communication**

1. **Step 1: Bob Starts the DHushCP Responder**
   - Bob runs the **DHushCP** Responder script on his laptop, listening for a Discover packet from Alice.
   - His Responder listens for DHCP Discover packets that contain a special identifier (DHushCP-ID, option 224) set by **DHushCP**.
   - This ensures that his Responder only responds to legitimate DHushCP Initiator packets and ignores other DHCP traffic.

2. **Step 2: Alice Starts the DHushCP Initiator**
   - Alice runs the **DHushCP** Initiator on her laptop.
   - Her Initiator sends a DHCP Discover packet that contains her public ECC key, along with the DHushCP-ID (option 224) and a unique session ID (option 225).
   - This packet is **broadcast** in the local wireless network range.

3. **Step 3: Key Exchange and Secure Communication**
   - Responder:
     - Receives Alice's DHCP Discover packet.
     - Extracts the session ID and reassembles Alice's public ECC key.
     - Generates its own ECC key pair.
     - Fragments and embeds its public ECC key, DHushCP-ID, and the extracted session ID into a DHCP Discover packet.
     - Sends the DHCP Discover packet.
   
   - Initiator:
     - Receives the Responder's DHCP Discover packet.
     - Extracts and reassembles the Responder's public ECC key.
     - Derives the shared AES key using her private ECC key and the Responder's public ECC key.
     - Prompts the user to input a message (e.g., "Meet at the corner at 2 PM").
     - Encrypts the message using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Fragments and embeds the encrypted message with the checksum and session ID into a DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted message to the Responder.

4. **Step 4: Receiving and Responding to Messages**
   - Responder:
     - Receives the encrypted DHCP Discover packet from Alice.
     - Reassembles and decrypts the message using the shared AES key.
     - Displays the decrypted message to Bob.
     - Prompts Bob to input a reply (e.g., "Understood. See you there.").
     - Encrypts the reply using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Fragments and embeds the encrypted reply with the checksum and session ID into a DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted reply back to Alice.
   
   - Initiator:
     - Receives the encrypted DHCP Discover packet containing Bob's reply.
     - Reassembles and decrypts the reply using the shared AES key.
     - Displays the decrypted reply message to Alice.
     - Performs cleanup by deleting encryption keys, clearing system logs, and resetting the terminal.

#### ⚠️ **One-Time Message Exchange Design**
- **DHushCP is designed for short-form, one-time message exchanges**.
- After each message exchange, the session is terminated, and the ECC keys are securely deleted. If further communication is needed, the process should be restarted from scratch, with **new ECC key pairs** being generated.
- This approach maximizes security by ensuring that each communication session is unique and does not reuse any cryptographic keys.

#### **Why This Setup Is Effective**
- The entire exchange happens within **standard DHCP Discover packets**, blending into regular network traffic.
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