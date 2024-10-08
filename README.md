![DHushCP](docs/DHushCP.png)
# 🛡️ DHushCP: Covert Communication via DHCP 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
[![Stable Release](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/0SINTr/DHushCP/releases/tag/v0.2.0)
[![Last Commit](https://img.shields.io/github/last-commit/0SINTr/DHushCP)](https://github.com/0SINTr/DHushCP/commits/main/)

## 📖 Table of Contents

- [🛡️ DHushCP: Covert Communication via DHCP](#🛡️-dhushcp-secure-covert-communication-via-dhcp)
  - [🔍 Overview](#-overview)
  - [🚀 Features](#-features)
  - [🔄 Communication Flow](#-communication-flow)
  - [🕵️ Example Use Case](#%EF%B8%8F-example-use-case-for-dhushcp)
  - [🧮 Available Message Space](#-available-message-space-calculation)
  - [🖥️ System Requirements](#%EF%B8%8F-system-requirements)
  - [🛠️ Installation & Setup](#%EF%B8%8F-installation--setup)
  - [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  - [📜 License](#-license)

## 🔍 Overview

**DHushCP** is a Linux tool designed to facilitate **secure covert wireless communication** between two parties - an Initiator and a Responder - using standard **DHCP (Dynamic Host Configuration Protocol)** packets. 

**DHushCP** utilizes principles of **network steganography** by embedding encrypted messages within DHCP protocol fields that are not commonly inspected, such as Options 224, 225, 226. 

By inserting cryptographic elements within unused DHCP options, **DHushCP** enables hidden message exchanges outside existing network infrastructures without raising suspicion.

🍀 **NOTE:** This is an ongoing **reasearch project** for educational purposes rather than a full-fledged production-ready tool, so treat it accordingly.

### 💬 TLDR; DHushCP and Steganography
**Steganography** refers to hiding secrets in plain sight, and **DHushCP** does this two-fold:

- **It hides an encrypted message sent from A to B in an unused DHCP option field.**
  - **DHushCP** doesn't require the two hosts to route their communication through a specific network, access point or centralized app. By using plain DHCP Discover packets, the communication blends into normal traffic. Although the messages are **fully encrypted** back and forth between the two hosts, it is advisable to keep a **low number** of message exchanges per session, so that the amount of Discover packets being sent by the hosts doesn't raise any eyebrows. See the **Use Case** below for an example.
- **It uses only DHCP Discover packets to communicate the keys and messages.**
  - At first, the use of **DHCP Discover** packets might seem strange, due to the broadcast nature of these packets. However, this obfuscates the **DHushCP** communication even more compared to even the first iteration of **DHushCP** where the two hosts were actually performing a complete *Discover - Offer - Request - Ack* sequence that was hiding the message exchange. By using DHCP Discover packets only, **DHushCP** is now stealthier since no rogue DHCP server activity can be detected by a sniffer.

## 🚀 Features

- **End-to-End Encryption:** Utilizes Elliptic Curve Cryptography (ECC) for secure message exchange between **Initiator** and **Responder**.
- **Message Embedding:** Efficiently embeds keys and messages to fit within DHCP option constraints, ensuring seamless transmission.
- **Checksum Verification:** Implements SHA-256 checksums to ensure data integrity and authenticity.
- **Session Management:** Generates unique session IDs to maintain communication integrity and prevent message mixing.
- **Automated Cleanup:** Automatically handles session termination and cleans up sensitive data upon completion.
- **User-Friendly Interface:** Interactive prompts guide users through message input and confirmation steps.

## 🔄 Communication Flow

1. **Initial Exchange:**
   - **Initiator:**
     - Generates a unique session ID.
     - Detects and selects the active wireless interface.
     - Generates an ECC key pair (private/public keys).
     - Embeds its public key, the DHUSHCP_ID (option 224), and session ID (option 225) into the DHCP Discover packet.
     - Sends the DHCP Discover packet and waits for the Responder's public key.
   
   - **Responder:**
     - Listens for DHCP Discover packets with option 224 set to DHUSHCP_ID.
     - Upon receiving a valid DHCP Discover (option 224 set to DHUSHCP_ID), extracts the session ID from option 225.
     - Extracts and reassembles the Initiator's public ECC key from the correct DHCP option.
     - Generates its own ECC key pair.
     - Embeds its public key, the DHUSHCP_ID, and the extracted session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover and waits for Initiator's message.

2. **Message Transmission:**
   - **Initiator:**
     - Receives the Responder's public key from the DHCP Discover packet.
     - Derives the shared AES key using its private ECC key and the Responder's public ECC key.
     - Prompts the user to input a message to send to the Responder.
     - Encrypts the message using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted message with the checksum and session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted message.
   
   - **Responder:**
     - Receives the encrypted DHCP Discover packet from the Initiator.
     - Extracts and decrypts the message using the shared AES key.
     - Displays the decrypted message to the Responder user.
     - Prompts the Responder user to input a reply message.
     - Encrypts the reply using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted reply with the checksum and session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted reply.

3. **Finalization:**
   - **Initiator:**
     - Receives the encrypted DHCP Discover packet containing the Responder's reply.
     - Decrypts the reply using the shared AES key.
     - Displays the decrypted reply message to the Initiator user.
     - Upon request (`Ctrl+C`), performs cleanup by deleting encryption keys, clearing system logs (syslog, auth), and resetting the terminal.
   
   - **Responder:**
     - Upon request (`Ctrl+C`), performs cleanup by deleting encryption keys, clearing system logs (syslog, auth), and resetting the terminal.

## 🕵️ **Example Use Case for DHushCP**

#### **Scenario: Covert Communication in a Public Space**

Imagine a scenario where two individuals (Alice and Bob) need to communicate covertly while being in a public space, such as a coffee shop. 

They both arrive separately and sit at different tables, appearing to be independent customers. They do not connect to the public Wi-Fi network, but their laptops are within wireless range of each other.

#### **Problem**
Alice and Bob need to exchange a crucial message without using any messaging app, or creating any obvious network link or visible ad-hoc connection that could attract attention and be easily detected by anyone monitoring the network.

🔴 **Prerequisites:**
- Prior to their arrival, Alice and Bob **should already know** the DHUSHCP_ID they're going to use *and* who's going to run the **Initiator** and the **Responder**, respectively.
- They ensure that the DHUSHCP_ID is communicated **securely** between them before initiating the communication. Use a strong, unpredictable identifier (e.g. `n1c3_w3ath3r_eh?`).

#### **Solution: Using DHushCP for Covert Communication**

1. **Step 1: Bob Starts the DHushCP Responder**
   - Bob runs the **DHushCP** Responder script on his laptop, listening for a Discover packet from Alice.
   - His Responder listens for DHCP Discover packets that contain the identifier (DHUSHCP_ID, option 224) set with **--id DHUSHCP_ID**.
   - This ensures that his Responder only responds to legitimate **DHushCP** Initiator packets and ignores other DHCP traffic.

2. **Step 2: Alice Starts the DHushCP Initiator**
   - Alice runs the **DHushCP** Initiator on her laptop, with the same value for **--id DHUSHCP_ID**.
   - Her Initiator sends a DHCP Discover packet that contains her public ECC key, along with the DHUSHCP_ID (option 224) and a unique session ID (option 225).
   - This packet is **broadcast** in the local wireless network range.

3. **Step 3: Key Exchange and Secure Communication**
   - **Responder**:
     - Receives Alice's DHCP Discover packet.
     - Extracts the session ID and reassembles Alice's public ECC key.
     - Generates its own ECC key pair.
     - Embeds its public ECC key, the DHUSHCP_ID, and the extracted session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover packet.
   
   - **Initiator**:
     - Receives the Responder's DHCP Discover packet.
     - Extracts and reassembles the Responder's public ECC key.
     - Derives the shared AES key using her private ECC key and the Responder's public ECC key.
     - Prompts the user to input a message (e.g., "Meet at the corner at 2 PM").
     - Encrypts the message using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted message with the checksum and session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted message to the Responder.

4. **Step 4: Receiving and Responding to Messages**
   - **Responder**:
     - Receives the encrypted DHCP Discover packet from Alice.
     - Decrypts the message using the shared AES key.
     - Displays the decrypted message to Bob.
     - Prompts Bob to input a reply (e.g., "Understood. See you there.").
     - Encrypts the reply using the shared AES key with AES-GCM and appends a SHA-256 checksum.
     - Embeds the encrypted reply with the checksum and session ID into a new DHCP Discover packet.
     - Sends the DHCP Discover packet containing the encrypted reply back to Alice.
     - Upon request, performs cleanup by deleting encryption keys, clearing system logs, and resetting the terminal.
   
   - **Initiator**:
     - Receives the encrypted DHCP Discover packet containing Bob's reply.
     - Decrypts the reply using the shared AES key.
     - Displays the decrypted reply message to Alice.
     - Upon request, performs cleanup by deleting encryption keys, clearing system logs, and resetting the terminal.

#### **Why This Setup Is Effective**
- The entire exchange happens within **standard DHCP Discover packets**, blending into regular network traffic.
- There is no centralized app or devices, **no visible Wi-Fi connection** or direct link between Alice and Bob.
- After the communication ends, both laptops securely delete the ECC keys, system logs and clear the terminal.
- Useful when Alice and Bob want to avoid suspicion and keep their presence discreet while exchanging critical information.

#### **Additional Recommendation**
- Prior to running the Initiator or the Responder, disable shell history using `set +o history`, then enable it when the communication is ended using `set -o history`.

### 🧮 **Available Message Space Calculation**

- **Total Usable Space In DHCP Option:** 255 bytes
- **AES-GCM Encryption Overhead (Nonce):** 12 bytes
- **AES-GCM Encryption Overhead (AuthTag):** 16 bytes
- **SHA-256 Checksum Size:** 32 bytes
- **Available Message Space:** 255 bytes - 60 bytes = **195 bytes**

**NOTE!** The current limit for messages is **100 characters**.

## 🖥️ System Requirements

- **Operating System:** Linux-based systems (e.g., Ubuntu, Debian, Fedora)
  - Latest release thoroughly tested and functional on **Ubuntu 24.04**.
- **Python Version:** Python 3.8 or higher
- **Dependencies:**
  - `scapy` for packet crafting and sniffing
  - `cryptography` for ECC encryption and checksum generation
- **Privileges:** Root or sudo access to send and receive DHCP packets
- **Network Interface:** Active wireless interface in UP state

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/0SINTr/DHushCP.git
   cd DHushCP
   ```

2. **Install Dependencies:** Ensure you have Python 3.8 or higher installed. Then, install the required Python packages:
   ```bash
   sudo apt install python3-scapy
   sudo apt install python3-cryptography
   ```

3. **Configure Wireless Interface:**

Ensure that your wireless interface is active and in the UP state.
**DHushCP** will automatically detect and prompt you to select the active interface if multiple are detected.

4. **Run the Scripts:** Both Initiator and Responder scripts require root privileges to send and sniff DHCP packets. You can run the scripts using `sudo`:

**Responder:**
```
   set +o history
   sudo python3 responder.py --id DHUSHCP_ID
```

**Initiator:**
```
   set +o history
   sudo python3 responder.py --id DHUSHCP_ID
```

Follow the on-screen prompts on the **Initiator** to initiate and manage the communication session. Make sure the **Responder** is already listening.

## ⚠️ Disclaimer
**DHushCP** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **DHushCP** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
No license is provided for this software, therefore the work is under exclusive copyright by default. Read more about what this means [here](https://choosealicense.com/no-permission/).