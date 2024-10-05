# 🛡️ DHushCP: Secure Covert Communication via DHCP 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![GitHub Issues](https://img.shields.io/github/issues/yourusername/DHushCP.svg)
![GitHub Forks](https://img.shields.io/github/forks/yourusername/DHushCP.svg)
![GitHub Stars](https://img.shields.io/github/stars/yourusername/DHushCP.svg)

## 📖 Table of Contents

- [🛡️ DHushCP: Secure Covert Communication via DHCP](#🛡️-dhushcp-secure-covert-communication-via-dhcp)
  - [🔍 Overview](#🔍-overview)
  - [🚀 Features](#🚀-features)
  - [🔐 Security Highlights](#🔐-security-highlights)
  - [📈 Advantages](#📈-advantages)
  - [🔄 Communication Flow](#🔄-communication-flow)
  - [💡 Real-Life Use Case](#💡-real-life-use-case)
  - [🖥️ System Requirements](#🖥️-system-requirements)
  - [🛠️ Installation & Setup](#🛠️-installation--setup)
  - [📚 Usage](#📚-usage)
  - [⚠️ Disclaimer](#⚠️-disclaimer)
  - [🤝 Contributing](#🤝-contributing)
  - [📜 License](#📜-license)

## 🔍 Overview

**DHushCP** is a sophisticated framework designed to facilitate **secure covert communication** between a client and server using standard **DHCP (Dynamic Host Configuration Protocol)** packets. By embedding cryptographic elements within DHCP options, DHushCP enables hidden message exchanges over existing network infrastructures without raising suspicion.

## 🚀 Features

- **End-to-End Encryption:** Utilizes RSA asymmetric encryption to secure messages between client and server.
- **Session Management:** Generates unique session IDs to maintain communication integrity and prevent message mixing.
- **Message Fragmentation:** Efficiently fragments messages to fit within DHCP option constraints, ensuring seamless transmission.
- **Automated Cleanup:** Automatically handles session termination and cleans up sensitive data upon completion.
- **User-Friendly Interface:** Interactive prompts guide users through message input and confirmation steps.
- **Checksum Verification:** Implements SHA-256 checksums to ensure data integrity and authenticity.

## 🔐 Security Highlights

- **Asymmetric Cryptography:** Ensures that only the intended recipient can decrypt the messages using their private key.
- **Checksum Validation:** Protects against data tampering and corruption by verifying message integrity.
- **Automated Key Management:** Generates and manages RSA keys securely within the scripts, minimizing exposure.
- **Session Isolation:** Unique session IDs prevent unauthorized access and maintain communication boundaries.
- **Secure Cleanup:** Removes sensitive information from memory and attempts to clear system logs post-session.

## 📈 Advantages

- **Stealthy Communication:** Leverages common network protocols (DHCP) to facilitate hidden message exchanges, reducing the likelihood of detection.
- **No Additional Infrastructure:** Operates over existing network setups without the need for specialized hardware or software.
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
     - Sends a DHCP Discover packet embedding its public key, a DHushCP-ID (option 224), and the session ID (option 225).
   
   - **Server:**
     - Receives the DHCP Discover packet.
     - Extracts and reassembles the client's public key.
     - Generates its own RSA key pair.
     - Sends a DHCP Offer packet embedding its public key, DHushCP-ID, and the same session ID.

2. **Message Transmission:**
   - **Client:**
     - Receives the DHCP Offer.
     - Prompts the user to input a message.
     - Encrypts the message using the server's public key.
     - Fragments the encrypted message and embeds it across DHCP options.
     - Sends a DHCP Request packet with the encrypted message and session ID.
   
   - **Server:**
     - Receives the DHCP Request.
     - Reassembles and decrypts the client's message using its private key.
     - Displays the message to the server user.
     - Prompts the server user to press Enter to confirm reading the message.
     - Prompts the server user to input a reply.
     - Encrypts the reply using the client's public key.
     - Fragments the encrypted reply and embeds it across DHCP options.
     - Sends a DHCP Ack packet with the encrypted reply and session ID.

3. **Finalization:**
   - **Client:**
     - Receives the DHCP Ack.
     - Reassembles and decrypts the server's reply using its private key.
     - Displays the message to the user.
     - Waits for the user to press Enter to confirm reading the message.
     - Sends a DHCP Release packet and performs cleanup.
   
   - **Server:**
     - Receives the DHCP Release packet.
     - Automatically performs cleanup, removing sensitive data and terminating the session.

## 💡 Real-Life Use Case

**Scenario:** A journalist needs to securely communicate sensitive information to their source without drawing attention to their communication channels. Utilizing **DHushCP**, both parties can exchange encrypted messages over standard DHCP traffic within their local network. This method ensures that their communication remains hidden within normal network operations, protecting the confidentiality of their interactions from potential surveillance or interception.

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
   pip install scapy cryptography
   ```

3. **Grant Necessary Permissions:** Both client and server scripts require root privileges to send and sniff DHCP packets. You can run the scripts using `sudo`:
   ```bash
   sudo python3 client.py
   sudo python3 server.py
   ```

4. **Configure Wireless Interface:**

Ensure that your wireless interface is active and in the UP state.
The scripts will automatically detect and prompt you to select the active interface if multiple are detected.

5. **Run the Scripts:**

**Server:**
`sudo python3 server.py`

**Client:**
`sudo python3 client.py`

Follow the on-screen prompts to initiate and manage the communication session.

## 📚 Usage

1. **Start the Server:**

- Run the server script on the intended host.
- The server will listen for DHCP Discover packets from the client.
- Upon receiving a DHCP Discover, the server will send a DHCP Offer embedding its public key and session ID.

2. **Initiate Communication from the Client:**

- Run the client script on the client's machine.
- The client sends a DHCP Discover embedding its public key and session ID.
- Upon receiving the DHCP Offer from the server, the client prompts the user to input a message, encrypts it using the server's public key, and sends a DHCP Request.

3. **Server Responds:**

- The server decrypts the client's message, displays it to the server user, and prompts the user to input a reply.
- The server encrypts the reply using the client's public key and sends a DHCP Ack.

4. **Finalize the Session:**

- The client decrypts the server's reply, displays it to the user, and upon user confirmation, sends a DHCP Release.
- The server detects the Release and performs cleanup automatically, terminating the session.

## ⚠️ Disclaimer
**DHushCP** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **DHushCP** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
This project is licensed under the **MIT License**.


