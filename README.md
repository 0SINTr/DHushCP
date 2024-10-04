# **DHushCP: Covert Communication Using DHCP**

## **Summary**
**DHushCP** is a covert communication tool that uses the DHCP protocol to enable secure and hidden message exchange between two machines. By embedding encrypted messages into DHCP option fields, DHushCP establishes a secure communication channel that blends seamlessly into regular network traffic, making it extremely difficult to detect. This tool is ideal for scenarios where privacy and stealth are paramount, such as discreet communications in public places or controlled environments.

With features like RSA public-key encryption, message fragmentation, and automatic cleanup, DHushCP ensures that communication is not only secure but also leaves no traces behind once the session is completed.

## **Why Use DHushCP?**
In environments where privacy and security are crucial, traditional messaging applications and network connections can leave traces or be detected easily. **DHushCP** provides a unique solution by using a widely accepted network management protocol (DHCP) for message exchange. It turns a standard protocol into a covert communication channel without creating persistent connections or visible network links, making it an ideal tool for:

- **Stealth Communication in Public Spaces:** Communicate discreetly without establishing visible connections.
- **Red Team Operations:** Test the robustness of network monitoring tools and identify detection gaps.
- **Privacy and Security Research:** Explore covert communication methods in secure environments.

### **Key Security and Privacy Features**
1. **Ephemeral Network Traffic:**
   - DHushCP leverages broadcast-based DHCP packets to exchange messages, leaving no visible network connections and blending into normal network noise.

2. **Stealthy Communication Using Standard Protocols:**
   - By using DHCP, which is essential for network operation, DHushCP avoids detection by intrusion detection systems (IDS) and firewalls that are configured to monitor more active communication protocols.

3. **RSA Public-Key Encryption:**
   - DHushCP exchanges RSA public keys during the initial handshake and encrypts messages using the recipient’s public key, ensuring that only the intended recipient can read the content.

4. **Fragmented Message Embedding:**
   - Encrypted messages are split into smaller fragments and embedded across multiple DHCP option fields (`43`, `60`, `77`, and `125`), making it difficult to reconstruct the entire message.

5. **Automatic Secure Cleanup:**
   - After communication ends, DHushCP deletes the RSA keys from memory, clears the terminal screen, and exits, leaving no traces on the devices.

## **How DHushCP Works**
### **Step-by-Step Communication Process**
1. **Public Key Exchange:**
   - The **Client** sends a `DHCP Discover` packet that contains its RSA public key fragmented across DHCP option fields.
   - The **Server** responds with a `DHCP Offer` packet containing its own RSA public key, also fragmented across the same DHCP option fields.
   - Both parties reassemble the fragments and extract each other’s public keys.

2. **Message Input and Encryption:**
   - Once the public keys are exchanged:
     - The **Client** inputs a message to send to the Server.
     - The **Server** inputs a message to send back to the Client.
   - Each message is encrypted using the recipient’s public key to ensure only the intended recipient can decrypt it.

3. **Fragmented Message Transmission:**
   - The encrypted messages are fragmented into smaller chunks and embedded into the DHCP Request and Ack packets.
   - Each fragment is assigned a sequence number and the total number of fragments to facilitate reassembly.

4. **Message Reception and Decryption:**
   - The **Server** receives the client’s `DHCP Request` packet, reassembles the fragments, decrypts the message, and displays it.
   - The **Client** receives the server’s `DHCP Ack` packet, reassembles the fragments, decrypts the message, and displays it.

5. **Secure Cleanup:**
   - After both messages have been read, DHushCP sends a `DHCP Release` packet to indicate the end of communication, deletes all keys from memory, clears the screen, and prints a confirmation dot (`.`) before exiting.

## **Features**
1. **Stealth Communication Using DHCP:**
   - Embeds encrypted messages into DHCP option fields, blending into regular network traffic.
   
2. **Asymmetric Encryption:**
   - Uses RSA public-key encryption to protect messages, ensuring that only the intended recipient can read the message.

3. **Message Fragmentation Across DHCP Options:**
   - Splits messages into multiple fragments across DHCP options, making detection and reconstruction difficult.

4. **Dynamic Message Input:**
   - Both the client and server receive user input messages during the communication, providing flexibility in the exchanged content.

5. **Automatic Trace Removal:**
   - Cleans up all keys and data, clears the screen, and exits, ensuring no residual data is left behind.

## **Recommended System Requirements**
### **Client and Server Machine Specifications**
- **Operating System**: Linux (e.g., Ubuntu, Debian, Kali Linux)
- **Python Version**: 3.6 or higher
- **Required Libraries**:
  - `scapy`: For crafting and sending custom DHCP packets.
  - `cryptography`: For RSA encryption and decryption.
  - `os` and `sys`: For system-level commands and secure cleanup.

- **Network Interface**: Wireless interface (e.g., `wlan0`) that supports raw packet injection and sniffing.
- **Memory**: 512MB or higher (minimal for running Python scripts).
- **Disk Space**: Minimal, less than 10MB for required dependencies.

## **Installation and Setup**
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your_username/DHushCP.git
   cd DHushCP
   ```

2. **Install Required Dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3-scapy
   pip3 install cryptography
   ```

3. **Run the Server and Client:**
- Start the server on one machine:
   ```bash
   sudo python3 server.py
   ```
- Start the client on the other machine:
   ```bash
   sudo python3 client.py
   ```

4. **Message Exchange and Cleanup:**
- The client and server will exchange messages. Once both parties have read the messages, the tool will automatically clean up and exit.

## **Security Considerations**
- **Message Size Limitations**: Messages must be concise due to the limitations of DHCP option fields. If a message is too large, it won’t fit within the available options.
- **Monitor Mode for Wireless Interfaces**: Ensure that the wireless interfaces used support monitor mode and raw packet manipulation.
- **Controlled Environments**: Always test DHushCP in controlled environments to avoid unintended detection.

## **References on Network Steganography**
DHushCP utilizes principles of **network steganography** by embedding encrypted messages within protocol fields that are not commonly inspected. Network steganography involves hiding data in plain sight by using legitimate network protocols. To learn more about this concept, check out the following resources:

1. **"A Survey of Network Steganography Techniques"** by Mazurczyk, W., & Szczypiorski, K.
   - Explores various network steganography methods and how they can be used to hide communication within existing protocols.
   - [Link to paper](https://www.researchgate.net/publication/220742214_A_Survey_of_Network_Steganography_Techniques)

2. **"Steganography in Network Protocols"** by Hans-Peter Frey.
   - Discusses the application of steganography techniques in different network protocols, including TCP, UDP, and ICMP.
   - [Link to research](https://ieeexplore.ieee.org/document/6072786)

3. **"The Use of Covert Channels in Network Steganography"** by Szczypiorski, K.
   - Analyzes how covert channels can be created in network protocols to enable hidden communications.
   - [Link to paper](https://ieeexplore.ieee.org/document/7849782)

## **Disclaimer**
This tool is intended for educational and research purposes only. The developers are not responsible for any misuse or illegal activities conducted with this tool. Always obtain proper authorization before using DHushCP in any network.






