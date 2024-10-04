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

### **1. Public Key Exchange:**
#### **Client:**
1. **Generates RSA Key Pair:**
   - The client generates a fresh RSA public-private key pair.
   
2. **Sends `DHCP Discover` Packet:**
   - The client embeds its RSA **public key** into multiple DHCP option fields (`43`, `60`, `77`, and `125`) as a series of fragmented data chunks.
   - It then broadcasts a `DHCP Discover` packet, which includes these fragmented options.

#### **Server:**
1. **Receives `DHCP Discover` Packet:**
   - The server receives the `DHCP Discover` packet, extracts, and reassembles the RSA **public key** sent by the client.

2. **Generates RSA Key Pair:**
   - The server generates its own RSA public-private key pair.
   
3. **Sends `DHCP Offer` Packet:**
   - The server embeds its RSA **public key** into the same DHCP option fields (`43`, `60`, `77`, and `125`) and sends it back to the client in a `DHCP Offer` packet.

#### **Client:**
- **Receives `DHCP Offer` Packet:**
  - The client reassembles the server’s RSA **public key** from the fragmented options in the `DHCP Offer` packet.
  
### **2. Message Input and Encryption:**
#### **Client:**
1. **Prompts User for a Message:**
   - After receiving the server’s public key, the client prompts the user to input a message to send to the server.
   
2. **Encrypts Message:**
   - The client encrypts the input message using the **server’s public key** to ensure that only the server can decrypt and read the content.

3. **Validates Message Size:**
   - The client ensures that the encrypted message fits into the available DHCP options (`43`, `60`, `77`, and `125`). If the message is too large, the user is prompted to shorten it.

#### **Server:**
- **No action needed in this step** until it receives the client’s encrypted message in the next step.

### **3. Fragmented Message Transmission:**
#### **Client:**
1. **Splits Encrypted Message into Fragments:**
   - The client splits the encrypted message into smaller chunks, each fitting within the size constraints of the chosen DHCP options.
   
2. **Sends `DHCP Request` Packet:**
   - The client embeds the fragments into the DHCP option fields (`43`, `60`, `77`, and `125`) of a `DHCP Request` packet and sends it to the server.

#### **Server:**
1. **Receives and Reassembles Fragments:**
   - The server receives the `DHCP Request` packet, extracts the fragmented message from the DHCP options, and reassembles the complete encrypted message.

2. **Decrypts the Message:**
   - The server decrypts the message using its **private key**, and the content is displayed in plaintext on the terminal for the user.

3. **Prompts User for a Response:**
   - The server then prompts the user to input a response message to send back to the client.

4. **Encrypts the Response Message:**
   - The server encrypts its response using the **client’s public key**.

### **4. Message Reception and Decryption:**
#### **Server:**
1. **Splits Encrypted Response into Fragments:**
   - The server splits its encrypted response message into multiple chunks to fit into the available DHCP option fields.
   
2. **Sends `DHCP Ack` Packet:**
   - The server embeds the fragments into the `DHCP Ack` packet and sends it to the client.

#### **Client:**
1. **Receives and Reassembles Fragments:**
   - The client receives the `DHCP Ack` packet, extracts the fragments, and reassembles the complete encrypted response message.

2. **Decrypts the Message:**
   - The client decrypts the message using its **private key** and displays it in plaintext on the terminal.

3. **Confirms Successful Reception:**
   - The client waits for the user to confirm that they have read the server’s message before initiating the cleanup process.

### **5. Secure Cleanup:**
#### **Client-Side Cleanup:**
1. **Sends a DHCP Release Packet**:
   - The client sends a `DHCP Release` packet to formally indicate the end of the communication session.
   
2. **Deletes All Cryptographic Keys**:
   - The client securely deletes its own RSA private key as well as the server's public key from memory to prevent any post-session data recovery.

3. **Clears the Terminal Screen**:
   - The screen is cleared to erase any visible trace of the communication session, including the displayed messages.

4. **Prints a Confirmation Dot (`.`)**:
   - A simple `.` is printed on the screen to indicate that the cleanup was successful and that the client has safely terminated the session.

#### **Server-Side Cleanup:**
1. **Receives the DHCP Release Packet**:
   - The server waits for and receives the `DHCP Release` packet from the client, acknowledging that the communication has ended.

2. **Deletes All Cryptographic Keys**:
   - The server securely deletes its own RSA private key as well as the client's public key from memory, ensuring that no sensitive data remains.

3. **Clears the Terminal Screen**:
   - The terminal screen is cleared to erase all displayed content, preventing any residual information from being recovered.

4. **Prints a Confirmation Dot (`.`)**:
   - Similar to the client, the server prints a `.` to indicate that the cleanup process was successfully completed and that the server session has safely ended.

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
   pip install cryptography
   pip install scapy
   ```

3. **Run the Server and Client:**
- Start the server on one machine:
   ```bash
   sudo python server.py
   ```
- Start the client on the other machine:
   ```bash
   sudo python client.py
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