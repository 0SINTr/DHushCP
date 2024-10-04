# 🕵️‍♂️ **DHushCP: Covert Communication Using DHCP**

## 📝 **Summary**
**DHushCP** is a covert communication tool that uses the DHCP protocol to enable secure and hidden message exchange between two machines. **DHushCP** utilizes principles of **network steganography** by embedding encrypted messages within protocol fields that are not commonly inspected. Network steganography involves hiding data in plain sight by using legitimate network protocols.

By embedding encrypted messages into DHCP option fields, **DHushCP** establishes a secure communication channel that blends seamlessly into regular network traffic, making it extremely difficult to detect. This tool is ideal for scenarios where privacy and stealth are paramount, such as discreet communications in public places or controlled environments.

With features like RSA public-key encryption, message fragmentation, custom DHCP options for server validation, and automatic cleanup, **DHushCP** ensures that communication is not only secure but also leaves no traces behind once the session is completed.

## 🔒 **Why Use DHushCP?**
In environments where privacy and security are crucial, traditional messaging applications and network connections can leave traces or be detected easily. **DHushCP** provides a unique solution by using a widely accepted network management protocol (DHCP) for message exchange. It turns a standard protocol into a covert communication channel without creating persistent connections or visible network links, making it an ideal tool for:

- **Stealth Communication in Public Spaces:** Communicate discreetly without establishing visible connections.
- **Red Team Operations:** Test the robustness of network monitoring tools and identify detection gaps.
- **Privacy and Security Research:** Explore covert communication methods in secure environments.

### 🔑 **Key Security and Privacy Features**
1. **Ephemeral Network Traffic:**
   - **DHushCP** leverages broadcast-based DHCP packets to exchange messages, leaving no visible network connections and blending into normal network noise.

2. **Stealthy Communication Using Standard Protocols:**
   - By using DHCP, which is essential for network operation, **DHushCP** avoids detection by intrusion detection systems (IDS) and firewalls that are configured to monitor more active communication protocols.

3. **RSA Public-Key Encryption:**
   - **DHushCP** exchanges RSA public keys during the initial handshake and encrypts messages using the recipient’s public key, ensuring that only the intended recipient can read the content.

4. **Fragmented Message Embedding:**
   - Encrypted messages are split into smaller fragments and embedded across multiple DHCP option fields (`43`, `60`, `77`, and `125`), making it difficult to reconstruct the entire message.

5. **Custom DHCP Option for Server Validation:**
   - To prevent interference from other DHCP servers in the vicinity, **DHushCP** uses a **custom DHCP option** (`224`) that serves as a unique identifier. This ensures that the client only accepts offers from the intended **DHushCP** server and ignores any other DHCP Offers that might be present.

6. **Automatic Secure Cleanup:**
   - After communication ends, **DHushCP** deletes the RSA keys from memory, clears the terminal screen, and exits, leaving no traces on the devices.

## 🔧 **How DHushCP Works**
### 🗂️ **Step-by-Step Communication Process**

#### 1️⃣ **Public Key Exchange**
- **Client:**
  - Generates a fresh RSA public-private key pair.
  - Sends a `DHCP Discover` packet containing its public key, split across multiple DHCP options, along with a **custom DHCP option** (`224`) to uniquely identify the **DHushCP** session.

- **Server:**
  - Receives the `DHCP Discover` packet, validates the **custom DHCP option** (`224`), and reassembles the client’s public key.
  - Generates its own RSA key pair.
  - Sends a `DHCP Offer` packet containing its own public key, split across DHCP options, and includes the **custom DHCP option** (`224`).

- **Client:**
  - Receives and reassembles the server’s public key from the fragmented options in the `DHCP Offer` packet.
  - Validates the **custom DHCP option** to ensure that the `DHCP Offer` is from the intended **DHushCP** server.

#### 2️⃣ **Message Input and Encryption**
- **Client:**
  - Prompts the user for a message to send to the server.
  - Encrypts the message using the **server’s public key**.
  - Validates the encrypted message size to ensure it can fit into the available DHCP options.

#### 3️⃣ **Fragmented Message Transmission**
- **Client:**
  - Splits the encrypted message into smaller fragments and embeds them into the DHCP options.
  - Sends a `DHCP Request` packet containing these message fragments.

- **Server:**
  - Receives and reassembles the encrypted message from the DHCP options.
  - Decrypts the message using its **private key**.
  - Prompts the user for a response message to send back.

#### 4️⃣ **Message Reception and Decryption**
- **Server:**
  - Splits its encrypted response into fragments and sends them in a `DHCP Ack` packet.

- **Client:**
  - Receives and reassembles the response.
  - Decrypts the message using its **private key** and displays it.

#### 5️⃣ **Secure Cleanup**
- **Client:**
  - Sends a `DHCP Release` packet to formally indicate the end of the communication.
  - Deletes its own RSA private key and the server’s public key from memory.
  - Clears the terminal screen and prints a confirmation dot (`.`).

- **Server:**
  - Receives the `DHCP Release` packet from the client.
  - Deletes its own RSA private key and the client’s public key from memory.
  - Clears the terminal screen and prints a confirmation dot (`.`).

## 📏 **Calculating Maximum Message Length**

DHushCP uses multiple DHCP option fields to embed encrypted messages. To estimate the maximum plaintext message size that can be securely transmitted, we need to consider the available space in these DHCP options and the RSA encryption overhead.

### 🧮 **Step-by-Step Calculation**

1. **Total Available Space Per DHCP Option Field**
   - DHCP options are defined to have a maximum capacity of **255 bytes** each.
   - However, each DHCP option field has **4 bytes of metadata overhead**:
     - **Option Number**: 1 byte
     - **Length Field**: 1 byte
     - **Fragmentation Metadata**: 2 bytes (1 for sequence number, 1 for total fragments)

   - **Usable space per option field**:  
   \[
   255 - 4 = 251 \, \text{bytes}
   \]

2. **Total Space Across Multiple DHCP Option Fields**
   - DHushCP utilizes **four different DHCP option fields** (`43`, `60`, `77`, and `125`) for message embedding.
   
   - **Total usable space across 4 options**:  
   \[
   251 \, \text{bytes/option} \times 4 \, \text{options} = 1004 \, \text{bytes}
   \]

3. **Impact of RSA Encryption on Message Size**
   - DHushCP uses **RSA-2048** encryption for secure message exchange.
   - For **RSA-2048** with **OAEP padding**, the maximum plaintext size per RSA block is **245 bytes**.
   - After encryption, each RSA block becomes **256 bytes**.
   
   - **Number of complete RSA blocks** that fit within the available DHCP space:  
   \[
   \text{Number of RSA blocks} = \left\lfloor \frac{1004}{256} \right\rfloor = 3 \, \text{RSA blocks}
   \]

4. **Calculating the Maximum Plaintext Message Size**
   - Each RSA block can hold a maximum of **245 bytes** of plaintext.
   - For **3 RSA blocks**, the maximum plaintext message size is:
   
   \[
   245 \, \text{bytes/block} \times 3 \, \text{blocks} = 735 \, \text{bytes}
   \]

### 📊 **Summary of Message Length Calculations**
- **Usable Space per DHCP Option**: 251 bytes
- **Total Usable Space Across 4 Options**: 1004 bytes
- **Maximum Encrypted Message Size**: 1004 bytes
- **Maximum Plaintext Message Size**: **735 bytes**

### 🔐 **Practical Considerations**
- The above calculations assume that the message fits into **three RSA blocks**.
- If the message is larger, the number of fragments and corresponding overhead increase, reducing the effective message size.
- If additional DHCP option fields are used, the message size can be increased accordingly.

By following this calculation, users can estimate how long their plaintext message can be before encryption to fit within the limits of the DHCP options used by DHushCP.

## 💡 **Summary of Features**
1. **Stealth Communication Using DHCP:**
   - Embeds encrypted messages into DHCP option fields, blending into regular network traffic.

2. **Asymmetric Encryption:**
   - Uses RSA public-key encryption to protect messages, ensuring that only the intended recipient can read the message.

3. **Message Fragmentation Across DHCP Options:**
   - Splits messages into multiple fragments across DHCP options, making detection and reconstruction difficult.

4. **Custom DHCP Option Filtering:**
   - Uses a custom DHCP option (`224`) to validate that the client and server are communicating exclusively with each other.

5. **Dynamic Message Input:**
   - Both the client and server receive user input messages during the communication, providing flexibility in the exchanged content.

6. **Automatic Trace Removal:**
   - Cleans up all keys and data, clears the screen, and exits, ensuring no residual data is left behind.

## 🖥️ **Recommended System Requirements**
- **Operating System**: Linux (e.g., Ubuntu, Debian, Kali Linux)
- **Python Version**: 3.6 or higher
- **Required Libraries**:
  - `scapy`: For crafting and sending custom DHCP packets.
  - `cryptography`: For RSA encryption and decryption.
  - `os` and `sys`: For system-level commands and secure cleanup.

- **Network Interface**: Wireless interface (e.g., `wlan0`) that supports raw packet injection and sniffing.
- **Memory**: 512MB or higher.
- **Disk Space**: Minimal, less than 10MB for required dependencies.

## 📦 **Installation and Setup**
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

## 🔐 **Security Considerations**
- **Message Size Limitations**: Messages must be concise due to the limitations of DHCP option fields. If a message is too large, it won’t fit within the available options.
- **Monitor Mode for Wireless Interfaces**: Ensure that the wireless interfaces used support monitor mode and raw packet manipulation.
- **Controlled Environments**: Always test **DHushCP** in controlled environments to avoid unintended detection.

## ⚠️ **Disclaimers**
- This tool is intended for educational and research purposes only. 
- The developers are not responsible for any misuse or illegal activities conducted with this tool. 
- Always obtain proper authorization before using **DHushCP** in any network.