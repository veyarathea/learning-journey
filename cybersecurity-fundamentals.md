<h1 align="center">
  <span style="color:#F2A65A">C</span>
  <span style="color:#F4C784">y</span>
  <span style="color:#D9775F">b</span>
  <span style="color:#C97C5D">e</span>
  <span style="color:#F2A65A">r</span>
  <span style="color:#F4C784">s</span>
  <span style="color:#D9775F">e</span>
  <span style="color:#C97C5D">c</span>
  <span style="color:#F2A65A">u</span>
  <span style="color:#F4C784">r</span>
  <span style="color:#D9775F">i</span>
  <span style="color:#C97C5D">t</span>
  <span style="color:#F2A65A">y</span>
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Fundamentals-D9775F?style=flat-square&logo=security&logoColor=white" />
  <img src="https://img.shields.io/badge/Summary-F4C784?style=flat-square&logo=book&logoColor=white" />
  <img src="https://img.shields.io/badge/Algorithms-F2A65A?style=flat-square&logo=algorithm&logoColor=white" />
  <img src="https://img.shields.io/badge/Tools-C97C5D?style=flat-square&logo=toolbox&logoColor=white" />
</p>

<p align="center">✦ ✧ ❖ ✧ ✦</p>

<p align="center">
Summarizes <b>fundamental cybersecurity topics</b>.  
Each section includes <b>explanations</b>, <b>study cases</b>, <b>key terms</b>,  
<b>associated algorithms</b>, <b>tools</b>, and their <b>functions & benefits</b>.
</p>

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/1.-Cryptography-D9775F?style=flat-square&logo=security&logoColor=white" />
</h1>

*Securing data by transforming it to protect information from unauthorized access.*

### ❖ Study Case
A website stores passwords as plain text. When the database leaks, all user accounts are exposed.  
✅ **Solution:** Hash passwords before storage.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Encryption**  
  **Definition:**  
  Encryption is a cryptographic process that transforms readable data (plaintext)
  into an unreadable format (ciphertext) using mathematical algorithms and secret keys,
  so that only authorized parties can access the information.

  *Algorithms:* AES, DES, 3DES  
  *Tools:* OpenSSL, GnuPG  
  *Function:* Protects data confidentiality during storage and transmission  
  *Benefit:* Prevents attackers from reading sensitive data even if intercepted

- **Decryption**  
  **Definition:**  
  Decryption is the reverse operation of encryption, where encrypted data is converted
  back into its original readable form using the correct cryptographic key.

  *Algorithms:* AES, RSA  
  *Tools:* OpenSSL  
  *Function:* Allows authorized users to access protected data  
  *Benefit:* Ensures secure yet usable systems

- **Hashing**  
  **Definition:**  
  Hashing is a one-way cryptographic process that converts data into a fixed-length value
  that cannot be reversed to retrieve the original input.

  *Algorithms:* SHA-256, SHA-512, bcrypt, Argon2  
  *Tools:* OpenSSL, bcrypt/Argon2 libraries  
  *Function:* Protects credentials without storing original values  
  *Benefit:* Limits damage if databases are leaked

- **Symmetric Encryption**  
  **Definition:**  
  Symmetric encryption is an encryption method that uses the same secret key
  for both encrypting and decrypting data.

  *Algorithms:* AES, DES  
  *Tools:* OpenSSL  
  *Function:* Efficient encryption for large data  
  *Benefit:* Fast and suitable for bulk data protection

- **Asymmetric Encryption**  
  **Definition:**  
  Asymmetric encryption uses two different but mathematically related keys:
  a public key for encryption and a private key for decryption.

  *Algorithms:* RSA, ECC  
  *Tools:* OpenSSL, GPG  
  *Function:* Secure key exchange and identity verification  
  *Benefit:* Enables secure communication without pre-shared keys

- **Encoding (not encryption)**  
  **Definition:**  
  Encoding is the process of converting data into another format
  to ensure safe transmission or compatibility, without providing security.

  *Algorithms:* Base64, URL Encoding  
  *Tools:* CyberChef  
  *Function:* Ensures data compatibility across systems  
  *Benefit:* Prevents data corruption (not for security)

- **Secure Communication**  
  **Definition:**  
  Secure communication refers to methods that protect data while it is being transmitted
  over a network, ensuring confidentiality and integrity.

  *Protocols:* TLS, SSL  
  *Tools:* OpenSSL, Wireshark  
  *Function:* Encrypts client–server communication  
  *Benefit:* Prevents credential sniffing and MITM attacks
<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/2.-Digital_Forensics-F4C784?style=flat-square&logo=file&logoColor=white" />
</h1>

*Identifying, collecting, and analyzing digital evidence after incidents.*

### ❖ Study Case
System logs are analyzed to determine unauthorized access times and methods.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Log Analysis**  
  **Definition:**  
  Log analysis is the process of examining system-generated records
  to understand events, activities, and potential security incidents.

  *Algorithms:* Pattern Matching, Regular Expressions  
  *Tools:* Splunk, ELK Stack, grep  
  *Function:* Detects suspicious actions and anomalies  
  *Benefit:* Helps trace attacks and improve defenses

- **File Integrity Checking**  
  **Definition:**  
  File integrity checking ensures that files have not been altered,
  corrupted, or tampered with since their original state.

  *Algorithms:* MD5, SHA-1, SHA-256  
  *Tools:* Hashdeep, OpenSSL  
  *Function:* Verifies files have not been altered  
  *Benefit:* Preserves evidence authenticity

- **Timeline Reconstruction**  
  **Definition:**  
  Timeline reconstruction is the process of ordering events chronologically
  to understand how an incident unfolded over time.

  *Algorithms:* Merge Sort, Quick Sort  
  *Tools:* Autopsy, Plaso  
  *Function:* Rebuilds sequence of incidents  
  *Benefit:* Clarifies how attacks occurred

- **Evidence Validation**  
  **Definition:**  
  Evidence validation ensures that collected digital evidence
  remains accurate, intact, and trustworthy.

  *Algorithms:* Checksum Comparison, Hash Matching  
  *Tools:* FTK Imager  
  *Function:* Ensures evidence integrity  
  *Benefit:* Makes findings reliable and admissible

- **Incident Correlation**  
  **Definition:**  
  Incident correlation links multiple security events
  to identify patterns and relationships between them.

  *Algorithms:* Log Correlation  
  *Tools:* SIEM (Splunk, Wazuh)  
  *Function:* Connects related security events  
  *Benefit:* Reveals broader attack patterns

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/3.-Network_Security-D9775F?style=flat-square&logo=network&logoColor=white" />
</h1>

*Protecting data during transmission between systems.*

### ❖ Study Case
Public Wi-Fi intercepts login data when HTTPS is not used.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Secure Communication**  
  **Definition:**  
  Secure communication refers to the protection of data exchanged between systems
  over a network so that it cannot be intercepted, modified, or read by unauthorized parties.
  This is essential for applications that transmit credentials or sensitive information.

  *Algorithms:* TLS, AES, RSA, ECDHE  
  *Tools:* OpenSSL, Wireshark  

  *Function (Tools):*  
  - **OpenSSL:** implements encrypted communication using TLS/SSL  
  - **Wireshark:** analyzes network traffic to verify whether data is encrypted  

  *Benefit (Term):*  
  - Prevents credential interception  
  - Protects user privacy during data transmission  

- **Firewall Filtering**  
  **Definition:**  
  Firewall filtering is the process of controlling network traffic
  by allowing or blocking packets based on predefined security rules.

  *Algorithms:* Packet Filtering, Stateful Inspection  
  *Tools:* iptables, pfSense  

  *Function (Tools):*  
  - **iptables:** defines low-level traffic filtering rules  
  - **pfSense:** provides firewall management through a user-friendly interface  

  *Benefit (Term):*  
  - Reduces attack surface  
  - Prevents unauthorized network access  


- **Packet Inspection**  
  **Definition:**  
  Packet inspection involves examining network packets
  to detect malicious payloads, suspicious patterns, or policy violations.

  *Techniques:* Deep Packet Inspection (DPI)  
  *Tools:* Wireshark, Suricata  

  *Function (Tools):*  
  - **Wireshark:** captures and analyzes packet contents  
  - **Suricata:** detects intrusions based on traffic behavior  

  *Benefit (Term):*  
  - Detects malware communication  
  - Helps identify network-based attacks  

- **Man-in-the-Middle (MITM) Defense**  
  **Definition:**  
  MITM defense refers to mechanisms that prevent attackers
  from intercepting or altering communication between two parties.

  *Algorithms:* TLS Handshake, Certificate Validation  
  *Tools:* Wireshark, Burp Suite (learning environment)  

  *Function (Tools):*  
  - **Wireshark:** identifies insecure or unencrypted connections  
  - **Burp Suite:** demonstrates interception risks in testing environments  

  *Benefit (Term):*  
  - Ensures authenticity of communication  
  - Prevents data manipulation  

- **Key Exchange**  
  **Definition:**  
  Key exchange is the process of securely sharing encryption keys
  between communicating parties before encrypted communication begins.

  *Algorithms:* Diffie-Hellman, Elliptic Curve Diffie-Hellman (ECDH)  
  *Tools:* OpenSSL  

  *Function (Tools):*  
  - **OpenSSL:** securely negotiates encryption keys  

  *Benefit (Term):*  
  - Enables encrypted sessions without exposing secret keys  
  - Strengthens communication security  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/4.-CIA_Triad-F4C784?style=flat-square&logo=shield&logoColor=white" />
</h1>

*Defining security goals: Confidentiality, Integrity, and Availability.*

### ❖ Study Case
A user accesses admin features without permission checks.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Confidentiality**  
  **Definition:**  
  Confidentiality ensures that sensitive information
  is accessible only to authorized users and systems.

  *Algorithms:* AES, RSA  
  *Tools:* OpenSSL, HashiCorp Vault  

  *Function (Tools):*  
  - **OpenSSL:** encrypts data to protect confidentiality  
  - **Vault:** securely stores secrets and encryption keys  

  *Benefit (Term):*  
  - Prevents data leakage  
  - Protects user privacy  


- **Integrity**  
  **Definition:**  
  Integrity ensures that data remains accurate and unchanged
  unless modified by authorized entities.

  *Algorithms:* HMAC, SHA-256  
  *Tools:* OpenSSL  

  *Function (Tools):*  
  - **OpenSSL:** generates hashes and message authentication codes  

  *Benefit (Term):*  
  - Detects unauthorized modifications  
  - Maintains data trustworthiness  


- **Availability**  
  **Definition:**  
  Availability ensures that systems and services
  remain accessible and functional when needed.

  *Methods:* Load Balancing, Rate Limiting  
  *Tools:* Nginx, HAProxy  

  *Function (Tools):*  
  - **Nginx:** distributes traffic and applies rate limiting  
  - **HAProxy:** balances load across servers  

  *Benefit (Term):*  
  - Prevents service downtime  
  - Improves system reliability  

- **Authentication**  
  **Definition:**  
  Authentication verifies the identity of a user or system
  before granting access.

  *Algorithms:* bcrypt, JWT, OAuth  
  *Tools:* Auth0, Firebase Auth  

  *Function (Tools):*  
  - **Auth0:** manages authentication workflows  
  - **Firebase Auth:** handles user login securely  

  *Benefit (Term):*  
  - Prevents unauthorized access  
  - Reduces impersonation risk

- **Authorization**  
  **Definition:**  
  Authorization determines what actions or resources
  an authenticated user is allowed to access.

  *Models:* RBAC, ABAC  
  *Tools:* Keycloak, Open Policy Agent  

  *Function (Tools):*  
  - **Keycloak:** manages user roles and permissions  
  - **OPA:** enforces authorization policies  

  *Benefit (Term):*  
  - Prevents privilege abuse  
  - Enforces least-privilege principle  

- **Session Management**  
  **Definition:**  
  Session management handles user sessions
  after authentication has been completed.

  *Algorithms:* JWT, Session Tokens  
  *Tools:* Redis  

  *Function (Tools):*  
  - **Redis:** stores session data securely  

  *Benefit (Term):*  
  - Prevents session hijacking  
  - Improves user experience securely  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/5.-Malware-F2A65A?style=flat-square&logo=virus&logoColor=white" />
</h1>

*Software designed to harm systems or steal data.*

### ❖ Study Case
A trojan disguised as free software installs spyware.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Virus**  
  **Definition:**  
  A virus is malicious software that attaches itself to legitimate files
  and spreads when those files are executed.

  *Algorithms:* Self-replication  
  *Tools:* ClamAV  

  *Function (Tools):*  
  - **ClamAV:** detects virus signatures  

  *Benefit (Term):*  
  - Understanding viruses helps prevent infections  


- **Trojan**  
  **Definition:**  
  A trojan disguises itself as legitimate software
  to trick users into installing malicious programs.

  *Techniques:* Code Obfuscation  
  *Tools:* Metasploit (lab), UPX  

  *Function (Tools):*  
  - **UPX:** demonstrates executable packing techniques  

  *Benefit (Term):*  
  - Awareness reduces installation risk  


- **Spyware**  
  **Definition:**  
  Spyware secretly monitors user activity
  and collects sensitive information.

  *Algorithms:* Keylogging  
  *Tools:* Process Monitor, Wireshark  

  *Function (Tools):*  
  - **Process Monitor:** observes suspicious processes  

  *Benefit (Term):*  
  - Detection protects user privacy  


- **Worm**  
  **Definition:**  
  A worm is malware that spreads automatically
  across networks without user interaction.

  *Algorithms:* Network Propagation  
  *Tools:* Wireshark  

  *Function (Tools):*  
  - **Wireshark:** monitors abnormal network traffic  

  *Benefit (Term):*  
  - Understanding worms limits outbreaks  


- **Malware Detection**  
  **Definition:**  
  Malware detection identifies malicious software
  through behavioral or signature-based analysis.

  *Algorithms:* Signature-based, Behavior-based  
  *Tools:* VirusTotal, YARA  

  *Function (Tools):*  
  - **YARA:** defines malware detection rules  

  *Benefit (Term):*  
  - Prevents system compromise  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/6.-Social_Engineering-D9775F?style=flat-square&logo=users&logoColor=white" />
</h1>

*Exploiting human behavior instead of technical flaws.*

### ❖ Study Case
Phishing emails trick users into entering passwords.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Phishing**  
  **Definition:**  
  Phishing is a social engineering technique
  that tricks users into revealing sensitive information.

  *Algorithms:* Email Classification  
  *Tools:* SpamAssassin, Google Safe Browsing  

  *Function (Tools):*  
  - **SpamAssassin:** filters phishing emails  

  *Benefit (Term):*  
  - Reduces successful social attacks  

- **Impersonation**  
  **Definition:**  
  Impersonation involves attackers pretending
  to be trusted individuals or organizations.

  *Techniques:* Identity Spoofing  
  *Tools:* Email Header Analyzer  

  *Function (Tools):*  
  - **Header Analyzer:** detects forged email sources  

  *Benefit (Term):*  
  - Prevents trust exploitation  

- **Behavior Analysis**  
  **Definition:**  
  Behavior analysis identifies abnormal user activity
  that may indicate malicious intent.

  *Algorithms:* Anomaly Detection  
  *Tools:* SIEM, UEBA  

  *Function (Tools):*  
  - **SIEM:** correlates user behavior logs  

  *Benefit (Term):*  
  - Detects insider threats  

- **Risk Scoring**  
  **Definition:**  
  Risk scoring assigns numerical values
  to actions based on threat likelihood.

  *Algorithms:* Scoring Models  
  *Tools:* Fraud Detection Systems  

  *Function (Tools):*  
  - **Fraud Systems:** calculate behavioral risk  

  *Benefit (Term):*  
  - Enables proactive defense  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>

---

## <h1 align="center">
  <img src="https://img.shields.io/badge/7.-Cyber_Attacks-F4C784?style=flat-square&logo=alert&logoColor=white" />
</h1>

*Attempts to gain unauthorized access or disrupt systems.*

### ❖ Study Case
Repeated password guessing succeeds without protections.

### 🔑 Terms, Meanings, Algorithms, Tools, Functions & Benefits

- **Brute Force Attack**  
  **Definition:**  
  A brute force attack systematically tries all possible combinations
  to guess passwords or encryption keys.

  *Algorithms:* Exhaustive Search  
  *Tools:* Hydra (lab)  

  *Function (Tools):*  
  - **Hydra:** simulates brute force attempts in testing  

  *Benefit (Term):*  
  - Encourages strong authentication defenses  

- **Dictionary Attack**  
  **Definition:**  
  A dictionary attack uses predefined wordlists
  to guess commonly used passwords.

  *Algorithms:* Wordlist Matching  
  *Tools:* John the Ripper  

  *Function (Tools):*  
  - **John:** tests password strength  

  *Benefit (Term):*  
  - Promotes secure password policies  

- **Denial of Service (DoS)**  
  **Definition:**  
  DoS attacks overwhelm systems
  to make services unavailable.

  *Algorithms:* Flooding  
  *Tools:* hping3 (lab)  

  *Function (Tools):*  
  - **hping3:** generates traffic for testing  

  *Benefit (Term):*  
  - Improves availability planning  

- **Rate Limiting**  
  **Definition:**  
  Rate limiting restricts the number of requests
  a user or system can make.

  *Algorithms:* Token Bucket, Leaky Bucket  
  *Tools:* Nginx, Cloudflare  

  *Function (Tools):*  
  - **Cloudflare:** enforces rate limits  

  *Benefit (Term):*  
  - Prevents abuse and attacks  

- **Threat Modeling**  
  **Definition:**  
  Threat modeling identifies potential security risks
  during system design.

  *Methods:* STRIDE  
  *Tools:* OWASP Threat Dragon  

  *Function (Tools):*  
  - **Threat Dragon:** visualizes threats  

  *Benefit (Term):*  
  - Prevents vulnerabilities early  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>
