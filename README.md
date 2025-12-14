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
</p>

<p align="center">
  ✦ ✧ ❖ ✧ ✦
</p>

<p align="center">
Summarizes <b>fundamental cybersecurity topics</b>.  
Each section includes <b>explanations</b>, <b>study cases</b>, <b>key terms</b>, and <b>associated algorithms</b>.
</p>

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/1.-Cryptography-D9775F?style=flat-square&logo=security&logoColor=white" />
</p>

*Securing data by transforming it to protect information from unauthorized access.*

### ❖ Study Case
A website stores passwords as plain text. When the database leaks, all user accounts are exposed.  
✅ **Solution:** Hash passwords before storage.

### 🔑 Terms, Meanings & Algorithms
- **Encryption** – Process of converting readable data into unreadable form.  
  *Algorithms:* AES, DES, 3DES  

- **Decryption** – Process of converting encrypted data back to readable form.  
  *Algorithms:* AES, RSA  

- **Hashing** – One-way transformation for password storage.  
  *Algorithms:* SHA-256, SHA-512, bcrypt, Argon2  

- **Symmetric Encryption** – Same key for encryption & decryption.  
  *Algorithms:* AES, DES  

- **Asymmetric Encryption** – Uses public & private keys.  
  *Algorithms:* RSA, ECC  

- **Encoding (not encryption)** – Converts data for transport only.  
  *Algorithms:* Base64, URL Encoding  

- **Secure Communication** – Protects data in transit.  
  *Protocols/Algorithms:* TLS, SSL, RSA + AES  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/2.-Digital_Forensics-F4C784?style=flat-square&logo=file&logoColor=white" />
</p>

*Identifying, collecting, and analyzing digital evidence after incidents.*

### ❖ Study Case
System logs are analyzed to determine unauthorized access times and methods.

### 🔑 Terms, Meanings & Algorithms
- **Log Analysis** – Reviewing system records.  
  *Methods:* Pattern Matching, Regular Expressions  

- **File Integrity Checking** – Verifying files are not altered.  
  *Algorithms:* MD5, SHA-1, SHA-256  

- **Timeline Reconstruction** – Ordering events chronologically.  
  *Algorithms:* Merge Sort, Quick Sort  

- **Evidence Validation** – Ensuring evidence authenticity.  
  *Algorithms:* Checksum Comparison, Hash Matching  

- **Incident Correlation** – Linking multiple events together.  
  *Techniques:* Correlation Rules, Log Correlation Algorithms  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/3.-Network_Security-D9775F?style=flat-square&logo=network&logoColor=white" />
</p>

*Protecting data during transmission between systems.*

### ❖ Study Case
Public Wi-Fi intercepts login data when HTTPS is not used.

### 🔑 Terms, Meanings & Algorithms
- **Secure Communication** – Encrypting data over networks.  
  *Algorithms:* TLS, AES, RSA, ECDHE  

- **Firewall Filtering** – Controls network traffic.  
  *Algorithms:* Packet Filtering, Stateful Inspection  

- **Packet Inspection** – Analyzing transmitted data.  
  *Techniques:* Deep Packet Inspection (DPI)  

- **Man-in-the-Middle Attack** – Intercepting communication.  
  *Defense Algorithms:* TLS Handshake, Certificate Verification  

- **Key Exchange** – Secure key sharing.  
  *Algorithms:* Diffie-Hellman, Elliptic Curve Diffie-Hellman  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <<h1 align="center">
  <img src="https://img.shields.io/badge/4.-CIA_Triad-F4C784?style=flat-square&logo=shield&logoColor=white" />
</p>

*Defining security goals: Confidentiality, Integrity, and Availability.*

### ❖ Study Case
A user accesses admin features without permission checks.

### 🔑 Terms, Meanings & Algorithms
- **Confidentiality** – Preventing unauthorized access.  
  *Algorithms:* AES, RSA, Access Control Lists  

- **Integrity** – Preventing unauthorized data changes.  
  *Algorithms:* HMAC, SHA-256, Digital Signatures  

- **Availability** – Ensuring system access.  
  *Methods:* Load Balancing, Rate Limiting  

- **Authentication** – Verifying user identity.  
  *Algorithms/Methods:* Password Hashing (bcrypt), JWT, OAuth  

- **Authorization** – Controlling user permissions.  
  *Models:* RBAC, ABAC  

- **Session Management** – Tracking logged-in users.  
  *Algorithms:* Session Tokens, JWT  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/5.-Malware-F2A65A?style=flat-square&logo=virus&logoColor=white" />
</p>

*Software designed to harm systems or steal data.*

### ❖ Study Case
A trojan disguised as free software installs spyware.

### 🔑 Terms, Meanings & Algorithms
- **Virus** – Attaches to legitimate files. *Techniques:* Self-replication algorithms  
- **Trojan** – Disguised as safe software. *Techniques:* Code Obfuscation  
- **Spyware** – Steals user information. *Techniques:* Keylogging Algorithms  
- **Worm** – Spreads automatically. *Algorithms:* Network Propagation Algorithms  
- **Malware Detection** – Identifying malicious software. *Algorithms:* Signature-based, Behavior-based Detection  
- **Evasion** – Avoiding detection. *Algorithms:* Polymorphic Code, Packing  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/6.-Social_Engineering-D9775F?style=flat-square&logo=users&logoColor=white" />
</p>

*Exploiting human behavior instead of technical flaws.*

### ❖ Study Case
Phishing emails trick users into entering passwords.

### 🔑 Terms, Meanings & Algorithms
- **Phishing** – Fake messages to steal data. *Algorithms:* Email Classification, Spam Filtering Algorithms  
- **Impersonation** – Pretending to be trusted entities. *Techniques:* Identity Spoofing  
- **Behavior Analysis** – Detecting unusual user actions. *Algorithms:* Anomaly Detection  
- **Risk Scoring** – Measuring suspicious behavior. *Algorithms:* Scoring Models  
- **Awareness Defense** – Reducing user mistakes. *Methods:* Rule-based Filtering  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>


## <h1 align="center">
  <img src="https://img.shields.io/badge/7.-Cyber_Attacks-F4C784?style=flat-square&logo=alert&logoColor=white" />
</p>

*Attempts to gain unauthorized access or disrupt systems.*

### ❖ Study Case
Repeated password guessing succeeds without protections.

### 🔑 Terms, Meanings & Algorithms
- **Brute Force Attack** – Repeated guessing. *Algorithms:* Exhaustive Search  
- **Dictionary Attack** – Using common password lists. *Algorithms:* Wordlist Matching  
- **Denial of Service (DoS)** – Overloading systems. *Techniques:* Traffic Flooding Algorithms  
- **Rate Limiting** – Restricting requests. *Algorithms:* Token Bucket, Leaky Bucket  
- **Threat Modeling** – Identifying risks. *Methods:* STRIDE Model  
- **Input Validation** – Preventing malicious input. *Algorithms:* Validation Rules, Sanitization  

<div align="center">✧❖✦❖✧❖✦❖✧❖✦</div>
