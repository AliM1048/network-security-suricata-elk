# Project Technologies & Attack Analysis

## 1. Technology Stack Overview

### Suricata (The IDS Engine)

- **What it is:** An open-source, high-performance Network Intrusion Detection System (NIDS), IPS, and Network Security Monitoring engine.
- **Role in Project:** Acts as the "blue team" defender, listening to network traffic between the attacker and the web server to detect malicious patterns using defined rules.
- **Advantages:**
  - **Multi-threaded:** Can process high-bandwidth traffic efficiently (unlike older versions of Snort).
  - **EVE JSON Output:** Produces modern, structured logs that are easy to parse and act upon programmatically.
  - **Protocol Awareness:** Can understand HTTP, TLS, DNS, etc., allowing for advanced rule matching (e.g., matching a specific HTTP User-Agent).
- **Limitations:**
  - **Signature Dependency:** Primarily relies on known signatures. It cannot detect a brand-zero-day attack if no rule exists for it (unless anomaly detection is configured).
  - **Encrypted Traffic:** Cannot inspect the content of HTTPS traffic without a decryption setup (TLS termination).

### Nginx (The Target)

- **What it is:** A high-performance web server, reverse proxy, and load balancer.
- **Role in Project:** Acts as the "victim" web server hosting the application endpoints.
- **Advantages:**
  - **Performance:** Extremely fast and efficient/lightweight resource usage.
  - **Stability:** Widely used and battle-tested.
- **Limitations:**
  - **Static Nature:** As a web server, it doesn't inherently inspect traffic for attacks (unless using modules like ModSecurity). It will happily serve a malicious payload if not configured otherwise.

### Kali Linux Rolling (The Attacker)

- **What it is:** A Debian-based Linux distribution specifically designed for digital forensics and penetration testing.
- **Role in Project:** Acts as the "red team" attacker node, providing the environment and tools to launch attacks.
- **Advantages:**
  - **Tool Suite:** Comes pre-packaged with thousands of security tools (`nmap`, `metasploit`, `hydra`, `hping3`), eliminating the need for manual installation.
  - **Rolling Release:** Always has the latest versions of tools and exploits.
- **Limitations:**
  - **Size:** The Docker image is relatively large.
  - **Noise:** Some tools in Kali are "noisy" and easily detected by IDS (which is actually good for this project).

### Filebeat (The Shipper)

- **What it is:** A lightweight shipper for forwarding and centralizing log data from the Elastic Stack.
- **Role in Project:** Reads Suricata's `eve.json` log file and ships the events to Elasticsearch for indexing.
- **Advantages:**
  - **Lightweight:** Uses minimal memory and CPU.
  - **Reliability:** Supports "backpressure"—if Elasticsearch is busy, Filebeat slows down reading logs so data isn't lost.
- **Limitations:**
  - **Processing Power:** It is primarily a shipper. It cannot perform complex data transformations or enrichment (Logstash is usually used for that).

---

## 2. Attack Scenarios & Libraries

The attacks in this project were executed using standard penetration testing tools and scripts.

### 1. ICMP Ping

- **Description:** Connectivity test using the Internet Control Message Protocol (ICMP).
- **Tool/Library:** `ping` (part of `iputils` package).
- **How it works:** Uses raw sockets to construct an ICMP ECHO_REQUEST. If the target is live and not blocking ICMP, it replies with ECHO_REPLY.
- **IDS Detection:** Suricata detects the specific ICMP protocol headers.

### 2. Nmap Port Scan

- **Description:** scanning the target to find open ports (services).
- **Tool/Library:** `nmap` (Network Mapper).
- **How it works:** We used `nmap -sS` (SYN Scan). It sends a TCP SYN packet.
  - If Target replies `SYN-ACK` -> Port is **OPEN**.
  - If Target replies `RST` -> Port is **CLOSED**.
  - This is stealthier than a full TCP connection because it doesn't complete the handshake.
- **IDS Detection:** Suricata counts the number of SYN packets from a single source within a short time window.

### 3. SYN Flood (Denial of Service)

- **Description:** Attempting to exhaust server resources to make it unresponsive.
- **Tool/Library:** `hping3` (Packet Generator & Analyzer).
- **How it works:** `hping3` allows crafting raw TCP/IP packets. It sends thousands of SYN packets with spoofed or random source IPs. The server opens a "connection state" for each, waiting for an ACK that never comes, exhausting system RAM/connection table.
- **IDS Detection:** Suricata detects an abnormal rate of SYN packets without corresponding ACK packets.

### 4. Web Application Attacks (HTTP)

These attacks target the application logic rather than the network stack.

- **Tool/Library:** `curl` (Client URL command line tool, built on `libcurl`) and **Bash** scripting.

#### A. Suspicious Access & Brute Force

- **Attack:** Repeatedly trying to access `/admin`, `/login`, or guessing passwords.
- **Library:** Bash `for` loops are used to automate `curl` requests rapidly.
- **How it works:** `curl -X POST -d "user=admin&pass=123" ...` sends standard HTTP POST requests. Suricata counts the frequency of requests to the sensitive `/login` endpoint.

#### B. SQL Injection (SQLi)

- **Attack:** Injecting malicious SQL commands into input fields.
- **Payloads:** `UNION SELECT`, `OR 1=1`, `DROP TABLE`.
- **How it works:** The attacker hopes the backend code concatenates this input directly into a database query.
  - _Normal:_ `SELECT * FROM users WHERE name = '$input'`
  - _Injected:_ `SELECT * FROM users WHERE name = '' OR 1=1` (Always True -> logs you in).
- **IDS Detection:** Suricata looks for specific keywords (`UNION`, `SELECT`, `OR`) and regex patterns in the HTTP URI or Body.

#### C. Directory Traversal

- **Attack:** Trying to access files outside the web root.
- **Payloads:** `../`, `../../etc/passwd`, `%2e%2e%2f` (URL encoded).
- **How it works:** Exploits improper file path validation. If successful, `curl` would download the contents of specific system files.
- **IDS Detection:** Suricata looks for the `../` pattern or its encoded variants in the HTTP URI.
