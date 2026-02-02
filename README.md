# Automated Attack Script

## Overview

This script automates all attack scenarios for the Network Security Project.

## What It Does

The script automatically executes **7 comprehensive attack scenarios**:

### 1. ICMP Ping Detection

- Sends ping requests to test network connectivity
- Detects basic reconnaissance activities
- **Rule IDs:** 1000001

### 2. Nmap Port Scanning

- Scans ports 1-1000 for reconnaissance detection
- Identifies port scanning patterns
- **Rule IDs:** 1000002

### 3. SYN Flood Attack

- Simulates DoS-style traffic for 15 seconds
- Tests resistance to volumetric attacks
- High-speed packet flooding

### 4. Suspicious HTTP Access

- Tests unauthorized access to admin, login, and sensitive paths
- Attempts to access .env and config.php files
- **Rule IDs:** 1000003, 1000004

### 5. SQL Injection Attempts ⚠️ NEW

- **UNION SELECT** - Attempts to extract data from database
- **OR 1=1** - Bypasses authentication logic
- **DROP TABLE** - Destructive database commands
- **Rule IDs:** 1000005, 1000006, 1000007

### 6. Directory Traversal Attacks ⚠️ NEW

- **Basic traversal** - Uses `../` to access parent directories
- **Encoded traversal** - URL-encoded path traversal (`%2e%2e%2f`)
- **/etc/passwd access** - Attempts to read sensitive system files
- **Rule IDs:** 1000008, 1000009, 1000010

### 7. Brute Force Login ⚠️ NEW

- Simulates 15 rapid login attempts
- Tests authentication rate limiting
- Threshold-based detection (10+ attempts in 30 seconds)
- **Rule IDs:** 1000011, 1000012

## Usage

### Step 1: Start Your Docker Environment

```bash
docker compose up -d
```

Wait 10-15 seconds for all containers to be ready.

### Step 2: Run the Attack Script

```bash
docker exec attacker bash /attacker/run_attacks.sh
```

**Alternative:** Copy and paste inside the attacker container:

```bash
# First, enter the attacker container
docker exec -it attacker bash

# Then run the script
bash /attacker/run_attacks.sh
```

## What to Expect

The script will:

- ✅ Automatically install required tools (nmap, hping3, curl)
- ✅ Discover the web server IP address
- ✅ Execute all **7 attack scenarios** sequentially
- ✅ Display colored output for each attack phase
- ✅ Show completion status with summary

**Estimated Time:** ~60-75 seconds

## Viewing Results

After the attacks complete, you can:

### View Suricata Fast Log (Quick Summary)

```bash
docker exec suricata cat /var/log/suricata/fast.log
```

### View Suricata EVE JSON (Detailed)

```bash
docker exec suricata cat /var/log/suricata/eve.json | tail -50
```

### View in Kibana Dashboard (Visual Analytics)

Open your browser: `http://localhost:5601`

## Troubleshooting

**Problem:** "Could not find web server"

- **Solution:** Make sure docker-compose is running: `docker compose up -d`

**Problem:** "Permission denied"

- **Solution:** Make script executable: `chmod +x attacker/run_attacks.sh`

**Problem:** "hping3: command not found"

- **Solution:** The script auto-installs tools, but you can manually install:
  ```bash
  docker exec -it attacker bash
  apt update && apt install -y nmap hping3 curl
  ```

## Expected Suricata Detections

You should see alerts for all **12 detection rules**:

### Network-Level Attacks

- ✅ **ICMP Ping Detected** (sid:1000001)
- ✅ **Potential Nmap Scan** (sid:1000002)

### HTTP-Level Attacks

- ✅ **Suspicious Admin Access Attempt** (sid:1000003)
- ✅ **Suspicious Login Access Attempt** (sid:1000004)

### SQL Injection Attacks

- ✅ **SQL Injection Attack Detected** (sid:1000005)
- ✅ **SQL Injection Attack Detected - OR 1=1** (sid:1000006)
- ✅ **SQL Injection Attack Detected - DROP TABLE** (sid:1000007)

### Directory Traversal Attacks

- ✅ **Directory Traversal Attack Detected** (sid:1000008)
- ✅ **Directory Traversal Attack Detected - Encoded** (sid:1000009)
- ✅ **Directory Traversal Attack - /etc/passwd** (sid:1000010)

### Brute Force Attacks

- ✅ **Brute Force Attack - Multiple Login Attempts** (sid:1000011)
- ✅ **Brute Force Attack - Multiple Failed Auth** (sid:1000012)

## Attack Timing

The automated script includes strategic pauses between attacks to ensure:

- Proper packet capture
- Clear separation in logs
- Suricata processing time
- Easier analysis of results
