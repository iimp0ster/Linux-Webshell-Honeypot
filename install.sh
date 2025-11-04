#!/bin/bash
# Sigma Honeypot Lab - Automated Installation Script
# https://github.com/YOUR_USERNAME/sigma-honeypot-lab

set -e  # Exit on any error

echo "=========================================="
echo "  Sigma Detection Lab - Automated Setup  "
echo "=========================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Get username
read -p "Enter your username (will be created if doesn't exist): " USERNAME
read -s -p "Enter password for dashboard: " DASHBOARD_PASS
echo ""
echo ""

# Validate inputs
if [ -z "$USERNAME" ] || [ -z "$DASHBOARD_PASS" ]; then
    echo "Error: Username and password cannot be empty"
    exit 1
fi

# Update system
echo "[1/10] Updating system..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

# Create user if doesn't exist
if ! id "$USERNAME" &>/dev/null; then
    echo "[2/10] Creating user $USERNAME..."
    adduser --disabled-password --gecos "" $USERNAME
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
else
    echo "[2/10] User $USERNAME already exists, skipping..."
fi

# Install Docker
echo "[3/10] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    usermod -aG docker $USERNAME
    rm get-docker.sh
else
    echo "Docker already installed, skipping..."
fi

# Install dependencies
echo "[4/10] Installing dependencies..."
apt-get install -y -qq docker-compose auditd audispd-plugins wget curl

# Install Sysmon for Linux
echo "[5/10] Installing Sysmon for Linux..."
if ! command -v sysmon &> /dev/null; then
    wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
    dpkg -i packages-microsoft-prod.deb
    apt-get update -qq
    apt-get install -y -qq sysmonforlinux
    wget -q https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export-linux.xml -O /etc/sysmon-config.xml
    sysmon -accepteula -i /etc/sysmon-config.xml
    rm packages-microsoft-prod.deb
else
    echo "Sysmon already installed, skipping..."
fi

# Create directory structure
echo "[6/10] Creating project directories..."
mkdir -p /opt/sigma-lab/{honeypot/webroot/uploads,logs/{apache,honeypot},sigma_rules,dashboard,parsed_logs,sample_webshells}

# Download project files from GitHub
echo "[7/10] Downloading project files..."
cd /opt/sigma-lab

# Download docker-compose.yml
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/docker-compose.yml -o docker-compose.yml

# Download honeypot files
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/honeypot/webroot/index.php -o honeypot/webroot/index.php

# Download dashboard files
mkdir -p dashboard
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/dashboard/Dockerfile -o dashboard/Dockerfile
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/dashboard/sigma_dashboard.py -o dashboard/sigma_dashboard.py

# Download sample webshells
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sample_webshells/simple_shell.php -o sample_webshells/simple_shell.php
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sample_webshells/china_chopper.php -o sample_webshells/china_chopper.php
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sample_webshells/wso_shell.php -o sample_webshells/wso_shell.php
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sample_webshells/b374k_mini.php -o sample_webshells/b374k_mini.php

# Download example Sigma rules
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sigma_rules/webshell_upload.yml -o sigma_rules/webshell_upload.yml
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sigma_rules/command_execution.yml -o sigma_rules/command_execution.yml
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/sigma_rules/network_connection.yml -o sigma_rules/network_connection.yml

# Update docker-compose with password
sed -i "s/DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=$DASHBOARD_PASS/" docker-compose.yml

echo "[8/10] Configuring auditd..."
# Configure auditd rules
cat > /etc/audit/rules.d/webshell.rules <<'AUDITEOF'
-w /opt/sigma-lab/honeypot/webroot/uploads/ -p wa -k webshell_upload
-a always,exit -F arch=b64 -S execve -k command_execution
-w /usr/bin/wget -p x -k webshell_download
-w /usr/bin/curl -p x -k webshell_download
-w /bin/bash -p x -k shell_execution
AUDITEOF
service auditd restart

# Set permissions
echo "[9/10] Setting permissions..."
chmod -R 755 /opt/sigma-lab
chmod 777 /opt/sigma-lab/honeypot/webroot/uploads
chmod 777 /opt/sigma-lab/logs/honeypot
chown -R $USERNAME:$USERNAME /opt/sigma-lab

# Configure firewall
echo "[10/10] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force reset
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw --force enable
fi

# Deploy containers
echo ""
echo "Deploying containers..."
cd /opt/sigma-lab
docker-compose up -d

# Wait for containers to start
sleep 10

# Get public IP
PUBLIC_IP=$(curl -s ifconfig.me || echo "YOUR_SERVER_IP")

echo ""
echo "=========================================="
echo "  ✓ Installation Complete!"
echo "=========================================="
echo ""
echo "Honeypot URL: http://$PUBLIC_IP"
echo "Dashboard: SSH tunnel required"
echo ""
echo "From your local machine, run:"
echo "  ssh -L 8501:localhost:8501 $USERNAME@$PUBLIC_IP"
echo ""
echo "Then browse to: http://localhost:8501"
echo "Password: $DASHBOARD_PASS"
echo ""
echo "Sample webshells are pre-loaded at:"
echo "  http://$PUBLIC_IP/samples/"
echo ""
echo "Start writing Sigma rules immediately!"
echo "Real attacks will appear within 24-48 hours."
echo ""
echo "Documentation: https://github.com/YOUR_USERNAME/sigma-honeypot-lab"
echo ""
