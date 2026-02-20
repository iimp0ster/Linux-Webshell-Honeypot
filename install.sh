#!/bin/bash
# Linux Webshell Honeypot - Automated Installation Script
# https://github.com/iimp0ster/Linux-Webshell-Honeypot

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

GITHUB_RAW="https://raw.githubusercontent.com/iimp0ster/Linux-Webshell-Honeypot/main"
INSTALL_DIR="/opt/sigma-lab"

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
read -rp "Enter your username (will be created if it doesn't exist): " USERNAME
read -rs -p "Enter password for dashboard: " DASHBOARD_PASS
echo ""
echo ""

# Validate inputs
if [[ -z "$USERNAME" || -z "$DASHBOARD_PASS" ]]; then
    echo "Error: Username and password cannot be empty"
    exit 1
fi

# Validate username is safe for shell use (alphanumeric + underscore/hyphen)
if [[ ! "$USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Username must contain only alphanumeric characters, underscores, or hyphens"
    exit 1
fi

# Update system
echo "[1/10] Updating system..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

# Create user if doesn't exist
if ! id "$USERNAME" &>/dev/null; then
    echo "[2/10] Creating user $USERNAME..."
    adduser --disabled-password --gecos "" "$USERNAME"
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
    usermod -aG docker "$USERNAME"
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
    UBUNTU_VER=$(lsb_release -rs)
    wget -q "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VER}/packages-microsoft-prod.deb"
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
mkdir -p "${INSTALL_DIR}"/{honeypot/webroot/uploads,logs/{apache,honeypot},sigma_rules,dashboard,sample_webshells}

# Download project files from GitHub
echo "[7/10] Downloading project files..."

download_file() {
    local url="$1"
    local dest="$2"
    if ! curl -sSfL "$url" -o "$dest"; then
        echo "ERROR: Failed to download $url" >&2
        exit 1
    fi
}

download_file "${GITHUB_RAW}/docker-compose.yml"                                   "${INSTALL_DIR}/docker-compose.yml"
download_file "${GITHUB_RAW}/honeypot/webroot/index.php"                           "${INSTALL_DIR}/honeypot/webroot/index.php"
download_file "${GITHUB_RAW}/dashboard/Dockerfile"                                 "${INSTALL_DIR}/dashboard/Dockerfile"
download_file "${GITHUB_RAW}/dashboard/sigma_dashboard.py"                         "${INSTALL_DIR}/dashboard/sigma_dashboard.py"
download_file "${GITHUB_RAW}/dashboard/requirements.txt"                           "${INSTALL_DIR}/dashboard/requirements.txt"
download_file "${GITHUB_RAW}/sample_webshells/simple_shell.php"                    "${INSTALL_DIR}/sample_webshells/simple_shell.php"
download_file "${GITHUB_RAW}/sample_webshells/china_chopper.php"                   "${INSTALL_DIR}/sample_webshells/china_chopper.php"
download_file "${GITHUB_RAW}/sample_webshells/wso_shell.php"                       "${INSTALL_DIR}/sample_webshells/wso_shell.php"
download_file "${GITHUB_RAW}/sample_webshells/b374k_mini.php"                      "${INSTALL_DIR}/sample_webshells/b374k_mini.php"
download_file "${GITHUB_RAW}/sigma_rules/webshell_upload.yml"                      "${INSTALL_DIR}/sigma_rules/webshell_upload.yml"
download_file "${GITHUB_RAW}/sigma_rules/command_execution.yml"                    "${INSTALL_DIR}/sigma_rules/command_execution.yml"
download_file "${GITHUB_RAW}/sigma_rules/network_connection.yml"                   "${INSTALL_DIR}/sigma_rules/network_connection.yml"

# Write dashboard password to .env file (avoids sed special-character injection)
echo "DASHBOARD_PASSWORD=${DASHBOARD_PASS}" > "${INSTALL_DIR}/.env"
chmod 600 "${INSTALL_DIR}/.env"

echo "[8/10] Configuring auditd..."
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
chmod -R 755 "${INSTALL_DIR}"
# uploads dir: web server needs to write; group-writable is enough
chmod 775 "${INSTALL_DIR}/honeypot/webroot/uploads"
chmod 775 "${INSTALL_DIR}/logs/honeypot"
chown -R "$USERNAME:$USERNAME" "${INSTALL_DIR}"

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
cd "${INSTALL_DIR}"
docker-compose --env-file .env up -d --build

# Wait for containers to start
sleep 15

# Get public IP
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Honeypot URL: http://$PUBLIC_IP"
echo "Dashboard:    SSH tunnel required"
echo ""
echo "From your local machine, run:"
echo "  ssh -L 8501:localhost:8501 ${USERNAME}@${PUBLIC_IP}"
echo ""
echo "Then browse to: http://localhost:8501"
echo "Password stored in: ${INSTALL_DIR}/.env"
echo ""
echo "Sample webshells are pre-loaded at:"
echo "  http://$PUBLIC_IP/samples/"
echo ""
echo "Start writing Sigma rules immediately!"
echo "Real attacks typically appear within 24-48 hours."
echo ""
echo "Documentation: https://github.com/iimp0ster/Linux-Webshell-Honeypot"
echo ""
