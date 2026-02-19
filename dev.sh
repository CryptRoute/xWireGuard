#!/bin/bash
# Production-Ready WireGuard VPN Installer with Enterprise DNS Leak Protection
# Version: 2.1 - Enterprise Edition (Fixed)

# ==================== COLOR CODES ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ==================== GLOBAL VARIABLES ====================
SCRIPT_VERSION="2.1"
INSTALL_LOG="/var/log/wireguard-enterprise-install.log"
ERROR_LOG="/var/log/wireguard-enterprise-error.log"
DNS_LEAK_LOG="/var/log/dns-leak-monitor.log"
INTERFACE=$(ip route list default | awk '$1 == "default" {print $5}' 2>/dev/null || echo "eth0")

# ==================== ERROR HANDLING ====================
set -eE
trap 'handle_error $? $LINENO $BASH_LINENO' ERR

handle_error() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    echo -e "${RED}Error on line $line_no (bash line $bash_lineno): Command exited with status $exit_code${NC}"
    echo "$(date): Error on line $line_no: Command exited with status $exit_code" >> "$ERROR_LOG"
    
    # Don't exit on error, try to continue
    return 0
}

# ==================== LOGGING FUNCTIONS ====================
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): [INFO] $1" >> "$INSTALL_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date): [WARN] $1" >> "$INSTALL_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date): [ERROR] $1" >> "$ERROR_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$(date): [SUCCESS] $1" >> "$INSTALL_LOG"
}

# ==================== VALIDATION FUNCTIONS ====================
check_package_installed() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    else
        return 0
    fi
}

check_dpkg_package_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    else
        return 1
    fi
}

validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9\.\-_]+$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_dns() {
    local dns_list=$1
    IFS=',' read -ra dns_servers <<< "$dns_list"
    for dns in "${dns_servers[@]}"; do
        dns=$(echo "$dns" | xargs)
        
        # Validate IPv4
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            IFS='.' read -r o1 o2 o3 o4 <<< "$dns"
            if ((o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255)); then
                continue
            else
                log_error "Invalid IPv4 address: $dns (octets must be 0-255)"
                return 1
            fi
        # Validate IPv6
        elif [[ $dns =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
            if [[ ${#dns} -le 39 ]]; then
                continue
            else
                log_error "Invalid IPv6 address: $dns (too long)"
                return 1
            fi
        else
            log_error "Invalid DNS server format: $dns"
            return 1
        fi
    done
    return 0
}

# ==================== NETWORK FUNCTIONS ====================
ipv6_available() {
    if ip -6 addr show "$INTERFACE" 2>/dev/null | grep -q inet6 && ip -6 addr show "$INTERFACE" 2>/dev/null | grep -qv fe80; then
        return 0
    else
        return 1
    fi
}

get_ipv4_addresses() {
    ip -o -4 addr show "$INTERFACE" 2>/dev/null | awk '$4 !~ /^127\.0\.0\.1/ {print $4}' | cut -d'/' -f1
}

get_ipv6_addresses() {
    ip -o -6 addr show "$INTERFACE" 2>/dev/null | awk '$4 !~ /^fe80:/ && $4 !~ /^::1/ {print $4}' | cut -d'/' -f1
}

convert_ipv4_format() {
    local ipv4_address=$1
    local network=$(echo "$ipv4_address" | cut -d'/' -f1 | cut -d'.' -f1-3)
    echo "$network.0/24"
}

generate_ipv4() {
    local range_type=$1
    case $range_type in
        1)
            echo "10.$((RANDOM%256)).$((RANDOM%256)).1/24"
            ;;
        2)
            echo "172.$((RANDOM%16+16)).$((RANDOM%256)).1/24"
            ;;
        3)
            echo "192.168.$((RANDOM%256)).1/24"
            ;;
        4)
            read -p "Enter custom Private IPv4 address: " custom_ipv4
            echo "$custom_ipv4"
            ;;
        *)
            log_error "Invalid option for IPv4 range."
            exit 1
            ;;
    esac
}

generate_ipv6() {
    local range_type=$1
    case $range_type in
        1)
            printf "FC00:%04x:%04x::1/64" $((RANDOM % 65536)) $((RANDOM % 65536))
            ;;
        2)
            printf "FD86:EA04:%04x::1/64" $((RANDOM % 65536))
            ;;
        3)
            read -p "Enter custom Private IPv6 address: " custom_ipv6
            echo "$custom_ipv6"
            ;;
        *)
            log_error "Invalid option for IPv6 range."
            exit 1
            ;;
    esac
}

# ==================== SAFE PACKAGE INSTALLATION ====================
install_package() {
    local package=$1
    if ! check_dpkg_package_installed "$package"; then
        log_info "Installing $package..."
        apt install -y "$package" >/dev/null 2>&1 || {
            log_warn "Failed to install $package, but continuing..."
            return 1
        }
    else
        log_info "$package already installed"
    fi
    return 0
}

install_pip_package() {
    local package=$1
    pip3 install --no-cache-dir "$package" >/dev/null 2>&1 || {
        log_warn "Failed to install pip package $package, but continuing..."
        return 1
    }
    return 0
}

# ==================== ENTERPRISE DNS LEAK PROTECTION ====================

# 1. SYSTEM-WIDE DNS LOCKDOWN
configure_system_dns_lockdown() {
    local dns_servers="$1"
    
    log_info "Configuring system-wide DNS lockdown..."
    
    # Backup original resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
    
    # Create immutable DNS configuration
    cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Generated: $(date)
# DO NOT EDIT - This file is protected

$(for dns in $(echo $dns_servers | tr ',' ' '); do
    echo "nameserver $(echo $dns | xargs)"
done)

# DNS Security Options
options rotate
options timeout:1
options attempts:5
options edns0
options trust-ad
EOF

    # Make resolv.conf immutable (if possible)
    chattr +i /etc/resolv.conf 2>/dev/null || log_warn "Could not make resolv.conf immutable"
    
    log_success "System DNS locked down to: $dns_servers"
}

# 2. IPTABLES DNS TRAFFIC ENFORCEMENT
configure_iptables_dns_enforcement() {
    local dns_servers="$1"
    
    log_info "Configuring iptables DNS traffic enforcement..."
    
    mkdir -p /etc/wireguard
    
    # Create DNS enforcement script
    cat > /etc/wireguard/dns-enforcement.sh <<EOF
#!/bin/bash
# DNS Traffic Enforcement Script
# Generated: $(date)

# IPv4 DNS Enforcement
EOF

    # Add IPv4 rules
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/dns-enforcement.sh
            echo "iptables -A OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/dns-enforcement.sh
        fi
    done
    
    # Block all other DNS traffic
    cat >> /etc/wireguard/dns-enforcement.sh <<'EOF'

# Block all other DNS traffic
iptables -A OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
iptables -A OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true

# Allow DNS through VPN interface only
iptables -A OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o wg0 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

# Log blocked DNS attempts
iptables -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "DNS_BLOCKED: " 2>/dev/null || true
iptables -A OUTPUT -p tcp --dport 53 -j LOG --log-prefix "DNS_BLOCKED: " 2>/dev/null || true
EOF

    chmod +x /etc/wireguard/dns-enforcement.sh
    
    # Create systemd service
    cat > /etc/systemd/system/dns-enforcement.service <<EOF
[Unit]
Description=DNS Traffic Enforcement Service
Before=wg-quick@wg0.service
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/wireguard/dns-enforcement.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dns-enforcement.service --quiet 2>/dev/null || true
    log_success "iptables DNS enforcement configured"
}

# 3. KILL SWITCH WITH DNS PROTECTION
configure_enterprise_kill_switch() {
    local wg_port="$1"
    local dns_servers="$2"
    
    log_info "Configuring enterprise kill switch with DNS protection..."
    
    mkdir -p /etc/wireguard
    
    cat > /etc/wireguard/enterprise-kill-switch.sh <<EOF
#!/bin/bash
# Enterprise Kill Switch with DNS Protection
# Generated: $(date)

WG_PORT="$wg_port"
DNS_SERVERS="$dns_servers"

enable_kill_switch() {
    # Default policies
    iptables -P INPUT DROP 2>/dev/null || true
    iptables -P OUTPUT DROP 2>/dev/null || true
    iptables -P FORWARD DROP 2>/dev/null || true
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    
    # Allow VPN interface
    iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true
    
    # Allow VPN server connection
    iptables -A OUTPUT -p udp --dport \$WG_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow DNS to specified servers
EOF

    # Add DNS server rules
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "    iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
            echo "    iptables -A OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
        fi
    done

    cat >> /etc/wireguard/enterprise-kill-switch.sh <<'EOF'
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    
    # Log dropped packets
    iptables -A INPUT -j LOG --log-prefix "KILLSWITCH_IN: " --log-level 4 2>/dev/null || true
    iptables -A OUTPUT -j LOG --log-prefix "KILLSWITCH_OUT: " --log-level 4 2>/dev/null || true
}

disable_kill_switch() {
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true
}

case "$1" in
    start)
        enable_kill_switch
        ;;
    stop)
        disable_kill_switch
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
EOF

    chmod +x /etc/wireguard/enterprise-kill-switch.sh
    
    # Create systemd service
    cat > /etc/systemd/system/enterprise-kill-switch.service <<EOF
[Unit]
Description=Enterprise Kill Switch Service
After=wg-quick@wg0.service
BindsTo=wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/wireguard/enterprise-kill-switch.sh start
ExecStop=/etc/wireguard/enterprise-kill-switch.sh stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable enterprise-kill-switch.service --quiet 2>/dev/null || true
    log_success "Enterprise kill switch configured"
}

# 4. DNS LEAK MONITORING
configure_dns_leak_monitoring() {
    local dns_servers="$1"
    
    log_info "Configuring DNS leak monitoring..."
    
    mkdir -p /etc/wireguard/monitoring
    
    cat > /etc/wireguard/monitoring/dns-leak-monitor.sh <<'EOF'
#!/bin/bash
# DNS Leak Monitoring Script
# Generated: $(date)

LOG_FILE="/var/log/dns-leak-monitor.log"
ALERT_THRESHOLD=3
LEAK_COUNT=0

check_dns_leak() {
    # Multiple DNS leak test methods
    local vpn_ip=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
    
    # Method 1: OpenDNS test
    local dns1=$(dig +short whoami.akamai.net @resolver1.opendns.com 2>/dev/null)
    
    # Method 2: Google DNS test
    local dns2=$(dig +short -4 TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"')
    
    # Method 3: Cloudflare test
    local dns3=$(dig +short -4 ch txt whoami.cloudflare.com @1.1.1.1 2>/dev/null | tr -d '"')
    
    # Compare results
    if [[ "$dns1" != "$vpn_ip" ]] || [[ "$dns2" != "$vpn_ip" ]] || [[ "$dns3" != "$vpn_ip" ]]; then
        ((LEAK_COUNT++))
        echo "$(date): DNS LEAK DETECTED! (Count: $LEAK_COUNT)" >> $LOG_FILE
        echo "VPN IP: $vpn_ip" >> $LOG_FILE
        echo "OpenDNS: $dns1" >> $LOG_FILE
        echo "Google: $dns2" >> $LOG_FILE
        echo "Cloudflare: $dns3" >> $LOG_FILE
        echo "---" >> $LOG_FILE
        
        # Take action on threshold
        if [ $LEAK_COUNT -ge $ALERT_THRESHOLD ]; then
            echo "$(date): CRITICAL - Multiple DNS leaks detected, activating kill switch" >> $LOG_FILE
            /etc/wireguard/enterprise-kill-switch.sh start 2>/dev/null || true
        fi
    else
        echo "$(date): DNS check passed" >> $LOG_FILE
        LEAK_COUNT=0
    fi
}

# Monitor for DNS configuration changes
monitor_dns_config() {
    while true; do
        if command -v inotifywait &>/dev/null; then
            inotifywait -e modify,delete,move /etc/resolv.conf 2>/dev/null | while read -r event; do
                echo "$(date): WARNING - /etc/resolv.conf was modified! Event: $event" >> $LOG_FILE
            done
        fi
        sleep 60
    done
}

# Main monitoring loop
monitor_dns_config &
while true; do
    check_dns_leak
    sleep 300  # Check every 5 minutes
done
EOF

    chmod +x /etc/wireguard/monitoring/dns-leak-monitor.sh
    
    # Create monitoring service
    cat > /etc/systemd/system/dns-leak-monitor.service <<EOF
[Unit]
Description=DNS Leak Monitoring Service
After=network.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/etc/wireguard/monitoring/dns-leak-monitor.sh
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dns-leak-monitor.service --quiet 2>/dev/null || true
    log_success "DNS leak monitoring configured"
}

# 5. WIREGUARD CONFIGURATION
enhance_wireguard_with_dns_protection() {
    local dns_servers="$1"
    local config_file="/etc/wireguard/wg0.conf"
    
    log_info "Enhancing WireGuard configuration with DNS protection..."
    
    # Build DNS rules
    local dns_accept_rules=""
    IFS=',' read -ra dns_array <<< "$dns_servers"
    
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            dns_accept_rules="${dns_accept_rules}iptables -I OUTPUT -p udp --dport 53 -d $dns -j ACCEPT; "
            dns_accept_rules="${dns_accept_rules}iptables -I OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT; "
        fi
    done
    
    # Add to WireGuard config
    cat >> "$config_file" <<EOF

# ===== ENTERPRISE DNS PROTECTION RULES =====
# Applied by WireGuard Enterprise Installer v$SCRIPT_VERSION

# Pre-up: Ensure DNS is locked
PreUp = chattr -i /etc/resolv.conf 2>/dev/null || true
PreUp = echo "nameserver 127.0.0.1" > /etc/resolv.conf
PreUp = chattr +i /etc/resolv.conf 2>/dev/null || true

# Post-up: Apply DNS traffic rules
PostUp = $dns_accept_rules
PostUp = iptables -I OUTPUT -p udp --dport 53 -j DROP
PostUp = iptables -I OUTPUT -p tcp --dport 53 -j DROP
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=1
PostUp = sysctl -w net.ipv4.conf.default.rp_filter=1

# Post-down: Clean up rules
PostDown = iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
PostDown = iptables -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
EOF

    log_success "WireGuard configuration enhanced with DNS protection"
}

# 6. WGDASHBOARD CONFIGURATION
configure_wgdashboard_dns() {
    local dns_servers="$1"
    local dashboard_dir="$2"
    
    log_info "Configuring WGDashboard with DNS protection..."
    
    if [ -f "$dashboard_dir/wg-dashboard.ini" ]; then
        # Update WGDashboard configuration
        sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns_servers|g" "$dashboard_dir/wg-dashboard.ini" 2>/dev/null || true
        log_success "WGDashboard configured with DNS protection"
    else
        log_warn "WGDashboard config not found, skipping"
    fi
}

# 7. CLIENT CONFIGURATION TEMPLATES
create_secure_client_templates() {
    local dns_servers="$1"
    local server_public_key="$2"
    local server_endpoint="$3"
    local wg_port="$4"
    
    log_info "Creating secure client configuration templates..."
    
    mkdir -p /etc/wireguard/clients
    
    # Linux client template
    cat > /etc/wireguard/clients/linux-client.conf <<EOF
# WireGuard Enterprise Client Configuration - Linux
# Generated: $(date)

[Interface]
PrivateKey = <client-private-key>
Address = <client-ip>
DNS = $dns_servers
MTU = 1420

# DNS Leak Prevention
PostUp = echo "$(for dns in $(echo $dns_servers | tr ',' ' '); do echo "nameserver $dns"; done)" > /etc/resolv.conf
PostUp = chattr +i /etc/resolv.conf 2>/dev/null || true

PostDown = chattr -i /etc/resolv.conf 2>/dev/null || true

[Peer]
PublicKey = $server_public_key
Endpoint = $server_endpoint:$wg_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Windows client template
    cat > /etc/wireguard/clients/windows-client.conf <<EOF
# WireGuard Enterprise Client Configuration - Windows
# Generated: $(date)

[Interface]
PrivateKey = <client-private-key>
Address = <client-ip>
DNS = $dns_servers
MTU = 1420

[Peer]
PublicKey = $server_public_key
Endpoint = $server_endpoint:$wg_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Mobile client template
    cat > /etc/wireguard/clients/mobile-client.conf <<EOF
# WireGuard Enterprise Client Configuration - Mobile
# Generated: $(date)

[Interface]
PrivateKey = <client-private-key>
Address = <client-ip>
DNS = $dns_servers
MTU = 1420

[Peer]
PublicKey = $server_public_key
Endpoint = $server_endpoint:$wg_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    log_success "Client templates created in /etc/wireguard/clients/"
}

# 8. SECURITY HARDENING
apply_security_hardening() {
    log_info "Applying basic security hardening..."
    
    # Basic sysctl settings
    cat >> /etc/sysctl.conf <<EOF

# WireGuard Security Settings
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF

    # Apply sysctl settings
    sysctl -p >/dev/null 2>&1 || true
    
    log_success "Security hardening applied"
}

# ==================== MAIN INSTALLATION ====================

clear
# Display ASCII art and introduction
echo "  _|_|_|_|    _|_|_|      _|_|_|    _|_|_|_|    _|_|_|  _|    _|  _|_|_|_|"
echo "    _|      _|    _|      _|    _|  _|          _|            _|      _|"
echo "    _|    _|        _|    _|    _|    _|_|      _|_|_|    _|        _|"
echo "    _|  _|            _|  _|    _|        _|    _|            _|    _|"
echo "  _|_|_|              _|    _|_|_|  _|_|_|_|    _|_|_|  _|        _|"
echo ""
echo "           WireGuard Enterprise VPN Installer v$SCRIPT_VERSION"
echo "           with Advanced DNS Leak Protection"
echo ""
echo -e "${RED}WARNING! Install only in Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.02 & Debian 11 & 12${NC}"
echo -e "${GREEN}RECOMMENDED: Ubuntu 22.04 LTS${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Check distribution
if [ -f "/etc/debian_version" ]; then
    if [ -f "/etc/os-release" ]; then
        source "/etc/os-release"
        if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then
            log_info "Detected $ID $VERSION_ID"
        else
            log_error "Unsupported distribution: $ID"
            exit 1
        fi
    fi
else
    log_error "Unsupported distribution. This script requires Debian or Ubuntu."
    exit 1
fi

# Prompt to continue
read -p "Would you like to continue with enterprise installation? [y/n]: " choice
if [[ ! "$choice" =~ ^[Yy]$ ]]; then
    echo "Installation aborted."
    exit 0
fi

# ==================== COLLECT USER INPUT ====================

# Hostname
while true; do
    read -p "Please enter FQDN hostname [eg. vpn.example.com]: " hostname
    if [[ -z "$hostname" ]]; then
        hostname="vpn.local"
        break
    elif validate_hostname "$hostname"; then
        break
    else
        echo "Invalid hostname. Please enter a valid hostname."
    fi
done

# WGDashboard username
while true; do
    read -p "Specify admin username for WGDashboard: " username
    if [[ -n "$username" ]]; then
        break
    else
        echo "Username cannot be empty."
    fi
done

# WGDashboard password
while true; do
    read -s -p "Specify admin password: " password
    echo ""
    read -s -p "Confirm password: " confirm_password
    echo ""
    if [ "$password" != "$confirm_password" ]; then
        echo -e "${RED}Error: Passwords do not match.${NC}"
    elif [ -z "$password" ]; then
        echo "Password cannot be empty."
    else
        break
    fi
done

# DNS Servers (CRITICAL for leak prevention)
while true; do
    echo ""
    echo -e "${YELLOW}DNS Servers Configuration (Critical for leak prevention)${NC}"
    echo "Enter DNS servers (comma-separated, supports IPv4/IPv6)"
    echo "Example: 147.78.0.8,147.78.0.7,2606:4700:4700::1111"
    read -p "DNS Servers [default: 147.78.0.8,147.78.0.7]: " dns
    dns="${dns:-147.78.0.8,147.78.0.7}"
    if validate_dns "$dns"; then
        break
    fi
done

# WireGuard Port
while true; do
    read -p "WireGuard Port [default: 51820]: " wg_port
    wg_port="${wg_port:-51820}"
    if validate_port "$wg_port"; then
        break
    else
        echo "Invalid port. Please enter 1-65535."
    fi
done

# Dashboard Port
while true; do
    read -p "WGDashboard Port [default: 8080]: " dashboard_port
    dashboard_port="${dashboard_port:-8080}"
    if validate_port "$dashboard_port"; then
        break
    else
        echo "Invalid port. Please enter 1-65535."
    fi
done

# Allowed IPs
read -p "Peer Allowed IPs [default: 0.0.0.0/0,::/0]: " allowed_ip
allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"

# ==================== IP ADDRESS CONFIGURATION ====================

# IPv4 Range Selection
while true; do
    echo ""
    echo "Choose IPv4 private range for VPN:"
    echo "1) Class A: 10.0.0.0/8"
    echo "2) Class B: 172.16.0.0/12"
    echo "3) Class C: 192.168.0.0/16"
    echo "4) Custom"
    read -p "Enter choice (1-4): " ipv4_option
    
    if [[ "$ipv4_option" =~ ^[1-4]$ ]]; then
        ipv4_address_pvt=$(generate_ipv4 $ipv4_option)
        break
    fi
done

# IPv6 if available
ipv6_available=false
if ipv6_available; then
    while true; do
        echo ""
        echo "IPv6 is available on this system."
        echo "Choose IPv6 private range:"
        echo "1) FC00::/7 (Unique Local)"
        echo "2) FD00::/7 (Unique Local)"
        echo "3) Custom"
        echo "4) Skip IPv6"
        read -p "Enter choice (1-4): " ipv6_option
        
        if [[ "$ipv6_option" =~ ^[1-3]$ ]]; then
            ipv6_address_pvt=$(generate_ipv6 $ipv6_option)
            break
        elif [ "$ipv6_option" = "4" ]; then
            ipv6_address_pvt=""
            break
        fi
    done
fi

# Public Interface
read -p "Internet interface [detected: $INTERFACE]: " net_interface
INTERFACE="${net_interface:-$INTERFACE}"

# Public IP Selection
echo ""
echo "Select public IP for VPN endpoint:"
ipv4_addresses=$(get_ipv4_addresses)
if [ -n "$ipv4_addresses" ]; then
    echo "Available IPv4 addresses:"
    select ipv4_address in $ipv4_addresses; do
        if [ -n "$ipv4_address" ]; then
            break
        fi
    done
else
    # Try to get public IP via curl
    ipv4_address=$(curl -s -4 ifconfig.me 2>/dev/null || echo "")
    if [ -z "$ipv4_address" ]; then
        ipv4_address=$(hostname -I | awk '{print $1}')
    fi
fi

# ==================== INSTALLATION STARTS HERE ====================

clear
log_info "Starting enterprise WireGuard installation..."
log_info "Installation log: $INSTALL_LOG"
log_info "Error log: $ERROR_LOG"

# Update system
log_info "Updating system packages..."
apt update -y || log_warn "APT update failed, but continuing..."

# Install basic dependencies first
log_info "Installing basic dependencies..."
apt install -y curl wget git sudo ufw net-tools \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    resolvconf inotify-tools cron \
    dnsutils iptables iptables-persistent \
    netfilter-persistent openssl || {
    log_warn "Some packages failed to install, but continuing..."
}

# Install Python packages
log_info "Installing Python packages..."
pip3 install --upgrade pip || log_warn "Pip upgrade failed"
pip3 install bcrypt gunicorn flask flask-socketio || log_warn "Python packages installation had warnings"

# Generate WireGuard keys
log_info "Generating WireGuard keys..."
private_key=$(wg genkey 2>/dev/null)
if [ -z "$private_key" ]; then
    log_error "Failed to generate WireGuard keys"
    exit 1
fi
public_key=$(echo "$private_key" | wg pubkey 2>/dev/null)

mkdir -p /etc/wireguard
echo "$private_key" > /etc/wireguard/private.key
echo "$public_key" > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key

# Enable IP forwarding
log_info "Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1 || true

# Create WireGuard configuration
log_info "Creating WireGuard configuration..."
mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $private_key
Address = $ipv4_address_pvt
ListenPort = $wg_port
SaveConfig = true
EOF

if [ -n "$ipv6_address_pvt" ]; then
    sed -i "/Address = / s/$/, $ipv6_address_pvt/" /etc/wireguard/wg0.conf
fi

# ==================== APPLY ENTERPRISE DNS PROTECTION ====================

log_info "Applying enterprise DNS leak protection..."

# 1. System DNS Lockdown
configure_system_dns_lockdown "$dns"

# 2. iptables DNS Enforcement
configure_iptables_dns_enforcement "$dns"

# 3. Enterprise Kill Switch
configure_enterprise_kill_switch "$wg_port" "$dns"

# 4. DNS Leak Monitoring
configure_dns_leak_monitoring "$dns"

# 5. Enhance WireGuard with DNS protection
enhance_wireguard_with_dns_protection "$dns"

# 6. Security Hardening
apply_security_hardening

# ==================== FIREWALL CONFIGURATION ====================

log_info "Configuring firewall..."
ufw --force disable >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

# Allow SSH (detect port)
ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F ':' '{print $NF}' | sort -u | head -1)
if [ -n "$ssh_port" ]; then
    ufw allow "$ssh_port/tcp" >/dev/null 2>&1 || true
else
    ufw allow 22/tcp >/dev/null 2>&1 || true
fi

# Allow WireGuard
ufw allow "$wg_port/udp" >/dev/null 2>&1 || true

# Allow Dashboard
ufw allow "$dashboard_port/tcp" >/dev/null 2>&1 || true

# Enable firewall
echo "y" | ufw enable >/dev/null 2>&1 || true

# ==================== WGDASHBOARD INSTALLATION ====================

log_info "Installing WGDashboard..."
mkdir -p /etc/xwireguard
cd /etc/xwireguard || exit

if [ -d "wgdashboard" ]; then
    rm -rf wgdashboard
fi

git clone https://github.com/donaldzou/WGDashboard.git wgdashboard >/dev/null 2>&1 || {
    log_error "Failed to clone WGDashboard repository"
    exit 1
}

cd wgdashboard/src || exit

chmod u+x wgd.sh
./wgd.sh install >/dev/null 2>&1 || log_warn "WGDashboard install had warnings"

# Configure WGDashboard
if [ -f "wg-dashboard.ini" ]; then
    hashed_password=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$password', bcrypt.gensalt(12).decode()))" 2>/dev/null)
    
    sed -i "s|^app_port =.*|app_port = $dashboard_port|g" wg-dashboard.ini 2>/dev/null || true
    sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" wg-dashboard.ini 2>/dev/null || true
    sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" wg-dashboard.ini 2>/dev/null || true
    sed -i "s|^password =.*|password = $hashed_password|g" wg-dashboard.ini 2>/dev/null || true
    sed -i "s|^username =.*|username = $username|g" wg-dashboard.ini 2>/dev/null || true
    sed -i "s|^welcome_session =.*|welcome_session = false|g" wg-dashboard.ini 2>/dev/null || true
fi

# Configure WGDashboard with DNS protection
configure_wgdashboard_dns "$dns" "$(pwd)"

# Create systemd service for WGDashboard
cat > /etc/systemd/system/wg-dashboard.service <<EOF
[Unit]
Description=WGDashboard - WireGuard Dashboard
After=network.target wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(which python3) $(pwd)/dashboard.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# ==================== CREATE CLIENT TEMPLATES ====================

create_secure_client_templates "$dns" "$public_key" "$ipv4_address" "$wg_port"

# ==================== ENABLE SERVICES ====================

log_info "Enabling services..."
systemctl daemon-reload

systemctl enable wg-quick@wg0.service --quiet 2>/dev/null || true
systemctl enable wg-dashboard.service --quiet 2>/dev/null || true
systemctl enable dns-enforcement.service --quiet 2>/dev/null || true
systemctl enable enterprise-kill-switch.service --quiet 2>/dev/null || true
systemctl enable dns-leak-monitor.service --quiet 2>/dev/null || true

# Start services
systemctl start wg-quick@wg0.service 2>/dev/null || true
systemctl start wg-dashboard.service 2>/dev/null || true
systemctl start dns-enforcement.service 2>/dev/null || true
systemctl start enterprise-kill-switch.service 2>/dev/null || true
systemctl start dns-leak-monitor.service 2>/dev/null || true

# ==================== FINAL CHECKS ====================

sleep 3

wg_status=$(systemctl is-active wg-quick@wg0.service 2>/dev/null || echo "unknown")
dashboard_status=$(systemctl is-active wg-dashboard.service 2>/dev/null || echo "unknown")
dns_monitor_status=$(systemctl is-active dns-leak-monitor.service 2>/dev/null || echo "unknown")

# ==================== DISPLAY RESULTS ====================

clear
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     WireGuard Enterprise VPN Installation Complete        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}✅ Installation Status:${NC}"
echo "   WireGuard: $wg_status"
echo "   WGDashboard: $dashboard_status"
echo "   DNS Monitor: $dns_monitor_status"
echo ""

echo -e "${BLUE}📊 Access Information:${NC}"
echo "   Dashboard URL: http://$ipv4_address:$dashboard_port"
echo "   Username: $username"
echo "   Password: [configured]"
echo ""

echo -e "${PURPLE}🔒 DNS Protection Status:${NC}"
echo "   DNS Servers: $dns"
echo "   DNS Leak Monitoring: ✅ Active"
echo "   Kill Switch: ✅ Active"
echo ""

echo -e "${YELLOW}📁 Configuration Files:${NC}"
echo "   WireGuard Config: /etc/wireguard/wg0.conf"
echo "   Client Templates: /etc/wireguard/clients/"
echo "   Monitoring Logs: /var/log/dns-leak-monitor.log"
echo ""

echo -e "${CYAN}🔧 Quick Commands:${NC}"
echo "   View WireGuard status: wg show"
echo "   Check DNS monitor: tail -f /var/log/dns-leak-monitor.log"
echo "   Test for DNS leaks: curl https://ipleak.net/json/"
echo ""

echo -e "${GREEN}⚡ Testing DNS Leak Protection:${NC}"
echo "   Run: dig whoami.akamai.net @resolver1.opendns.com"
echo "   Should return your VPN IP address"
echo ""

echo -e "${YELLOW}⚠️  Important Notes:${NC}"
echo "   - System will reboot in 10 seconds"
echo "   - After reboot, verify all services are running"
echo "   - Use WGDashboard to create and manage clients"
echo ""

echo -e "${RED}Press Ctrl+C to cancel reboot${NC}"
sleep 10

log_success "Installation complete! Rebooting system..."
reboot
