#!/bin/bash

# ==================== COLOR CODES ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ==================== GLOBAL VARIABLES ====================
SCRIPT_VERSION="2.2"
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
    return 0
}

# Function to check if a package is installed
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

# Function to validate the port number
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    else
        return 1
    fi
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

# ==================== DNS LEAK PROTECTION ====================

# 1. SYSTEM DNS LOCKDOWN
configure_system_dns_lockdown() {
    local dns_servers="$1"
    
    log_info "Configuring system-wide DNS lockdown..."
    
    chattr -i /etc/resolv.conf 2>/dev/null || true
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
    
    if [[ "$dns_servers" == "127.0.0.1" ]] || [[ "$dns_servers" == "127.0.0.1#5353" ]]; then
        cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Using local Unbound resolver
# Generated: $(date)
nameserver 127.0.0.1
options rotate
options timeout:1
options attempts:5
EOF
    else
        cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Generated: $(date)
$(for dns in $(echo $dns_servers | tr ',' ' '); do
    echo "nameserver $(echo $dns | xargs)"
done)
options rotate
options timeout:1
options attempts:5
EOF
    fi

    chattr +i /etc/resolv.conf 2>/dev/null || log_warn "Could not make resolv.conf immutable"
    log_success "System DNS locked down to: $dns_servers"
}

# 2. FIXED UNBOUND CONFIGURATION
configure_unbound_dns() {
    local dns_servers="$1"
    
    log_info "Installing and configuring Unbound DNS resolver..."
    
    # Kill any process using port 53
    fuser -k 53/tcp 53/udp 2>/dev/null || true
    
    # Stop all potential DNS services
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true
    systemctl stop unbound 2>/dev/null || true
    
    # Install Unbound
    DEBIAN_FRONTEND=noninteractive apt install -y unbound unbound-anchor dnsutils >/dev/null 2>&1
    
    # Backup original config
    [ -f /etc/unbound/unbound.conf ] && mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup
    
    # Create Unbound configuration with proper settings
    cat > /etc/unbound/unbound.conf <<EOF
# Unbound configuration for WireGuard Enterprise
# Generated: $(date)

server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2
    msg-cache-size: 50m
    rrset-cache-size: 100m
    outgoing-range: 4096
    qname-minimisation: yes
    verbosity: 1
    use-syslog: yes
    do-not-query-localhost: no
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # Root key location
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    
    # Disable DNSSEC for faster resolution (optional)
    # val-log-level: 2
    
forward-zone:
    name: "."
EOF

    # Add forwarders
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        echo "    forward-addr: $dns" >> /etc/unbound/unbound.conf
    done

    # Create root key directory and set permissions
    mkdir -p /var/lib/unbound
    chown -R unbound:unbound /var/lib/unbound
    
    # Generate root key
    unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || touch /var/lib/unbound/root.key
    chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
    
    # Set permissions
    chown -R unbound:unbound /etc/unbound
    
    # Start Unbound with proper service configuration
    systemctl daemon-reload
    
    # Mask resolved if it exists
    systemctl mask systemd-resolved 2>/dev/null || true
    
    # Enable and start Unbound
    systemctl enable unbound
    
    # Try to start Unbound
    if systemctl start unbound; then
        sleep 3
        if dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
            log_success "Unbound configured successfully on port 53"
            configure_system_dns_lockdown "127.0.0.1"
            return 0
        fi
    fi
    
    # If port 53 fails, try port 5353
    log_warn "Unbound on port 53 failed, trying port 5353..."
    
    # Update configuration for port 5353
    sed -i 's/port: 53/port: 5353/' /etc/unbound/unbound.conf
    
    if systemctl restart unbound; then
        sleep 3
        if dig @127.0.0.1 -p 5353 google.com +short >/dev/null 2>&1; then
            log_success "Unbound configured successfully on port 5353"
            
            # Configure resolv.conf for port 5353
            chattr -i /etc/resolv.conf 2>/dev/null || true
            cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Using local Unbound resolver on port 5353
nameserver 127.0.0.1
options rotate timeout:1 attempts:5
EOF
            chattr +i /etc/resolv.conf 2>/dev/null || true
            log_success "System DNS configured to use Unbound on port 5353"
            return 0
        fi
    fi
    
    # If both fail, fall back to direct DNS
    log_error "Unbound failed to start. Checking logs..."
    journalctl -u unbound --no-pager -n 20 >> "$ERROR_LOG"
    log_warn "Falling back to direct DNS servers"
    configure_system_dns_lockdown "$dns_servers"
    return 1
}

# 3. IPTABLES DNS ENFORCEMENT
configure_iptables_dns_enforcement() {
    local dns_servers="$1"
    
    log_info "Configuring iptables DNS traffic enforcement..."
    
    mkdir -p /etc/wireguard
    
    cat > /etc/wireguard/dns-enforcement.sh <<EOF
#!/bin/bash
# DNS Traffic Enforcement Script
# Generated: $(date)

# Flush existing DNS rules
iptables -F OUTPUT 2>/dev/null || true

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
    
    cat >> /etc/wireguard/dns-enforcement.sh <<'EOF'

# Allow local DNS resolver
iptables -A OUTPUT -d 127.0.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

# Block all other DNS traffic
iptables -A OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
iptables -A OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true

# Allow DNS through VPN interface
iptables -A OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o wg0 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

# Log blocked DNS attempts
iptables -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "DNS_BLOCKED: " --log-level 4 2>/dev/null || true
EOF

    chmod +x /etc/wireguard/dns-enforcement.sh
    
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

# 4. ENTERPRISE KILL SWITCH
configure_enterprise_kill_switch() {
    local wg_port="$1"
    local dns_servers="$2"
    local ssh_port="$3"
    local dashboard_port="$4"
    
    log_info "Configuring enterprise kill switch with DNS protection..."
    
    mkdir -p /etc/wireguard
    
    cat > /etc/wireguard/enterprise-kill-switch.sh <<EOF
#!/bin/bash
# Enterprise Kill Switch with DNS Protection
# Generated: $(date)

WG_PORT="$wg_port"
SSH_PORT="$ssh_port"
DASHBOARD_PORT="$dashboard_port"
DNS_SERVERS="$dns_servers"

enable_kill_switch() {
    # Flush existing rules
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    
    # Default policies
    iptables -P INPUT DROP 2>/dev/null || true
    iptables -P OUTPUT DROP 2>/dev/null || true
    iptables -P FORWARD DROP 2>/dev/null || true
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    
    # Allow local DNS resolver (Unbound)
    iptables -A INPUT -s 127.0.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -d 127.0.0.1 -p udp --sport 53 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -s 127.0.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -d 127.0.0.1 -p tcp --sport 53 -j ACCEPT 2>/dev/null || true
EOF

    # Add upstream DNS server rules
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "    iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
            echo "    iptables -A INPUT -p udp --sport 53 -s $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
        fi
    done

    cat >> /etc/wireguard/enterprise-kill-switch.sh <<'EOF'
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport $SSH_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow Dashboard
    iptables -A INPUT -p tcp --dport $DASHBOARD_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport $DASHBOARD_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow WireGuard
    iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp --sport $WG_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    
    # Allow ICMP
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT 2>/dev/null || true
    
    # Logging
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "KILLSWITCH_IN: " --log-level 4 2>/dev/null || true
    iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "KILLSWITCH_OUT: " --log-level 4 2>/dev/null || true
}

disable_kill_switch() {
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
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
    
    cat > /etc/systemd/system/enterprise-kill-switch.service <<EOF
[Unit]
Description=Enterprise Kill Switch Service
After=unbound.service wg-quick@wg0.service network.target
BindsTo=wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/etc/wireguard/enterprise-kill-switch.sh start
ExecStop=/etc/wireguard/enterprise-kill-switch.sh stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable enterprise-kill-switch.service --quiet 2>/dev/null || true
    log_success "Enterprise kill switch configured"
}

# 5. DNS LEAK MONITORING
configure_dns_leak_monitoring() {
    log_info "Configuring DNS leak monitoring..."
    
    mkdir -p /etc/wireguard/monitoring
    
    cat > /etc/wireguard/monitoring/dns-leak-monitor.sh <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/dns-leak-monitor.log"
ALERT_THRESHOLD=3
LEAK_COUNT=0

check_dns_leak() {
    local vpn_ip=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
    local dns1=$(dig +short whoami.akamai.net @resolver1.opendns.com 2>/dev/null)
    local dns2=$(dig +short -4 TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"')
    
    if [[ -n "$vpn_ip" && "$vpn_ip" != "unknown" ]]; then
        if [[ "$dns1" != "$vpn_ip" ]] || [[ "$dns2" != "$vpn_ip" ]]; then
            ((LEAK_COUNT++))
            echo "$(date): DNS LEAK DETECTED! (Count: $LEAK_COUNT)" >> $LOG_FILE
            echo "VPN IP: $vpn_ip, DNS1: $dns1, DNS2: $dns2" >> $LOG_FILE
            
            if [ $LEAK_COUNT -ge $ALERT_THRESHOLD ]; then
                echo "$(date): CRITICAL - Activating kill switch" >> $LOG_FILE
                /etc/wireguard/enterprise-kill-switch.sh start 2>/dev/null || true
            fi
        else
            echo "$(date): DNS check passed" >> $LOG_FILE
            LEAK_COUNT=0
        fi
    fi
}

while true; do
    check_dns_leak
    sleep 300
done
EOF

    chmod +x /etc/wireguard/monitoring/dns-leak-monitor.sh
    
    cat > /etc/systemd/system/dns-leak-monitor.service <<EOF
[Unit]
Description=DNS Leak Monitor
After=network.target

[Service]
Type=simple
ExecStart=/etc/wireguard/monitoring/dns-leak-monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dns-leak-monitor.service --quiet 2>/dev/null || true
    log_success "DNS leak monitoring configured"
}

# 6. Convert IPv4 address format
convert_ipv4_format() {
    local ipv4_address=$1
    local network=$(echo "$ipv4_address" | cut -d'/' -f1 | cut -d'.' -f1-3)
    echo "$network.0/24"
}

# 7. Validate DNS
validate_dns() {
    local dns_list=$1
    IFS=',' read -ra dns_servers <<< "$dns_list"
    for dns in "${dns_servers[@]}"; do
        dns=$(echo "$dns" | xargs)
        
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            IFS='.' read -r o1 o2 o3 o4 <<< "$dns"
            if ((o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255)); then
                continue
            else
                log_error "Invalid IPv4 address: $dns"
                return 1
            fi
        elif [[ $dns =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
            if [[ ${#dns} -le 39 ]]; then
                continue
            else
                log_error "Invalid IPv6 address: $dns"
                return 1
            fi
        else
            log_error "Invalid DNS server format: $dns"
            return 1
        fi
    done
    return 0
}

# 8. Security Hardening
apply_security_hardening() {
    log_info "Applying security hardening..."
    
    cat >> /etc/sysctl.conf <<EOF

# WireGuard Security Settings
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF

    sysctl -p >/dev/null 2>&1 || true
    log_success "Security hardening applied"
}

# ==================== MAIN INSTALLATION ====================

# Install required packages
install_requirements() {
    log_info "Installing required packages..."
    
    apt update -y >/dev/null 2>&1
    
    for pkg in curl wget git sudo ufw inotify-tools cron dnsutils net-tools; do
        if ! check_dpkg_package_installed $pkg; then
            apt install -y $pkg >/dev/null 2>&1
        fi
    done
}

# Clear screen
clear

# Display banner
echo "  _|_|_|_|    _|_|_|      _|_|_|    _|_|_|_|    _|_|_|  _|    _|  _|_|_|_|"
echo "    _|      _|    _|      _|    _|  _|          _|            _|      _|"
echo "    _|    _|        _|    _|    _|    _|_|      _|_|_|    _|        _|"
echo "    _|  _|            _|  _|    _|        _|    _|            _|    _|"
echo "  _|_|_|              _|    _|_|_|  _|_|_|_|    _|_|_|  _|        _|"
echo ""
echo "                                  xWireGuard Management & Server"
echo ""
echo -e "\e[1;31mWARNING! Install only in Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04 & Debian 11 & 12 systems ONLY\e[0m"
echo -e "\e[32mRECOMMENDED ==> Ubuntu 22.04\e[0m"
echo ""

# Check distribution
if [ -f "/etc/debian_version" ]; then
    if [ -f "/etc/os-release" ]; then
        source "/etc/os-release"
        if [ "$ID" = "debian" ]; then
            debian_version=$(cat /etc/debian_version)
            echo "Detected Debian $debian_version"
        elif [ "$ID" = "ubuntu" ]; then
            ubuntu_version=$(lsb_release -rs 2>/dev/null || echo "unknown")
            echo "Detected Ubuntu $ubuntu_version"
        else
            echo "Unsupported distribution."
            exit 1
        fi
    fi
else
    echo "Unsupported distribution."
    exit 1
fi

echo ""

read -p "Would you like to continue now? [y/n]: " choice
if [[ ! "$choice" =~ ^[Yy]$ ]]; then
    echo "Installation aborted."
    exit 0
fi

# Install requirements first
install_requirements

# Get installation parameters
validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9\.\-_]+$ ]]; then
        return 0
    else
        return 1
    fi
}

while true; do
    read -p "Please enter FQDN hostname [eg. localhost]: " hostname
    if [[ -z "$hostname" ]]; then
        hostname="localhost"
        break
    elif validate_hostname "$hostname"; then
        break
    else
        echo "Invalid hostname. Please enter a valid hostname."
    fi
done

while true; do
    read -p "Specify a Username for WGDashboard: " username
    if [[ -n "$username" ]]; then
        break
    else
        echo "Username cannot be empty."
    fi
done

while true; do
    read -s -p "Specify a Password: " password
    echo ""
    read -s -p "Confirm Password: " confirm_password
    echo ""
    if [ "$password" != "$confirm_password" ]; then
        echo -e "\e[1;31mError: Passwords do not match. Please try again.\e[0m"
    elif [ -z "$password" ]; then
        echo "Password cannot be empty."
    else
        break
    fi
done

while true; do
    echo ""
    echo -e "${YELLOW}DNS Servers Configuration${NC}"
    echo "Enter DNS servers (comma-separated)"
    echo "Example: 147.78.0.8,147.78.0.7"
    read -p "DNS Servers [default: 147.78.0.8,147.78.0.7]: " dns
    dns="${dns:-147.78.0.8,147.78.0.7}"
    if validate_dns "$dns"; then
        break
    fi
done

while true; do
    read -p "Please enter Wireguard Port [eg. 51820]: " wg_port
    wg_port="${wg_port:-51820}"
    if validate_port "$wg_port"; then
        break
    else
        echo "Error: Invalid port. Please enter a number between 1 and 65535."
    fi
done

read -p "Please enter Admin Dashboard Port [eg. 8080]: " dashboard_port
dashboard_port="${dashboard_port:-8080}"
echo ""

# IP address generation functions
ipv6_available() {
    if ip -6 addr show $interface 2>/dev/null | grep -q inet6 && ip -6 addr show $interface 2>/dev/null | grep -qv fe80; then
        return 0
    else
        return 1
    fi
}

generate_ipv4() {
    local range_type=$1
    case $range_type in
        1) echo "10.$((RANDOM%256)).$((RANDOM%256)).1/24" ;;
        2) echo "172.$((RANDOM%16+16)).$((RANDOM%256)).1/24" ;;
        3) echo "192.168.$((RANDOM%256)).1/24" ;;
        4) read -p "Enter custom Private IPv4 address: " custom; echo "$custom" ;;
        *) echo "10.0.0.1/24" ;;
    esac
}

generate_ipv6() {
    local range_type=$1
    case $range_type in
        1) printf "FC00:%04x:%04x::1/64" $((RANDOM % 65536)) $((RANDOM % 65536)) ;;
        2) printf "FD86:EA04:%04x::1/64" $((RANDOM % 65536)) ;;
        3) read -p "Enter custom Private IPv6 address: " custom; echo "$custom" ;;
        *) printf "FD00:%04x::1/64" $((RANDOM % 65536)) ;;
    esac
}

while true; do
    echo "Choose IP range type for IPv4:"
    echo "1) Class A: 10.0.0.0/8"
    echo "2) Class B: 172.16.0.0/12"
    echo "3) Class C: 192.168.0.0/16"
    echo "4) Specify custom Private IPv4"
    read -p "Enter your choice (1-4): " ipv4_option
    case $ipv4_option in
        1|2|3|4)
            ipv4_address_pvt=$(generate_ipv4 $ipv4_option)
            break
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done

if ipv6_available; then
    while true; do
        echo "Choose IP range type for IPv6:"
        echo "1) FC00::/7 (ULA)"
        echo "2) FD00::/7 (ULA)"
        echo "3) Specify custom Private IPv6"
        read -p "Enter your choice (1-3): " ipv6_option
        case $ipv6_option in
            1|2|3)
                ipv6_address_pvt=$(generate_ipv6 $ipv6_option)
                break
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    done
fi

echo "IPv4 Address: $ipv4_address_pvt"
[ -n "$ipv6_address_pvt" ] && echo "IPv6 Address: $ipv6_address_pvt"
echo ""

read -p "Specify Peer Endpoint Allowed IPs [default: 0.0.0.0/0,::/0]: " allowed_ip
allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"
echo ""

# Get interface and IPs
read -p "Enter internet interface [default: $interface]: " net_interface
interface="${net_interface:-$interface}"
echo ""

get_ipv4_addresses() {
    ip -o -4 addr show $interface 2>/dev/null | awk '$4 !~ /^127\.0\.0\.1/ {print $4}' | cut -d'/' -f1
}

get_ipv6_addresses() {
    ip -o -6 addr show $interface 2>/dev/null | awk '$4 !~ /^fe80:/ && $4 !~ /^::1/ {print $4}' | cut -d'/' -f1
}

if ipv6_available; then
    PS3="Select IP version: "
    options=("Public IPv4" "Public IPv6")
    select opt in "${options[@]}"; do
        case $REPLY in
            1)
                ipv4_addresses=$(get_ipv4_addresses)
                if [ -n "$ipv4_addresses" ]; then
                    echo "Available IPv4 addresses:"
                    select ipv4_address in $ipv4_addresses; do
                        [ -n "$ipv4_address" ] && break
                    done
                fi
                break
                ;;
            2)
                ipv6_addresses=$(get_ipv6_addresses)
                if [ -n "$ipv6_addresses" ]; then
                    echo "Available IPv6 addresses:"
                    select ipv6_address in $ipv6_addresses; do
                        [ -n "$ipv6_address" ] && break
                    done
                fi
                break
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    done
else
    ipv4_addresses=$(get_ipv4_addresses)
    if [ -n "$ipv4_addresses" ]; then
        echo "Available IPv4 addresses:"
        select ipv4_address in $ipv4_addresses; do
            [ -n "$ipv4_address" ] && break
        done
    fi
fi

clear
echo "Starting installation..."

# Update hostname
echo "$hostname" | tee /etc/hostname > /dev/null
hostnamectl set-hostname "$hostname"

# Configure Unbound (this will also set DNS)
configure_unbound_dns "$dns"

# Generate Wireguard keys
private_key=$(wg genkey 2>/dev/null)
echo "$private_key" | tee /etc/wireguard/private.key >/dev/null
public_key=$(echo "$private_key" | wg pubkey 2>/dev/null)

# Get SSH port
ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F ':' '{print $NF}' | sort -u | head -1)
ssh_port="${ssh_port:-22}"

# Apply DNS protection
log_info "Applying DNS leak protection..."
configure_iptables_dns_enforcement "$dns"
configure_enterprise_kill_switch "$wg_port" "$dns" "$ssh_port" "$dashboard_port"
configure_dns_leak_monitoring
apply_security_hardening

# Configure firewall
log_info "Configuring firewall..."
ufw --force disable >/dev/null 2>&1
ufw allow $ssh_port/tcp >/dev/null 2>&1
ufw allow $dashboard_port/tcp >/dev/null 2>&1
ufw allow $wg_port/udp >/dev/null 2>&1
ufw allow OpenSSH >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# Create directories
mkdir -p /etc/wireguard/network

# Create WireGuard configuration
cat > /etc/wireguard/wg0.conf <<EOF
# WireGuard Configuration for wg0
# Generated by xWireGuard Enterprise Installer v$SCRIPT_VERSION
# Created: $(date)

[Interface]
PrivateKey = $private_key
Address = $ipv4_address_pvt
ListenPort = $wg_port
EOF

if [ -n "$ipv6_address_pvt" ]; then
    sed -i "s|^Address = .*|&, $ipv6_address_pvt|" /etc/wireguard/wg0.conf
fi

# Add DNS protection to WireGuard config
cat >> /etc/wireguard/wg0.conf <<EOF

# DNS Protection Rules
PreUp = chattr -i /etc/resolv.conf 2>/dev/null || true
PreUp = echo "nameserver 127.0.0.1" > /etc/resolv.conf
PreUp = chattr +i /etc/resolv.conf 2>/dev/null || true

PostUp = iptables -I OUTPUT -p udp --dport 53 -j DROP
PostUp = iptables -I OUTPUT -p tcp --dport 53 -j DROP
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1

PostDown = iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
PostDown = iptables -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
PostDown = chattr -i /etc/resolv.conf 2>/dev/null || true
PostDown = cp /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null || true
EOF

# Create iptables script
ipv4_address_pvt0=$(convert_ipv4_format "$ipv4_address_pvt")
cat > /etc/wireguard/network/iptables.sh <<EOF
#!/bin/bash
while ! ip link show dev $interface up 2>/dev/null; do
    sleep 1
done
iptables -t nat -I POSTROUTING -s $ipv4_address_pvt0 -o $interface -j SNAT --to $ipv4_address 2>/dev/null || true
EOF

chmod +x /etc/wireguard/network/iptables.sh

# Create systemd service for iptables
cat > /etc/systemd/system/wireguard-iptables.service <<EOF
[Unit]
Description=Setup iptables rules for WireGuard
After=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/wireguard/network/iptables.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wireguard-iptables.service --quiet 2>/dev/null || true

# Install WGDashboard
log_info "Installing WGDashboard..."
cd /etc
mkdir -p xwireguard
cd xwireguard

if [ ! -d "wgdashboard" ]; then
    git clone https://github.com/donaldzou/WGDashboard.git wgdashboard
fi

cd wgdashboard/src || exit
pip install gunicorn -q
pip install -r requirements.txt -q
chmod +x wgd.sh
./wgd.sh install >/dev/null 2>&1

# Configure WGDashboard service
DASHBOARD_DIR=$(pwd)
PYTHON_PATH=$(which python3)
SERVICE_FILE="$DASHBOARD_DIR/wg-dashboard.service"

if [ -f "$SERVICE_FILE" ]; then
    sed -i "s|<absolute_path_of_wgdashboard_src>|$DASHBOARD_DIR|g" "$SERVICE_FILE"
    sed -i "/Environment=\"VIRTUAL_ENV={{VIRTUAL_ENV}}\"/d" "$SERVICE_FILE"
    sed -i "s|{{VIRTUAL_ENV}}/bin/python3|$PYTHON_PATH|g" "$SERVICE_FILE"
    cp "$SERVICE_FILE" /etc/systemd/system/wg-dashboard.service
    chmod 664 /etc/systemd/system/wg-dashboard.service
fi

# Enable services
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

# Configure dashboard credentials
if [ -f "$DASHBOARD_DIR/wg-dashboard.ini" ]; then
    hashed_password=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$password', bcrypt.gensalt(12)).decode())" 2>/dev/null)
    
    sed -i "s|^app_port =.*|app_port = $dashboard_port|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    sed -i "s|^password =.*|password = $hashed_password|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    sed -i "s|^username =.*|username = $username|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    sed -i "s|^welcome_session =.*|welcome_session = false|g" "$DASHBOARD_DIR/wg-dashboard.ini"
    
    systemctl restart wg-dashboard.service
fi

# Final checks
sleep 5

wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)
unbound_status=$(systemctl is-active unbound.service)

echo ""
echo "WireGuard Status: $wg_status"
echo "WGDashboard Status: $dashboard_status"
echo "Unbound Status: $unbound_status"
echo ""

if [ "$wg_status" = "active" ] && [ "$dashboard_status" = "active" ]; then
    clear
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     WireGuard Enterprise VPN Installation Complete        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}✅ Installation Status:${NC}"
    echo "   WireGuard: $wg_status"
    echo "   WGDashboard: $dashboard_status"
    echo "   Unbound: $unbound_status"
    echo ""
    echo -e "${BLUE}📊 Access Information:${NC}"
    echo "   Dashboard URL: http://$ipv4_address:$dashboard_port"
    echo "   Username: $username"
    echo ""
    echo -e "${PURPLE}🔒 DNS Protection:${NC}"
    echo "   DNS Servers: $dns"
    echo "   Local Resolver: $(grep -l "127.0.0.1" /etc/resolv.conf >/dev/null && echo "✅ Active" || echo "❌ Inactive")"
    echo ""
    echo -e "${YELLOW}📁 Configuration Files:${NC}"
    echo "   WireGuard: /etc/wireguard/wg0.conf"
    echo "   DNS Monitor: /var/log/dns-leak-monitor.log"
    echo ""
    echo -e "${CYAN}🔧 Quick Commands:${NC}"
    echo "   Check Unbound: systemctl status unbound"
    echo "   Test DNS: dig google.com"
    echo ""
    echo -e "${YELLOW}⚠️  System will reboot in 10 seconds${NC}"
    echo -e "${RED}Press Ctrl+C to cancel${NC}"
    sleep 10
    
    log_success "Installation complete! Rebooting..."
    reboot
else
    echo "Error: Installation failed. Please check services."
    echo "Check error log: $ERROR_LOG"
    
    # Show service status for debugging
    echo ""
    echo "Service statuses:"
    systemctl status unbound --no-pager -n 10
    echo ""
    echo "Check Unbound logs: journalctl -u unbound -n 50"
    exit 1
fi
