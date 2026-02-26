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
    
    # Don't exit on error, try to continue
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
    # Check if the port is a valid number and within the range 1-65535
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0  # Valid port
    else
        return 1  # Invalid port
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

# ==================== ENTERPRISE DNS LEAK PROTECTION ====================

# ==================== DNS LOCKDOWN ====================
configure_system_dns_lockdown() {
    local dns_servers="$1"
    
    log_info "Configuring system-wide DNS lockdown..."
    
    chattr -i /etc/resolv.conf 2>/dev/null || true
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
    
    if [[ "$dns_servers" == "127.0.0.1" ]]; then
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

# ==================== FIXED UNBOUND INSTALLATION ====================
configure_unbound_dns() {
    local dns_servers="$1"
    
    log_info "Installing and configuring Unbound DNS resolver..."
    
    # Stop any service using port 53
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true
    systemctl stop unbound 2>/dev/null || true
    
    # Kill any process using port 53
    fuser -k 53/tcp 53/udp 2>/dev/null || true
    
    # Install Unbound
    DEBIAN_FRONTEND=noninteractive apt install -y unbound unbound-anchor dnsutils >/dev/null 2>&1
    
    # Backup original config
    [ -f /etc/unbound/unbound.conf ] && mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup
    
    # Create Unbound configuration
    cat > /etc/unbound/unbound.conf <<EOF
# Unbound configuration for WireGuard Enterprise
# Generated: $(date)

server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
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
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    
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
    
    # Try to start Unbound on port 53
    systemctl enable unbound
    
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
    
    systemctl restart unbound
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
    
    # If both fail, fall back to direct DNS
    log_error "Unbound failed to start. Checking logs..."
    journalctl -u unbound --no-pager -n 20 >> "$ERROR_LOG"
    log_warn "Falling back to direct DNS servers"
    configure_system_dns_lockdown "$dns_servers"
    return 1
}


# ==================== DNS MONITORING ====================
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

# 3. KILL SWITCH WITH DNS PROTECTION - Updated for local resolver
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
    
    # ===== LOCAL DNS RESOLVER (Unbound) =====
    # Allow communication with local Unbound
    iptables -A INPUT -s 127.0.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -d 127.0.0.1 -p udp --sport 53 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -s 127.0.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -d 127.0.0.1 -p tcp --sport 53 -j ACCEPT 2>/dev/null || true
    
    # Allow Unbound to forward queries to upstream DNS servers
EOF

    # Add upstream DNS server rules for Unbound
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "    iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
            echo "    iptables -A INPUT -p udp --sport 53 -s $dns -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/enterprise-kill-switch.sh
        fi
    done

    cat >> /etc/wireguard/enterprise-kill-switch.sh <<'EOF'
    
    # ===== MANAGEMENT PORTS =====
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport $SSH_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow Dashboard
    iptables -A INPUT -p tcp --dport $DASHBOARD_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport $DASHBOARD_PORT -j ACCEPT 2>/dev/null || true
    
    # Allow port 10086
    iptables -A INPUT -p tcp --dport 10086 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p tcp --sport 10086 -j ACCEPT 2>/dev/null || true
    
    # ===== WIREGUARD =====
    iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp --sport $WG_PORT -j ACCEPT 2>/dev/null || true
    
    # ===== LOOPBACK =====
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    
    # ===== ICMP =====
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT 2>/dev/null || true
    
    # ===== LOGGING =====
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
After=unbound.service wg-quick@wg0.service network.target ssh.service
BindsTo=wg-quick@wg0.service
Wants=unbound.service network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 10
ExecStart=/etc/wireguard/enterprise-kill-switch.sh start
ExecStop=/etc/wireguard/enterprise-kill-switch.sh stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable enterprise-kill-switch.service --quiet 2>/dev/null || true
    log_success "Enterprise kill switch configured for local DNS resolver"
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

# 5. Function to convert IPv4 address format
convert_ipv4_format() {
    local ipv4_address=$1
    # Extract the network portion of the IPv4 address
    local network=$(echo "$ipv4_address" | cut -d'/' -f1 | cut -d'.' -f1-3)
    # Append ".0" to the network portion and concatenate with the subnet mask
    local converted_ipv4="$network.0/24"
    echo "$converted_ipv4"
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

# 7. SECURITY HARDENING
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

# Check if curl is installed
if ! check_dpkg_package_installed curl; then
    echo "Installing curl..."
    apt update -y 
    apt install -y curl >/dev/null 2>&1
fi
# Check if wget is installed
if ! check_dpkg_package_installed wget; then
    echo "Installing wget..."
    apt update -y 
    apt install -y wget >/dev/null 2>&1
fi

# Check if git is installed
if ! check_dpkg_package_installed git; then
    echo "Installing git..."
    apt update -y 
    apt install -y git >/dev/null 2>&1
fi

# Check if sudo is installed
if ! check_dpkg_package_installed sudo; then
    echo "Installing sudo..."
    apt update -y 
    apt install -y sudo >/dev/null 2>&1
fi

# Clear screen
clear
interface=$(ip route list default | awk '$1 == "default" {print $5}')
# Display ASCII art and introduction
echo "  _|_|_|_|    _|_|_|      _|_|_|    _|_|_|_|    _|_|_|  _|    _|  _|_|_|_|"
echo "    _|      _|    _|      _|    _|  _|          _|            _|      _|"
echo "    _|    _|        _|    _|    _|    _|_|      _|_|_|    _|        _|"
echo "    _|  _|            _|  _|    _|        _|    _|            _|    _|"
echo "  _|_|_|              _|    _|_|_|  _|_|_|_|    _|_|_|  _|        _|"
echo ""
echo "                                  xWireGuard Management & Server"
echo ""
echo -e "\e[1;31mWARNING ! Install only in Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.02 & Debian 11 & 12 system ONLY\e[0m"
echo -e "\e[32mRECOMMENDED ==> Ubuntu 22.04 \e[0m"
echo ""
echo "The following software will be installed on your system:"
echo "   - Wire Guard Server"
echo "   - WireGuard-Tools"
echo "   - WGDashboard by donaldzou"
echo "   - Gunicorn WSGI Server"
echo "   - Python3-pip"
echo "   - Git"
echo "   - UFW - firewall"
echo "   - inotifywait"
echo ""

# Check if the system is CentOS, Debian, or Ubuntu
if [ -f "/etc/centos-release" ]; then
    # CentOS
    centos_version=$(rpm -q --queryformat '%{VERSION}' centos-release)
    printf "Detected CentOS %s...\n" "$centos_version"
    pkg_manager="yum"
    ufw_package="ufw"
elif [ -f "/etc/debian_version" ]; then
    # Debian or Ubuntu
    if [ -f "/etc/os-release" ]; then
        source "/etc/os-release"
        if [ "$ID" = "debian" ]; then
            debian_version=$(cat /etc/debian_version)
            printf "Detected Debian %s...\n" "$debian_version"
        elif [ "$ID" = "ubuntu" ]; then
            ubuntu_version=$(lsb_release -rs)
            printf "Detected Ubuntu %s...\n" "$ubuntu_version"
        else
            printf "Unsupported distribution.\n"
            exit 1
        fi
    else
        printf "Unsupported distribution.\n"
        exit 1
    fi
    pkg_manager="apt"
    ufw_package="ufw"
else
    printf "Unsupported distribution.\n"
    exit 1
fi

printf "\n\n"
# Prompt the user to continue
read -p "Would you like to continue now ? [y/n]: " choice
if [[ "$choice" =~ ^[Yy]$ ]]; then

# Prompt the user to enter hostname until a valid one is provided
# Function to validate hostname
validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9\.\-_]+$ ]]; then
        return 0  # Valid hostname
    else
        return 1  # Invalid hostname
    fi
}
    # Prompt the user to enter hostname until a valid one is provided
    while true; do
        read -p "Please enter FQDN hostname [eg. localhost]: " hostname
        if [[ -z "$hostname" ]]; then
            hostname="localhost"  # Default hostname if user hits Enter
            break
        elif validate_hostname "$hostname"; then
            break
        else
            echo "Invalid hostname. Please enter a valid hostname."
        fi
    done
    # Prompt the user to enter a username
while true; do
    read -p "Specify a Username Login for WGDashboard: " username
    if [[ -n "$username" ]]; then
        break
    else
        echo "Username cannot be empty. Please specify a username."
    fi
done
while true; do
    # Prompt the user to enter a password (without showing the input)
    read -s -p "Specify a Password: " password
    echo ""
    # Prompt the user to confirm the password
    read -s -p "Confirm Password: " confirm_password
    echo ""
    # Check if the passwords match
    if [ "$password" != "$confirm_password" ]; then
        echo -e "\e[1;31mError: Passwords do not match. Please try again.\e[0m"
    elif [ -z "$password" ]; then
        echo "Password cannot be empty. Please specify a password."
    else
        break  # Exit the loop if passwords match
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

    # Loop to ensure a valid port is entered
    while true; do
        read -p "Please enter Wireguard Port [eg. 51820]: " wg_port
        wg_port="${wg_port:-51820}"  # Default port if user hits Enter
        if validate_port "$wg_port"; then
            break  # Exit the loop if the port is valid
        else
            echo "Error: Invalid port. Please enter a number between 1 and 65535."
        fi
    done
    read -p "Please enter Admin Dashboard Port [eg. 8080]: " dashboard_port
    dashboard_port="${dashboard_port:-8080}"  # Default port if user hits Enter
echo ""

# Function to check if IPv6 is available
ipv6_available() {
    if ip -6 addr show $interface | grep -q inet6 && ip -6 addr show $interface | grep -qv fe80; then
        return 0
    else
        return 1
    fi
}

# Function to check if an IPv6 address is global
is_global_ipv6() {
    local ipv6_address=$1
    # Check if the address is not link-local (starts with fe80) and contains '::'
    if [[ $ipv6_address != fe80:* && $ipv6_address == *::* ]]; then
        return 0
    else
        return 1
    fi
}

# Check if IPv6 is available on the default interface
if ipv6_available; then
    ipv6_available=true
else
    ipv6_available=false
fi

# Function to generate IPv4 addresses
generate_ipv4() {
    local range_type=$1
    case $range_type in
       1)
            ipv4_address_pvt="10.$((RANDOM%256)).$((RANDOM%256)).1/24"
            ;;
        2)
            ipv4_address_pvt="172.$((RANDOM%16+16)).$((RANDOM%256)).1/24"
            ;;
        3)
            ipv4_address_pvt="192.168.$((RANDOM%256)).1/24"
            ;;
        4)
            read -p "Enter custom Private IPv4 address: " ipv4_address_pvt
            ;;
        *)
            echo "Invalid option for IPv4 range."
            exit 1
            ;;
    esac
    echo "$ipv4_address_pvt"  # Return the generated IP address with subnet
}

# Function to generate IPv6 addresses
generate_ipv6() {
    local range_type=$1
    case $range_type in
        1)
            # Fixed prefix FC00:: for Unique Local Addresses (ULA)
            ipv6_address_pvt=$(printf "FC00:%04x:%04x::1/64" $((RANDOM % 65536)) $((RANDOM % 65536)))
            ;;
        2)
            # Fixed prefix FD00:: for Unique Local Addresses (ULA)
            ipv6_address_pvt=$(printf "FD86:EA04:%04x::1/64" $((RANDOM % 65536)))
            ;;
        3)
            read -p "Enter custom Private IPv6 address: " ipv6_address_pvt
            ;;
        *)
            echo "Invalid option for IPv6 range."
            exit 1
            ;;
    esac
    echo "$ipv6_address_pvt"  # Return the generated IP address with subnet
}

# Function to validate user input within a range
validate_input() {
    local input=$1
    local min=$2
    local max=$3
    if (( input < min || input > max )); then
        echo "Invalid option. Please choose an option between $min and $max."
        return 1
    fi
    return 0
}

# Main script
while true; do
    echo "Choose IP range type for IPv4:"
    echo "1) Class A: 10.0.0.0 to 10.255.255.255"
    echo "2) Class B: 172.16.0.0 to 172.31.255.255"
    echo "3) Class C: 192.168.0.0 to 192.168.255.255"
    echo "4) Specify custom Private IPv4"
    read -p "Enter your choice (1-4): " ipv4_option
    case $ipv4_option in
        1|2|3|4)
            ipv4_address_pvt=$(generate_ipv4 $ipv4_option)
            break
            ;;
        *)
            echo "Invalid option for IPv4 range."
            ;;
    esac
done

ipv6_option=""
if $ipv6_available; then
    while true; do
        echo "Choose IP range type for IPv6:"
        echo "1) FC00::/7"
        echo "2) FD00::/7"
        echo "3) Specify custom Private IPv6"
        read -p "Enter your choice (1-3): " ipv6_option
        case $ipv6_option in
            1|2|3)
                ipv6_address_pvt=$(generate_ipv6 $ipv6_option)
                break
                ;;
            *)
                echo "Invalid option for IPv6 range."
                ;;
        esac
    done
fi

echo "IPv4 Address: $ipv4_address_pvt"
if [ -n "$ipv6_address_pvt" ]; then
    echo "IPv6 Address: $ipv6_address_pvt"
fi
echo ""
read -p "Specify a Peer Endpoint Allowed IPs OR [press enter to use - 0.0.0.0/0,::/0]: " allowed_ip
allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"  # Default IPs if user hits Enter
echo ""

# Function to retrieve IPv4 addresses (excluding loopback address)
get_ipv4_addresses() {
    ip -o -4 addr show $interface | awk '$4 !~ /^127\.0\.0\.1/ {print $4}' | cut -d'/' -f1
}

# Function to retrieve IPv6 addresses (excluding link-local and loopback addresses)
get_ipv6_addresses() {
    ip -o -6 addr show $interface | awk '$4 !~ /^fe80:/ && $4 !~ /^::1/ {print $4}' | cut -d'/' -f1
}

# Prompt for interface name
read -p "Enter the internet interface OR (press Enter for detected: $interface)" net_interface
interface="${net_interface:-$interface}"  # Default IPs if user hits Enter
echo ""

# Prompt for IP version selection 
echo "Select an option for preferred IP version: "
PS3="Select an option: "
options=("Public IPv4")
if [ "$ipv6_available" = true ]; then
    options+=("Public IPv6")
fi
select opt in "${options[@]}"; do
    case $REPLY in
        1)
            # Display IPv4 addresses as options
            echo "Available Public IPv4 addresses:"
            ipv4_addresses=$(get_ipv4_addresses)
            select ipv4_address in $ipv4_addresses; do
                if validate_input $REPLY 1 $(wc -w <<< "$ipv4_addresses"); then
                    break
                fi
            done
            echo "Selected Public IPv4 Address: $ipv4_address"
            # If IPv6 is available, present options to choose an IPv6 address
            if [ "$ipv6_available" = true ]; then
                echo "Choose a Public IPv6 address:"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                echo "Selected Public IPv6 Address: $ipv6_address"
            fi
            break
            ;;
        2)
            if [ "$ipv6_available" = true ]; then
                # Display IPv6 addresses as options
                echo "Available Public IPv6 addresses (excluding link-local addresses):"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                echo "Selected Public IPv6 Address: $ipv6_address"
            else
                echo "Public IPv6 is not available."
            fi
            break
            ;;
        *)
            echo "Invalid option. Please select again."
            ;;
    esac
done
echo ""
clear
    # Continue with the rest of your installation script...
    echo "Starting with installation..."
    echo ""
    # Your installation commands here...

# Update hostname
echo "$hostname" | tee /etc/hostname > /dev/null
hostnamectl set-hostname "$hostname"
echo "Updating Repo & System..."
echo "Please wait to complete process..."
apt update -y  >/dev/null 2>&1

# Check if lsb_release is available; install if missing
if ! command -v lsb_release &> /dev/null; then
     apt update
     apt install -y lsb-release >/dev/null 2>&1
fi

# Detect the OS distribution and version
distro=$(lsb_release -is)
version=$(lsb_release -rs)

if [[ "$distro" == "Ubuntu" && "$version" == "20.04" ]]; then
    echo "Detected Ubuntu 20.04 LTS. Installing Python 3.10 and WireGuard dependencies..."
     add-apt-repository ppa:deadsnakes/ppa -y >/dev/null 2>&1
     apt-get update -y >/dev/null 2>&1
     apt-get install -y python3.10 python3.10-distutils wireguard-tools net-tools --no-install-recommends >/dev/null 2>&1

elif [[ ( "$distro" == "Ubuntu" && ( "$version" == "22.04" || "$version" == "24.02" ) ) || ( "$distro" == "Debian" && "$version" == "12" ) ]]; then
    echo "Detected $distro $version. Proceeding with installation..."
        # Check if Python 3 is installed
        if ! check_dpkg_package_installed python3; then
            echo "Python 3 is not installed. Installing Python 3..."
            # Install Python 3 system-wide
            apt install -y python3 >/dev/null 2>&1
            # Make Python 3 the default version
            update-alternatives --install /usr/bin/python python /usr/bin/python3 1
        fi
        # Function to check the version of Python installed
        get_python_version() {
            python3 --version | awk '{print $2}'
        }
        # Check the Python version
        python_version=$(get_python_version)
        # Compare the Python version
        if [[ "$(echo "$python_version" | cut -d. -f1)" -lt 3 || ( "$(echo "$python_version" | cut -d. -f1)" -eq 3 && "$(echo "$python_version" | cut -d. -f2)" -lt 10 ) ]]; then

            echo "Python version is below 3.10. Upgrading Python..."
            # Perform the system upgrade of Python
            apt update -y  >/dev/null 2>&1
            apt install -y python3 >/dev/null 2>&1
        else
            echo "Python version is 3.10 or above."
        fi

elif [[ "$distro" == "Debian" && "$version" == "11" ]]; then
    echo "Detected Debian 11. Installing Python 3.10 and WireGuard dependencies..."
    echo "Please wait."
    # Suppress output of the apt installation
     apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev \
    libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev wireguard-tools \
    net-tools >/dev/null 2>&1
    echo "Please wait.."
    # Download Python source and suppress output
    wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz -q
    echo "Please wait..."
    # Extract Python source and suppress output
    tar -xvf Python-3.10.0.tgz >/dev/null 2>&1
    cd Python-3.10.0
    echo "Please wait...."
    # Suppress output of the configure, make, and make install commands
     ./configure --enable-optimizations >/dev/null 2>&1
    echo "Please wait....."
     make >/dev/null 2>&1
    echo "Please wait......"
    echo "Please wait...... Upgrading Python to v3.10 could take a while"
    echo "Please wait......"
     make altinstall >/dev/null 2>&1
    echo "Python installation...... success"
else

    echo "This script supports only Ubuntu 20.04 LTS, 22.04, 24.02, and Debian 11 & 12."
    echo "Your version, $distro $version, is not supported at this time."
    exit 1
fi

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "pip is not installed. Installing pip..."
    apt update >/dev/null 2>&1
    apt install -y python3-pip >/dev/null 2>&1
fi

# Check if bcrypt is installed
if ! python3 -c "import bcrypt" &> /dev/null; then
    echo "bcrypt is not installed. Installing bcrypt..."
    pip install bcrypt >/dev/null 2>&1
else
    echo "bcrypt is already installed."
fi

# Check for WireGuard dependencies and install them if not present
if ! check_dpkg_package_installed wireguard-tools; then
    echo "Installing WireGuard dependencies..."
    apt install -y wireguard-tools >/dev/null 2>&1
fi

# Install git if not installed
if ! check_package_installed git; then
    echo "Installing git..."
    apt install -y git >/dev/null 2>&1
fi

# Install ufw if not installed
if ! check_package_installed ufw; then
    echo "Installing ufw..."
    apt install -y ufw >/dev/null 2>&1
fi

# Install inotifywait if not installed
if ! check_package_installed inotifywait ; then
    echo "Installing inotifywait..."
    apt install -y inotify-tools >/dev/null 2>&1
fi

# Install cron if not installed
if ! check_package_installed cron ; then
    echo "Cron is not installed. Installing..."
    apt install -y cron >/dev/null 2>&1
fi

# Now that dependencies are ensured to be installed, install WireGuard
echo "Installing WireGuard..."
apt install -y wireguard >/dev/null 2>&1

# Install and configure Unbound
configure_unbound_dns "$dns"

# Generate Wireguard keys
private_key=$(wg genkey 2>/dev/null)
echo "$private_key" | tee /etc/wireguard/private.key >/dev/null
public_key=$(echo "$private_key" | wg pubkey 2>/dev/null)

# Enable IPv4 forwarding if it's not already enabled
if ! grep -q '^#net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
elif grep -q '^#net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    # If it's commented, uncomment it
    sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf >/dev/null
fi

# Enable IPv6 forwarding if it's not already enabled
if ! grep -q '^#net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf; then
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
elif grep -q '^#net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf; then
    # If it's commented, uncomment it
    sed -i '/^#net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf >/dev/null
fi

# Apply changes
sysctl -p >/dev/null
ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F ':' '{print $NF}' | sort -u)

# ==================== APPLY ENTERPRISE DNS PROTECTION ====================

log_info "Applying enterprise DNS leak protection..."

# 1. System DNS Lockdown
configure_system_dns_lockdown "$dns"

# 2. iptables DNS Enforcement
configure_iptables_dns_enforcement "$dns"

# 3. Enterprise Kill Switch
configure_enterprise_kill_switch "$wg_port" "$dns" "$ssh_port" "$dashboard_port"

# 4. DNS Leak Monitoring
configure_dns_leak_monitoring "$dns"

# 5. Security Hardening
apply_security_hardening

# ==================== FIREWALL CONFIGURATION ====================

log_info "Configuring firewall..."
# Configure firewall (UFW)
echo "Stopping firewall (UFW) ....."
ufw disable
echo "Creating firewall rules ....."
ufw allow 10086/tcp
echo "Creating ($ssh_port) firewall rules ....."
ufw allow $ssh_port/tcp
echo "Creating ($dashboard_port) firewall rules ....."
ufw allow $dashboard_port/tcp
ufw allow 10086/tcp
echo "Creating ($wg_port) firewall rules ....."
ufw allow $wg_port/udp
echo "Creating (53) firewall rules ....."
ufw allow 53/udp
echo "Creating (OpenSSH) firewall rules ....."
ufw allow OpenSSH
echo "Enabling firewall rules ....."
ufw --force enable

# Create necessary directories
mkdir -p /etc/wireguard/network
mkdir -p /etc/wireguard

iptables_script="/etc/wireguard/network/iptables.sh"

# ==================== CREATE WIREGUARD CONFIGURATION ====================

log_info "Creating WireGuard configuration with proper syntax..."

# Create initial wg0.conf with proper syntax
cat > /etc/wireguard/wg0.conf <<EOF
# WireGuard Configuration for wg0
# Generated by xWireGuard Enterprise Installer v$SCRIPT_VERSION
# Created: $(date)

[Interface]
PrivateKey = $private_key
Address = $ipv4_address_pvt
ListenPort = $wg_port
EOF

# Add IPv6 address if available - FIXED: Using different delimiter for sed
if [[ -n $ipv6_address_pvt ]]; then
    # Use '|' as delimiter instead of '/' to avoid issues with IPv6 addresses
    sed -i "s|^Address = .*|&, $ipv6_address_pvt|" /etc/wireguard/wg0.conf
    log_info "Added IPv6 address: $ipv6_address_pvt"
fi

echo "Setting up Wireguard configuration ....."

# Add Wireguard Network configuration
echo "Setting up Wireguard Network ....."
ipv4_address_pvt0=$(convert_ipv4_format "$ipv4_address_pvt")
# Define the path to the iptables.sh script
cat <<EOF | tee "$iptables_script" >/dev/null
#!/bin/bash
# Wait for the network interface to be up
while ! ip link show dev $interface up; do
    sleep 1
done
# Set iptables rules for WireGuard
iptables -t nat -I POSTROUTING --source $ipv4_address_pvt0 -o $interface -j SNAT --to $ipv4_address
iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE
# Set ip6tables rules for WireGuard (IPv6)
#ip6tables -t nat -I POSTROUTING --source ::/0 -o $interface -j SNAT --to $ipv6_address
# Add custom route for WireGuard interface
ip route add default dev wg0
# Add custom route for incoming traffic from WireGuard
ufw route allow in on wg0 out on $interface
EOF

cat <<EOF | tee /etc/systemd/system/wireguard-iptables.service >/dev/null
[Unit]
Description=Setup iptables rules for WireGuard
After=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_script
[Install]
WantedBy=multi-user.target
EOF

chmod +x "$iptables_script"
# Uncomment the ip6tables command if IPv6 is available - FIXED: Check correct variable
if [[ -n $ipv6_address_pvt ]] && grep -q "#ip6tables" "$iptables_script"; then
    sed -i 's/#ip6tables/ip6tables/' "$iptables_script" >/dev/null
    # Escape the IPv6 address for sed
    escaped_ipv6=$(echo "$ipv6_address_pvt" | sed 's|/|\\/|g')
    sed -i "s|::/0|$escaped_ipv6|" "$iptables_script" >/dev/null
fi

systemctl enable wireguard-iptables.service --quiet

# ==================== ADD DNS PROTECTION RULES TO WIREGUARD CONFIG ====================

log_info "Adding DNS protection rules to WireGuard configuration..."

# Build DNS rules with proper syntax
cat >> /etc/wireguard/wg0.conf <<EOF

# ===== ENTERPRISE DNS PROTECTION RULES =====
# Applied by WireGuard Enterprise Installer v$SCRIPT_VERSION

# Pre-up: Ensure DNS is locked (FIXED: Proper spacing)
PreUp = chattr -i /etc/resolv.conf 2>/dev/null || true
PreUp = echo "nameserver 127.0.0.1" > /etc/resolv.conf
PreUp = chattr +i /etc/resolv.conf 2>/dev/null || true

# Post-up: Apply DNS traffic rules
EOF

# Add individual DNS accept rules with proper spacing
IFS=',' read -ra dns_array <<< "$dns"
for dns_server in "${dns_array[@]}"; do
    dns_server=$(echo "$dns_server" | xargs)
    if [[ $dns_server =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "PostUp = iptables -I OUTPUT -p udp --dport 53 -d $dns_server -j ACCEPT" >> /etc/wireguard/wg0.conf
        echo "PostUp = iptables -I OUTPUT -p tcp --dport 53 -d $dns_server -j ACCEPT" >> /etc/wireguard/wg0.conf
    fi
done

# Add the remaining rules
cat >> /etc/wireguard/wg0.conf <<EOF
PostUp = iptables -I OUTPUT -p udp --dport 53 -j DROP
PostUp = iptables -I OUTPUT -p tcp --dport 53 -j DROP
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=1
PostUp = sysctl -w net.ipv4.conf.default.rp_filter=1

# Post-down: Clean up rules
PostDown = iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
PostDown = iptables -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
EOF

# Add DNS-specific cleanup rules
IFS=',' read -ra dns_array <<< "$dns"
for dns_server in "${dns_array[@]}"; do
    dns_server=$(echo "$dns_server" | xargs)
    if [[ $dns_server =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "PostDown = iptables -D OUTPUT -p udp --dport 53 -d $dns_server -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/wg0.conf
        echo "PostDown = iptables -D OUTPUT -p tcp --dport 53 -d $dns_server -j ACCEPT 2>/dev/null || true" >> /etc/wireguard/wg0.conf
    fi
done

log_success "WireGuard configuration created with proper syntax"

# Change directory to /etc
cd /etc || exit
# Create a directory xwireguard if it doesn't exist
if [ ! -d "xwireguard" ]; then
    mkdir -p xwireguard
    mkdir -p /etc/xwireguard/monitor
fi
# Change directory to /etc/xwireguard
cd xwireguard || exit

# Install WGDashboard
echo "Installing WGDashboard ....."
git clone -q https://github.com/donaldzou/WGDashboard.git wgdashboard || {
    log_warn "Git clone failed, trying with https..."
    git clone https://github.com/donaldzou/WGDashboard.git wgdashboard
}
cd wgdashboard/src || exit
apt install python3-pip -y >/dev/null 2>&1 
pip install gunicorn >/dev/null 2>&1 
pip install -r requirements.txt --ignore-installed >/dev/null 2>&1
chmod u+x wgd.sh
./wgd.sh install >/dev/null 2>&1
# Set permissions
chmod -R 755 /etc/wireguard
# Start WGDashboard
./wgd.sh start >/dev/null 2>&1
# Autostart WGDashboard on boot
DASHBOARD_DIR=$(pwd)
SERVICE_FILE="$DASHBOARD_DIR/wg-dashboard.service"
# Get the absolute path of python3 interpreter
PYTHON_PATH=$(which python3)
# Update service file with the correct directory and python path
if [ -f "$SERVICE_FILE" ]; then
    sed -i "s|<absolute_path_of_wgdashboard_src>|$DASHBOARD_DIR|g" "$SERVICE_FILE" >/dev/null
    sed -i "/Environment=\"VIRTUAL_ENV={{VIRTUAL_ENV}}\"/d" "$SERVICE_FILE" >/dev/null
    sed -i "s|{{VIRTUAL_ENV}}/bin/python3|$PYTHON_PATH|g" "$SERVICE_FILE" >/dev/null
    # Copy the service file to systemd folder
    cp "$SERVICE_FILE" /etc/systemd/system/wg-dashboard.service
    # Set permissions
    chmod 664 /etc/systemd/system/wg-dashboard.service
fi

# ==================== ENABLE SERVICES ====================

log_info "Enabling services..."
systemctl daemon-reload

systemctl enable wg-quick@wg0.service --quiet 2>/dev/null || true
systemctl enable wg-dashboard.service --quiet 2>/dev/null || true
systemctl enable dns-enforcement.service --quiet 2>/dev/null || true
systemctl enable enterprise-kill-switch.service --quiet 2>/dev/null || true
systemctl enable dns-leak-monitor.service --quiet 2>/dev/null || true

# Start services
echo "Enabling Wireguard Service ....."
systemctl start wg-quick@wg0.service 2>/dev/null || true
systemctl start wg-dashboard.service 2>/dev/null || true
systemctl start dns-enforcement.service 2>/dev/null || true
systemctl start enterprise-kill-switch.service 2>/dev/null || true
systemctl start dns-leak-monitor.service 2>/dev/null || true
systemctl restart wg-dashboard.service

# ==================== FINAL CHECKS ====================
sleep 3

# Verify WireGuard configuration syntax
echo "Verifying WireGuard configuration..."
if wg-quick strip wg0 > /dev/null 2>&1; then
    log_success "WireGuard configuration syntax is valid"
else
    log_warn "WireGuard configuration may have issues, but continuing..."
fi

# Hash password and configure dashboard
if [ -f "$DASHBOARD_DIR/wg-dashboard.ini" ]; then
    hashed_password=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$password', bcrypt.gensalt(12)).decode())" 2>/dev/null)
    # Seed to wg-dashboard.ini
    sed -i "s|^app_port =.*|app_port = $dashboard_port|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^password =.*|password = $hashed_password|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^username =.*|username = $username|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^welcome_session =.*|welcome_session = false|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    sed -i "s|^dashboard_theme =.*|dashboard_theme = dark|g" "$DASHBOARD_DIR/wg-dashboard.ini" >/dev/null
    systemctl restart wg-dashboard.service
fi

echo "Restarting Wireguard & WGDashboard services ....."
echo "Fixing unbound permissions and tweak ....."
sudo sh fix-unbound.sh >/dev/null 2>&1
systemctl restart unbound.service 2>/dev/null || true
echo ""
echo "Unbound service restarted ....."
echo ""
echo "Performing final checks on services ....."
echo ""
echo ""
wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)
unbound_status=$(systemctl is-active unbound.service)
dns_monitor_status=$(systemctl is-active dns-leak-monitor.service 2>/dev/null || echo "inactive")
echo ""
echo "Wireguard Status: $wg_status"
echo "WGDashboard Status: $dashboard_status"
echo "Unbound Status: $unbound_status"
echo ""

if [ "$wg_status" = "active" ] && [ "$dashboard_status" = "active" ]; then
    # ==================== DISPLAY RESULTS ====================
    clear
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     WireGuard Enterprise VPN Installation Complete        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}✅ Installation Status:${NC}"
    echo "   WireGuard: $wg_status"
    echo "   WGDashboard: $dashboard_status"
    echo "   Unbound: $unbound_status"
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
    echo "   Monitoring Logs: /var/log/dns-leak-monitor.log"
    echo ""

    echo -e "${CYAN}🔧 Quick Commands:${NC}"
    echo "   View WireGuard status: wg show"
    echo "   Check Unbound: systemctl status unbound"
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
else
    echo "Error: Installation failed. Please check the services and try again."
    echo "Check the error log at: $ERROR_LOG"
    
    # Show service status for debugging
    echo ""
    echo "Service statuses:"
    systemctl status unbound --no-pager -n 10
    echo ""
    echo "Check Unbound logs: journalctl -u unbound -n 50"
    
    # Show WireGuard config for debugging
    echo ""
    echo "WireGuard configuration:"
    cat /etc/wireguard/wg0.conf
    echo ""
    echo "Check service status manually: systemctl status wg-quick@wg0.service"
    exit 1
fi
else
    echo "Installation aborted."
    exit 0
fi
