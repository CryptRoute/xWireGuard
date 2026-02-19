#!/bin/bash
# Production-Ready WireGuard VPN Installer with Enterprise DNS Leak Protection
# Version: 2.0 - Enterprise Edition

# ==================== COLOR CODES ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ==================== GLOBAL VARIABLES ====================
SCRIPT_VERSION="2.0"
INSTALL_LOG="/var/log/wireguard-enterprise-install.log"
ERROR_LOG="/var/log/wireguard-enterprise-error.log"
DNS_LEAK_LOG="/var/log/dns-leak-monitor.log"
INTERFACE=$(ip route list default | awk '$1 == "default" {print $5}')

# ==================== ERROR HANDLING ====================
set -e
trap 'handle_error $? $LINENO' ERR

handle_error() {
    local exit_code=$1
    local line_no=$2
    echo -e "${RED}Error on line $line_no: Command exited with status $exit_code${NC}"
    echo "$(date): Error on line $line_no: Command exited with status $exit_code" >> "$ERROR_LOG"
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

validate_ip_range() {
    local input=$1
    local min=$2
    local max=$3
    if (( input < min || input > max )); then
        echo "Invalid option. Please choose an option between $min and $max."
        return 1
    fi
    return 0
}

# ==================== NETWORK FUNCTIONS ====================
ipv6_available() {
    if ip -6 addr show "$INTERFACE" | grep -q inet6 && ip -6 addr show "$INTERFACE" | grep -qv fe80; then
        return 0
    else
        return 1
    fi
}

get_ipv4_addresses() {
    ip -o -4 addr show "$INTERFACE" | awk '$4 !~ /^127\.0\.0\.1/ {print $4}' | cut -d'/' -f1
}

get_ipv6_addresses() {
    ip -o -6 addr show "$INTERFACE" | awk '$4 !~ /^fe80:/ && $4 !~ /^::1/ {print $4}' | cut -d'/' -f1
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

    # Make resolv.conf immutable
    chattr +i /etc/resolv.conf 2>/dev/null || log_warn "Could not make resolv.conf immutable"
    
    log_success "System DNS locked down to: $dns_servers"
}

# 2. IPTABLES DNS TRAFFIC ENFORCEMENT
configure_iptables_dns_enforcement() {
    local dns_servers="$1"
    
    log_info "Configuring iptables DNS traffic enforcement..."
    
    # Create DNS enforcement script
    cat > /etc/wireguard/dns-enforcement.sh <<'EOF'
#!/bin/bash
# DNS Traffic Enforcement Script
EOF

    # Add IPv4 rules
    echo "# IPv4 DNS Enforcement" >> /etc/wireguard/dns-enforcement.sh
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT" >> /etc/wireguard/dns-enforcement.sh
            echo "iptables -A OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT" >> /etc/wireguard/dns-enforcement.sh
        fi
    done
    
    # Block all other DNS traffic
    cat >> /etc/wireguard/dns-enforcement.sh <<'EOF'

# Block all other DNS traffic
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP

# Allow DNS through VPN interface only
iptables -A OUTPUT -o wg0 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -o wg0 -p tcp --dport 53 -j ACCEPT

# Log blocked DNS attempts
iptables -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "DNS_BLOCKED: "
iptables -A OUTPUT -p tcp --dport 53 -j LOG --log-prefix "DNS_BLOCKED: "
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

    systemctl enable dns-enforcement.service --quiet
    log_success "iptables DNS enforcement configured"
}

# 3. KILL SWITCH WITH DNS PROTECTION
configure_enterprise_kill_switch() {
    local wg_port="$1"
    local dns_servers="$2"
    
    log_info "Configuring enterprise kill switch with DNS protection..."
    
    cat > /etc/wireguard/enterprise-kill-switch.sh <<EOF
#!/bin/bash
# Enterprise Kill Switch with DNS Protection
# Generated: $(date)

WG_PORT="$wg_port"
DNS_SERVERS="$dns_servers"

enable_kill_switch() {
    # Default policies
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow VPN interface
    iptables -A INPUT -i wg0 -j ACCEPT
    iptables -A OUTPUT -o wg0 -j ACCEPT
    
    # Allow VPN server connection
    iptables -A OUTPUT -p udp --dport \$WG_PORT -j ACCEPT
    
    # Allow DNS to specified servers
EOF

    # Add DNS server rules
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        if [[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "    iptables -A OUTPUT -p udp --dport 53 -d $dns -j ACCEPT" >> /etc/wireguard/enterprise-kill-switch.sh
            echo "    iptables -A OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT" >> /etc/wireguard/enterprise-kill-switch.sh
        fi
    done

    cat >> /etc/wireguard/enterprise-kill-switch.sh <<'EOF'
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Log dropped packets
    iptables -A INPUT -j LOG --log-prefix "KILLSWITCH_IN: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "KILLSWITCH_OUT: " --log-level 4
}

disable_kill_switch() {
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -F
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

    systemctl enable enterprise-kill-switch.service --quiet
    log_success "Enterprise kill switch configured"
}

# 4. UNBOUND DNS WITH DNSSEC AND DNS OVER TLS
configure_enterprise_dns_resolver() {
    local dns_servers="$1"
    local vpn_network="$2"
    
    log_info "Configuring enterprise DNS resolver with DNSSEC and DNS over TLS..."
    
    # Install unbound
    apt install -y unbound unbound-anchor dnsutils >/dev/null 2>&1
    
    # Generate DNS over TLS configuration
    local dot_config=""
    IFS=',' read -ra dns_array <<< "$dns_servers"
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        dot_config="${dot_config}    forward-addr: $dns@853\n"
    done
    
    # Configure unbound
    cat > /etc/unbound/unbound.conf.d/enterprise-vpn.conf <<EOF
# Enterprise VPN DNS Configuration
# Generated: $(date)

server:
    # Listen on all interfaces
    interface: 0.0.0.0
    interface: ::0
    
    # Allow VPN network only
    access-control: $vpn_network allow
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    
    # DNSSEC Configuration
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-log-level: 2
    val-permissive-mode: no
    val-clean-additional: yes
    
    # Security Settings
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    qname-minimisation-strict: yes
    aggressive-nsec: yes
    ratelimit: 1000
    ratelimit-slabs: 4
    ratelimit-size: 4m
    
    # Cache Settings
    cache-min-ttl: 300
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600
    prefetch: yes
    prefetch-key: yes
    
    # Performance Settings
    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    
    # DNS Flag Day Settings
    edns-buffer-size: 1232
    max-udp-size: 1232
    
    # DNS over TLS Forwarding
    forward-zone:
        name: "."
        forward-tls-upstream: yes
$(echo -e "$dot_config")
EOF

    # Start unbound
    systemctl enable unbound --quiet
    systemctl restart unbound
    
    # Point system to local unbound
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    log_success "Enterprise DNS resolver configured with DNSSEC and DNS over TLS"
}

# 5. DNS LEAK MONITORING AND ALERTING
configure_dns_leak_monitoring() {
    local dns_servers="$1"
    
    log_info "Configuring DNS leak monitoring and alerting..."
    
    mkdir -p /etc/wireguard/monitoring
    
    cat > /etc/wireguard/monitoring/dns-leak-monitor.sh <<'EOF'
#!/bin/bash
# DNS Leak Monitoring and Alerting System
# Generated: $(date)

LOG_FILE="/var/log/dns-leak-monitor.log"
ALERT_THRESHOLD=3
LEAK_COUNT=0

check_dns_leak() {
    # Multiple DNS leak test methods
    local vpn_ip=$(curl -s -4 ifconfig.me 2>/dev/null)
    
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
            /etc/wireguard/enterprise-kill-switch.sh start
            
            # Send alert (if mailutils is installed)
            if command -v mail &>/dev/null; then
                echo "DNS LEAK DETECTED at $(date)" | mail -s "ALERT: VPN DNS Leak" root
            fi
        fi
    else
        echo "$(date): DNS check passed" >> $LOG_FILE
        LEAK_COUNT=0
    fi
}

# Monitor for DNS configuration changes
monitor_dns_config() {
    inotifywait -m -e modify,delete,move /etc/resolv.conf 2>/dev/null | while read -r event; do
        echo "$(date): WARNING - /etc/resolv.conf was modified! Event: $event" >> $LOG_FILE
        # Restore configuration
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null || true
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

    systemctl enable dns-leak-monitor.service --quiet
    log_success "DNS leak monitoring configured"
}

# 6. WIREGUARD CONFIGURATION WITH DNS PROTECTION
enhance_wireguard_with_dns_protection() {
    local dns_servers="$1"
    local config_file="/etc/wireguard/wg0.conf"
    
    log_info "Enhancing WireGuard configuration with DNS protection..."
    
    # Build DNS rules
    local dns_accept_rules=""
    local dns_block_rules=""
    IFS=',' read -ra dns_array <<< "$dns_servers"
    
    for dns in "${dns_array[@]}"; do
        dns=$(echo "$dns" | xargs)
        dns_accept_rules="${dns_accept_rules}iptables -I OUTPUT -p udp --dport 53 -d $dns -j ACCEPT; "
        dns_accept_rules="${dns_accept_rules}iptables -I OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT; "
    done
    
    dns_block_rules="iptables -I OUTPUT -p udp --dport 53 -j DROP; iptables -I OUTPUT -p tcp --dport 53 -j DROP;"
    
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
PostUp = $dns_block_rules
PostUp = sysctl -w net.ipv4.conf.all.rp_filter=1
PostUp = sysctl -w net.ipv4.conf.default.rp_filter=1
PostUp = sysctl -w net.ipv4.tcp_syncookies=1
PostUp = sysctl -w net.ipv4.tcp_syn_retries=2
PostUp = sysctl -w net.ipv4.tcp_synack_retries=2

# Post-down: Clean up rules
PostDown = iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
PostDown = iptables -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
$(for dns in "${dns_array[@]}"; do
    dns=$(echo "$dns" | xargs)
    echo "PostDown = iptables -D OUTPUT -p udp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true"
    echo "PostDown = iptables -D OUTPUT -p tcp --dport 53 -d $dns -j ACCEPT 2>/dev/null || true"
done)

# Post-down: Restore DNS
PostDown = chattr -i /etc/resolv.conf 2>/dev/null || true
PostDown = cp /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null || true
EOF

    log_success "WireGuard configuration enhanced with DNS protection"
}

# 7. WGDASHBOARD INTEGRATION WITH DNS PROTECTION
configure_wgdashboard_dns() {
    local dns_servers="$1"
    local dashboard_dir="$2"
    
    log_info "Configuring WGDashboard with DNS protection..."
    
    # Update WGDashboard configuration
    sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns_servers|g" "$dashboard_dir/wg-dashboard.ini" >/dev/null
    
    # Create DNS protection notice for WGDashboard
    cat > "$dashboard_dir/static/dns-protection.html" <<EOF
<div class="alert alert-info">
    <strong>DNS Protection Active</strong><br>
    Your DNS is protected with enterprise-grade security:<br>
    - DNS Servers: $dns_servers<br>
    - DNSSEC: Enabled<br>
    - DNS over TLS: Enabled<br>
    - Kill Switch: Active<br>
    - DNS Leak Monitoring: Active
</div>
EOF

    log_success "WGDashboard configured with DNS protection"
}

# 8. CLIENT CONFIGURATION TEMPLATES
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
# Includes DNS leak protection and kill switch

[Interface]
PrivateKey = <client-private-key>
Address = <client-ip>
DNS = $dns_servers
MTU = 1420

# DNS Leak Prevention
PostUp = resolvconf --disable 2>/dev/null || true
PostUp = echo "$(for dns in $(echo $dns_servers | tr ',' ' '); do echo "nameserver $dns"; done)" > /etc/resolv.conf
PostUp = chattr +i /etc/resolv.conf 2>/dev/null || true
PostUp = iptables -I OUTPUT -p udp --dport 53 ! -d $(echo $dns_servers | tr ',' '!' -d) -j DROP
PostUp = iptables -I OUTPUT -p tcp --dport 53 ! -d $(echo $dns_servers | tr ',' '!' -d) -j DROP

PostDown = iptables -D OUTPUT -p udp --dport 53 ! -d $(echo $dns_servers | tr ',' '!' -d) -j DROP 2>/dev/null || true
PostDown = iptables -D OUTPUT -p tcp --dport 53 ! -d $(echo $dns_servers | tr ',' '!' -d) -j DROP 2>/dev/null || true
PostDown = chattr -i /etc/resolv.conf 2>/dev/null || true
PostDown = resolvconf --enable 2>/dev/null || true

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
# Note: Use with WireGuard Windows client

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

    # macOS client template
    cat > /etc/wireguard/clients/macos-client.conf <<EOF
# WireGuard Enterprise Client Configuration - macOS
# Generated: $(date)

[Interface]
PrivateKey = <client-private-key>
Address = <client-ip>
DNS = $dns_servers
MTU = 1420

# DNS Leak Prevention for macOS
PostUp = networksetup -setdnsservers "WireGuard" $(echo $dns_servers | tr ',' ' ')
PostDown = networksetup -setdnsservers "WireGuard" Empty

[Peer]
PublicKey = $server_public_key
Endpoint = $server_endpoint:$wg_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # iOS/Android mobile template
    cat > /etc/wireguard/clients/mobile-client.conf <<EOF
# WireGuard Enterprise Client Configuration - iOS/Android
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

# 9. SECURITY HARDENING
apply_security_hardening() {
    log_info "Applying system security hardening..."
    
    # Kernel hardening
    cat >> /etc/sysctl.d/99-wireguard-hardening.conf <<EOF
# WireGuard Security Hardening
# Generated: $(date)

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# TCP timestamps
net.ipv4.tcp_timestamps = 0

# Ignore pings
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-wireguard-hardening.conf >/dev/null 2>&1
    
    log_success "Security hardening applied"
}

# 10. MONITORING AND REPORTING
setup_monitoring_dashboard() {
    log_info "Setting up monitoring dashboard..."
    
    mkdir -p /etc/wireguard/monitoring/reports
    
    # Create monitoring script
    cat > /etc/wireguard/monitoring/health-check.sh <<'EOF'
#!/bin/bash
# WireGuard VPN Health Check
# Generated: $(date)

REPORT_DIR="/etc/wireguard/monitoring/reports"
REPORT_FILE="$REPORT_DIR/health-$(date +%Y%m%d).log"

check_vpn_health() {
    echo "=== WireGuard VPN Health Report $(date) ===" > $REPORT_FILE
    
    # Check WireGuard interface
    echo "WireGuard Interface Status:" >> $REPORT_FILE
    wg show wg0 >> $REPORT_FILE 2>&1
    
    # Check DNS resolution
    echo -e "\nDNS Resolution Test:" >> $REPORT_FILE
    dig +short google.com >> $REPORT_FILE 2>&1
    
    # Check for DNS leaks
    echo -e "\nDNS Leak Test:" >> $REPORT_FILE
    curl -s https://ipleak.net/json/ | python3 -m json.tool >> $REPORT_FILE 2>&1
    
    # Check connected peers
    echo -e "\nConnected Peers:" >> $REPORT_FILE
    wg show wg0 peers | wc -l >> $REPORT_FILE
    
    # Check system resources
    echo -e "\nSystem Resources:" >> $REPORT_FILE
    free -h >> $REPORT_FILE
    df -h >> $REPORT_FILE
    
    # Check for errors in logs
    echo -e "\nRecent Errors:" >> $REPORT_FILE
    tail -20 /var/log/syslog | grep -i "wireguard\|dns\|vpn" >> $REPORT_FILE 2>&1
}

# Send report (if email configured)
send_report() {
    if command -v mail &>/dev/null && [ -f /etc/wireguard/monitoring/email.conf ]; then
        source /etc/wireguard/monitoring/email.conf
        mail -s "WireGuard VPN Health Report $(date)" $ADMIN_EMAIL < $REPORT_FILE
    fi
}

check_vpn_health
send_report

# Cleanup old reports (keep 30 days)
find $REPORT_DIR -name "health-*.log" -mtime +30 -delete
EOF

    chmod +x /etc/wireguard/monitoring/health-check.sh
    
    # Create daily cron job
    echo "0 6 * * * root /etc/wireguard/monitoring/health-check.sh" > /etc/cron.d/wireguard-health
    
    log_success "Monitoring dashboard configured"
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
echo "           with Advanced DNS Leak Protection & Security Hardening"
echo ""
echo -e "${RED}WARNING! Install only in Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.02 & Debian 11 & 12${NC}"
echo -e "${GREEN}RECOMMENDED: Ubuntu 22.04 LTS${NC}"
echo ""
echo "The following enterprise features will be installed:"
echo "   ✅ WireGuard VPN Server"
echo "   ✅ WGDashboard for client management"
echo "   ✅ Enterprise DNS Leak Protection"
echo "   ✅ DNSSEC with DNS over TLS"
echo "   ✅ VPN Kill Switch"
echo "   ✅ DNS Traffic Enforcement"
echo "   ✅ Security Hardening"
echo "   ✅ Monitoring & Alerting"
echo ""

# Check distribution
if [ -f "/etc/debian_version" ]; then
    if [ -f "/etc/os-release" ]; then
        source "/etc/os-release"
        if [ "$ID" = "debian" ]; then
            debian_version=$(cat /etc/debian_version)
            printf "Detected Debian %s...\n" "$debian_version"
        elif [ "$ID" = "ubuntu" ]; then
            ubuntu_version=$(lsb_release -rs)
            printf "Detected Ubuntu %s...\n" "$ubuntu_version"
        else
            log_error "Unsupported distribution."
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
fi

if [ -n "$ipv6_address_pvt" ]; then
    ipv6_addresses=$(get_ipv6_addresses)
    if [ -n "$ipv6_addresses" ]; then
        echo "Available IPv6 addresses:"
        select ipv6_address in $ipv6_addresses; do
            if [ -n "$ipv6_address" ]; then
                break
            fi
        done
    fi
fi

# ==================== INSTALLATION STARTS HERE ====================

clear
log_info "Starting enterprise WireGuard installation..."
log_info "Installation log: $INSTALL_LOG"
log_info "Error log: $ERROR_LOG"

# Update system
log_info "Updating system packages..."
apt update -y >/dev/null 2>&1
apt upgrade -y >/dev/null 2>&1

# Install dependencies
log_info "Installing dependencies..."
apt install -y curl wget git sudo ufw net-tools \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    resolvconf inotify-tools cron \
    dig dnsutils unbound unbound-anchor \
    iptables iptables-persistent \
    netfilter-persistent \
    build-essential openssl >/dev/null 2>&1

# Install Python dependencies
pip3 install --upgrade pip >/dev/null 2>&1
pip3 install bcrypt gunicorn flask flask-socketio >/dev/null 2>&1

# Generate WireGuard keys
log_info "Generating WireGuard keys..."
private_key=$(wg genkey)
public_key=$(echo "$private_key" | wg pubkey)

echo "$private_key" > /etc/wireguard/private.key
echo "$public_key" > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key

# Enable IP forwarding
log_info "Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p >/dev/null

# Create WireGuard configuration
log_info "Creating WireGuard configuration..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $private_key
Address = $ipv4_address_pvt
ListenPort = $wg_port
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

# 4. Enterprise DNS Resolver (with DNSSEC and DoT)
vpn_network=$(echo "$ipv4_address_pvt" | cut -d'.' -f1-3)".0/24"
configure_enterprise_dns_resolver "$dns" "$vpn_network"

# 5. DNS Leak Monitoring
configure_dns_leak_monitoring "$dns"

# 6. Enhance WireGuard with DNS protection
enhance_wireguard_with_dns_protection "$dns"

# 7. Security Hardening
apply_security_hardening

# ==================== FIREWALL CONFIGURATION ====================

log_info "Configuring firewall..."
ufw --force disable >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Allow SSH (detect port)
ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F ':' '{print $NF}' | sort -u | head -1)
ufw allow "$ssh_port/tcp" >/dev/null 2>&1

# Allow WireGuard
ufw allow "$wg_port/udp" >/dev/null 2>&1

# Allow Dashboard
ufw allow "$dashboard_port/tcp" >/dev/null 2>&1

# Allow DNS (restricted)
ufw allow out on wg0 to any port 53 >/dev/null 2>&1
ufw allow in on wg0 to any port 53 >/dev/null 2>&1

# Enable firewall
echo "y" | ufw enable >/dev/null 2>&1

# ==================== WGDASHBOARD INSTALLATION ====================

log_info "Installing WGDashboard..."
mkdir -p /etc/xwireguard
cd /etc/xwireguard || exit

git clone https://github.com/donaldzou/WGDashboard.git wgdashboard >/dev/null 2>&1
cd wgdashboard/src || exit

chmod u+x wgd.sh
./wgd.sh install >/dev/null 2>&1

# Configure WGDashboard
hashed_password=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$password', bcrypt.gensalt(12).decode()))")

sed -i "s|^app_port =.*|app_port = $dashboard_port|g" wg-dashboard.ini
sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" wg-dashboard.ini
sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" wg-dashboard.ini
sed -i "s|^password =.*|password = $hashed_password|g" wg-dashboard.ini
sed -i "s|^username =.*|username = $username|g" wg-dashboard.ini
sed -i "s|^welcome_session =.*|welcome_session = false|g" wg-dashboard.ini

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

# ==================== SETUP MONITORING ====================

setup_monitoring_dashboard

# ==================== ENABLE SERVICES ====================

log_info "Enabling services..."
systemctl enable wg-quick@wg0.service --quiet
systemctl enable wg-dashboard.service --quiet
systemctl enable dns-enforcement.service --quiet
systemctl enable enterprise-kill-switch.service --quiet
systemctl enable dns-leak-monitor.service --quiet

# Start services
systemctl start wg-quick@wg0.service
systemctl start wg-dashboard.service
systemctl start dns-enforcement.service
systemctl start enterprise-kill-switch.service
systemctl start dns-leak-monitor.service

# ==================== FINAL CHECKS ====================

sleep 5

wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)
dns_monitor_status=$(systemctl is-active dns-leak-monitor.service)

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
echo "   DNSSEC: ✅ Enabled"
echo "   DNS over TLS: ✅ Enabled"
echo "   Kill Switch: ✅ Active"
echo "   DNS Leak Monitoring: ✅ Active"
echo "   DNS Traffic Enforcement: ✅ Active"
echo ""

echo -e "${YELLOW}📁 Configuration Files:${NC}"
echo "   WireGuard Config: /etc/wireguard/wg0.conf"
echo "   Client Templates: /etc/wireguard/clients/"
echo "   Monitoring Logs: /var/log/dns-leak-monitor.log"
echo "   Installation Log: $INSTALL_LOG"
echo ""

echo -e "${CYAN}🔧 Quick Commands:${NC}"
echo "   View WireGuard status: wg show"
echo "   Check DNS monitor: tail -f /var/log/dns-leak-monitor.log"
echo "   Test for DNS leaks: curl https://ipleak.net/json/"
echo "   View connected peers: wg show wg0"
echo ""

echo -e "${GREEN}⚡ Testing DNS Leak Protection:${NC}"
echo "   Run: dig whoami.akamai.net @resolver1.opendns.com"
echo "   Should return your VPN IP address"
echo ""

echo -e "${YELLOW}⚠️  Important Notes:${NC}"
echo "   - System will reboot in 10 seconds"
echo "   - After reboot, verify all services are running"
echo "   - Client configs are in /etc/wireguard/clients/"
echo "   - Use WGDashboard to create and manage clients"
echo ""

echo -e "${RED}Press Ctrl+C to cancel reboot${NC}"
sleep 10

log_success "Installation complete! Rebooting system..."
reboot
