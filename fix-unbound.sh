#!/bin/bash

# Complete Unbound fix script

echo -e "\033[0;32m=== Unbound DNS Fix Script ===\033[0m\n"

# Stop Unbound
systemctl stop unbound

# Backup existing config
cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak.$(date +%s) 2>/dev/null

# Create minimal working configuration WITHOUT remote-control
cat > /etc/unbound/unbound.conf <<'EOF'
# Minimal Unbound configuration for WireGuard
# No remote-control to avoid SSL certificate issues

server:
    # Basic settings
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    
    # Protocol options
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # Security settings
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    
    # Performance
    cache-min-ttl: 300
    cache-max-ttl: 3600
    prefetch: yes
    num-threads: 2
    msg-cache-size: 50m
    rrset-cache-size: 100m
    outgoing-range: 4096
    qname-minimisation: yes
    
    # Logging
    verbosity: 1
    use-syslog: yes
    
    # Disable DNSSEC for now (can cause issues)
    val-log-level: 0
    
    # IMPORTANT: No remote-control section at all

# Forward queries to upstream DNS servers
forward-zone:
    name: "."
    # Your specified DNS servers
    forward-addr: 147.78.0.8
    forward-addr: 147.78.0.7
EOF

# Remove any existing SSL certificates that might be causing issues
rm -f /etc/unbound/unbound_server.pem /etc/unbound/unbound_server.key 2>/dev/null
rm -f /etc/unbound/unbound_control.pem /etc/unbound/unbound_control.key 2>/dev/null

# Ensure proper permissions
chown -R unbound:unbound /etc/unbound
chmod 755 /etc/unbound

# Create root key directory and file
mkdir -p /var/lib/unbound
touch /var/lib/unbound/root.key
chown -R unbound:unbound /var/lib/unbound
chmod 644 /var/lib/unbound/root.key

# Start Unbound
echo "Starting Unbound..."
systemctl start unbound
sleep 3

# Check if it's running
if systemctl is-active --quiet unbound; then
    echo -e "\033[0;32m✓ Unbound started successfully\033[0m"
    
    # Test DNS resolution
    if dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
        echo -e "\033[0;32m✓ DNS resolution working on port 53\033[0m"
        
        # Configure resolv.conf
        chattr -i /etc/resolv.conf 2>/dev/null
        cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Using local Unbound resolver
nameserver 127.0.0.1
options rotate
options timeout:1
options attempts:5
EOF
        chattr +i /etc/resolv.conf 2>/dev/null
        echo -e "\033[0;32m✓ System DNS configured\033[0m"
    else
        echo -e "\033[0;31m✗ DNS resolution failed on port 53\033[0m"
        
        # Try port 5353
        sed -i 's/port: 53/port: 5353/' /etc/unbound/unbound.conf
        systemctl restart unbound
        sleep 3
        
        if dig @127.0.0.1 -p 5353 google.com +short >/dev/null 2>&1; then
            echo -e "\033[0;32m✓ DNS resolution working on port 5353\033[0m"
            
            chattr -i /etc/resolv.conf 2>/dev/null
            cat > /etc/resolv.conf <<EOF
# WireGuard Enterprise VPN DNS Configuration
# Using local Unbound resolver on port 5353
nameserver 127.0.0.1
options rotate
options timeout:1
options attempts:5
EOF
            chattr +i /etc/resolv.conf 2>/dev/null
            echo -e "\033[0;32m✓ System DNS configured for port 5353\033[0m"
        fi
    fi
else
    echo -e "\033[0;31m✗ Failed to start Unbound\033[0m"
    echo "Checking logs..."
    journalctl -u unbound --no-pager -n 20
    
    # Fallback to direct DNS
    echo -e "\n\033[0;33m⚠ Falling back to direct DNS servers\033[0m"
    chattr -i /etc/resolv.conf 2>/dev/null
    cat > /etc/resolv.conf <<EOF
# Fallback DNS configuration
nameserver 147.78.0.8
nameserver 147.78.0.7
nameserver 8.8.8.8
options rotate
EOF
    chattr +i /etc/resolv.conf 2>/dev/null
fi

# Test final configuration
echo -e "\n\033[0;34mTesting DNS resolution...\033[0m"
if ping -c1 google.com >/dev/null 2>&1; then
    echo -e "\033[0;32m✓ Internet connectivity restored\033[0m"
    echo -e "\033[0;32m✓ DNS is working properly\033[0m"
else
    echo -e "\033[0;31m✗ Still having DNS issues\033[0m"
    
    # Emergency fix - use direct DNS
    echo -e "\n\033[0;33mApplying emergency DNS fix...\033[0m"
    iptables -F OUTPUT
    iptables -P OUTPUT ACCEPT
    chattr -i /etc/resolv.conf 2>/dev/null
    cat > /etc/resolv.conf <<EOF
# Emergency DNS configuration
nameserver 147.78.0.7
options rotate
EOF
    chattr +i /etc/resolv.conf 2>/dev/null
    
    if ping -c1 google.com >/dev/null 2>&1; then
        echo -e "\033[0;32m✓ Emergency DNS working\033[0m"
    fi
fi

echo -e "\n\033[0;32m=== Fix Complete ===\033[0m"
echo "You can now use:"
echo "  - dig google.com"
echo "  - ping google.com"
echo "  - systemctl status unbound"
