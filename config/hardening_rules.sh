#!/bin/bash

# Function to disable unnecessary services
disable_unnecessary_services() {
    log "Disabling unnecessary services..."
    services_to_disable=("telnet" "rlogin" "rexec" "vsftpd" "xinetd")

    for service in "${services_to_disable[@]}"; do
        systemctl disable $service 2>/dev/null
        systemctl stop $service 2>/dev/null
        log "$service has been disabled."
    done
}

# Function to enforce strong SSH configuration
secure_ssh() {
    log "Securing SSH configuration..."
    
    # Disable root login
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (key-based authentication only)
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Disable empty passwords
    sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # Set the SSH protocol to 2 (disabling SSHv1)
    sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
    
    systemctl restart ssh || log "Error: Failed to restart SSH service."
    log "SSH configuration hardened."
}

# Function to secure the bootloader with a password
secure_grub() {
    log "Securing GRUB bootloader..."

    # Set GRUB password (prompt for password)
    grub_password=$(grub-mkpasswd-pbkdf2 | grep -oP '(?<=grub.pbkdf2.sha512.).*')
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root ${grub_password}" >> /etc/grub.d/40_custom
    
    # Use timeout to limit execution time
    if ! timeout 10s bash -c 'update-grub'; then
        log "GRUB security hardening was skipped or failed due to timeout."
        return 1
    fi

    log "GRUB bootloader secured."
}

# Function to disable IPv6 if not required
disable_ipv6() {
    log "Disabling IPv6..."

    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    log "IPv6 disabled."
}

# Function to configure and enforce firewall rules
configure_firewall() {
    log "Configuring firewall rules..."

    # Ensure iptables-persistent is installed
    if ! dpkg -l | grep -q iptables-persistent; then
        apt-get install iptables-persistent -y || log "Error: Failed to install iptables-persistent."
    fi

    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.0/8 -j DROP

    # Allow inbound SSH (port 22)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # Allow inbound HTTP/HTTPS (ports 80 and 443)
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT

    # Allow outbound DNS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4 || log "Error: Failed to save iptables rules."

    log "Firewall rules configured."
}

# Function to enable automatic security updates
enable_unattended_upgrades() {
    log "Enabling unattended upgrades..."
    apt-get install unattended-upgrades -y || log "Error: Failed to install unattended-upgrades."
    dpkg-reconfigure --priority=low unattended-upgrades || log "Error: Failed to configure unattended-upgrades."
    log "Unattended upgrades enabled."
}

# Function to remove unused packages
remove_unused_packages() {
    log "Removing unused packages..."
    apt-get autoremove -y
    apt-get autoclean -y
    log "Unused packages removed."
}
    
