#!/bin/bash

# Set DEBIAN_FRONTEND to noninteractive to avoid prompts
export DEBIAN_FRONTEND=noninteractive

# Create reports directory if it doesn't exist
mkdir -p reports

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> reports/summary_report.txt
}

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

# Function to secure SSH configuration
secure_ssh() {
    log "Securing SSH configuration..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
    systemctl restart ssh || log "Error: Failed to restart SSH service."
    log "SSH configuration hardened."
}

# Function to secure GRUB bootloader
secure_grub() {
    log "Securing GRUB bootloader..."
    grub_password=$(grub-mkpasswd-pbkdf2 | grep -oP '(?<=grub.pbkdf2.sha512.).*')
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root ${grub_password}" >> /etc/grub.d/40_custom
    update-grub || log "Error: Failed to update GRUB."
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

# Function to configure firewall rules
configure_firewall() {
    log "Configuring firewall rules..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.0/8 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    
    # Create the directory if it doesn't exist
    mkdir -p /etc/iptables
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4 || log "Error: Failed to save iptables rules."
    log "Firewall rules configured."
}

# Function to enable automatic security updates
enable_unattended_upgrades() {
    log "Enabling unattended upgrades..."
    
    # Install unattended-upgrades if not already installed
    apt-get install unattended-upgrades -y || log "Error: Failed to install unattended-upgrades."
    
    # Preconfigure unattended-upgrades to automatically accept defaults
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    echo "unattended-upgrades unattended-upgrades/upgrade_type select unattended-upgrades" | debconf-set-selections
    
    # Reconfigure unattended-upgrades in non-interactive mode
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

# Function to perform user and group audit
user_group_audit() {
    log "Starting User and Group Audit..."
    echo 'Users and Groups on the server:' > reports/user_group_audit.txt
    cut -d: -f1 /etc/passwd >> reports/user_group_audit.txt
    cut -d: -f1 /etc/group >> reports/user_group_audit.txt
    
    # Check for users with UID 0 (root privileges)
    echo "Users with UID 0:" >> reports/user_group_audit.txt
    awk -F: '($3 == 0) {print $1 " has UID 0"}' /etc/passwd >> reports/user_group_audit.txt

    # Check for users without passwords
    echo "Users without passwords:" >> reports/user_group_audit.txt
    awk -F: '($2 == "" ) {print $1 " has no password set"}' /etc/shadow >> reports/user_group_audit.txt
    
    log "User and Group Audit completed."
}

# Function to perform file and directory permissions audit
file_dir_audit() {
    log "Starting File and Directory Permissions Audit..."
    echo 'World-writable files:' > reports/file_permissions.txt
    find / -path /proc -prune -o -type f -perm -o+w -exec ls -l {} \; 2>/dev/null >> reports/file_permissions.txt

    # Check for .ssh directory permissions
    echo '.ssh directory permissions:' >> reports/file_permissions.txt
    find /home -type d -name ".ssh" -exec chmod 700 {} \; -exec echo "{} permissions set to 700" \; >> reports/file_permissions.txt

    # Check for files with SUID or SGID bits set
    echo 'Files with SUID/SGID bits set:' >> reports/file_permissions.txt
    find / -path /proc -prune -o -perm /6000 -type f -exec ls -l {} \; >> reports/file_permissions.txt

    log "File and Directory Permissions Audit completed."
}

# Function to perform service audit
service_audit() {
    log "Starting Service Audit..."
    disable_unnecessary_services
    echo 'Running services:' > reports/service_audit.txt
    systemctl list-units --type=service --state=running >> reports/service_audit.txt
    log "Service Audit completed."
}

# Function to perform firewall and network audit
firewall_network_audit() {
    log "Starting Firewall and Network Security Audit..."
    ufw status > reports/firewall_network.txt
    iptables -L >> reports/firewall_network.txt
    ss -tuln >> reports/firewall_network.txt
    log "Firewall and Network Security Audit completed."
}

# Function to perform IP and network configuration check
ip_network_check() {
    log "Starting IP and Network Configuration Check..."
    hostname -I > reports/ip_network_check.txt
    ip route >> reports/ip_network_check.txt
    cat /etc/resolv.conf >> reports/ip_network_check.txt

    # Public vs. Private IP Check
    echo "Public vs. Private IP Check:" >> reports/ip_network_check.txt
    ip -o addr show | awk '{print $2, $4}' | while read line; do
        ip=$(echo $line | awk '{print $2}' | cut -d'/' -f1)
        if [[ $ip == 10.* || $ip == 172.16.* || $ip == 192.168.* ]]; then
            echo "$ip is a private IP" >> reports/ip_network_check.txt
        else
            echo "$ip is a public IP" >> reports/ip_network_check.txt
        fi
    done
    
    log "IP and Network Configuration Check completed."
}

# Function to send email alerts for critical issues
send_alerts() {
    log "Checking for critical issues..."
    if grep -q "CRITICAL" reports/summary_report.txt; then
        mail -s "Critical Security Alert" admin@example.com < reports/summary_report.txt
        log "Critical issues found. Alert email sent."
    else
        log "No critical issues found."
    fi
}

# Main Execution
log "Starting Security Audit and Hardening Process..."

user_group_audit
file_dir_audit
service_audit
firewall_network_audit
ip_network_check
configure_firewall
enable_unattended_upgrades
remove_unused_packages
secure_grub
secure_ssh
disable_ipv6

log "Security Audit and Hardening Process completed."
send_alerts
echo "Script successfully executed"
