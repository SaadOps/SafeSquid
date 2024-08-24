#!/bin/bash

# Load configuration files
source config/hardening_rules.sh
source config/custom_checks.sh

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> reports/summary_report.txt
}

# 1. User and Group Audits
user_group_audit() {
    log "Starting User and Group Audit..."
    echo "Users and Groups on the server:" 
    cut -d: -f1 /etc/passwd
    cut -d: -f1 /etc/group
    echo "Users with UID 0:"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    echo "Checking for users without passwords:"
    awk -F: '($2 == "" ) {print $1}' /etc/shadow
    log "User and Group Audit completed."
}

# 2. File and Directory Permissions
file_dir_audit() {
    log "Starting File and Directory Permissions Audit..."
    echo "World-writable files:"
    find / -type f -perm -o+w -exec ls -l {} \;
    echo ".ssh directories with insecure permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \;
    echo "Files with SUID/SGID bits set:"
    find / -type f -perm /6000 -exec ls -l {} \;
    log "File and Directory Permissions Audit completed."
}

# 3. Service Audits
service_audit() {
    log "Starting Service Audit..."
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo "Critical services (sshd, iptables) status:"
    systemctl status sshd iptables
    echo "Non-standard or insecure ports:"
    netstat -tuln | grep -vE "(:22|:80|:443)"
    log "Service Audit completed."
}

# 4. Firewall and Network Security
firewall_network_audit() {
    log "Starting Firewall and Network Security Audit..."
    echo "Firewall status:"
    ufw status
    iptables -L
    echo "Open ports and associated services:"
    ss -tuln
    echo "IP forwarding status:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
    log "Firewall and Network Security Audit completed."
}

# 5. IP and Network Configuration Checks
ip_network_check() {
    log "Starting IP and Network Configuration Check..."
    echo "IP addresses and their classification (Public/Private):"
    for ip in $(hostname -I); do
        if [[ "$ip" =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
            echo "$ip: Private"
        else
            echo "$ip: Public"
        fi
    done
    log "IP and Network Configuration Check completed."
}

# 6. Security Updates and Patching
security_updates() {
    log "Starting Security Updates and Patching Check..."
    echo "Checking for available updates:"
    apt-get update -qq && apt-get upgrade -s | grep -i security
    echo "Checking if unattended-upgrades is enabled:"
    dpkg-reconfigure --priority=low unattended-upgrades
    log "Security Updates and Patching Check completed."
}

# 7. Log Monitoring
log_monitoring() {
    log "Starting Log Monitoring..."
    echo "Suspicious log entries:"
    grep "Failed password" /var/log/auth.log | tail -n 10
    log "Log Monitoring completed."
}

# 8. Server Hardening Steps
server_hardening() {
    log "Starting Server Hardening..."
    echo "Applying SSH configuration hardening..."
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    echo "Securing GRUB bootloader..."
    grub-mkpasswd-pbkdf2
    log "Server Hardening completed."
}

# 9. Custom Security Checks
custom_security_checks() {
    log "Running custom security checks..."
    run_custom_checks
    log "Custom security checks completed."
}

# Main Execution
main() {
    log "Starting Security Audit and Hardening Process..."

    user_group_audit
    file_dir_audit
    service_audit
    firewall_network_audit
    ip_network_check
    security_updates
    log_monitoring
    server_hardening
    custom_security_checks

    log "Security Audit and Hardening Process completed."
}

# Run the main function
main
