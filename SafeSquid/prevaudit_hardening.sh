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
    # Check for weak passwords (using cracklib-check)
    echo "Checking for weak passwords:"
    while IFS=: read -r user _; do
        if [[ $(echo "password" | cracklib-check) == *"weak password"* ]]; then
            echo "User $user has a weak password."
        fi
    done < /etc/shadow
    log "User and Group Audit completed."
}

# 2. File and Directory Permissions
file_dir_audit() {
    log "Starting File and Directory Permissions Audit..."
    echo "World-writable files:"
    find / -type f -perm -o+w -exec ls -l {} \; 2>/dev/null
    echo ".ssh directories with insecure permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \; -exec chown $(stat -c '%U' {}) {} \;
    echo "Files with SUID/SGID bits set:"
    find / -type f -perm /6000 -exec ls -l {} \; 2>/dev/null
    log "File and Directory Permissions Audit completed."
}

# 3. Service Audits
service_audit() {
    log "Starting Service Audit..."
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo "Checking for unnecessary services:"
    disable_unnecessary_services
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
    echo "Checking if sensitive services are exposed on public IPs..."
    netstat -tuln | grep -E "22|80|443" | grep -vE "^127\.|^10\.|^172\.16\.|^192\.168\." && echo "Warning: Sensitive services exposed on public IPs."
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
    grep "unauthorized access" /var/log/syslog | tail -n 10
    log "Log Monitoring completed."
}

# 8. Server Hardening Steps
server_hardening() {
    log "Starting Server Hardening..."
    echo "Applying SSH configuration hardening..."
    secure_ssh
    echo "Disabling IPv6..."
    disable_ipv6
    echo "Securing GRUB bootloader..."
    secure_grub
    echo "Configuring and enforcing firewall rules..."
    configure_firewall
    echo "Enabling unattended upgrades and removing unused packages..."
    enable_unattended_upgrades
    remove_unused_packages
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
