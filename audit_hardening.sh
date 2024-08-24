    #!/bin/bash

    # Load configuration files
    source config/hardening_rules.sh
    source config/custom_checks.sh

    # Create reports directory if not exists
    mkdir -p reports

    # Function to log messages
    log() {
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> reports/summary_report.txt
    }

    # Function to send email alerts
    send_email_alert() {
        local subject="$1"
        local body="$2"
        echo "$body" | mail -s "$subject" admin@example.com
    }

    # Enhanced User and Group Audits
    user_group_audit() {
        log "Starting User and Group Audit..."
        {
            echo "Users and Groups on the server:" 
            cut -d: -f1 /etc/passwd
            cut -d: -f1 /etc/group
            echo "Users with UID 0:"
            awk -F: '$3 == 0 {print $1}' /etc/passwd
            echo "Checking for users without passwords:"
            awk -F: '($2 == "" ) {print $1}' /etc/shadow
            echo "Checking for weak passwords:"
            while IFS=: read -r user pass _ uid _ _ _ shell; do
                if [[ $shell != */nologin && $shell != */false ]]; then
                    if [[ -z $pass ]]; then
                        echo "User $user has no password set."
                    else
                        strength=$(echo "$pass" | cracklib-check)
                        if [[ $strength != *": OK"* ]]; then
                            echo "User $user has a weak password: $strength"
                        fi
                    fi
                fi
            done < /etc/shadow
        } > reports/user_group_audit.txt
        log "User and Group Audit completed."
    }

    # File and Directory Permissions
    file_dir_audit() {
        log "Starting File and Directory Permissions Audit..."
        {
            echo "World-writable files:"
            find / -type f -perm -o+w -exec ls -l {} \; 2>/dev/null
            echo ".ssh directories with insecure permissions:"
            find /home -type d -name ".ssh" -exec ls -ld {} \;
            echo "Files with SUID/SGID bits set:"
            find / -type f -perm /6000 -exec ls -l {} \; 2>/dev/null
        } > reports/file_permissions.txt
        log "File and Directory Permissions Audit completed."
    }

    # Service Audits
    service_audit() {
        log "Starting Service Audit..."
        {
            echo "Running services:"
            systemctl list-units --type=service --state=running

            echo "Checking for unnecessary services:"
            disable_unnecessary_services

            echo "Checking critical services (sshd, iptables):"
            
            # Check if sshd is installed and running
            if systemctl is-active --quiet sshd; then
                echo "SSHD service is running."
            else
                echo "SSHD service is not running. Please check the OpenSSH server."
            fi

            # Check if iptables is installed
            if command -v iptables >/dev/null 2>&1; then
                echo "iptables is installed."
            else
                echo "iptables is not found. Please install iptables."
            fi

            echo "Non-standard or insecure ports:"
            netstat -tuln | grep -vE "(:22|:80|:443)"
        } > reports/service_audit.txt
        log "Service Audit completed."
    }

    # Firewall and Network Security
    firewall_network_audit() {
        log "Starting Firewall and Network Security Audit..."
        {
            echo "Firewall status:"
            ufw status
            iptables -L
            echo "Open ports and associated services:"
            ss -tuln
            echo "IP forwarding status:"
            sysctl net.ipv4.ip_forward
            sysctl net.ipv6.conf.all.forwarding
        } > reports/firewall_network.txt
        log "Firewall and Network Security Audit completed."
    }

    # IP and Network Configuration Checks
    ip_network_check() {
        log "Starting IP and Network Configuration Check..."
        {
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
        } > reports/ip_network_config.txt
        log "IP and Network Configuration Check completed."
    }

    # Security Updates and Patching
    security_updates() {
        log "Starting Security Updates and Patching Check..."
        {
            echo "Checking for available updates:"
            apt-get update -qq && apt-get upgrade -s | grep -i security
            echo "Configuring unattended-upgrades:"
            enable_unattended_upgrades          
        } > reports/security_updates.txt
        log "Security Updates and Patching Check completed."
    }

    # Log Monitoring
    log_monitoring() {
        log "Starting Log Monitoring..."
        {
            echo "Suspicious log entries:"
            grep "Failed password" /var/log/auth.log | tail -n 10
            grep "unauthorized access" /var/log/syslog | tail -n 10
        } > reports/suspicious_logs.txt
        log "Log Monitoring completed."
    }

    # Server Hardening Steps
    server_hardening() {
        log "Starting Server Hardening..."
        {
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
        } > reports/hardening_actions.txt
        log "Server Hardening completed."
    }

    # Custom Security Checks
    custom_security_checks() {
        log "Running custom security checks..."
        run_custom_checks > reports/custom_checks.txt
        log "Custom security checks completed."
    }

    # Function to generate comprehensive report
    generate_comprehensive_report() {
        log "Generating comprehensive security report..."
        report_file="security_audit_report_$(date +%Y%m%d).txt"
        {
            echo "========================================"
            echo "      Security Audit Report"
            echo "      $(date)"
            echo "========================================"
            echo
            echo "1. User and Group Audit Results:"
            cat reports/user_group_audit.txt
            echo
            echo "2. File and Directory Permission Issues:"
            cat reports/file_permissions.txt
            echo
            echo "3. Service Audit Results:"
            cat reports/service_audit.txt
            echo
            echo "4. Firewall and Network Security Status:"
            cat reports/firewall_network.txt
            echo
            echo "5. IP and Network Configuration:"
            cat reports/ip_network_config.txt
            echo
            echo "6. Security Updates Status:"
            cat reports/security_updates.txt
            echo
            echo "7. Suspicious Log Entries:"
            cat reports/suspicious_logs.txt
            echo
            echo "8. Server Hardening Actions:"
            cat reports/hardening_actions.txt
            echo
            echo "9. Custom Security Check Results:"
            cat reports/custom_checks.txt
            echo
            echo "========================================"
            echo "End of Report"
            echo "========================================"
        } > "$report_file"

        log "Comprehensive report generated: $report_file"

        # Check for critical issues and send email if found
        if grep -q "CRITICAL" "$report_file"; then
            send_email_alert "CRITICAL Security Issues Detected" "Critical security issues have been detected. Please review the attached report immediately." < "$report_file"
        fi
    }

    # Handle script termination
    cleanup() {
        log "Script terminated."
        exit 1
    }

    # Trap signals
    trap cleanup INT TERM

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

        generate_comprehensive_report

        log "Security Audit and Hardening Process completed."
    }

    # Run the main function
    main
