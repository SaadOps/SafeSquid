
---

# Security Audit and Server Hardening Script

## Overview

This Bash script automates both security audits and the server hardening process for Linux servers. It is modular and reusable, allowing easy deployment across multiple servers to ensure they meet stringent security standards. The script includes checks for common security vulnerabilities, IPv4/IPv6 configurations, public vs. private IP identification, and the implementation of recommended hardening measures.

## Features

- **User and Group Audits**
  - Lists all users and groups on the server.
  - Checks for users with UID 0 (root privileges) and reports any non-standard users.
  - Identifies and reports users without passwords or with weak passwords.

- **File and Directory Permissions Checks**
  - Scans for files and directories with world-writable permissions.
  - Checks `.ssh` directories for secure permissions.
  - Reports files with SUID or SGID bits set, particularly on executables.

- **Service Audits**
  - Lists all running services and checks for unnecessary or unauthorized services.
  - Ensures that critical services (e.g., `sshd`, `iptables`) are running and properly configured.
  - Checks that no services are listening on non-standard or insecure ports.

- **Firewall and Network Security Checks**
  - Verifies that a firewall (e.g., `iptables`, `ufw`) is active and configured to block unauthorized access.
  - Reports any open ports and their associated services.
  - Checks for IP forwarding or other insecure network configurations.

- **IP and Network Configuration Checks (IPv4/IPv6)**
  - Identifies whether the server's IP addresses are public or private.
  - Provides a summary of all IP addresses, specifying which are public and which are private.
  - Ensures that sensitive services (e.g., SSH) are not exposed on public IPs unless required.

- **Security Updates and Patching**
  - Checks for and reports available security updates or patches.
  - Ensures the server is configured to receive and install security updates regularly.

- **Log Monitoring**
  - Checks for suspicious log entries that may indicate a security breach, such as multiple failed login attempts on SSH.

- **Server Hardening Steps**
  - **SSH Configuration**: Enforces key-based authentication, disables password-based logins, and ensures SSH keys are securely stored.
  - Disables IPv6 if not required, following recommended guidelines.
  - Secures the GRUB bootloader by setting a password to prevent unauthorized changes.
  - Configures firewall rules, including default deny settings and specific port allowances.
  - Implements unattended-upgrades to apply security updates automatically and remove unused packages.

- **Custom Security Checks**
  - Allows for the easy addition of custom security checks based on specific organizational policies.
  - Includes a configuration file where custom checks can be defined and managed.

- **Reporting and Alerting**
  - Generates a summary report of the security audit and hardening process, highlighting issues needing attention.
  - Optionally sends email alerts if critical vulnerabilities or misconfigurations are found.

## Prerequisites

- A Linux server (Debian-based distribution recommended)
- Root or sudo privileges

## Installation and Configuration

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SaadOps/SafeSquid.git
   cd security-audit-hardening
   ```

2. **Make the script executable:**
   ```bash
   chmod +x audit_hardening.sh
   ```

3. **Edit configuration files:**
   - `config/hardening_rules.sh`: Customize hardening measures.
   - `config/custom_checks.sh`: Add organization-specific security checks.

## Usage

Run the script with sudo privileges:

```bash
sudo ./audit_hardening.sh
```

The script will generate reports in the `reports/` directory, including a comprehensive `security_audit_report_YYYYMMDD.txt`.

## Example Configuration Files

### `config/hardening_rules.sh`
```bash
#!/bin/bash

disable_unnecessary_services() {
    services_to_disable=("telnet" "rlogin" "rexec")
    for service in "${services_to_disable[@]}"; do
        systemctl disable $service 2>/dev/null
        systemctl stop $service 2>/dev/null
    done
}

secure_ssh() {
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

disable_ipv6() {
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

configure_firewall() {
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}
# Add more hardening functions as needed
```

### `config/custom_checks.sh`
```bash
#!/bin/bash

run_custom_checks() {
    # Check for .rhosts files
    echo "Checking for .rhosts files..."
    find / -name ".rhosts" -exec rm -f {} \;

    # Check for weak SSL/TLS configurations
    echo "Checking SSL/TLS configurations..."
    grep -r "SSLProtocol" /etc/apache2/
    grep -r "ssl_protocols" /etc/nginx/

    # Check for world-writable files
    echo "Checking for world-writable files..."
    find / -type f -perm -2 -ls 2>/dev/null

    # Add more custom checks as needed
}
```

## Troubleshooting

- **Command Not Found Errors**: Install required tools:
  ```bash
  sudo apt-get update
  sudo apt-get install -y net-tools iptables ufw cracklib-runtime
  ```

- **Permission Denied Errors**: Ensure you're running the script with `sudo`.

- **Script Fails to Modify Configuration Files**: Verify file existence and permissions.