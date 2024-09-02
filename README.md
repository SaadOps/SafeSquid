
---

# Security Audit and Hardening Script

## Overview

This Bash script automates the security audit and hardening process for Linux servers. It is designed to be reusable and modular, allowing deployment across multiple servers to ensure they meet stringent security standards. The script performs various checks and applies hardening measures to enhance the security of the server.

## Features

- **User and Group Audits**: Lists users and groups, checks for root privileges and users without passwords.
- **File and Directory Permissions**: Scans for world-writable files, checks `.ssh` directory permissions, and reports files with SUID/SGID bits set.
- **Service Audits**: Lists running services, disables unnecessary services, and checks service configurations.
- **Firewall and Network Security**: Configures firewall rules, verifies firewall status, and checks network configurations.
- **IP and Network Configuration**: Identifies public vs. private IP addresses and ensures sensitive services are not exposed unnecessarily.
- **Security Updates and Patching**: Configures automatic security updates and removes unused packages.
- **Log Monitoring**: Monitors logs for suspicious entries.
- **Server Hardening**: Secures SSH configuration, disables IPv6 (if not needed), and secures the GRUB bootloader.
- **Custom Security Checks**: Allows for easy extension with custom checks based on organizational policies.

## Requirements

- **OS**: Debian-based Linux distributions (e.g., Ubuntu).
- **Packages**: `systemctl`, `sed`, `grub-mkpasswd-pbkdf2`, `apt-get`, `iptables`, `ufw`, `dpkg-reconfigure`, `mail`.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/security-audit-hardening.git
   cd security-audit-hardening
   ```

2. **Make the Script Executable**:
   ```bash
   chmod +x audit_hardening.sh
   ```

## Usage

Run the script with root privileges to perform the security audit and hardening:

```bash
sudo ./audit_hardening.sh
```

### Script Breakdown

- **`disable_unnecessary_services`**: Disables and stops unnecessary services.
- **`secure_ssh`**: Hardens SSH configuration by disabling root login and password authentication.
- **`secure_grub`**: Secures the GRUB bootloader with a password.
- **`disable_ipv6`**: Disables IPv6 if not required.
- **`configure_firewall`**: Configures iptables firewall rules.
- **`enable_unattended_upgrades`**: Enables automatic security updates.
- **`remove_unused_packages`**: Removes unused packages and cleans up.
- **`user_group_audit`**: Audits user and group configurations.
- **`file_dir_audit`**: Checks file and directory permissions.
- **`service_audit`**: Audits running services and checks for unnecessary services.
- **`firewall_network_audit`**: Audits firewall and network configurations.
- **`ip_network_check`**: Checks IP and network configurations, including public vs. private IPs.
- **`send_alerts`**: Sends email alerts if critical issues are found.

## Configuration

Customize the script by editing the configuration file (if applicable) to add or modify security checks according to your organization's policies.

## Reporting

The script generates reports in the `reports` directory:

- `summary_report.txt`: Contains general log messages and status updates.
- `user_group_audit.txt`: Details on users and groups.
- `file_permissions.txt`: Reports on file and directory permissions.
- `service_audit.txt`: Lists running services.
- `firewall_network.txt`: Contains firewall and network security details.
- `ip_network_check.txt`: Provides IP and network configuration details.

## Alerts

The script can send email alerts if critical issues are found. Ensure the `mail` command is configured correctly on your system. Update the email address in the `send_alerts` function as needed.

## Customization

To add custom security checks:

1. Edit the script to include new functions.
2. Update the main execution block to call these functions.
3. Ensure new checks are documented and included in the reporting.
