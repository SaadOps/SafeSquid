# Comprehensive Bash Scripts for Server Monitoring and Security Hardening

## Overview

This repository contains two Bash scripts developed to address different technical tasks:

1. **Monitoring System Resources for a Proxy Server**
2. **Automating Security Audits and Server Hardening on Linux Servers**

Each script is designed to perform specific functions, such as monitoring system resources or automating security audits, and can be customized and extended as needed. The scripts are modular, efficient, and come with comprehensive documentation to help users easily deploy and utilize them.

---

## Set 1: Monitoring System Resources for a Proxy Server

### Description

This Bash script provides a real-time dashboard for monitoring various system resources on a proxy server. It refreshes the data every few seconds and allows users to call specific parts of the dashboard individually using command-line switches.

### Features

1. **Top 10 Most Used Applications**
   - Displays the top 10 applications consuming the most CPU and memory.

2. **Network Monitoring**
   - Shows the number of concurrent connections to the server.
   - Displays packets in and out (in MB).

3. **Disk Usage**
   - Displays the disk space usage by mounted partitions.
   - Highlights partitions using more than 80% of the space.

4. **System Load**
   - Shows the current load average for the system.
   - Includes a breakdown of CPU usage (user, system, idle, etc.).

5. **Memory Usage**
   - Displays total, used, and free memory.
   - Shows swap memory usage.

6. **Process Monitoring**
   - Displays the number of active processes.
   - Shows the top 5 processes in terms of CPU and memory usage.

7. **Service Monitoring**
   - Monitors the status of essential services like sshd, nginx/apache, iptables, etc.

8. **Custom Dashboard**
   - Provides command-line switches to view specific parts of the dashboard (e.g., `-cpu`, `-memory`, `-network`).

### Performance Considerations

- The script is designed to be efficient, with minimal impact on system performance.
- Real-time data updates are handled with care to ensure smooth operation without overloading the server.

### Extensibility

The script is modular and can be easily extended to include additional monitoring features. Users can modify the script to fit specific needs by adding or customizing functions.

---

## Set 2: Script for Automating Security Audits and Server Hardening on Linux Servers

### Description

This Bash script automates the security audit and hardening process for Linux servers. It is designed to be reusable and modular, making it easy to deploy across multiple servers to ensure they meet stringent security standards.

### Features

1. **User and Group Audits**
   - Lists all users and groups on the server.
   - Checks for users with UID 0 (root privileges) and reports any non-standard users.
   - Identifies and reports users without passwords or with weak passwords.

2. **File and Directory Permissions**
   - Scans for files and directories with world-writable permissions.
   - Checks `.ssh` directories for secure permissions.
   - Reports files with SUID or SGID bits set, particularly on executables.

3. **Service Audits**
   - Lists all running services and checks for any unnecessary or unauthorized services.
   - Ensures critical services (e.g., sshd, iptables) are running and properly configured.
   - Checks that no services are listening on non-standard or insecure ports.

4. **Firewall and Network Security**
   - Verifies that a firewall (e.g., iptables, ufw) is active and configured to block unauthorized access.
   - Reports open ports and their associated services.
   - Checks for and reports any IP forwarding or other insecure network configurations.

5. **IP and Network Configuration Checks**
   - Identifies whether the server's IP addresses are public or private.
   - Provides a summary of all IP addresses assigned to the server, specifying which are public and which are private.
   - Ensures that sensitive services (e.g., SSH) are not exposed on public IPs unless required.

6. **Security Updates and Patching**
   - Checks for and reports any available security updates or patches.
   - Ensures that the server is configured to receive and install security updates regularly.

7. **Log Monitoring**
   - Checks for any recent suspicious log entries that may indicate a security breach, such as too many login attempts on SSH.

8. **Server Hardening Steps**
   - SSH configuration for key-based authentication and disabling password-based login.
   - Disabling IPv6 (if not required).
   - Securing the bootloader with a password.
   - Implementing recommended iptables rules.

9. **Custom Security Checks**
   - Allows the script to be easily extended with custom security checks based on specific organizational policies or requirements.
   - Includes a configuration file where custom checks can be defined and managed.

10. **Reporting and Alerting**
    - Generates a summary report of the security audit and hardening process, highlighting any issues that need attention.
    - Optionally, sends email alerts or notifications if critical vulnerabilities or misconfigurations are found.

### Extensibility

- The script is modular and can be extended with additional security checks.
- Users can define custom checks in the provided configuration file.

### Reporting

- The script generates a comprehensive report that summarizes the findings of the security audit and hardening process.
- Optional email alerts can be configured to notify administrators of critical issues.

---

## Conclusion

Both scripts are designed to be efficient, customizable, and user-friendly. They can be easily integrated into your server management practices to monitor system resources and ensure security compliance. Detailed instructions and examples are provided to help users get started quickly.


---
