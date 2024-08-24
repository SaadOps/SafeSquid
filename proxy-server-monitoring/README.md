# Proxy Server Resource Monitoring Dashboard

This Bash script provides a comprehensive system resource monitoring dashboard for a proxy server. It offers real-time insights into various system metrics and allows users to view specific parts of the dashboard using command-line switches.

## Features

1. Top 10 Most Used Applications (CPU and Memory)
2. Network Monitoring (Concurrent connections and Packet in/out)
3. Disk Usage (with warnings for high usage)
4. System Load (Load average and CPU breakdown)
5. Memory Usage (Including swap)
6. Process Monitoring
7. Service Monitoring
8. Custom Dashboard with command-line switches

## Prerequisites

- Bash shell
- Standard Linux utilities (ps, ss, df, top, free, systemctl)

## Installation and Configuration

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SaadOps/SafeSquid.git
   cd proxy-server-monitoring
   ```

2. **Make the script executable:**
   ```bash
   chmod +x monitor.sh
   ```

## Usage

- Run the script:

  - For full dashboard:
    ```
    ./monitor.sh
    ```

  - For specific parts of the dashboard:
    ```
    ./monitor.sh [-cpu] [-memory] [-network] [-disk] [-load] [-process] [-service]
    ```

The script refreshes the displayed information every 5 seconds.

## Command-line Switches

- `-cpu`: Display system load and CPU breakdown
- `-memory`: Show memory usage including swap
- `-network`: Display network monitoring information
- `-disk`: Show disk usage with warnings for high usage
- `-load`: Same as `-cpu`
- `-process`: Display process monitoring information
- `-service`: Show status of essential services

## Examples

1. View full dashboard:

`./monitor.sh`  

2. Monitor only CPU and memory:
`./monitor.sh -cpu -memory`


3. Check disk usage and network:
`./monitor.sh -disk -network`

4. Monitor processes and services:
`./monitor.sh -process -service`

## Output Sections

1. **Top 10 Most Used Applications**: Displays PID, PPID, command, memory usage, and CPU usage.

2. **Network Monitoring**: Shows the number of concurrent connections and packet in/out rate.

3. **Disk Usage**: Displays usage for all mounted partitions with warnings for those using over 80% space.

4. **System Load**: Shows current load average and CPU usage breakdown.

5. **Memory Usage**: Displays total, used, and free memory, including swap usage.

6. **Process Monitoring**: Shows the number of active processes and top 5 processes by CPU and memory usage.

7. **Service Monitoring**: Lists all currently running services.

## Customization

The script is modular, with each monitoring aspect in its own function. To add new monitoring capabilities:

1. Create a new function for the monitoring task.
2. Add a new command-line switch in the argument handling section.
3. Update the usage function to include the new switch.

## Troubleshooting

- Ensure you have necessary permissions to run the script and access system information.
- Verify that all required utilities are installed on your system.
- For network monitoring, ensure the script can identify an active network interface.

