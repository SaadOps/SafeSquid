
---

# Proxy Server Resource Monitoring Dashboard

This Bash script is designed to provide a real-time monitoring dashboard for system resources on a proxy server. It offers comprehensive insights into various system metrics and allows users to access specific sections of the dashboard using command-line switches. This tool is essential for ensuring optimal server performance and proactive issue detection.

## Features

- **Top 10 Most Used Applications (CPU and Memory):** Identifies resource-heavy applications.
- **Network Monitoring:** Monitors concurrent connections and packet in/out rates.
- **Disk Usage:** Analyzes disk usage, providing warnings when usage is high.
- **System Load:** Displays load averages and detailed CPU usage.
- **Memory Usage:** Tracks memory usage, including swap space.
- **Process Monitoring:** Lists running processes and their resource consumption.
- **Service Monitoring:** Checks the status of essential services.
- **Custom Dashboard:** Allows users to view specific sections using command-line switches.

## Prerequisites

Ensure the following are available on your system:
- Bash shell
- Standard Linux utilities (`ps`, `ss`, `df`, `top`, `free`, `systemctl`)

## Installation

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

### Running the Full Dashboard

To run the complete monitoring dashboard, simply execute:
```bash
./monitor.sh
```

### Running Specific Dashboard Sections

You can also view specific sections by using the appropriate command-line switches:
```bash
./monitor.sh [-cpu] [-memory] [-network] [-disk] [-load] [-process] [-service]
```

- **`-cpu`**: Display system load and CPU breakdown.
- **`-memory`**: Show memory usage including swap.
- **`-network`**: Display network monitoring information.
- **`-disk`**: Show disk usage with warnings for high usage.
- **`-load`**: Same as `-cpu`.
- **`-process`**: Display process monitoring information.
- **`-service`**: Show status of essential services.

### Example Usage

1. **Full Dashboard**:  
   Display all monitoring metrics:
   ```bash
   ./monitor.sh
   ```

2. **Monitor CPU and Memory Only**:  
   ```bash
   ./monitor.sh -cpu -memory
   ```

3. **Check Disk Usage and Network**:  
   ```bash
   ./monitor.sh -disk -network
   ```

4. **Monitor Processes and Services**:  
   ```bash
   ./monitor.sh -process -service
   ```

## Output Sections

### 1. Top 10 Most Used Applications
- Displays PID, PPID, command, memory usage, and CPU usage.
  
### 2. Network Monitoring
- Shows the number of concurrent connections and packet in/out rate.
  
### 3. Disk Usage
- Displays usage for all mounted partitions with warnings for those using over 80% of space.
  
### 4. System Load
- Shows current load average and CPU usage breakdown.
  
### 5. Memory Usage
- Displays total, used, and free memory, including swap usage.
  
### 6. Process Monitoring
- Lists active processes and highlights the top 5 processes by CPU and memory usage.
  
### 7. Service Monitoring
- Lists all currently running services.

## Customization

The script is modular, with each monitoring aspect contained in its own function. To add new monitoring capabilities:

1. **Create a New Function**: Define the monitoring logic in a new function.
2. **Add Command-Line Switch**: Modify the argument handling section to recognize the new switch.
3. **Update Usage Section**: Ensure the new switch is documented in the usage instructions.

## Troubleshooting

- **Permissions:** Ensure you have necessary permissions to run the script and access system information.
- **Dependencies:** Verify that all required utilities are installed.
- **Network Monitoring:** Ensure the script can identify an active network interface.

