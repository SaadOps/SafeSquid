#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 [-cpu] [-memory] [-network] [-disk] [-load] [-process] [-service]"
    exit 1
}

# Function to display Top 10 Most Used Applications
top_10_apps() {
    echo "Top 10 Most Used Applications (CPU and Memory):"
    if ! ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11; then
        echo "Error: Failed to retrieve top 10 applications."
    fi
    echo ""
}

# Function to display Network Monitoring
network_monitoring() {
    echo "Network Monitoring:"
    echo "Number of concurrent connections:"
    if ! ss -tun | wc -l; then
        echo "Error: Failed to retrieve network connection count."
    fi
    
    echo "Packet in/out (MB):"
    if [ -f /proc/net/dev ]; then
        # Determine the active interface
        INTERFACE=$(ip -o link show | awk '/state UP/ {print $2}' | sed 's/://')
        
        if [ -z "$INTERFACE" ]; then
            echo "No active network interfaces found."
            return
        fi

        echo "Monitoring interface: $INTERFACE"

        rx_bytes=$(awk -v iface="$INTERFACE" -F: '/^'"$INTERFACE"'/ {print $2}' /proc/net/dev | awk '{print $1}')
        tx_bytes=$(awk -v iface="$INTERFACE" -F: '/^'"$INTERFACE"'/ {print $2}' /proc/net/dev | awk '{print $10}')
        sleep 1
        rx_bytes_new=$(awk -v iface="$INTERFACE" -F: '/^'"$INTERFACE"'/ {print $2}' /proc/net/dev | awk '{print $1}')
        tx_bytes_new=$(awk -v iface="$INTERFACE" -F: '/^'"$INTERFACE"'/ {print $2}' /proc/net/dev | awk '{print $10}')
        
        if [ -z "$rx_bytes" ] || [ -z "$tx_bytes" ] || [ -z "$rx_bytes_new" ] || [ -z "$tx_bytes_new" ]; then
            echo "Error: Failed to retrieve network data for $INTERFACE."
            return
        fi

        rx_rate=$(( (rx_bytes_new - rx_bytes) / 1024 ))
        tx_rate=$(( (tx_bytes_new - tx_bytes) / 1024 ))
        echo "In: $rx_rate KB/s, Out: $tx_rate KB/s"
    else
        echo "Error: /proc/net/dev not found."
    fi
    echo ""
}

# Function to display Disk Usage
disk_usage() {
    echo "Disk Usage:"
    df -h | awk 'NR==1 {print $1, $5; next} $5+0 > 80 {print "Warning: " $1 " is using " $5 " of space."} $5+0 <= 80 {print $1 " is using " $5 " of space."}'
    echo ""
}

# Function to display System Load
system_load() {
    echo "System Load:"
    echo "Current load average:"
    if ! uptime; then
        echo "Error: Failed to retrieve system load information."
    fi
    echo "CPU Breakdown:"
    if ! top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print "User: " (100 - $1) "%, System: " $1 "%, Idle: " (100 - $1) "%"}'; then
        echo "Error: Failed to retrieve CPU usage information."
    fi
    echo ""
}

# Function to display Memory Usage
memory_usage() {
    echo "Memory Usage:"
    if ! free -h; then
        echo "Error: Failed to retrieve memory usage information."
    fi
    echo ""
}

# Function to display Process Monitoring
process_monitoring() {
    echo "Process Monitoring:"
    echo "Number of active processes:"
    if ! ps aux | wc -l; then
        echo "Error: Failed to retrieve process information."
    fi
    echo "Top 5 Processes (CPU and Memory):"
    if ! ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6; then
        echo "Error: Failed to retrieve process information."
    fi
    echo ""
}


# Function to display Service Monitoring
service_monitoring() {
    echo "Service Monitoring:"
    
    # Get the list of all active services
    active_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')
    
    if [ -z "$active_services" ]; then
        echo "No services are currently running."
    else
        for service in $active_services; do
            echo "$service is running"
        done
    fi
    echo ""
}


# Handle command-line switches
if [[ $# -eq 0 ]]; then
    top_10_apps
    network_monitoring
    disk_usage
    system_load
    memory_usage
    process_monitoring
    service_monitoring
else
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -cpu) system_load ;;
            -memory) memory_usage ;;
            -network) network_monitoring ;;
            -disk) disk_usage ;;
            -load) system_load ;;
            -process) process_monitoring ;;
            -service) service_monitoring ;;
            *) usage ;;
        esac
        shift
    done
fi

# Refresh the dashboard every few seconds
while :; do
    clear
    if [[ $# -eq 0 ]]; then
        top_10_apps
        network_monitoring
        disk_usage
        system_load
        memory_usage
        process_monitoring
        service_monitoring
    fi
    sleep 5
done
