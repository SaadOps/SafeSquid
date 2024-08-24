#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 [-cpu] [-memory] [-network] [-disk] [-load] [-process] [-service]"
    exit 1
}

# Function to display Top 10 Most Used Applications
top_10_apps() {
    echo "Top 10 Most Used Applications (CPU and Memory):"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11
    echo ""
}

# Function to display Network Monitoring
network_monitoring() {
    echo "Network Monitoring:"
    echo "Number of concurrent connections:"
    ss -tun | wc -l
    
    echo "Packet in/out (KB):"
    if [ -f /proc/net/dev ]; then
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
    warning_count=$(df -h | awk '$5+0 > 80 {print "Warning: " $1 " is using " $5 " of space."}')
    
    if [ -n "$warning_count" ]; then
        echo "$warning_count"
    else
        echo "All partitions are using less than 80% of space."
    fi

    df -h || echo "Error: Failed to retrieve disk usage information."
    echo ""
}

# Function to display System Load
system_load() {
    echo "System Load:"
    echo "Current load average:"
    uptime
    
    echo "CPU Breakdown:"
    top -bn1 | grep "Cpu(s)" | sed -n 's/.*, *\([0-9.]*\)%* id.*/\1/p' | awk '{print "User: " (100 - $1) "%, System: " (100 - $1) "%, Idle: " $1 "%"}'
    echo ""
}

# Function to display Memory Usage
memory_usage() {
    echo "Memory Usage:"
    free -h
    echo ""
}

# Function to display Process Monitoring
process_monitoring() {
    echo "Process Monitoring:"
    echo "Number of active processes:"
    ps aux | wc -l
    
    echo "Top 5 Processes (CPU and Memory):"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
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

# Handle command-line switches and refresh the dashboard
if [[ $# -eq 0 ]]; then
    while :; do
        clear
        top_10_apps
        network_monitoring
        disk_usage
        system_load
        memory_usage
        process_monitoring
        service_monitoring
        sleep 5
    done
else
    while :; do
        clear
        for arg in "$@"; do
            case $arg in
                -cpu) system_load ;;
                -memory) memory_usage ;;
                -network) network_monitoring ;;
                -disk) disk_usage ;;
                -load) system_load ;;
                -process) process_monitoring ;;
                -service) service_monitoring ;;
                *) usage ;;
            esac
        done
        sleep 5
    done
fi
