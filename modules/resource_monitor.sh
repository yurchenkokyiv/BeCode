#!/bin/bash

# Load configuration
source ./config/thresholds.conf
LOG_FILE="./logs/resource_monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Ensure log directory exists
mkdir -p ./logs

# Log function
log() {
    echo "[$DATE] $1" >> "$LOG_FILE"
}

# CPU Monitoring
check_cpu() {
    load=$(uptime | awk -F 'load average:' '{ print $2 }' | cut -d',' -f1 | xargs)
    load_int=${load%.*}

    log "CPU Load Average: $load"

    if (( $(echo "$load > $CPU_THRESHOLD" | bc -l) )); then
        log "ALERT: CPU load ($load) exceeded threshold ($CPU_THRESHOLD)"
        ./alerts/email_alert.sh "CPU Alert" "High CPU load detected: $load"
    fi
}

# Memory Monitoring
check_memory() {
    read total used free <<< $(free -m | awk '/Mem:/ {print $2, $3, $4}')
    mem_usage=$((100 * used / total))

    log "Memory Usage: $mem_usage% ($used MB used of $total MB)"

    if (( mem_usage > MEMORY_THRESHOLD )); then
        log "ALERT: Memory usage ($mem_usage%) exceeded threshold ($MEMORY_THRESHOLD%)"
        ./alerts/email_alert.sh "Memory Alert" "High memory usage detected: $mem_usage%"
    fi
}

# Disk Monitoring
check_disk() {
    while IFS= read -r line; do
        usage=$(echo "$line" | awk '{print $5}' | tr -d '%')
        mount_point=$(echo "$line" | awk '{print $6}')
        log "Disk Usage on $mount_point: $usage%"

        if (( usage > DISK_THRESHOLD )); then
            log "ALERT: Disk usage ($usage%) on $mount_point exceeded threshold ($DISK_THRESHOLD%)"
            ./alerts/email_alert.sh "Disk Alert" "High disk usage detected on $mount_point: $usage%"
        fi
    done <<< "$(df -h --output=source,pcent,target | tail -n +2)"
}

# Generate Summary (optional, can be called daily)
generate_summary() {
    echo -e "\n===== Daily Summary [$DATE] =====" >> "$LOG_FILE"
    check_cpu
    check_memory
    check_disk
    echo -e "==================================\n" >> "$LOG_FILE"
}

# Main
check_cpu
check_memory
check_disk
