#!/bin/bash

# Script to update Kali Purple with improved lock handling and output

# Configuration
LOG_FILE="/var/log/kali_purple_update_$(date +%F_%H-%M-%S).log"
VERBOSE=1 # 1 for verbose, 0 for quiet
CONFIRM=1 # 1 to prompt for confirmation, 0 to skip
BACKUP_DIR="/root/kali_backup_$(date +%F_%H-%M-%S)"
MAX_RETRIES=3 # Number of retries for lock check
RETRY_DELAY=5 # Seconds to wait between retries

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log_message() {
    local message="$1"
    echo -e "$message" >> "$LOG_FILE"
    [ $VERBOSE -eq 1 ] && echo -e "$message"
}

# Function to check for errors
check_error() {
    local exit_code=$1
    local message=$2
    if [ $exit_code -ne 0 ]; then
        log_message "${RED}Error: $message${NC}"
        exit 1
    fi
}

# Trap for cleanup on error or interrupt
cleanup() {
    log_message "${YELLOW}Script interrupted or failed. Cleaning up...${NC}"
    exit 1
}
trap cleanup ERR INT

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    log_message "${RED}This script must be run as root. Please use sudo or run as root.${NC}"
    exit 1
fi

# Check internet connectivity
log_message "Checking internet connectivity..."
ping -c 1 8.8.8.8 > /dev/null 2>&1
check_error $? "No internet connection. Please check your network and try again."

# Check disk space (at least 1GB free)
log_message "Checking available disk space..."
FREE_SPACE=$(df -m / | tail -1 | awk '{print $4}')
if [ "$FREE_SPACE" -lt 1024 ]; then
    log_message "${RED}Insufficient disk space. At least 1GB is required. Current free space: $FREE_SPACE MB${NC}"
    exit 1
fi

# Check for apt locks with retry mechanism
log_message "Checking for package manager locks..."
for ((i=1; i<=MAX_RETRIES; i++)); do
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        log_message "${YELLOW}Package manager lock detected (/var/lib/dpkg/lock-frontend). Attempt $i of $MAX_RETRIES...${NC}"
        # Identify process holding the lock
        LOCK_PID=$(lsof /var/lib/dpkg/lock-frontend | awk 'NR>1 {print $2}' | sort -u)
        if [ -n "$LOCK_PID" ]; then
            log_message "${YELLOW}Process holding lock: PID $LOCK_PID ($(ps -p $LOCK_PID -o comm= 2>/dev/null || echo 'unknown'))${NC}"
            log_message "${YELLOW}Waiting $RETRY_DELAY seconds before retrying...${NC}"
            sleep $RETRY_DELAY
        else
            log_message "${YELLOW}Stale lock detected. Attempting to remove...${NC}"
            rm -f /var/lib/dpkg/lock-frontend
            check_error $? "Failed to remove stale lock file."
            break
        fi
    else
        log_message "${GREEN}No package manager locks detected.${NC}"
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        log_message "${RED}Error: Another package manager is still running after $MAX_RETRIES attempts.${NC}"
        log_message "${RED}Please stop the process (e.g., 'sudo kill $LOCK_PID') or wait and try again.${NC}"
        exit 1
    fi
done

# Create backup directory
log_message "Creating backup directory at $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"
check_error $? "Failed to create backup directory."

# Backup critical files
log_message "Backing up /etc/apt/sources.list..."
cp /etc/apt/sources.list "$BACKUP_DIR/sources.list.bak"
check_error $? "Failed to back up sources.list."

# Confirmation prompt
if [ $CONFIRM -eq 1 ]; then
    log_message "${YELLOW}This script will update Kali Purple, including dist-upgrade. Continue? (y/N)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_message "Update cancelled by user."
        exit 0
    fi
fi

