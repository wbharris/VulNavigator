#!/usr/bin/env bash
#
# kali_purple_update.sh
# Keep a Kali Purple system up‑to‑date and prune old log files.
# --------------------------------------------------------------

# Strict error handling
set -euo pipefail

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
LOG_DIR="${HOME}/kali_update_logs"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
LOG_FILE="${LOG_DIR}/kali_update_${TIMESTAMP}.log"

# Number of most‑recent logs to keep
KEEP_LOGS=2

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------
log() {
    # Print to console *and* append to log file
    echo -e "$1" | tee -a "${LOG_FILE}"
}

run() {
    # Execute a command, log it, and abort on failure
    log "[RUN] $*"
    "$@" >>"${LOG_FILE}" 2>&1
}

die() {
    log "\n⚠️  $*"
    exit 1
}

prune_logs() {
    # Delete all log files except the newest $KEEP_LOGS ones.
    # Works even if there are fewer than $KEEP_LOGS files.
    log "\n🧹 Pruning old log files (keeping the latest ${KEEP_LOGS}) ..."
    # List files sorted newest‑first, skip the first $KEEP_LOGS entries, then delete the rest.
    mapfile -t old_logs < <(ls -1t "${LOG_DIR}"/kali_update_*.log 2>/dev/null | tail -n +$((KEEP_LOGS + 1)))
    if [[ ${#old_logs[@]} -gt 0 ]]; then
        rm -f "${old_logs[@]}"
        log "Removed ${#old_logs[@]} old log file(s)."
    else
        log "No old logs to remove."
    fi
}

# ------------------------------------------------------------------
# Pre‑flight checks
# ------------------------------------------------------------------
[[ "$EUID" -eq 0 ]] || die "This script must be run as root (use sudo)."

mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"

log "=== Kali Purple update started at $(date) ==="
log "Log file: ${LOG_FILE}"
log ""

# ------------------------------------------------------------------
# Update steps (each wrapped in its own function for clarity)
# ------------------------------------------------------------------
configure_dpkg() {
    log "\n🔧 Configuring dpkg ..."
    run dpkg --configure -a
}

install_missing_deps() {
    log "\n📦 Installing missing dependencies ..."
    run apt install -f -y
}

check_for_broken() {
    log "\n🔍 Checking for broken packages ..."
    if ! apt-get check >>"${LOG_FILE}" 2>&1; then
        log "⚠️  apt-get check reported issues – they will be addressed by later steps."
    fi
}

update_package_lists() {
    log "\n📡 Updating package lists ..."
    run apt update
}

upgrade_packages() {
    log "\n⬆️ Upgrading installed packages (apt upgrade) ..."
    run apt upgrade -y
}

full_system_upgrade() {
    log "\n🚀 Performing full system upgrade (apt full-upgrade) ..."
    run apt full-upgrade -y
}

autoremove_and_clean() {
    log "\n🧹 Removing unnecessary packages ..."
    run apt --purge autoremove -y

    log "\n🗑️ Cleaning package cache ..."
    run apt autoclean
}

# ------------------------------------------------------------------
# Execution flow
# ------------------------------------------------------------------
{
    configure_dpkg
    install_missing_deps
    check_for_broken
    update_package_lists
    upgrade_packages
    full_system_upgrade
    autoremove_and_clean
} || die "An error occurred during the update process."

log "\n✅ Update completed successfully!"
log "=== Finished at $(date) ==="

# ------------------------------------------------------------------
# House‑keeping: prune old logs
# ------------------------------------------------------------------
prune_logs#!/usr/bin/env bash
#
# kali_purple_update.sh
# Keep a Kali Purple system up‑to‑date and prune old log files.
# --------------------------------------------------------------

# Strict error handling
set -euo pipefail

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
LOG_DIR="${HOME}/kali_update_logs"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
LOG_FILE="${LOG_DIR}/kali_update_${TIMESTAMP}.log"

# Number of most‑recent logs to keep
KEEP_LOGS=2

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------
log() {
    # Print to console *and* append to log file
    echo -e "$1" | tee -a "${LOG_FILE}"
}

run() {
    # Execute a command, log it, and abort on failure
    log "[RUN] $*"
    "$@" >>"${LOG_FILE}" 2>&1
}

die() {
    log "\n⚠️  $*"
    exit 1
}

prune_logs() {
    # Delete all log files except the newest $KEEP_LOGS ones.
    # Works even if there are fewer than $KEEP_LOGS files.
    log "\n🧹 Pruning old log files (keeping the latest ${KEEP_LOGS}) ..."
    # List files sorted newest‑first, skip the first $KEEP_LOGS entries, then delete the rest.
    mapfile -t old_logs < <(ls -1t "${LOG_DIR}"/kali_update_*.log 2>/dev/null | tail -n +$((KEEP_LOGS + 1)))
    if [[ ${#old_logs[@]} -gt 0 ]]; then
        rm -f "${old_logs[@]}"
        log "Removed ${#old_logs[@]} old log file(s)."
    else
        log "No old logs to remove."
    fi
}

# ------------------------------------------------------------------
# Pre‑flight checks
# ------------------------------------------------------------------
[[ "$EUID" -eq 0 ]] || die "This script must be run as root (use sudo)."

mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}"

log "=== Kali Purple update started at $(date) ==="
log "Log file: ${LOG_FILE}"
log ""

# ------------------------------------------------------------------
# Update steps (each wrapped in its own function for clarity)
# ------------------------------------------------------------------
configure_dpkg() {
    log "\n🔧 Configuring dpkg ..."
    run dpkg --configure -a
}

install_missing_deps() {
    log "\n📦 Installing missing dependencies ..."
    run apt install -f -y
}

check_for_broken() {
    log "\n🔍 Checking for broken packages ..."
    if ! apt-get check >>"${LOG_FILE}" 2>&1; then
        log "⚠️  apt-get check reported issues – they will be addressed by later steps."
    fi
}

update_package_lists() {
    log "\n📡 Updating package lists ..."
    run apt update
}

upgrade_packages() {
    log "\n⬆️ Upgrading installed packages (apt upgrade) ..."
    run apt upgrade -y
}

full_system_upgrade() {
    log "\n🚀 Performing full system upgrade (apt full-upgrade) ..."
    run apt full-upgrade -y
}

autoremove_and_clean() {
    log "\n🧹 Removing unnecessary packages ..."
    run apt --purge autoremove -y

    log "\n🗑️ Cleaning package cache ..."
    run apt autoclean
}

# ------------------------------------------------------------------
# Execution flow
# ------------------------------------------------------------------
{
    configure_dpkg
    install_missing_deps
    check_for_broken
    update_package_lists
    upgrade_packages
    full_system_upgrade
    autoremove_and_clean
} || die "An error occurred during the update process."

log "\n✅ Update completed successfully!"
log "=== Finished at $(date) ==="

# ------------------------------------------------------------------
# House‑keeping: prune old logs
# ------------------------------------------------------------------
prune_logs