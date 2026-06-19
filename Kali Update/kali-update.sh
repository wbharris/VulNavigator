#!/usr/bin/env bash
# Kali Linux - Complete Update & Cleanup Script
# Full system update + thorough cleanup for Kali Rolling
# - Updates packages, firmware, flatpaks, snaps
# - Removes old kernels (keeps current + previous one)
# - Thorough cleanup (residual configs, snap revisions, etc.)
# - Keeps only the last 3 log files
# Usage: sudo ./kali-update.sh
# Recommended: run weekly

set -euo pipefail

# ────────────────────────────────────────────────────────────────
# Colors
# ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ────────────────────────────────────────────────────────────────
# Logging (keep only last 3 updates)
# ────────────────────────────────────────────────────────────────
LOG_DIR="/var/log/kali-update"
LOG_FILE="$LOG_DIR/kali-update-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

log()      { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
info()     { echo -e "${BLUE}[INFO]${NC} $1"; }
success()  { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn()     { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error()    { echo -e "${RED}[ERROR]${NC} $1"; }

# Keep only the last 3 log files (past three updates)
log "Cleaning up old logs (keeping last 3)..."
find "$LOG_DIR" -name "kali-update-*.log" -type f -printf '%T@ %p\n' \
    | sort -n | head -n -3 | cut -d' ' -f2- | xargs -r rm -f

# ────────────────────────────────────────────────────────────────
# Environment
# ────────────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# ────────────────────────────────────────────────────────────────
# Safety checks
# ────────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

info "Checking internet connectivity..."
if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    error "No internet connection detected."
    exit 1
fi

info "Checking available disk space (need ≥ 2 GB)..."
avail_kb=$(df / --output=avail | tail -n 1)
if [ "$avail_kb" -lt 2097152 ]; then
    error "Less than 2 GB free on root filesystem."
    exit 1
fi

# Record disk usage before
BEFORE=$(df -h / | tail -1 | awk '{print $3}')

# ────────────────────────────────────────────────────────────────
# Helper for non-critical steps
# ────────────────────────────────────────────────────────────────
safe_run() {
    local desc="$1"; shift
    info "$desc"
    if ! "$@"; then
        warn "$desc failed — continuing anyway"
    fi
}

# ────────────────────────────────────────────────────────────────
# Refresh Kali keyring
# ────────────────────────────────────────────────────────────────

info "Refreshing Kali archive keyring..."
KEYRING_URL="https://archive.kali.org/archive-keyring.gpg"
KEYRING_PATH="/usr/share/keyrings/kali-archive-keyring.gpg"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$KEYRING_URL" -o "$KEYRING_PATH" || warn "Failed to refresh keyring via curl"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$KEYRING_PATH" "$KEYRING_URL" || warn "Failed to refresh keyring via wget"
else
    warn "curl/wget not available — skipping keyring refresh"
fi

# ────────────────────────────────────────────────────────────────
# Core update
# ────────────────────────────────────────────────────────────────

info "Configuring any interrupted package installations..."
dpkg --configure -a || warn "dpkg --configure -a had issues"

info "Fixing broken dependencies..."
apt install -f -y || warn "apt install -f had issues"

info "Updating package lists..."
apt update

info "Checking package cache integrity (apt-get check)..."
apt-get check || warn "Package cache check reported issues"

info "Upgrading packages..."
apt upgrade -y || warn "apt upgrade had issues"

info "Listing upgradable packages after initial upgrade:"
apt list --upgradable 2>/dev/null || true

info "Performing full system upgrade..."
apt full-upgrade -y

# ────────────────────────────────────────────────────────────────
# Complete cleanup
# ────────────────────────────────────────────────────────────────

info "Removing unnecessary packages (autoremove --purge)..."
apt --purge autoremove -y || warn "autoremove had issues"

info "Cleaning package cache (autoclean + clean)..."
apt autoclean
apt clean

# Purge residual configuration files
info "Purging residual configuration files..."
apt purge '~c' -y || warn "Purging residual configs had issues"

# Remove old kernels (keep current + previous one)
info "Removing old kernels (keeping current + previous)..."
KERNELS=$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/ {print $2}' | grep -v "$(uname -r)" | sort -V | head -n -1 || true)
if [ -n "$KERNELS" ]; then
    echo "$KERNELS" | xargs apt purge -y || warn "Old kernel removal had issues"
    # Also remove matching headers and modules
    for k in $KERNELS; do
        echo "$k" | sed 's/linux-image/linux-headers/' | xargs apt purge -y 2>/dev/null || true
        echo "$k" | sed 's/linux-image/linux-modules/'  | xargs apt purge -y 2>/dev/null || true
    done
else
    info "No old kernels to remove."
fi

# Update GRUB if kernels were removed
if [ -n "$KERNELS" ] && command -v update-grub >/dev/null 2>&1; then
    safe_run "Updating GRUB bootloader" update-grub
fi

# Flatpak cleanup
if command -v flatpak >/dev/null 2>&1; then
    safe_run "Updating Flatpaks" flatpak update -y
    safe_run "Removing unused Flatpaks" flatpak uninstall --unused -y
fi

# Snap cleanup (including old revisions)
if command -v snap >/dev/null 2>&1; then
    safe_run "Refreshing Snaps" snap refresh
    # Remove disabled/old revisions
    snap list --all | awk '/disabled/{print $1, $3}' | while read snapname revision; do
        snap remove "$snapname" --revision="$revision" 2>/dev/null || true
    done
fi

# Firmware updates
if command -v fwupdmgr >/dev/null 2>&1; then
    safe_run "Refreshing firmware metadata" fwupdmgr refresh --force
    safe_run "Applying firmware updates" fwupdmgr update -y || true
fi

# Clean old journal logs (keep last 30 days)
if command -v journalctl >/dev/null 2>&1; then
    safe_run "Vacuuming journal logs (last 30 days)" journalctl --vacuum-time=30d
fi

# Clean partial apt lists
info "Cleaning partial package lists..."
rm -rf /var/lib/apt/lists/partial/*

# Update locate database if installed
if command -v updatedb >/dev/null 2>&1; then
    safe_run "Updating locate database" updatedb
fi

# Rebuild man page database
if command -v mandb >/dev/null 2>&1; then
    safe_run "Rebuilding man page database" mandb -q
fi

# ────────────────────────────────────────────────────────────────
# Final status
# ────────────────────────────────────────────────────────────────

AFTER=$(df -h / | tail -1 | awk '{print $3}')

if [ -f /var/run/reboot-required ]; then
    warn "Reboot is required to complete some updates (kernel, libc, etc.)."
    warn "Run: sudo reboot"
else
    success "No reboot required."
fi

success "Kali update and cleanup completed successfully!"
log "Disk space used: $BEFORE → $AFTER"
log "Full log saved to: $LOG_FILE"
exit 0
