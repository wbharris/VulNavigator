# Kali Update

One clean update & cleanup script for Kali Linux.

## Main Script

**`kali-update.sh`** — The complete update and cleanup script.

### What it does

**Update:**
- Refreshes Kali keyring
- Fixes interrupted installs and broken packages
- `apt update`
- Package cache check (`apt-get check`)
- `apt upgrade`
- `apt full-upgrade`

**Cleanup:**
- `apt --purge autoremove`
- `apt autoclean` + `apt clean`
- Purge residual config files (`apt purge '~c'`)
- Remove old kernels (keeps current + previous for safety)
- Remove old snap revisions
- Update + remove unused Flatpaks
- Firmware updates (fwupdmgr)
- Vacuum journal logs (last 30 days)
- Clean partial apt lists
- Update locate database (if present)
- Rebuild man database
- Update GRUB after kernel changes

**Other:**
- Tracks disk usage before/after
- Keeps only the last **3** log files
- Color output + clear logging
- Safety checks (root, internet, disk space)

### Usage

```bash
sudo ./kali-update.sh
```

Run periodically (recommended weekly).

### Logging

Logs go to `/var/log/kali-update/`

Only the most recent 3 logs are kept automatically.

### Safety

- Must run as root.
- Requires at least 2GB free disk space.
- Keeps current + one previous kernel as fallback.
- Non-critical steps won't stop the script.

### Scheduling

**Cron example (weekly):**

```bash
0 4 * * 0 /path/to/Kali\ Update/kali-update.sh >> /var/log/kali-update/cron.log 2>&1
```

Or use a systemd timer for more control.

### Notes

This is the single, cleaned-up version. Older scripts have been removed.
