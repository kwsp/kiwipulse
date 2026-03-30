# system-monitor

Periodic system health checks with Discord alerts. Designed for Debian/Ubuntu servers with systemd.

## What it checks

| Check | Alert condition |
|---|---|
| **Disk usage** | Any mount point > 80% full (space or inodes) |
| **Services** | Any monitored systemd service not `active` |
| **Security updates** | Pending `apt-get` security upgrades |
| **SSL certificates** | Expiry within 30 days (critical at < 7 days) |
| **Backups** | Backup file/dir not modified within 26 hours |
| **System load** | 1-minute load average > 2× CPU count |
| **Memory** | Available memory < 10% of total |

All thresholds are configurable via `.env`.

## Setup

### 1. Clone and install dependencies

```bash
git clone <repo> /opt/system-monitor
cd /opt/system-monitor
uv sync
```

### 2. Configure

```bash
cp .env.example .env
$EDITOR .env
```

At minimum set `DISCORD_WEBHOOK_URL`. Configure `SERVICES`, `SSL_DOMAINS`, and `BACKUP_PATHS` for your server.

### 3. Test

```bash
./run.sh
```

### 4. Install the cron job

```bash
crontab -e
```

Add this line (runs hourly, logs to syslog):

```
7 * * * * /opt/system-monitor/run.sh >> /var/log/system-monitor.log 2>&1
```

Rotate the log with logrotate (`/etc/logrotate.d/system-monitor`):

```
/var/log/system-monitor.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
```

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | — | Discord webhook URL (required for alerts) |
| `SERVICES` | — | Space-separated systemd system service names |
| `USER_SERVICES` | — | Space-separated systemd `--user` service names |
| `SSL_DOMAINS` | — | Space-separated domains to check SSL expiry |
| `BACKUP_PATHS` | — | Comma-separated file/dir paths to check |
| `DISK_ALERT_PCT` | `80` | Disk/inode usage alert threshold (%) |
| `MEMORY_ALERT_PCT` | `90` | Memory usage alert threshold (%) |
| `LOAD_ALERT_MULTIPLIER` | `2.0` | Load alert = this × CPU count |
| `SSL_WARN_DAYS` | `30` | Days before cert expiry to warn |
| `BACKUP_MAX_AGE_HOURS` | `26` | Max hours since backup last modified |
