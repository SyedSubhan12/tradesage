#!/bin/bash
# Setup script for MA130 backup server
# Run this on your MA130 server to prepare it for TradeSage backups

set -e

echo "=== TradeSage MA130 Backup Server Setup ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Variables
BACKUP_USER="tradesage_backup"
BACKUP_BASE_PATH="/data/tradesage/backups"
LOG_PATH="/var/log/tradesage"

echo "1. Creating backup user..."
if ! id "$BACKUP_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$BACKUP_USER"
    echo "   User $BACKUP_USER created"
else
    echo "   User $BACKUP_USER already exists"
fi

echo
echo "2. Creating directory structure..."
mkdir -p "$BACKUP_BASE_PATH"
mkdir -p "$LOG_PATH"
mkdir -p "/home/$BACKUP_USER/.ssh"

# Set proper permissions
chown -R "$BACKUP_USER:$BACKUP_USER" "$BACKUP_BASE_PATH"
chown -R "$BACKUP_USER:$BACKUP_USER" "$LOG_PATH"
chmod 755 "$BACKUP_BASE_PATH"
chmod 755 "$LOG_PATH"

echo "   Directories created with proper permissions"

echo
echo "3. Installing required packages..."
apt-get update
apt-get install -y \
    postgresql-client \
    gzip \
    rsync \
    monitoring-plugins \
    python3-pip

echo "   Packages installed"

echo
echo "4. Setting up SSH access..."
# Generate SSH key for the backup user if it doesn't exist
if [ ! -f "/home/$BACKUP_USER/.ssh/authorized_keys" ]; then
    touch "/home/$BACKUP_USER/.ssh/authorized_keys"
    chmod 600 "/home/$BACKUP_USER/.ssh/authorized_keys"
    chown "$BACKUP_USER:$BACKUP_USER" "/home/$BACKUP_USER/.ssh/authorized_keys"
    echo "   SSH authorized_keys file created"
    echo "   Add your tenant-service public key to: /home/$BACKUP_USER/.ssh/authorized_keys"
else
    echo "   SSH already configured"
fi

echo
echo "5. Creating backup monitoring script..."
cat > "/usr/local/bin/check_backup_storage.sh" << 'EOF'
#!/bin/bash
# Check backup storage usage

BACKUP_PATH="/data/tradesage/backups"
THRESHOLD=80

USAGE=$(df -h "$BACKUP_PATH" | awk 'NR==2 {print $5}' | sed 's/%//')

if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "WARNING: Backup storage usage is ${USAGE}% (threshold: ${THRESHOLD}%)"
    exit 1
else
    echo "OK: Backup storage usage is ${USAGE}%"
    exit 0
fi
EOF

chmod +x "/usr/local/bin/check_backup_storage.sh"
echo "   Monitoring script created"

echo
echo "6. Setting up log rotation..."
cat > "/etc/logrotate.d/tradesage" << EOF
$LOG_PATH/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 $BACKUP_USER $BACKUP_USER
}
EOF

echo "   Log rotation configured"

echo
echo "7. Creating backup cleanup cron job..."
cat > "/etc/cron.d/tradesage-backup-cleanup" << EOF
# Cleanup old backups daily at 5 AM
0 5 * * * $BACKUP_USER find $BACKUP_BASE_PATH -name "*.sql.gz" -mtime +30 -delete
EOF

echo "   Cleanup cron job created"

echo
echo "8. Setting up disk space alert..."
cat > "/usr/local/bin/disk_space_alert.sh" << 'EOF'
#!/bin/bash
# Alert if disk space is low

BACKUP_PATH="/data/tradesage/backups"
THRESHOLD=85
EMAIL="ops@tradesage.com"

USAGE=$(df -h "$BACKUP_PATH" | awk 'NR==2 {print $5}' | sed 's/%//')

if [ "$USAGE" -gt "$THRESHOLD" ]; then
    SUBJECT="MA130 Backup Storage Alert: ${USAGE}% used"
    MESSAGE="Warning: Backup storage on MA130 is ${USAGE}% full.\n\nPath: $BACKUP_PATH\n\nPlease investigate and free up space if needed."
    echo -e "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"
fi
EOF

chmod +x "/usr/local/bin/disk_space_alert.sh"

# Add to crontab
cat >> "/etc/cron.d/tradesage-backup-cleanup" << EOF
# Check disk space every hour
0 * * * * root /usr/local/bin/disk_space_alert.sh
EOF

echo "   Disk space monitoring configured"

echo
echo "9. Creating backup verification script..."
cat > "/usr/local/bin/verify_backups.sh" << 'EOF'
#!/bin/bash
# Verify backup integrity

BACKUP_PATH="/data/tradesage/backups"
LOG_FILE="/var/log/tradesage/backup_verification.log"

echo "Starting backup verification at $(date)" >> "$LOG_FILE"

find "$BACKUP_PATH" -name "*.sql.gz" -type f -mtime -1 | while read backup; do
    if gzip -t "$backup" 2>/dev/null; then
        echo "OK: $backup" >> "$LOG_FILE"
    else
        echo "CORRUPT: $backup" >> "$LOG_FILE"
        # Send alert
        echo "Corrupt backup detected: $backup" | mail -s "MA130 Backup Corruption Alert" ops@tradesage.com
    fi
done

echo "Verification completed at $(date)" >> "$LOG_FILE"
EOF

chmod +x "/usr/local/bin/verify_backups.sh"

# Add to crontab
cat >> "/etc/cron.d/tradesage-backup-cleanup" << EOF
# Verify backups daily at 6 AM
0 6 * * * $BACKUP_USER /usr/local/bin/verify_backups.sh
EOF

echo "   Backup verification script created"

echo
echo "10. Setting up firewall rules..."
if command -v ufw &> /dev/null; then
    ufw allow from 10.0.0.0/24 to any port 22 comment "TradeSage backup SSH"
    echo "   Firewall rules added (SSH from 10.0.0.0/24)"
else
    echo "   UFW not found, please configure firewall manually"
fi

echo
echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "1. Add the tenant-service SSH public key to: /home/$BACKUP_USER/.ssh/authorized_keys"
echo "2. Update the email address in monitoring scripts if needed"
echo "3. Adjust firewall rules for your network"
echo "4. Test SSH connection from tenant-service"
echo
echo "Test command from tenant-service:"
echo "ssh $BACKUP_USER@$(hostname -I | awk '{print $1}') 'ls -la $BACKUP_BASE_PATH'"
echo 