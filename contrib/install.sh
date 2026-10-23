#!/bin/sh
# Install distrust plus the timer/hooks. Run from the repo root as root.
set -eu
install -m 0755 distrust /usr/local/bin/distrust
install -d /etc/distrust /var/lib/distrust
install -m 0644 contrib/systemd/distrust-apply.service contrib/systemd/distrust-apply.timer \
	contrib/systemd/distrust-apply.path /etc/systemd/system/
[ -d /etc/apt/apt.conf.d ] && install -m 0644 contrib/apt/99distrust /etc/apt/apt.conf.d/
[ -d /etc/pacman.d/hooks ] && install -m 0644 contrib/pacman/distrust.hook /etc/pacman.d/hooks/
systemctl daemon-reload
systemctl enable --now distrust-apply.timer distrust-apply.path
echo "installed; try: distrust backends"
