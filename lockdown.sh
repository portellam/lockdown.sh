#!/bin/bash

#
# Filename:       lockdown.sh
# Version:        1.0.1
# Description:    Lockdown your Linux install. The simple zero-config Linux
#                 hardening script.
# Author(s):      Dom Ginger <github.com/dolegi>
# Maintainer(s):  Alex Portell <github.com/portellam>
#

#
# TODO:
# - [ ] refactor all functions.
#   - [ ] add comments.
#   - [ ] adhere to 80/24 rule.
# - [ ] organize functions.
#

function apt_update
{
  # Update package list
  apt update

  # Apt upgrade packages
  apt upgrade -y

  # Apt full upgrade
  apt full-upgrade -y
}

function configure_iptables
{
  # iptables
  apt install -y iptables-persistent

  # Flush existing rules
  iptables -F

  # Defaults
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # Accept loopback input
  iptables -A INPUT -i lo -p all -j ACCEPT

  # Allow three-way Handshake
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Stop Masked Attacks
  iptables -A INPUT -p icmp --icmp-type 13 -j DROP
  iptables -A INPUT -p icmp --icmp-type 17 -j DROP
  iptables -A INPUT -p icmp --icmp-type 14 -j DROP
  iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT

  # Discard invalid Packets
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A FORWARD -m state --state INVALID -j DROP
  iptables -A OUTPUT -m state --state INVALID -j DROP

  # Drop Spoofing attacks
  iptables -A INPUT -s 10.0.0.0/8 -j DROP
  iptables -A INPUT -s 169.254.0.0/16 -j DROP
  iptables -A INPUT -s 172.16.0.0/12 -j DROP
  iptables -A INPUT -s 127.0.0.0/8 -j DROP
  iptables -A INPUT -s 192.168.0.0/24 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -d 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 240.0.0.0/5 -j DROP
  iptables -A INPUT -d 240.0.0.0/5 -j DROP
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 239.255.255.0/24 -j DROP
  iptables -A INPUT -d 255.255.255.255 -j DROP

  # Drop packets with excessive RST to avoid Masked attacks
  iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second \
    --limit-burst 2 -j ACCEPT

  # Block ips doing portscan for 24 hours
  iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
  iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

  # After 24 hours remove IP from block list
  iptables -A INPUT   -m recent --name portscan --remove
  iptables -A FORWARD -m recent --name portscan --remove

  # Allow ssh
  iptables -A INPUT -p tcp -m tcp --dport 141 -j ACCEPT

  # Allow Ping
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

  # Allow one ssh connection at a time
  iptables -A INPUT -p tcp --syn --dport 141 -m connlimit --connlimit-above 2 -j \
    REJECT

  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
}

function install_fail2ban
{
  apt install -y fail2ban
}

function configure_kernel
{
  echo \
    "net.ipv4.conf.all.accept_redirects: 0"\
    "net.ipv4.conf.all.accept_source_route: 0"\
    "net.ipv4.conf.all.log_martians: 1"\
    "net.ipv4.conf.all.rp_filter: 1"\
    "net.ipv4.conf.all.secure_redirects: 1"\
    "net.ipv4.conf.all.send_redirects: 0"\
    "net.ipv4.conf.default.accept_redirects: 0"\
    "net.ipv4.conf.default.accept_source_route: 0"\
    "net.ipv4.conf.default.log_martians: 1"\
    "net.ipv4.conf.default.rp_filter: 1"\
    "net.ipv4.conf.default.secure_redirects: 1"\
    "net.ipv4.conf.default.send_redirects: 0"\
    "net.ipv4.icmp_echo_ignore_broadcasts: 1"\
    "net.ipv4.icmp_ignore_bogus_error_responses: 1"\
    "net.ipv4.icmp_echo_ignore_all: 0"\
    "net.ipv4.ip_forward: 0"\
    "net.ipv4.tcp_rfc1337: 1"\
    "net.ipv4.tcp_syncookies: 1"\
    "net.ipv6.conf.all.accept_redirects: 0"\
    "net.ipv6.conf.all.forwarding: 0"\
    "net.ipv6.conf.all.accept_source_route: 0"\
    "net.ipv6.conf.default.accept_redirects: 0"\
    "net.ipv6.conf.default.accept_source_route: 0"\
    "fs.protected_hardlinks: 1"\
    "fs.protected_symlinks: 1"\
    "kernel.core_uses_pid: 1"\
    "kernel.perf_event_paranoid: 2"\
    "kernel.kptr_restrict: 2"\
    "kernel.randomize_va_space: 2"\
    "kernel.sysrq: 0"\
    "kernel.yama.ptrace_scope: 1" \

    > /etc/sysctl.d/80-lockdown.conf || return 1

  sysctl --system
}

function automatic_updates
{
  # Enable automatic updates
  apt install -y unattended-upgrades
  dpkg-reconfigure -plow unattended-upgrades
}

function configure_auditd
{
  # Install auditd
  apt install -y auditd

  # Add config
  echo -e \
    "# Remove any existing rules"\
    "-D"\
    ""\
    "# Buffer Size"\
    "# Might need to be increased, depending on the load of your system."\
    "-b 8192"\
    ""\
    "# Failure Mode"\
    "# 0=Silent"\
    "# 1=printk, print failure message"\
    "# 2=panic, halt system"\
    "-f 1"\
  ""\
    "# Audit the audit logs."\
    "-w /var/log/audit/ -k auditlog"\
  ""\
    "## Auditd configuration"\
    "## Modifications to audit configuration that occur while the audit (check your paths)"\
    "-w /etc/audit/ -p wa -k auditconfig"\
    "-w /etc/libaudit.conf -p wa -k auditconfig"\
    "-w /etc/audisp/ -p wa -k audispconfig"\
  ""\
    "# Schedule jobs"\
    "-w /etc/cron.allow -p wa -k cron"\
    "-w /etc/cron.deny -p wa -k cron"\
    "-w /etc/cron.d/ -p wa -k cron"\
    "-w /etc/cron.daily/ -p wa -k cron"\
    "-w /etc/cron.hourly/ -p wa -k cron"\
    "-w /etc/cron.monthly/ -p wa -k cron"\
    "-w /etc/cron.weekly/ -p wa -k cron"\
    "-w /etc/crontab -p wa -k cron"\
    "-w /var/spool/cron/crontabs/ -k cron"\
  ""\
    "## user, group, password databases"\
    "-w /etc/group -p wa -k etcgroup"\
    "-w /etc/passwd -p wa -k etcpasswd"\
    "-w /etc/gshadow -k etcgroup"\
    "-w /etc/shadow -k etcpasswd"\
    "-w /etc/security/opasswd -k opasswd"\
  ""\
    "# Monitor usage of passwd command"\
    "-w /usr/bin/passwd -p x -k passwd_modification"\
  ""\
    "# Monitor user/group tools"\
    "-w /usr/sbin/groupadd -p x -k group_modification"\
    "-w /usr/sbin/groupmod -p x -k group_modification"\
    "-w /usr/sbin/addgroup -p x -k group_modification"\
    "-w /usr/sbin/useradd -p x -k user_modification"\
    "-w /usr/sbin/usermod -p x -k user_modification"\
    "-w /usr/sbin/adduser -p x -k user_modification"\
  ""\
    "# Login configuration and stored info"\
    "-w /etc/login.defs -p wa -k login"\
    "-w /etc/securetty -p wa -k login"\
    "-w /var/log/faillog -p wa -k login"\
    "-w /var/log/lastlog -p wa -k login"\
    "-w /var/log/tallylog -p wa -k login"\
  ""\
    "# Network configuration"\
    "-w /etc/hosts -p wa -k hosts"\
    "-w /etc/network/ -p wa -k network"\
  ""\
    "## system startup scripts"\
    "-w /etc/inittab -p wa -k init"\
    "-w /etc/init.d/ -p wa -k init"\
    "-w /etc/init/ -p wa -k init"\
  ""\
    "# Library search paths"\
    "-w /etc/ld.so.conf -p wa -k libpath"\
  ""\
    "# Kernel parameters and modules"\
    "-w /etc/sysctl.conf -p wa -k sysctl"\
    "-w /etc/modprobe.conf -p wa -k modprobe"\
  ""\
    "# SSH configuration"\
    "-w /etc/ssh/sshd_config -k sshd"\
  ""\
    "# Hostname"\
    "-a exit,always -F arch=b32 -S sethostname -k hostname"\
    "-a exit,always -F arch=b64 -S sethostname -k hostname"\
  ""\
    "# Log all commands executed by root"\
    "-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd"\
    "-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd"\
  ""\
    "## Capture all failures to access on critical elements"\
    "-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess"\
    "-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess"\
  ""\
    "## su/sudo"\
    "-w /bin/su -p x -k priv_esc"\
    "-w /usr/bin/sudo -p x -k priv_esc"\
    "-w /etc/sudoers -p rw -k priv_esc"\
  ""\
    "# Poweroff/reboot tools"\
    "-w /sbin/halt -p x -k power"\
    "-w /sbin/poweroff -p x -k power"\
    "-w /sbin/reboot -p x -k power"\
    "-w /sbin/shutdown -p x -k power"\
  ""\
    "# Make the configuration immutable"\
    "-e 2" \
    > /etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
}

function disable_core_dumps
{
  # Disable core dumps
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo "ulimit -c 0" >> /etc/profile
}

function restrict_login
{
  # Set login.defs
  sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
  sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
  echo "SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000" >> /etc/login.defs
}

function secure_ssh
{
  # Secure ssh
  echo "
ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
AllowTcpForwarding no
Port 141
PasswordAuthentication no
" >> /etc/ssh/sshd_config
  sed -i s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config
  sed -i s/^UsePAM.*/UsePAM\ no/ /etc/ssh/sshd_config
}

function create_admin_user
{
  # Create admin user
  echo "Enter admin username"; read -r username
  adduser "$username"
  mkdir "/home/$username/.ssh"
  cp /root/.ssh/authorized_keys "/home/$username/.ssh/authorized_keys"
  chown -R "$username" "/home/$username/.ssh"
  usermod -aG sudo "$username"

  # Restrict ssh to admin user
  echo "
AllowUsers $username
PermitRootLogin no
" >> /etc/ssh/sshd_config
}

function add_legal_banner
{
  # Add legal banner
  echo \
    "Unauthorized access to this server is prohibited."\
    "Legal action will be taken. Disconnect now." \
    > /etc/issue

  echo \
    "Unauthorized access to this server is prohibited."
    "Legal action will be taken. Disconnect now." \
    > /etc/issue.net
}

function install_recommended_packages
{
  # Install recommended packages
  apt install -y \
    acct \
    aide \
    apt-listbugs \
    apt-listchanges \
    debsecan \
    debsums \
    libpam-cracklib \
    needrestart \
    usbguard
}

function setup_aide
{
  # Setup aide
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

function enable_process_accounting
{
  # Enable process accounting
  systemctl enable acct.service
  systemctl start acct.service
}

function disable_uncommon_filesystems
{
  # Disable uncommon filesystems
  echo "install cramfs /bin/true"\
    "install freevxfs /bin/true"\
    "install hfs /bin/true"\
    "install hfsplus /bin/true"\
    "install jffs2 /bin/true"\
    "install squashfs /bin/true" \
  >> /etc/modprobe.d/filesystems.conf
}

function disable_firewire
{
  echo \
    "install udf /bin/true"\
    "blacklist firewire-core"\
    "blacklist firewire-ohci"\
    "blacklist firewire-sbp2" \
    >> /etc/modprobe.d/blacklist.conf
}

function disable_usb
{
  echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}

function disable_uncommon_protocols
{
  echo \
    "install sctp /bin/true"\
    "install dccp /bin/true"\
    "install rds /bin/true"\
    "install tipc /bin/true" \
    >> /etc/modprobe.d/protocols.conf
}

function change_root_permissions
{
 # Change /root permissions
  chmod 700 /root
  chmod 750 /home/debian
}

function restrict_access_to_compilers
{
  # Restrict access to compilers
  chmod o-rx /usr/bin/as
}

function move_tmp_to_tmpfs
{
  # Move tmp to tmpfs
  echo "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab
}

function remount_dir_with_restrictions
{
  # Mount tmp with noexec
  mount -o remount,noexec /tmp

  # Mount /proc with hidepid=2
  mount -o remount,rw,hidepid=2 /proc

  # Mount /dev with noexec
  mount -o remount,noexec /dev

  # Mount /run as nodev
  mount -o remount,nodev /run
}

function purge_old_packages
{
  # Purge old/removed packages
  apt autoremove -y || return 1
  apt purge -y "$( dpkg --list | grep '^rc' | awk '{print $2}' )"
}

#
# DESC:   Prompt the user to execute the command.
# $1:     the command name as a string.
# $2:     the prompt as a string.
# RETURN: If the prompt is answered and the command passes, return 0.
#         If the command fails, return 1.
#         If the prompt is not answered, return 255.
#
  function run
  {
    local -r str_command="${1}"
    local -r str_prompt="${2}"

    typeset -f "${str_command}" | tail --lines +2

    echo -e "${str_prompt}"
    echo -en "$0: Run the above command(s)? [Y/n]: "

    read -r str_answer

    if [ "${str_answer}" != "${answer#[Yy]}" ] ;then
      echo "$0: Skipped command(s)."
      return 255
    fi

    if ! ${str_command}; then
      echo "$0: Failure."
      return 1
    fi

    echo "$0: Success."
    return 0
  }

#
# DESC:   Main execution.
# RETURN: If all prompted commands pass, return 0.
#         If one or more command(s) fail, return 1.
#
  function main
  {
    local -Ar dict_command_prompts=(
      ["apt_update"]="Update and upgrade all packages"
      ["configure_iptables"]="Configure iptables"
      ["install_fail2ban"]="Install fail2ban"
      ["configure_kernel"]="Configure kernel"
      ["automatic_updates"]="Setup automatic updates"
      ["configure_auditd"]="Setup auditd"
      ["disable_core_dumps"]="Disable core dumps"
      ["restrict_login"]="Restrict login"
      ["secure_ssh"]="Secure ssh"
      ["create_admin_user"]="Create admin user"
      ["add_legal_banner"]="Add legal banner"
      ["install_recommended_packages"]="Install recommended packages"
      ["setup_aide"]="Setup aide"
      ["enable_process_accounting"]="Enable process accounting"
      ["disable_uncommon_filesystems"]="Disable unused filesystems"
      ["disable_firewire"]="Disable firewire"
      ["disable_usb"]="Disable usb"
      ["disable_uncommon_protocols"]="Disable uncommon protocols"
      ["change_root_permissions"]="Change root dir permissions"
      ["restrict_access_to_compilers"]="Restrict access to compilers"
      ["move_tmp_to_tmpfs"]="Move tmp to tmpfs"

      ["remount_dir_with_restrictions"]="Remount /tmp /proc /dev /run to be more "\
        "restrictive"

      ["purge_old_packages"]="Purge old packages"
      ["reboot"]="Reboot"
    )

    for str_key in "${!dict_command_prompts[@]}"; do
      local value="${dict_command_prompts["${str_key}"]}"

      run "${str_key}" "${str_value}"

      if [[ "${?}" -eq 1 ]]; then
        echo "$0: Script has failed."
        return 1
      fi
    done

    echo "$0: Script finished successfully."
    return 0
  }

#
# Main
#
  main
  exit "${?}"