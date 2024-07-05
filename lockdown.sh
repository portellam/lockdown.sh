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
# - [ ] determine package manager and run updates or installs.

#
# DESC: Additions
#


#
# DESC: Access Restrictions
#


#
# DESC: Installs
#


#
# DESC: Removals
#


#
# RETURN: If successful, return 0.
#         If not successful, return 1.
#
  function apt_update
  {
    # Update package list
    apt update || return 1

    # Apt upgrade packages
    apt upgrade -y || return 1

    # Apt full upgrade
    apt full-upgrade -y || return 1
  }

#
# RETURN: Return code from last statement.
#
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
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -s 10.0.0.0/8 -j DROP
    iptables -A INPUT -s 127.0.0.0/8 -j DROP
    iptables -A INPUT -s 169.254.0.0/16 -j DROP
    iptables -A INPUT -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -s 192.168.0.0/24 -j DROP
    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP

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

#
# RETURN: Return code from last statement.
#
  function install_fail2ban
  {
    apt install -y fail2ban
  }

#
# RETURN: If successful, return 0.
#         If not successful, return 1.
#
  function configure_kernel
  {
    echo -e \
      "net.ipv4.conf.all.accept_redirects: 0\n"\
      "net.ipv4.conf.all.accept_source_route: 0\n"\
      "net.ipv4.conf.all.log_martians: 1\n"\
      "net.ipv4.conf.all.rp_filter: 1\n"\
      "net.ipv4.conf.all.secure_redirects: 1\n"\
      "net.ipv4.conf.all.send_redirects: 0\n"\
      "net.ipv4.conf.default.accept_redirects: 0\n"\
      "net.ipv4.conf.default.accept_source_route: 0\n"\
      "net.ipv4.conf.default.log_martians: 1\n"\
      "net.ipv4.conf.default.rp_filter: 1\n"\
      "net.ipv4.conf.default.secure_redirects: 1\n"\
      "net.ipv4.conf.default.send_redirects: 0\n"\
      "net.ipv4.icmp_echo -e_ignore_broadcasts: 1\n"\
      "net.ipv4.icmp_ignore_bogus_error_responses: 1\n"\
      "net.ipv4.icmp_echo -e_ignore_all: 0\n"\
      "net.ipv4.ip_forward: 0\n"\
      "net.ipv4.tcp_rfc1337: 1\n"\
      "net.ipv4.tcp_syncookies: 1\n"\
      "net.ipv6.conf.all.accept_redirects: 0\n"\
      "net.ipv6.conf.all.forwarding: 0\n"\
      "net.ipv6.conf.all.accept_source_route: 0\n"\
      "net.ipv6.conf.default.accept_redirects: 0\n"\
      "net.ipv6.conf.default.accept_source_route: 0\n"\
      "fs.protected_hardlinks: 1\n"\
      "fs.protected_symlinks: 1\n"\
      "kernel.core_uses_pid: 1\n"\
      "kernel.perf_event_paranoid: 2\n"\
      "kernel.kptr_restrict: 2\n"\
      "kernel.randomize_va_space: 2\n"\
      "kernel.sysrq: 0\n"\
      "kernel.yama.ptrace_scope: 1" \

      > /etc/sysctl.d/80-lockdown.conf || return 1

    sysctl --system || return 1
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
    "# Remove any existing rules\n"\
    "-D\n"\
    "\n"\
    "# Buffer Size\n"\
    "# Might need to be increased, depending on the load of your system.\n"\
    "-b 8192\n"\
    "\n"\
    "# Failure Mode\n"\
    "# 0=Silent\n"\
    "# 1=printk, print failure message\n"\
    "# 2=panic, halt system\n"\
    "-f 1\n"\
    "\n"\
    "# Audit the audit logs.\n"\
    "-w /var/log/audit/ -k auditlog\n"\
    "\n"\
    "## Auditd configuration\n"\

    "## Modifications to audit configuration that occur while the audit " \
      "(check your paths)\n"\

    "-w /etc/audit/ -p wa -k auditconfig\n"\
    "-w /etc/libaudit.conf -p wa -k auditconfig\n"\
    "-w /etc/audisp/ -p wa -k audispconfig\n"\
    "\n"\
    "# Schedule jobs\n"\
    "-w /etc/cron.allow -p wa -k cron\n"\
    "-w /etc/cron.deny -p wa -k cron\n"\
    "-w /etc/cron.d/ -p wa -k cron\n"\
    "-w /etc/cron.daily/ -p wa -k cron\n"\
    "-w /etc/cron.hourly/ -p wa -k cron\n"\
    "-w /etc/cron.monthly/ -p wa -k cron\n"\
    "-w /etc/cron.weekly/ -p wa -k cron\n"\
    "-w /etc/crontab -p wa -k cron\n"\
    "-w /var/spool/cron/crontabs/ -k cron\n"\
    "\n"\
    "## user, group, password databases\n"\
    "-w /etc/group -p wa -k etcgroup\n"\
    "-w /etc/passwd -p wa -k etcpasswd\n"\
    "-w /etc/gshadow -k etcgroup\n"\
    "-w /etc/shadow -k etcpasswd\n"\
    "-w /etc/security/opasswd -k opasswd\n"\
    "\n"\
    "# Monitor usage of passwd command\n"\
    "-w /usr/bin/passwd -p x -k passwd_modification\n"\
    "\n"\
    "# Monitor user/group tools\n"\
    "-w /usr/sbin/groupadd -p x -k group_modification\n"\
    "-w /usr/sbin/groupmod -p x -k group_modification\n"\
    "-w /usr/sbin/addgroup -p x -k group_modification\n"\
    "-w /usr/sbin/useradd -p x -k user_modification\n"\
    "-w /usr/sbin/usermod -p x -k user_modification\n"\
    "-w /usr/sbin/adduser -p x -k user_modification\n"\
    "\n"\
    "# Login configuration and stored info\n"\
    "-w /etc/login.defs -p wa -k login\n"\
    "-w /etc/securetty -p wa -k login\n"\
    "-w /var/log/faillog -p wa -k login\n"\
    "-w /var/log/lastlog -p wa -k login\n"\
    "-w /var/log/tallylog -p wa -k login\n"\
    "\n"\
    "# Network configuration\n"\
    "-w /etc/hosts -p wa -k hosts\n"\
    "-w /etc/network/ -p wa -k network\n"\
    "\n"\
    "## system startup scripts\n"\
    "-w /etc/inittab -p wa -k init\n"\
    "-w /etc/init.d/ -p wa -k init\n"\
    "-w /etc/init/ -p wa -k init\n"\
    "\n"\
    "# Library search paths\n"\
    "-w /etc/ld.so.conf -p wa -k libpath\n"\
    "\n"\
    "# Kernel parameters and modules\n"\
    "-w /etc/sysctl.conf -p wa -k sysctl\n"\
    "-w /etc/modprobe.conf -p wa -k modprobe\n"\
    "\n"\
    "# SSH configuration\n"\
    "-w /etc/ssh/sshd_config -k sshd\n"\
    "\n"\
    "# Hostname\n"\
    "-a exit,always -F arch=b32 -S sethostname -k hostname\n"\
    "-a exit,always -F arch=b64 -S sethostname -k hostname\n"\
    "\n"\
    "# Log all commands executed by root\n"\
    "-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd\n"\
    "-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd\n"\
    "\n"\
    "## Capture all failures to access on critical elements\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k " \
      "unauthedfileacess\n"\

    "-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k " \
      "unauthedfileacess\n"\

    "\n"\
    "## su/sudo\n"\
    "-w /bin/su -p x -k priv_esc\n"\
    "-w /usr/bin/sudo -p x -k priv_esc\n"\
    "-w /etc/sudoers -p rw -k priv_esc\n"\
    "\n"\
    "# Poweroff/reboot tools\n"\
    "-w /sbin/halt -p x -k power\n"\
    "-w /sbin/poweroff -p x -k power\n"\
    "-w /sbin/reboot -p x -k power\n"\
    "-w /sbin/shutdown -p x -k power\n"\
    "\n"\
    "# Make the configuration immutable\n"\
    "-e 2" \
    > /etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
}

function disable_core_dumps
{
  # Disable core dumps
  echo -e "* hard core 0" >> /etc/security/limits.conf
  echo -e "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo -e "ulimit -c 0" >> /etc/profile
}

function restrict_login
{
  # Set login.defs
  sed --in-place s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed --in-place s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
  sed --in-place s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs

  echo -e \
    "SHA_CRYPT_MIN_ROUNDS 1000000\n"\
    "SHA_CRYPT_MAX_ROUNDS 100000000" \
    >> /etc/login.defs
}

function secure_ssh
{
  # Secure ssh
  echo -e \
    "ClientAliveCountMax 2\n"\
    "Compression no\n"\
    "LogLevel VERBOSE\n"\
    "MaxAuthTries 3\n"\
    "MaxSessions 2\n"\
    "TCPKeepAlive no\n"\
    "AllowAgentForwarding no\n"\
    "AllowTcpForwarding no\n"\
    "Port 141\n"\
    "PasswordAuthentication no\n"\
    >> /etc/ssh/sshd_config

  sed --in-place s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config
  sed --in-place s/^UsePAM.*/UsePAM\ no/ /etc/ssh/sshd_config
}

function create_admin_user
{
  # Create admin user
  echo -e -n "Enter admin username: "
  read -r str_username
  adduser "${str_username}"
  mkdir "/home/${str_username}/.ssh"
  cp /root/.ssh/authorized_keys "/home/${str_username}/.ssh/authorized_keys"
  chown --recursive "${str_username}" "/home/${str_username}/.ssh"
  usermod --append --groups sudo "${str_username}"

  # Restrict ssh to admin user
  echo -e \
    "AllowUsers ${str_username}\n"\
    "PermitRootLogin no\n" \
    >> /etc/ssh/sshd_config
}

function add_legal_banner
{
  # Add legal banner
  echo -e \
    "Unauthorized access to this server is prohibited.\n"\
    "Legal action will be taken. Disconnect now." \
    > /etc/issue

  echo -e \
    "Unauthorized access to this server is prohibited.\n"\
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
  echo -e "install cramfs /bin/true\n"\
    "install freevxfs /bin/true\n"\
    "install hfs /bin/true\n"\
    "install hfsplus /bin/true\n"\
    "install jffs2 /bin/true\n"\
    "install squashfs /bin/true" \
  >> /etc/modprobe.d/filesystems.conf
}

function disable_firewire
{
  echo -e \
    "install udf /bin/true\n"\
    "blacklist firewire-core\n"\
    "blacklist firewire-ohci\n"\
    "blacklist firewire-sbp2" \
    >> /etc/modprobe.d/blacklist.conf
}

function disable_usb
{
  echo -e "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}

function disable_uncommon_protocols
{
  echo -e \
    "install sctp /bin/true\n"\
    "install dccp /bin/true\n"\
    "install rds /bin/true\n"\
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
  echo -e "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab
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
      echo -e "$0: Skipped command(s)."
      return 255
    fi

    if ! ${str_command}; then
      echo -e "$0: Failure."
      return 1
    fi

    echo -e "$0: Success."
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
      local str_value="${dict_command_prompts["${str_key}"]}"

      run "${str_key}" "${str_value}"

      if [[ "${?}" -eq 1 ]]; then
        echo -e "$0: Script has failed."
        return 1
      fi
    done

    echo -e "$0: Script finished successfully."
    return 0
  }

#
# Main
#
  main
  exit "${?}"