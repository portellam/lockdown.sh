#!/bin/bash

#
# Filename:       lockdown.sh
# Version:        1.0.1
# Description:    Lockdown your Linux install. The simple zero-config Linux
#                 hardening script.
# Author(s):      Dom Ginger <github.com/dolegi>
# Maintainer(s):  Alex Portell <github.com/portellam>
#

# TODO: review https://en.wikipedia.org/wiki/Package_manager.

#
# parameters
#
  declare -a ARR_ARGUMENTS="${*}"
  declare BOOL_DO_EVERYTHING=false
  declare -i INT_SSH_PORT=141

#
# logic
#
  #
  # DESC:   Main execution.
  # RETURN: If all prompted commands pass, return 0.
  #         If one or more command(s) fail, return 1.
  #
    function main
    {
      parse_arguments || return 1

      local -Ar dict_command_prompts=(
        ["apt_update"]="Update and upgrade all packages"
        ["configure_iptables"]="Configure iptables"
        ["install_fail2ban"]="Install fail2ban"
        ["configure_kernel"]="Configure kernel"
        ["install_unattended_upgrades"]="Setup automatic updates"
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
  # DESC: Helpers
  #
    #
    # DESC:   Overwrite output to file.
    # $1:     the output as an array reference.
    # $2:     the file name as a string.
    # RETURN: If the write is successful, return 0.
    #         If not, return 1.
    #
      function overwrite_file
      {
        local -n ref_arr_output="${1}"
        local -r str_file_name="${2}"

        echo > "${str_file_name}"
        write_file "arr_output" "${str_file_name}" || return 1
      }

    #
    # DESC:   Parse argument.
    # $1:     the argument as a string.
    # RETURN: If the argument is a match or is null, return 0.
    #         If not a match, return 1.
    #
      function parse_argument
      {
        case "${1}" in
          "-a" | "--all" )
            BOOL_DO_EVERYTHING=true
            ;;

          "" )
            return 0
            ;;

          * )
            return 1
            ;;
        esac
      }

    #
    # DESC:   Parse arguments.
    # RETURN: If parse is successful, return 0.
    #         If not, return 1.
    #
      function parse_arguments
      {
        if ! printf "%s\n" "${ARR_ARGUMENTS[@]}" | sort | uniq --repeated; then
          echo -e "$0: Duplicate argument(s)."
          return 1
        fi

        for str_argument in "${ARR_ARGUMENTS[*]}"; do
          parse_argument "${str_argument}" || return 1
        done
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

        if ! "${BOOL_DO_EVERYTHING}"; then
          echo -en "$0: Run the above command(s)? [Y/n]: "

          read -r str_answer

          if [ "${str_answer}" != "${answer#[Yy]}" ] ;then
            echo -e "$0: Skipped command(s)."
            return 255
          fi
        fi

        if ! ${str_command}; then
          echo -e "$0: Failure."
          return 1
        fi

        echo -e "$0: Success."
        return 0
      }

    #
    # DESC:   Write output to file.
    # $1:     the output as an array reference.
    # $2:     the file name as a string.
    # RETURN: If the write is successful, return 0.
    #         If not, return 1.
    #
      function write_file
      {
        local -n ref_arr_output="${1}"
        local -r str_file_name="${2}"

        if [[ "ref_arr_output" == "" ]]; then
          return 1
        fi

        for str_line in "${ref_arr_output[*]}"; do
          echo -e "${str_line}" >> "${str_file_name}" || return 1
        done
      }

  #
  # DESC: Additions
  #
    #
    # DESC:   Add legal banner to warn unauthorized users.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function add_legal_banner
      {
        # Add legal banner
        local -a arr_output=(
          "Unauthorized access to this server is prohibited"
          "Legal action will be taken. Disconnect now."
        )

        write_file "arr_output" "/etc/issue" || return 1
        write_file "arr_output" "/etc/issue.net" || return 1
      }

    #
    # DESC:   Update packages via APT.
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
    # DESC:   Configure auditing logger.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function configure_auditd
      {
        # Install auditd
        install_package "auditd" || return 1

        # Add config
        local -ar arr_output=(
          "# Remove any existing rules"
          "-D"
          ""
          "# Buffer Size"
          "# Might need to be increased, depending on the load of your system."
          "-b 8192"
          ""
          "# Failure Mode"
          "# 0=Silent"
          "# 1=printk, print failure message"
          "# 2=panic, halt system"
          "-f 1"
          ""
          "# Audit the audit logs."
          "-w /var/log/audit/ -k auditlog"
          ""
          "## Auditd configuration"

          "## Modifications to audit configuration that occur while the audit " \
            "(check your paths)"

          "-w /etc/audit/ -p wa -k auditconfig"
          "-w /etc/libaudit.conf -p wa -k auditconfig"
          "-w /etc/audisp/ -p wa -k audispconfig"
          ""
          "# Schedule jobs"
          "-w /etc/cron.allow -p wa -k cron"
          "-w /etc/cron.deny -p wa -k cron"
          "-w /etc/cron.d/ -p wa -k cron"
          "-w /etc/cron.daily/ -p wa -k cron"
          "-w /etc/cron.hourly/ -p wa -k cron"
          "-w /etc/cron.monthly/ -p wa -k cron"
          "-w /etc/cron.weekly/ -p wa -k cron"
          "-w /etc/crontab -p wa -k cron"
          "-w /var/spool/cron/crontabs/ -k cron"
          ""
          "## user, group, password databases"
          "-w /etc/group -p wa -k etcgroup"
          "-w /etc/passwd -p wa -k etcpasswd"
          "-w /etc/gshadow -k etcgroup"
          "-w /etc/shadow -k etcpasswd"
          "-w /etc/security/opasswd -k opasswd"
          ""
          "# Monitor usage of passwd command"
          "-w /usr/bin/passwd -p x -k passwd_modification"
          ""
          "# Monitor user/group tools"
          "-w /usr/sbin/groupadd -p x -k group_modification"
          "-w /usr/sbin/groupmod -p x -k group_modification"
          "-w /usr/sbin/addgroup -p x -k group_modification"
          "-w /usr/sbin/useradd -p x -k user_modification"
          "-w /usr/sbin/usermod -p x -k user_modification"
          "-w /usr/sbin/adduser -p x -k user_modification"
          ""
          "# Login configuration and stored info"
          "-w /etc/login.defs -p wa -k login"
          "-w /etc/securetty -p wa -k login"
          "-w /var/log/faillog -p wa -k login"
          "-w /var/log/lastlog -p wa -k login"
          "-w /var/log/tallylog -p wa -k login"
          ""
          "# Network configuration"
          "-w /etc/hosts -p wa -k hosts"
          "-w /etc/network/ -p wa -k network"
          ""
          "## system startup scripts"
          "-w /etc/inittab -p wa -k init"
          "-w /etc/init.d/ -p wa -k init"
          "-w /etc/init/ -p wa -k init"
          ""
          "# Library search paths"
          "-w /etc/ld.so.conf -p wa -k libpath"
          ""
          "# Kernel parameters and modules"
          "-w /etc/sysctl.conf -p wa -k sysctl"
          "-w /etc/modprobe.conf -p wa -k modprobe"
          ""
          "# SSH configuration"
          "-w /etc/ssh/sshd_config -k sshd"
          ""
          "# Hostname"
          "-a exit,always -F arch=b32 -S sethostname -k hostname"
          "-a exit,always -F arch=b64 -S sethostname -k hostname"
          ""
          "# Log all commands executed by root"
          "-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd"
          "-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd"
          ""
          "## Capture all failures to access on critical elements"

          "-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k " \
            "unauthedfileacess"

          "-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k " \
            "unauthedfileacess"

          ""
          "## su/sudo"
          "-w /bin/su -p x -k priv_esc"
          "-w /usr/bin/sudo -p x -k priv_esc"
          "-w /etc/sudoers -p rw -k priv_esc"
          ""
          "# Poweroff/reboot tools"
          "-w /sbin/halt -p x -k power"
          "-w /sbin/poweroff -p x -k power"
          "-w /sbin/reboot -p x -k power"
          "-w /sbin/shutdown -p x -k power"
          ""
          "# Make the configuration immutable"
          "-e 2"
        )

        write_file "arr_output" "/etc/audit/rules.d/audit.rules" || return 1
        systemctl enable auditd.service || return 1
        service auditd restart || return 1
      }

    #
    # DESC:   Harden network settings.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function configure_iptables
      {
        # iptables
        install_package "iptables-persistent" || return 1

        # Flush existing rules
        iptables -F || return 1

        # Defaults
        iptables -P INPUT DROP || return 1
        iptables -P FORWARD DROP || return 1
        iptables -P OUTPUT ACCEPT || return 1

        # Accept loopback input
        iptables -A INPUT -i lo -p all -j ACCEPT || return 1

        # Allow three-way Handshake
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || return 1

        # Stop Masked Attacks
        iptables -A INPUT -p icmp --icmp-type 13 -j DROP || return 1
        iptables -A INPUT -p icmp --icmp-type 17 -j DROP || return 1
        iptables -A INPUT -p icmp --icmp-type 14 -j DROP || return 1
        iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT || return 1

        # Discard invalid Packets
        iptables -A INPUT -m state --state INVALID -j DROP || return 1
        iptables -A FORWARD -m state --state INVALID -j DROP || return 1
        iptables -A OUTPUT -m state --state INVALID -j DROP || return 1

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
        iptables -A INPUT -p tcp -m tcp --dport "${INT_SSH_PORT}" -j ACCEPT

        # Allow Ping
        iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

        # Allow one ssh connection at a time
        iptables -A INPUT -p tcp --syn --dport "${INT_SSH_PORT}" -m connlimit \
          --connlimit-above 2 -j REJECT

        iptables-save > "/etc/iptables/rules.v4" || return 1
        ip6tables-save > "/etc/iptables/rules.v6" || return 1
      }

    #
    # DESC:   Harden kernel.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function configure_kernel
      {
        local -ar arr_output=(
          "net.ipv4.conf.all.accept_redirects: 0"
          "net.ipv4.conf.all.accept_source_route: 0"
          "net.ipv4.conf.all.log_martians: 1"
          "net.ipv4.conf.all.rp_filter: 1"
          "net.ipv4.conf.all.secure_redirects: 1"
          "net.ipv4.conf.all.send_redirects: 0"
          "net.ipv4.conf.default.accept_redirects: 0"
          "net.ipv4.conf.default.accept_source_route: 0"
          "net.ipv4.conf.default.log_martians: 1"
          "net.ipv4.conf.default.rp_filter: 1"
          "net.ipv4.conf.default.secure_redirects: 1"
          "net.ipv4.conf.default.send_redirects: 0"
          "net.ipv4.icmp_echo -e_ignore_broadcasts: 1"
          "net.ipv4.icmp_ignore_bogus_error_responses: 1"
          "net.ipv4.icmp_echo -e_ignore_all: 0"
          "net.ipv4.ip_forward: 0"
          "net.ipv4.tcp_rfc1337: 1"
          "net.ipv4.tcp_syncookies: 1"
          "net.ipv6.conf.all.accept_redirects: 0"
          "net.ipv6.conf.all.forwarding: 0"
          "net.ipv6.conf.all.accept_source_route: 0"
          "net.ipv6.conf.default.accept_redirects: 0"
          "net.ipv6.conf.default.accept_source_route: 0"
          "fs.protected_hardlinks: 1"
          "fs.protected_symlinks: 1"
          "kernel.core_uses_pid: 1"
          "kernel.perf_event_paranoid: 2"
          "kernel.kptr_restrict: 2"
          "kernel.randomize_va_space: 2"
          "kernel.sysrq: 0"
          "kernel.yama.ptrace_scope: 1"
        )

        write_file "arr_output" "/etc/sysctl.d/80-lockdown.conf" || return 1
        sysctl --system || return 1
      }

    #
    # DESC:   Enable process accounting.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function enable_process_accounting
      {
        # Enable process accounting
        systemctl enable acct.service || return 1
        systemctl start acct.service || return 1
      }

    #
    # DESC:   Install recommended packages.
    # RETURN: Return code from last statement.
    #
      function install_recommended_packages
      {
        # Install recommended packages
          install_package \
            "acct" \
            "aide" \
            "apt-listbugs" \
            "apt-listchanges" \
            "debsecan" \
            "debsums" \
            "libpam-cracklib" \
            "needrestart" \
            "usbguard"
      }

    #
    # DESC:   Moved /tmp to /tmpfs.
    # RETURN: Return code from last statement.
    #
      function move_tmp_to_tmpfs
      {
        # Move tmp to tmpfs
        echo -e "tmpfs /tmp tmpfs rw,nosuid,nodev" >> "/etc/fstab"
      }

    #
    # DESC:   Remount certain directories with restrictions.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function remount_dir_with_restrictions
      {
        # Mount tmp with noexec
        mount --options remount,noexec /tmp || return 1

        # Mount /proc with hidepid=2
        mount --options remount,rw,hidepid=2 /proc || return 1

        # Mount /dev with noexec
        mount --options remount,noexec /dev || return 1

        # Mount /run as nodev
        mount --options remount,nodev /run || return 1
      }

  #
  # DESC: Access Restrictions
  #
    #
    # DESC:   Create new admin user, with SSH privileges.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
    function create_admin_user
    {
      # Create admin user
      echo -e -n "Enter admin username: " || return 1
      read -r str_username || return 1
      adduser "${str_username}" || return 1
      mkdir "/home/${str_username}/.ssh" || return 1

      cp /root/.ssh/authorized_keys "/home/${str_username}/.ssh/authorized_keys" \
        || return 1

      chown --recursive "${str_username}" "/home/${str_username}/.ssh" || return 1
      usermod --append --groups sudo "${str_username}" || return 1

      # Restrict ssh to admin user
      local -ar arr_output=(
        "AllowUsers ${str_username}"
        "PermitRootLogin no"
      )

      write_file "arr_output" "/etc/ssh/sshd_config" || return 1
    }

    #
    # DESC:   Modify root permissions.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function change_root_permissions
      {
        # Change /root permissions
          chmod 700 /root || return 1
          chmod 750 /home/debian || return 1
      }

    #
    # DESC:   Restrict access to compilers.
    # RETURN: Return code from last statement.
    #
      function restrict_access_to_compilers
      {
        # Restrict access to compilers
        chmod o-rx /usr/bin/as
      }

    #
    # DESC:   Restrict user login session time.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function restrict_login
      {
        # Set login.defs
        sed --in-place s/UMASK.*/UMASK\ 027/ /etc/login.defs || return 1
        sed --in-place s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs || return 1
        sed --in-place s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs || return 1

        local -ar arr_output=(
          "SHA_CRYPT_MIN_ROUNDS 1000000"
          "SHA_CRYPT_MAX_ROUNDS 100000000" \
        )

        write_file "arr_output" "/etc/login.defs" || return 1
      }

    #
    # DESC:   Configure SSH for greater security.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function secure_ssh
      {
        # Secure ssh

        local -r str_file="/etc/ssh/sshd_config"

        local -ar arr_output=(
          "ClientAliveCountMax 2"
          "Compression no"
          "LogLevel VERBOSE"
          "MaxAuthTries 3"
          "MaxSessions 2"
          "TCPKeepAlive no"
          "AllowAgentForwarding no"
          "AllowTcpForwarding no"
          "Port ${INT_SSH_PORT}"
          "PasswordAuthentication no"
        )

        write_file "arr_output" "${str_file}" || return 1
        sed --in-place s/^X11Forwarding.*/X11Forwarding\ no/ "${str_file}" || return 1
        sed --in-place s/^UsePAM.*/UsePAM\ no/ "${str_file}" || return 1
      }

  #
  # DESC: Installs
  #
    # DESC:   Install a package and determine if it was installed.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function install_package
      {
        local -i int_counter=1
        local -r str_package_name_delim="${1}"

        apt install -y "${str_package_name_delim}" || return 1

        while true; do
          local str_this_package_name=$( \
            echo "${1}" | cut --delimiter ' ' --field "${int_counter}"
          )

          if [[ "${str_this_package_name}" -eq "" ]]; then
            break
          fi

          dpkg --status "${str_package_name}" | \
            perl -ne 'print if /Status/ && /install/' \
            || return 1

          (( int_counter++ ))
        done
      }

    #
    # DESC:   Install fail2ban.
    # RETURN: Return code from last statement.
    #
      function install_fail2ban
      {
        install_package "fail2ban"
      }

    #
    # DESC:   Install unattended-upgrades.
    # RETURN: Return code from last statement.
    #
      function install_unattended_upgrades
      {
        # Enable automatic updates
        install_package "unattended-upgrades"
      }

    #
    # DESC:   Setup Advanced Intrusion Detection Environment (AIDE).
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function setup_aide
      {
        # Setup aide
        aideinit || return 1
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || return 1
      }

  #
  # DESC: Removals
  #
    # DESC:   Disable core dumps.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function disable_core_dumps
      {
        # Disable core dumps
        echo -e "* hard core 0" >> "/etc/security/limits.conf" || return 1

        local -ar arr_output=(
          "ProcessSizeMax=0\n"
          "Storage=none" \
        )

        write_file "arr_output" "/etc/systemd/coredump.conf" || return 1
        echo -e "ulimit -c 0" >> "/etc/profile" || return 1
      }

    #
    # DESC:   Disable uncommon filesystems.
    # RETURN: Return code from last statement.
    #
      function disable_uncommon_filesystems
      {
        # Disable uncommon filesystems
        local -ar arr_output=(
          "install cramfs /bin/true"
          "install freevxfs /bin/true"
          "install hfs /bin/true"
          "install hfsplus /bin/true"
          "install jffs2 /bin/true"
          "install squashfs /bin/true"
        )

        write_file "arr_output" "/etc/modprobe.d/filesystems.conf" || return 1
      }

    #
    # DESC:   Disable Firewire storage.
    # RETURN: Return code from last statement.
    #
      function disable_firewire
      {
        local -ar arr_output=(
          "install udf /bin/true"
          "blacklist firewire-core"
          "blacklist firewire-ohci"
          "blacklist firewire-sbp2"
        )

        write_file "arr_output" "/etc/modprobe.d/blacklist.conf" || return 1
      }

    #
    # DESC:   Disable uncommon IP protocols.
    # RETURN: Return code from last statement.
    #
      function disable_uncommon_protocols
      {
        local -ar arr_output=(
          "install sctp /bin/true"
          "install dccp /bin/true"
          "install rds /bin/true"
          "install tipc /bin/true"
        )

        write_file "arr_output" "/etc/modprobe.d/protocols.conf" || return 1
      }

    #
    # DESC:   Disable USB storage.
    # RETURN: Return code from last statement.
    #
      function disable_usb
      {
        echo -e "blacklist usb-storage" >> "/etc/modprobe.d/blacklist.conf"
      }

    #
    # DESC:   Purge old packages.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function purge_old_packages
      {
        # Purge old/removed packages
        apt autoremove -y || return 1
        apt purge -y "$( dpkg --list | grep '^rc' | awk '{print $2}' )" || return 1
      }

#
# Main
#
  main
  exit "${?}"