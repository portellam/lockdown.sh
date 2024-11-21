#!/bin/bash

#
# Filename:       lockdown.sh
# Version:        1.0.2
# Description:    Lockdown your Linux install. The simple zero-config Linux
#                 hardening script.
# Author(s):      Dom Ginger <github.com/dolegi>
# Maintainer(s):  Alex Portell <github.com/portellam>
#

#
# parameters
#
  declare -r STR_SCRIPT_NAME="${0}"
  declare -a ARR_ARGUMENTS="${*}"
  declare BOOL_DO_EVERYTHING=false
  declare -i INT_SSH_PORT=141

  declare -ar ARR_COMMANDS=(
    #
    # Additions
    #
      "add_legal_banner"
      "apt_update"
      "configure_iptables"
      "configure_kernel"
      "enable_process_accounting"
      "remount_dir_with_restrictions"

    #
    # Installed Packages (1/2)
    #
      "install_unattended_upgrades"
      "install_fail2ban"
      "install_recommended_packages"
      "install_usbguard"

    #
    # Access Restrictions (1/2)
    #
      "usbguard_whitelist_current_devices"
      "usbguard_whitelist_all_devices"

    #
    # Installed Packages (2/2)
    #
      "configure_auditd"
      "setup_aide"

    #
    # Removals
    #
      "disable_core_dumps"
      "disable_firewire"
      "disable_usb"
      "disable_uncommon_filesystems"
      "disable_uncommon_protocols"
      "purge_old_packages"

    #
    # Access Restrictions (2/2)
    #
      "secure_ssh"
      "create_admin_user"
      "change_root_permissions"
      "restrict_access_to_compilers"
      "move_tmp_to_tmpfs"
      "restrict_login"

    "reboot"
  )

  declare -Ar DICT_COMMAND_PROMPTS=(
    #
    # Additions
    #
      ["add_legal_banner"]="Add legal banner."
      ["apt_update"]="Update and upgrade all packages."
      ["configure_iptables"]="Configure iptables."
      ["configure_kernel"]="Configure kernel."
      ["enable_process_accounting"]="Enable process accounting."
      ["remount_dir_with_restrictions"]="Remount /tmp /proc /dev /run with restrictions."

    #
    # Installed Packages
    #
      ["install_unattended_upgrades"]="Setup automatic updates."
      ["install_fail2ban"]="Install fail2ban."
      ["install_recommended_packages"]="Install recommended packages."
      ["install_usbguard"]="Install USBGuard."
      ["configure_auditd"]="Setup Auditd."
      ["setup_aide"]="Setup Advanced Intrusion Detection Environment (AIDE)."

    #
    # Removals
    #
      ["disable_core_dumps"]="Disable core dumps."
      ["disable_firewire"]="Disable Firewire storage."
      ["disable_usb"]="Disable USB storage."
      ["disable_uncommon_filesystems"]="Disable unused filesystems."
      ["disable_uncommon_protocols"]="Disable uncommon protocols."
      ["purge_old_packages"]="Purge old packages."

    #
    # Access Restrictions
    #
      ["create_admin_user"]="Create admin user."
      ["change_root_permissions"]="Change root directory permissions."
      ["restrict_access_to_compilers"]="Restrict access to compilers."
      ["move_tmp_to_tmpfs"]="Move /tmp to tmpfs."
      ["secure_ssh"]="Secure SSH."
      ["restrict_login"]="Restrict login."
      ["usbguard_whitelist_current_devices"]="USBGuard: Whitelist current devices."
      ["usbguard_whitelist_all_devices"]="USBGuard: Whitelist all devices."

    ["reboot"]="Reboot"
  )

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

      for str_command in ${ARR_COMMANDS[@]}; do
        local str_value="${DICT_COMMAND_PROMPTS["${str_command}"]}"

        run "${str_command}" "${str_value}"

        if [[ "${?}" -eq 1 ]]; then
          echo -e "${STR_SCRIPT_NAME}: Script has failed."
          return 1
        fi

        echo
      done

      echo -e "${STR_SCRIPT_NAME}: Script finished successfully."
      return 0
    }

  #
  # DESC: Helpers
  #
    #
    # DESC:   Does the package exist in cache?
    # $1:     the package name as a string.
    # RETURN: If the package exists, return 0.
    #         If not, return 1.
    #
      function does_package_exist_in_cache
      {
        if [[ -z "${1}" ]]; then
          return 0
        fi

        local -r str_result="$( \
          apt-cache search --names-only "${1}" | grep "${1}"
        )"

        if [[ -z "${str_result}" ]]; then
          return 1
        fi

        return 0
      }

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

        rm --force "${str_file_name}" || return 1
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
          echo -e "${STR_SCRIPT_NAME}: Duplicate argument(s)."
          return 1
        fi

        for str_argument in ${ARR_ARGUMENTS[*]}; do
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

        # typeset -f "${str_command}" | tail --lines +2 #NOTE: what does this do?

        echo -e "${str_prompt}"

        if ! "${BOOL_DO_EVERYTHING}"; then
          echo -en "${STR_SCRIPT_NAME}: Run the above command(s)? [Y/n]: "
          read -r str_answer

          if [ "${str_answer}" != "Y" ] \
            && [ "${str_answer}" != "y" ]; then
            echo -e "${STR_SCRIPT_NAME}: Skipped command(s)."
            return 255
          fi
        fi

        if ! eval ${str_command}; then
          echo -e "${STR_SCRIPT_NAME}: Failure."
          return 1
        fi

        echo -e "${STR_SCRIPT_NAME}: Success."
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

        for str_line in "${ref_arr_output[@]}"; do
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
          "Unauthorized access to this server is prohibited."
          "Legal action will be taken. Disconnect now."
        )

        overwrite_file "arr_output" "/etc/issue" || return 1
        overwrite_file "arr_output" "/etc/issue.net" || return 1
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

        # Allow cockpit
        if "$( command -v cockpit )" &> /dev/null; then
          iptables -A INPUT -p tcp -m tcp --dport 9090 -j ACCEPT
        fi

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
          "# File system"
          "fs.protected_hardlinks = 1"
          "fs.protected_symlinks = 1"
          ""
          "# Kernel"
          "kernel.core_uses_pid = 1"
          "kernel.perf_event_paranoid = 2"
          "kernel.kptr_restrict = 2"
          "kernel.randomize_va_space = 2"
          "kernel.sysrq = 0"
          "kernel.yama.ptrace_scope = 1"
          ""
          "# Network settings (IPv4)"
          "net.ipv4.conf.all.accept_redirects = 0"
          "net.ipv4.conf.all.accept_source_route = 0"
          "net.ipv4.conf.all.log_martians = 1"
          "net.ipv4.conf.all.rp_filter = 1"
          "net.ipv4.conf.all.secure_redirects = 1"
          "net.ipv4.conf.all.send_redirects = 0"
          "net.ipv4.conf.default.accept_redirects = 0"
          "net.ipv4.conf.default.accept_source_route = 0"
          "net.ipv4.conf.default.log_martians = 1"
          "net.ipv4.conf.default.rp_filter = 1"
          "net.ipv4.conf.default.secure_redirects = 1"
          "net.ipv4.conf.default.send_redirects = 0"
          "net.ipv4.icmp_echo_ignore_broadcasts = 1"
          "net.ipv4.icmp_ignore_bogus_error_responses = 1"
          "net.ipv4.icmp_echo_ignore_all = 0"
          "net.ipv4.ip_forward = 0"
          "net.ipv4.tcp_rfc1337 = 1"
          "net.ipv4.tcp_syncookies = 1"
          ""
          "# Network settings (IPv6)"
          "net.ipv6.conf.all.accept_redirects = 0"
          "net.ipv6.conf.all.forwarding = 0"
          "net.ipv6.conf.all.accept_source_route = 0"
          "net.ipv6.conf.default.accept_redirects = 0"
          "net.ipv6.conf.default.accept_source_route = 0"
        )

        overwrite_file "arr_output" "/etc/sysctl.d/80-lockdown.conf" || return 1
        sysctl --system || return 1
      }

    #
    # DESC:   Enable process accounting.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function enable_process_accounting
      {
        # Install process accounting
        install_package "acct" || return 1

        # Enable process accounting
        systemctl enable acct.service || return 1
        systemctl start acct.service || return 1
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
    # DESC:   Moved /tmp to /tmpfs.
    # RETURN: Return code from last statement.
    #
      function move_tmp_to_tmpfs
      {
        # Move tmp to tmpfs
        if [[ -d "/tmp" ]]; then
          echo -e "tmpfs /tmp tmpfs rw,nosuid,nodev" >> "/etc/fstab"

        else
          echo "Skipped."
        fi
      }

    #
    # DESC:   Remount certain directories with restrictions.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function remount_dir_with_restrictions
      {
        # Mount tmp with noexec
        if [[ -d "/tmp" ]]; then
          mount --options remount,noexec /tmp || return 1

        else
          echo "Skipped."
        fi

        # Mount /proc with hidepid=2
        if [[ -d "/proc" ]]; then
          mount --options remount,rw,hidepid=2 /proc || return 1

        else
          echo "Skipped."
        fi

        # Mount /dev with noexec
        if [[ -d "/dev" ]]; then
          mount --options remount,noexec /dev || return 1

        else
          echo "Skipped."
        fi

        # Mount /run as nodev
        if [[ -d "/run" ]]; then
          mount --options remount,nodev /run || return 1

        else
          echo "Skipped."
        fi
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
        echo -e -n "${STR_SCRIPT_NAME}: Enter admin username: " || return 1
        read -r str_username || return 1

        if ! getent passwd $1 > /dev/null 2&>1; then
          adduser "${str_username}" || return 1
        fi

        mkdir --parents "/home/${str_username}/.ssh" || return 1

        local -r str_keys_path="/root/.ssh/authorized_keys"

        if [[ -e "${str_keys_path}" ]]; then
          cp "" "/home/${str_username}/.ssh/authorized_keys" \
          || return 1
        fi

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
    #
    # DESC:   Install a package and determine if it was installed.
    # $*:     the packages to install as a space-delimited string.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function install_package
      {
        apt update || return 1

        local str_packages_delim=""

        for str_package in ${*}; do
          if [[ -z "${str_package}" ]]; then
            break
          fi

          if does_package_exist_in_cache "${str_package}"; then
            continue
          fi

          str_packages_delim+=" ${str_package}"
        done

        apt install -y "${str_packages_delim}" || return 1

        for str_package in ${*}; do
          if [[ -z "${str_package}" ]]; then
            break
          fi

          if does_package_exist_in_cache "${str_package}"; then
            continue
          fi

          dpkg --status "${str_package}" | \
            perl -ne 'print if /Status/ && /install/'  &> /dev/null \
            || return 1
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
            "needrestart"
      }

    #
    # DESC:   Install USBGuard.
    # RETURN: Return code from last statement.
    #
      function install_usbguard
      {
        install_package \
          "usbguard" \
          || return 1

        if ! "$( command -v usbguard )" &> /dev/null ; then
          return 1
        fi

        # In case USBGuard is setup without any whitelisted devices.
          systemctl disable usbguard || return 1
          systemctl stop usbguard || return 1

        echo -e "${STR_SCRIPT_NAME}: Disabled USBGuard." \
          "Please whitelist devices before re-enabling USBGuard."

        echo -e "${STR_SCRIPT_NAME}: To re-enable, please run:" \

        echo "\"systemctl enable usbguard\""
        echo "\"systemctl start usbguard\""

        return 0
      }

    #
    # DESC:   Setup Advanced Intrusion Detection Environment (AIDE).
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function setup_aide
      {
        local str_output="This may take a long time. By default, AIDE will scan "
        str_output+="all directories inside the root filesystem. Before continuing,"
        str_output+="please review and modify the .conf files within '/etc/aide/'."

        echo
        run "" "${str_output}" || return 0
        echo

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

        overwrite_file "arr_output" "/etc/modprobe.d/filesystems.conf" || return 1
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

        overwrite_file "arr_output" "/etc/modprobe.d/blacklist-firewire.conf" || return 1
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
        echo -e "blacklist usb-storage" > "/etc/modprobe.d/blacklist-usb.conf"
      }

    #
    # DESC:   Whitelist current USB devices.
    # RETURN: Return code from last statement.
    #
      function usbguard_whitelist_current_devices
      {
        if ! "$( command -v usbguard )" &> /dev/null; then
          return 0
        fi

        sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'
      }

    #
    # DESC:   Whitelist current USB devices.
    # RETURN: Return code from last statement.
    #
      function usbguard_whitelist_all_devices
      {
        if ! "$( command -v usbguard )" &> /dev/null; then
          return 0
        fi

        for str_device_path in /sys/bus/usb/devices/*/authorized; do
          echo 1 > "${str_device_path}" || return 1
        done
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

        uninstall_package \
          "$( dpkg --list | grep '^rc' | awk '{print $2}' )" \
          || return 1
      }

    #
    # DESC:   Uninstall a package and determine if it was uninstalled.
    # $*:     the packages to uninstall as a space-delimited string.
    # RETURN: If successful, return 0.
    #         If not successful, return 1.
    #
      function uninstall_package
      {
        apt update || return 1

        local str_packages_delim=""

        for str_package in ${*}; do
          if [[ -z "${str_package}" ]]; then
            break
          fi

          if does_package_exist_in_cache "${str_package}"; then
            continue
          fi

          str_packages_delim+=" ${str_package}"
        done

        echo "${str_package_delim}"
        apt remove "${str_package_delim}" || return 1

        for str_package in ${*}; do
          if [[ -z "${str_package}" ]]; then
            break
          fi

          if does_package_exist_in_cache "${str_package}"; then
            continue
          fi

          dpkg --status "${str_package}" | \
            perl -ne 'print if /Status/ && /deinstall/'  &> /dev/null \
            || return 1
        done
      }

#
# Main
#
  main
  exit "${?}"