<img align="left" width="100" height="100" src="/logo.png"/>
<br>

# lockdown.sh
### v1.0.3
`lockdown.sh` is a single-file zero-config shell script to be run to lockdown a
newly installed Linux OS. `lockdown.sh` aims to set a sensible baseline which
can be built upon for specific needs.

### [Download](#4-download)
#### View this repository on [Codeberg][01], [GitHub][02].
[01]: https://codeberg.org/portellam/lockdown.sh
[02]: https://github.com/portellam/lockdown.sh
##

## Table of Contents
- [1. Why?](#1-why)
- [2. Warning](#2-warning)
- [3. Supported Operating Systems](#3-supported-operating-systems)
- [4. Download](#4-download)
- [5. Usage](#5-usage)
- [6. Features](#6-features)
    - [6.1. Additions](#61-additions)
    - [6.2. Installed Packages](#62-installed-packages)
    - [6.3. Removals](#63-removals)
    - [6.4. Access Restrictions](#64-access-restrictions)
- [7. Contact](#7-contact)
- [8. References](#8-references)

## Contents
### 1. Why?
1. **Zero** Config
2. **Zero** Install
3. **Single file** shell script

### 2. Warning
`Lockdown.sh` changes the ssh port to `141`, and restricts ssh to key only for
the created admin user if an admin user is created.

### 3. Supported Operating Systems
- Debian 12 Bookworm
- Debian 10 Buster
- Debian 8 Jessie

**!** Debian-based operating systems should be supported:
  Ubuntu, Linux Mint, and Pop! OS.

### 4. Download
- Download the Latest Release:&ensp;[Codeberg][41], [GitHub][42]

- Download the script file:
    - `wget https://www.codeberg.org/portellam/lockdown.sh/master/lockdown.sh`
    - `wget https://www.github.com/portellam/lockdown.sh/master/lockdown.sh`

- Download the `.zip` file:
    1. Viewing from the top of the repository's (current) webpage, click the
        drop-down icon:
        - `···` on Codeberg.
        - `<> Code ` on GitHub.
    2. Click `Download ZIP` and save.
    3. Open the `.zip` file, then extract its contents.

- Clone the repository:
    1. Open a Command Line Interface (CLI) or Terminal.
        - Open a console emulator (for Debian systems: Konsole).
        - **Linux only:** Open an existing console: press `CTRL` + `ALT` + `F2`,
        `F3`, `F4`, `F5`, or `F6`.
            - **To return to the desktop,** press `CTRL` + `ALT` + `F7`.
            - `F1` is reserved for debug output of the Linux kernel.
            - `F7` is reserved for video output of the desktop environment.
            - `F8` and above are unused.
    2. Change your directory to your home folder or anywhere safe:
        - `cd ~`
    3. Clone the repository:
        - `git clone https://www.codeberg.org/portellam/lockdown.sh`
        - `git clone https://www.github.com/portellam/lockdown.sh`

[41]: https://codeberg.org/portellam/lockdown.sh/releases/latest
[42]: https://github.com/portellam/lockdown.sh/releases/latest

### 5. Usage
Run `lockdown.sh` as root, and select which sections to run when prompted.

```bash
chmod +x ./lockdown.sh
./lockdown.sh
```

### 6. Features
#### 6.1. Additions
- Adds daily cronjob to update packages on server.
- Adds a legal banner to `/etc/issue` and `/etc/issue.net`.
- Configures the kernel.
- Enables process accounting.
- Moves `tmp` to `tmpfs`.
- Remounts `/tmp`, `/proc`, `/dev`, and `/run` to be more restrictive.
- Updates packages.

#### 6.2. Installed Packages
- Installs and configures [auditd](#2) with sensible rules.
- Installs and sets up [aide](#1).
- Installs [fail2ban](#3).
- Installs packages recommended by [lynis](#4).
- Installs [usbguard](#5).

#### 6.3. Removals
- Disables core dumps.
- Disables uncommon filesystems.
- Disables firewire and usb storage.
- Disables uncommon network protocols.
- Purges old and removed packages.

#### 6.4. Access Restrictions
- Create a new admin user.
- Restricts access to `/root`.
- Restrict access to compilers.
- Restricts firewall to only allow SSH on `141`.
- Restricts logins.
- Restricts SSH and enables only the created admin user.
- usbguard: whitelist current devices.
- usbguard: whitelist all devices.

### 7. Contact
Do you need help? Please visit the [Issues][71] page.

[71]: https://github.com/portellam/lockdown.sh/issues
##

### 8. References
#### 1.
&ensp;&ensp;**aide/aide**. GitHub. Accessed July 2, 2024.

&ensp;&ensp;&ensp;&ensp;<sup>https://github.com/aide/aide.</sup>

#### 2.
&ensp;&ensp;**auditd(8): Audit Daemon**. Linux man page. Accessed July 2, 2024.

&ensp;&ensp;&ensp;&ensp;<sup>https://linux.die.net/man/8/auditd.</sup>

#### 3.
&ensp;&ensp;**fail2ban**. fail2ban. Accessed July 2, 2024.

&ensp;&ensp;&ensp;&ensp;<sup>https://www.fail2ban.org.</sup>

#### 4.
&ensp;&ensp;**CISOfy/lynis**. GitHub. Accessed July 2, 2024.

&ensp;&ensp;<sup>https://github.com/CISOfy/lynis.</sup>

#### 5.
&ensp;&ensp;**USBGuard/usbguard**. GitHub. Accessed July 8, 2024.

&ensp;&ensp;&ensp;&ensp;<sup>https://github.com/USBGuard/usbguard.</sup>
##

#### Click [here](#lockdownsh) to return to the top of this document.