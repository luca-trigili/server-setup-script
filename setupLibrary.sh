#!/bin/bash

# Utility functions

# Function to log messages to the output file & console
function log() {
    local level=${1}
    local message=${2}
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${level}] ${timestamp}: ${message}" | tee -a "${output_file}"
}

# Executes a command as a specific user
function execAsUser() {
    local username=${1}
    local exec_command=${2}
    sudo -u "${username}" -H bash -c "${exec_command}"
}

function validateSSHKey() {
    local sshKey="$1"
    if [[ ! "$sshKey" =~ ^ssh-(rsa|dss|ed25519|ecdsa) ]]; then
        log "ERROR" "Invalid SSH key format."
        exit 1
    fi
}

function validateUsername() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-zA-Z0-9_]+$ ]]; then
        log "ERROR" "Invalid username. Only alphanumeric characters and underscores are allowed."
        exit 1
    fi
}

function confirmUserCreate() {
    local username=${1}
    read -rp "User ${username} will be created. Proceed? (Y/N): " proceed_create
    if [[ ! "$proceed_create" =~ ^[Yy]$ ]]; then
        log "ERROR" "Create user ${username} aborted."
        exit 1
    fi
    return 0
}

function confirmUserUpdate() {
    local username=${1}
    read -rp "User ${username} already exists. Proceed with updating? (Y/N): " proceed_update
    if [[ ! "$proceed_update" =~ ^[Yy]$ ]]; then
        log "ERROR" "Update canceled for user ${username}."
        exit 1
    fi
    return 0
}

# Checks if user has root permission
function checkRootPermission() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root or with sudo privileges."
        exit 1
    fi
}

# Detects the current Linux distribution
function detectDistro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu) distro="ubuntu" ;;
            almalinux|rocky) distro="almalinux" ;;
            debian) distro="debian" ;;
            *) log "ERROR" "Unsupported distribution: $ID" && exit 1 ;;
        esac
        log "INFO" "Detected distribution: $distro"
    else
        log "ERROR" "Could not detect the distribution!" && exit 1
    fi
}

# Checks if a package is installed
function isPackageInstalled() {
    local package=${1}
    if [[ "$distro" == "ubuntu" ]]; then
        dpkg -l | grep -q "${package}"
    elif [[ "$distro" == "almalinux" ]]; then
        rpm -qa | grep -q "${package}"
    fi
}

# Installs a package only if it's not already installed
function installPackageIfNeeded() {
    local package=${1}
    if ! isPackageInstalled "${package}"; then
        log "INFO" "Installing ${package}..."
        if [[ "$distro" == "ubuntu" ]]; then
            apt-get install -y "${package}" || { log "ERROR" "Failed to install ${package}. Exiting."; exit 1; }
        elif [[ "$distro" == "almalinux" ]]; then
            dnf install -y "${package}" || { log "ERROR" "Failed to install ${package}. Exiting."; exit 1; }
        fi
    else
        log "INFO" "${package} is already installed."
    fi
}

function userExists() {
    local username=${1}
    id "${username}" &>/dev/null
}

function determineSudoGroup() {
    case "$distro" in
        ubuntu) echo 'sudo' ;;
        almalinux) echo 'wheel' ;;
        *) log "ERROR" "Unsupported distribution: ${distro}"; return 1 ;;
    esac
}

function addToGroup() {
    local username=${1}
    local group=${2}
    usermod -aG "$group" "$username"
}

function createUser() {
    local username=${1}
    case "$distro" in
        ubuntu) adduser --disabled-password --gecos "" "${username}" ;;
        almalinux) useradd -m -s /bin/bash "${username}" && passwd -d "${username}" ;;
    esac
}

function updateOrCreateUser() {
    local username=${1}
    local sudoGroup

    if [[ ! "${username}" ]]; then
      username=$(whoami)
    fi
    validateUsername "${username}"
    sudoGroup=$(determineSudoGroup)

    if userExists "${username}"; then
        confirmUserUpdate "${username}" || return 1
        log "INFO" "Updating user ${username}..."
    else
        confirmUserCreate "${username}"
        createUser "${username}"
    fi

    addToGroup "${username}" "${sudoGroup}"
    disablePasswordLogin "${username}"
    log "INFO" "User ${username} processed."
}

# Disables password login for a given user
function disablePasswordLogin() {
    local username=${1}
    passwd -l "${username}"
    log "INFO" "Password login disabled for ${username}."
}

# Disables the sudo password prompt for a user account by editing /etc/sudoers
function disableSudoPromptPassword() {
    local username="${1}"
    cp /etc/sudoers /etc/sudoers.bak
    echo "${username} ALL=(ALL) NOPASSWD: ALL" | (EDITOR='tee -a' visudo) >/dev/null 2>&1
    log "INFO" "sudo password prompt for ${username} paused."
}

# Reverts the original /etc/sudoers file
function revertSudoers() {
    cp /etc/sudoers.bak /etc/sudoers && rm -f /etc/sudoers.bak
    log "INFO" "sudo password prompt restored."
}

# Configures firewalld and allows OpenSSH
function setupOpenSSH() {
    installPackageIfNeeded "openssh-server"
    sudo systemctl enable sshd
    sudo systemctl start sshd
    log "INFO" "OpenSSH installed."
}

# Adds an SSH key to a user's authorized keys
function addSSHKey() {
    local username=${1}
    local sshKey=${2}
    validateSSHKey "${sshKey}"
    execAsUser "${username}" "mkdir -p ~/.ssh; chmod 700 ~/.ssh; touch ~/.ssh/authorized_keys" || {
        log "ERROR" "Failed to create .ssh directory for user ${username}."
        exit 1
    }
    execAsUser "${username}" "echo \"${sshKey}\" | sudo tee -a ~/.ssh/authorized_keys" || {
        log "ERROR" "Failed to add SSH key for user ${username}."
        exit 1
    }
    execAsUser "${username}" "chmod 600 ~/.ssh/authorized_keys"
}

# Hardening SSH
function hardenSSH() {
    local ssh_port=${1:-22}
    local ssh_config="/etc/ssh/sshd_config"

    # Disable root login
    sudo sed -i '/^#?PermitRootLogin/s/.*/PermitRootLogin no/' "$ssh_config"

    # Disable password auth
    sudo sed -i '/^#?PasswordAuthentication/s/.*/PasswordAuthentication no/' "$ssh_config"

    # Only strong MAC
    sudo bash -c "echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> $ssh_config"
    sudo bash -c "echo 'MACs hmac-sha2-512,hmac-sha2-256' >> $ssh_config"

    # Only strong algo
    sudo bash -c "echo 'KexAlgorithms curve25519-sha256@libssh.org' >> $ssh_config"

    # Limit max sessions per user
    sudo bash -c "echo 'MaxSessions 2' >> $ssh_config"

    # Enforce a 5m timeout for inactive sessions
    sudo bash -c "echo 'ClientAliveInterval 300' >> $ssh_config"
    sudo bash -c "echo 'ClientAliveCountMax 2' >> $ssh_config"

    # Change default SSH port
    sudo sed -i '/^#?Port/s/.*/Port ${ssh_port}/' "$ssh_config"
}

# Enables EPEL for AlmaLinux
function setupEPEL() {
    if [[ "$distro" == "almalinux" ]]; then
        installPackageIfNeeded "epel-release"
        log "INFO" "EPEL enabled."
    fi
}

# Configures firewalld and allows OpenSSH
function setupFirewall() {
    installPackageIfNeeded "firewalld"
    systemctl enable firewalld
    systemctl start firewalld
    log "INFO" "Firewall installed."
}

# Configures firewalld and allows OpenSSH
function hardenFirewall() {
    local ssh_port=${1:-22}
    firewall-cmd --permanent --add-port="${ssh_port}"/tcp
    firewall-cmd --permanent --remove-service=ssh
    firewall-cmd --reload
    log "INFO" "Firewall configured to allow OpenSSH."
}

# Configures Fail2Ban
function setupFail2Ban() {
    setupEPEL # Required in AlmaLinux
    installPackageIfNeeded "fail2ban"
    systemctl enable fail2ban
    systemctl start fail2ban
    log "INFO" "Fail2Ban installed and started to protect against brute-force attacks."
}

# Harden Fail2Ban with custom SSH port
# Arguments:
#   SSH Port (Optional) - defaults to 22
function hardenFail2BanSSH() {
    local ssh_port=${1:-22}

    # Configure Fail2Ban to monitor the custom SSH port
    sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

    # Restart Fail2Ban to apply changes
    sudo systemctl restart fail2ban

    echo "Fail2Ban configured to monitor SSH on port ${ssh_port}."
}

# Configures NTP (Chrony) service for time synchronization
function configureNTP() {
    installPackageIfNeeded "chrony"
    systemctl enable chronyd
    systemctl start chronyd
    log "INFO" "NTP configured using Chrony."
}

# Sets the server's timezone
function setTimezone() {
    local timezone=${1}
    timezone=${timezone:-"UTC"}
    timedatectl set-timezone "${timezone}"
    log "INFO" "Timezone set to ${timezone}."
}

# Configure daily automatic security updates for supported distributions
function setupAutomaticSecurityUpdates() {
    # Configure for AlmaLinux
    if [[ "$distro" == "almalinux" ]]; then
        installPackageIfNeeded "dnf-automatic"
        configureDnfAutomatic
        systemctl enable --now dnf-automatic.timer
        log "INFO" "Automatic security updates enabled for AlmaLinux."

    # Configure for Ubuntu
    elif [[ "$distro" == "ubuntu" ]]; then
        installPackageIfNeeded "unattended-upgrades"
        configureUnattendedUpgrades
        log "INFO" "Automatic security updates enabled for Ubuntu."

    else
        log "ERROR" "Unsupported OS for automatic updates."
    fi
}

# Configure dnf-automatic for AlmaLinux
function configureDnfAutomatic() {
    sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
    sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    sed -i 's/^random_sleep.*/random_sleep = 0/' /etc/dnf/automatic.conf
}

# Configure unattended-upgrades for Ubuntu
function configureUnattendedUpgrades() {
    dpkg-reconfigure --priority=low unattended-upgrades
    {
        echo 'APT::Periodic::Update-Package-Lists "1";'
        echo 'APT::Periodic::Unattended-Upgrade "1";'
    } > /etc/apt/apt.conf.d/20auto-upgrades

    local distro_id=''
    local distro_codename=''
    distro_id=$(lsb_release -is)
    distro_codename=$(lsb_release -cs)

    echo "Unattended-Upgrade::Allowed-Origins {\"${distro_id}:${distro_codename}-security\";};" > /etc/apt/apt.conf.d/50unattended-upgrades
}


# Updates the system packages
function updateSystem() {
    log "INFO" "Updating system packages..."
    if [[ "$distro" == "ubuntu" ]]; then
        apt-get update -y && apt-get upgrade -y
    elif [[ "$distro" == "almalinux" ]]; then
        dnf upgrade -y
    fi
    log "INFO" "System packages updated."
}

# Clean up package cache
function cleanupPackageCache() {
    log "INFO" "Cleaning up package cache..."
    if [[ "$distro" == "ubuntu" ]]; then
        apt-get autoremove -y && apt-get clean
    elif [[ "$distro" == "almalinux" ]]; then
        dnf autoremove -y && dnf clean all
    fi
}

# Gets the total physical memory in GB
function getPhysicalMemory() {
    local phymem
    phymem=$(free -g | awk '/^Mem:/{print $2}')
    echo $(( phymem > 0 ? phymem : 1 ))
}

# Creates a swap file if not already present
function createSwap() {
    if [[ ! -f /swapfile ]]; then
        local swapmem=$(($(getPhysicalMemory) * 2))
        swapmem=$((swapmem > 4 ? 4 : swapmem))  # Limit to 4GB
        fallocate -l "${swapmem}G" /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo "Swap file of ${swapmem}GB created."
    else
        echo "Swap file already exists."
    fi
}

# Mounts the swap file by updating /etc/fstab
function mountSwap() {
    cp /etc/fstab /etc/fstab.bak
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
}

# Modify the swapfile settings
function tweakSwapSettings() {
    local swappiness=${1}
    local vfs_cache_pressure=${2}
    sysctl vm.swappiness="${swappiness}"
    sysctl vm.vfs_cache_pressure="${vfs_cache_pressure}"
}

# Save the modified swap settings
function saveSwapSettings() {
    local swappiness=${1}
    local vfs_cache_pressure=${2}
    echo "vm.swappiness=${swappiness}" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=${vfs_cache_pressure}" >> /etc/sysctl.conf
}



