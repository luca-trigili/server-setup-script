#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Global Variables
output_file="output.log"
current_dir=""

# Get the current directory of the script
function getCurrentDir() {
    local current_dir="${BASH_SOURCE%/*}"
    [[ ! -d "${current_dir}" ]] && current_dir="$PWD"
    echo "${current_dir}"
}

# Include external functions from setupLibrary.sh
function includeDependencies() {
    source "${current_dir}/setupLibrary.sh"
}

current_dir=$(getCurrentDir)
includeDependencies

# Main function to control the setup process
function main() {
    checkRootPermission
    detectDistro

    read -rp "Enter username for a new account or an existing username to update: " username
    updateOrCreateUser "${username}"
    disableSudoPromptPassword "${username}"

    # Firewall, SSH, and security configurations
    read -rp $'Paste the public SSH key for the new user:\n' sshKey
    read -rp $'Choose a port for SSH (default 22):\n' sshPort
    log "INFO" "Configuring user and SSH..."
    setupOpenSSH
    addSSHKey "${username}" "${sshKey}"
    hardenSSH "${sshPort}"
    setupFirewall
    hardenFirewall "${sshPort}"
    setupFail2Ban
    hardenFail2BanSSH "${sshPort}"

    # Check for swap and create if necessary
    if ! hasSwap; then
        createSwap
        mountSwap
        tweakSwapSettings "10" "50"
        saveSwapSettings "10" "50"
    fi

    # Set the timezone for the server
    read -rp "Enter the timezone for the server (e.g., Europe/Rome, default is UTC): " timezone
    setTimezone "${timezone}"

    log "INFO" "Configuring NTP..."
    configureNTP
    setupAutomaticSecurityUpdates
    updateSystem

    sudo systemctl restart sshd
    cleanupPackageCache
    log "INFO" "Setup complete! Log file is located at ${output_file}"
}

# Check if a swap file already exists
function hasSwap() {
    [[ "$(sudo swapon -s)" == *"/swapfile"* ]]
}

# Cleanup function to revert sudoers if necessary
function cleanup() {
    if [[ -f "/etc/sudoers.bak" ]]; then
        revertSudoers
    fi
}

# Execute the main function
main