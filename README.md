# Bash setup script for servers

This is a setup script to automate the setup and provisioning of Ubuntu/AlmaLinux servers. It does the following:
* Adds or updates a user account with sudo access
* Disables password authentication to the server
* Deny root login to the server
* Setup OpenSSH package
* Adds a public ssh key for the new user account 
* Harden SSH 
* Setup Firewall (firewalld)
* Harden Firewall to allow SSH
* Setup Fail2Ban 
* Harden Fail2Ban to protect SSH
* Create Swap file based on machine's installed memory
* Set up the timezone for the server (Default to "UTC")
* Install Network Time Protocol

# Installation
SSH into your server and install git if it is not installed:
```bash
sudo apt-get update
sudo apt-get install git
```

Clone this repository into your home directory:
```bash
cd ~
git clone https://github.com/luca-trigili/server-setup-script.git
```

Run the setup script
```bash
cd server-setup-script
bash setup.sh
```

# Setup prompts
When the setup script is run, you will be prompted to enter the username of the new user account. 

Following that, you will then be prompted to add a public ssh key (which should be from your local machine) for the new account. To generate an ssh key from your local machine:
```bash
ssh-keygen -t ed25519 -a 200 -C "user@server" -f ~/.ssh/user_server_ed25519
cat ~/.ssh/user_server_ed25519.pub
```

Finally, you will be prompted to specify a [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) for the server. It will be set to 'UTC' if you do not specify a value.

# Supported versions
This setup script has been tested against AlmaLinux 9, please report if you test on other distro.

# Credits

Based on https://github.com/jasonheecs/ubuntu-server-setup.git
