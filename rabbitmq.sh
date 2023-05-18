#!/bin/sh

set -e

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root or using sudo."
    exit 1
fi

# Check for required dependencies and install if necessary
check_dependency() {
    local command_name="$1"
    local package_name="$2"
    if ! command -v "$command_name" &> /dev/null; then
        echo "$command_name not found, installing..."
        apt-get update
        apt-get install -y "$package_name"
    fi
}

check_dependency curl curl
check_dependency gnupg gnupg
check_dependency dpkg apt-transport-https

# Team RabbitMQ's main signing key
import_gpg_key() {
    local key_id="$1"
    local keyring_path="$2"
    local key_url="$3"
    if ! gpg --list-keys "$key_id" &> /dev/null; then
        echo "Importing GPG key $key_id..."
        curl -1sLf "$key_url" | gpg --dearmor | tee "$keyring_path" > /dev/null
    fi
}

import_gpg_key 0A9AF2115F4687BD29803A206B73A36E6026DFCA /usr/share/keyrings/com.rabbitmq.team.gpg "https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA"
import_gpg_key 0xf77f1eda57ebb1cc /usr/share/keyrings/net.launchpad.ppa.rabbitmq.erlang.gpg "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xf77f1eda57ebb1cc"
import_gpg_key io.packagecloud.rabbitmq /usr/share/keyrings/io.packagecloud.rabbitmq.gpg "https://packagecloud.io/rabbitmq/rabbitmq-server/gpgkey"

# Add apt repositories maintained by Team RabbitMQ
rabbitmq_repository="/etc/apt/sources.list.d/rabbitmq.list"
if [ ! -f "$rabbitmq_repository" ]; then
    echo "Adding RabbitMQ apt repositories..."
    cat << EOF > "$rabbitmq_repository"
## Provides modern Erlang/OTP releases
##
## "bionic" as distribution name should work for any reasonably recent Ubuntu or Debian release.
## See the release to distribution mapping table in RabbitMQ doc guides to learn more.
deb [signed-by=/usr/share/keyrings/net.launchpad.ppa.rabbitmq.erlang.gpg] http://ppa.launchpad.net/rabbitmq/rabbitmq-erlang/ubuntu bionic main
deb-src [signed-by=/usr/share/keyrings/net.launchpad.ppa.rabbitmq.erlang.gpg] http://ppa.launchpad.net/rabbitmq/rabbitmq-erlang/ubuntu bionic main

## Provides RabbitMQ
##
## "bionic" as distribution name should work for any reasonably recent Ubuntu or Debian release.
## See the release to distribution mapping table in RabbitMQ doc guides to learn more.
deb [signed-by=/usr/share/keyrings/io.packagecloud.rabbitmq.gpg] https://packagecloud.io/rabbitmq/rabbitmq-server/ubuntu/ bionic main
deb-src [signed-by=/usr/share/keyrings/io.packagecloud.rabbitmq.gpg] https://packagecloud.io/rabbitmq/rabbitmq-server/ubuntu/ bionic main
EOF
    apt-get update
fi

# Install Erlang packages
install_erlang_packages() {
    local packages=("erlang-base" "erlang-asn1" "erlang-crypto" "erlang-eldap"
                    "erlang-inets" "erlang-mnesia" "erlang-os-mon" "erlang-parsetools" "erlang-public-key"
                    "erlang-runtime-tools" "erlang-snmp" "erlang-ssl"
                    "erlang-syntax-tools" "erlang-tftp" "erlang-tools" "erlang-xmerl")
    local packages_to_install=()
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null; then
            packages_to_install+=("$package")
        fi
    done
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        echo "Installing Erlang packages..."
        apt-get install -y "${packages_to_install[@]}"
    fi
}

install_erlang_packages

# Install RabbitMQ server
if ! dpkg -s rabbitmq-server &> /dev/null; then
    echo "Installing RabbitMQ server..."
    apt-get install -y rabbitmq-server --fix-missing
fi

# Download and install rabbitmq_delayed_message_exchange plugin
rabbitmq_delayed_plugin_path="/usr/lib/rabbitmq/lib/rabbitmq_server-$(rabbitmqctl status | awk '/RabbitMQ version/ {print $3}' | sed 's/,//')/plugins/rabbitmq_delayed_message_exchange-3.11.1.ez"
if [ ! -f "$rabbitmq_delayed_plugin_path" ]; then
    echo "Downloading and installing rabbitmq_delayed_message_exchange plugin..."
    curl -L -o "$rabbitmq_delayed_plugin_path" "https://github.com/rabbitmq/rabbitmq-delayed-message-exchange/releases/download/3.11.1/rabbitmq_delayed_message_exchange-3.11.1.ez"
fi

# Enable RabbitMQ plugins
echo "Enabling RabbitMQ plugins..."
rabbitmq-plugins enable rabbitmq_management rabbitmq_prometheus rabbitmq_delayed_message_exchange

# Set RabbitMQ policy for high availability
echo "Setting RabbitMQ policy for high availability..."
rabbitmqctl set_policy ha-all "." '{"ha-mode":"all"}'

# Delete default guest user and add new operatorrmq user with administrator tag and permissions
echo "Deleting default guest user and adding new operatorrmq user with administrator tag and permissions..."
rabbitmqctl delete_user guest || true
rabbitmqctl add_user operatorrmq Passw0rdPassw0rd
rabbitmqctl set_user_tags operatorrmq administrator
rabbitmqctl set_permissions -p / operatorrmq ".*" ".*" ".*"

# Install openssh-server package
echo "Installing openssh-server package..."
apt-get install -y openssh-server

# Configure ufw firewall
echo "Configuring ufw firewall..."
ufw allow ssh
ufw allow proto tcp from any to any port 5672,15672,15692,4369,25672/tcp
ufw --force enable

echo "Installation completed successfully."
