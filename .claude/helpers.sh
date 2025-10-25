#!/bin/bash
# Helper script for extracting server credentials
# Usage: source .claude/helpers.sh

SERVERS_FILE=".claude/servers.json"

# Function to extract SSH key and save to temp file
get_ssh_key() {
    local server_name="${1:-hetzner_production}"
    local key_file="/tmp/${server_name}_key"

    python3 << EOF
import json
with open('$SERVERS_FILE', 'r') as f:
    servers = json.load(f)
    key = servers['$server_name']['ssh_key']
    with open('$key_file', 'w') as kf:
        kf.write(key)
EOF

    chmod 600 "$key_file"
    echo "$key_file"
}

# Function to get server host
get_host() {
    local server_name="${1:-hetzner_production}"
    python3 -c "import json; print(json.load(open('$SERVERS_FILE'))['$server_name']['host'])"
}

# Function to get server user
get_user() {
    local server_name="${1:-hetzner_production}"
    python3 -c "import json; print(json.load(open('$SERVERS_FILE'))['$server_name']['user'])"
}

# Function to SSH into server
ssh_server() {
    local server_name="${1:-hetzner_production}"
    local key_file=$(get_ssh_key "$server_name")
    local host=$(get_host "$server_name")
    local user=$(get_user "$server_name")

    ssh -i "$key_file" "${user}@${host}" "${@:2}"
    rm -f "$key_file"
}

# Function to get OAuth credentials
get_oauth() {
    local server_name="${1:-hetzner_production}"
    python3 << EOF
import json
with open('$SERVERS_FILE', 'r') as f:
    servers = json.load(f)
    server = servers['$server_name']
    print(f"Client ID: {server['oauth_client_id']}")
    print(f"Client Secret: {server['oauth_client_secret']}")
EOF
}

# Example usage:
# ssh_server hetzner_production "systemctl status workspace-mcp"
# get_oauth hetzner_production
