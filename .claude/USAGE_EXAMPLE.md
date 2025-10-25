# How Claude Code Uses .claude/servers.json

This document shows how Claude Code will access server credentials from `.claude/servers.json` in future conversations.

## Example 1: Reading Server Configuration

**User asks:** "Deploy the latest changes to production"

**Claude Code does:**

```bash
# Read the server configuration
cat .claude/servers.json

# Extract credentials programmatically
python3 << 'EOF'
import json
with open('.claude/servers.json', 'r') as f:
    config = json.load(f)['hetzner_production']

print(f"Connecting to: {config['host']}")
print(f"Deployment path: {config['deployment_path']}")
print(f"MCP URL: {config['mcp_url']}")
EOF

# Create temp SSH key file
python3 << 'EOF'
import json
with open('.claude/servers.json', 'r') as f:
    key = json.load(f)['hetzner_production']['ssh_key']
with open('/tmp/deploy_key', 'w') as f:
    f.write(key)
EOF

chmod 600 /tmp/deploy_key

# SSH to server and deploy
ssh -i /tmp/deploy_key root@49.13.150.39 "cd /opt/google_workspace_mcp && git pull && systemctl restart workspace-mcp"

# Clean up
rm -f /tmp/deploy_key
```

## Example 2: Checking Server Status

**User asks:** "Is the MCP server healthy?"

**Claude Code does:**

```bash
# Read MCP URL from config
MCP_URL=$(python3 -c "import json; print(json.load(open('.claude/servers.json'))['hetzner_production']['mcp_url'])")

# Check health endpoint
curl -s "$MCP_URL/health"
```

## Example 3: Updating OAuth Credentials

**User says:** "Here are new OAuth credentials: CLIENT_ID=..., SECRET=..."

**Claude Code does:**

```bash
# Update the servers.json with new credentials
python3 << 'EOF'
import json

with open('.claude/servers.json', 'r') as f:
    config = json.load(f)

config['hetzner_production']['oauth_client_id'] = 'NEW_CLIENT_ID'
config['hetzner_production']['oauth_client_secret'] = 'NEW_SECRET'

with open('.claude/servers.json', 'w') as f:
    json.dump(config, f, indent=2)

print("✓ OAuth credentials updated in .claude/servers.json")
EOF

# Deploy to server
# ... (extract key, SSH, update .env.production, restart service)
```

## Example 4: Adding a New Server

**User asks:** "Add a staging server at staging.example.com"

**Claude Code does:**

```bash
python3 << 'EOF'
import json

with open('.claude/servers.json', 'r') as f:
    config = json.load(f)

config['staging'] = {
    "description": "Staging server for testing",
    "host": "staging.example.com",
    "user": "deploy",
    "ssh_key": "... (user provides) ...",
    "mcp_url": "https://staging-mcp.example.com",
    "deployment_path": "/opt/mcp-staging",
    "oauth_client_id": "...",
    "oauth_client_secret": "..."
}

with open('.claude/servers.json', 'w') as f:
    json.dump(config, f, indent=2)

print("✓ Added staging server to configuration")
EOF
```

## Benefits

### 1. **No Secrets in Chat History**
Server credentials are read from the file system, not provided in every conversation.

### 2. **Persistent Configuration**
Credentials persist across Claude Code sessions without needing to re-enter them.

### 3. **Never Committed to Git**
The `.claude/*` pattern in `.gitignore` ensures secrets stay local.

### 4. **Easy to Update**
Single source of truth for all server configurations.

### 5. **Multiple Environments**
Easily manage dev, staging, and production servers in one file.

## Security Notes

- File has `600` permissions (owner read/write only)
- Entire `.claude/*` directory is in `.gitignore`
- SSH keys are never echoed to console in logs
- OAuth secrets are redacted in server logs
- Template file (without secrets) is safe to commit

## When Claude Code Might Ask You

Claude Code will ask you to provide credentials when:

1. `.claude/servers.json` doesn't exist yet
2. A specific server is not configured
3. Credentials need to be rotated
4. Adding a new deployment environment

Otherwise, Claude Code will quietly read from `.claude/servers.json` as needed.
