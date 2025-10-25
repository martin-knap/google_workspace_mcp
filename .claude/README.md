# .claude Directory

This directory contains Claude Code specific configuration and credentials that should **never be committed to git**.

## Files in this directory

### `servers.json` (NOT committed - in .gitignore)
Contains sensitive server credentials including:
- SSH keys
- Server addresses
- OAuth credentials
- Deployment paths

**Security:** This file has `600` permissions (read/write for owner only).

### `servers.json.template` (CAN be committed)
A template showing the structure for `servers.json`. Copy this to `servers.json` and fill in your actual credentials.

### `settings.local.json`
Claude Code local settings (automatically managed by Claude Code).

## Setup Instructions

1. **Copy the template:**
   ```bash
   cp .claude/servers.json.template .claude/servers.json
   ```

2. **Edit with your credentials:**
   ```bash
   # Use your preferred editor
   code .claude/servers.json
   # or
   vim .claude/servers.json
   ```

3. **Set secure permissions:**
   ```bash
   chmod 600 .claude/servers.json
   ```

4. **Verify it's not tracked by git:**
   ```bash
   git status .claude/servers.json
   # Should show nothing (file is ignored)
   ```

## How Claude Code Uses This

When you ask Claude Code to deploy or manage your servers, it will:

1. Read `servers.json` to get credentials
2. Use the SSH key to connect to the server
3. Access OAuth credentials for MCP server configuration
4. Reference the deployment path for updates

## Security Best Practices

- ✅ **Never** commit `servers.json` to git
- ✅ Keep file permissions at `600` (owner read/write only)
- ✅ Use different SSH keys for different environments (dev/staging/prod)
- ✅ Rotate OAuth credentials periodically
- ✅ Use SSH key passphrases when possible
- ❌ **Never** share this file or paste contents in public channels

## Adding a New Server

Add a new entry to `servers.json`:

```json
{
  "existing_server": { ... },
  "new_server": {
    "description": "New staging server",
    "host": "staging.example.com",
    "user": "deploy",
    "ssh_key": "...",
    "mcp_url": "https://staging-mcp.example.com",
    "deployment_path": "/opt/mcp",
    "oauth_client_id": "...",
    "oauth_client_secret": "..."
  }
}
```

## Backup Recommendations

Since this file is not in git, you should back it up securely:

1. **Password manager:** Store in 1Password, Bitwarden, etc.
2. **Encrypted backup:** Use `gpg` to encrypt before backing up
3. **Secure cloud storage:** Store in encrypted cloud storage

Example encrypted backup:
```bash
# Encrypt
gpg -c .claude/servers.json
# Creates: .claude/servers.json.gpg (safe to store in cloud)

# Decrypt
gpg .claude/servers.json.gpg
```
