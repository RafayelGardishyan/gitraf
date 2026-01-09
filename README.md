# gitraf

A CLI tool for managing git repositories on a self-hosted ogit server with Tailscale tailnet integration for access control.

## Features

- **Tailnet-aware access control** - Automatic detection of tailnet connection
- **SSH read/write access** - Full access when connected via tailnet
- **HTTPS read-only access** - Public repos accessible externally
- **Simple commands** - list, clone, create, delete, public, private, status

## Installation

Requires Go 1.21+

```bash
git clone https://git.rafayel.dev/gitraf.git
cd gitraf
./install.sh
```

Or manually:
```bash
git clone https://git.rafayel.dev/gitraf.git
cd gitraf
go build -o gitraf .
sudo mv gitraf /usr/local/bin/
```

## Updating

Update to the latest version (config is preserved):
```bash
gitraf update
```

## Configuration

Initialize with your server URLs:
```bash
gitraf config init <public_url> <tailnet_url>
```

Example:
```bash
gitraf config init https://git.example.com myserver.tail12345.ts.net
```

## Usage

```bash
# Check connection status
gitraf status

# List repositories
gitraf list

# Clone a repository (uses SSH on tailnet, HTTPS otherwise)
gitraf clone myrepo

# Show repository info
gitraf info myrepo

# Create a new repository (requires tailnet)
gitraf create myrepo

# Delete a repository (requires tailnet)
gitraf delete myrepo

# Make a repository public (requires tailnet)
gitraf public myrepo

# Make a repository private (requires tailnet)
gitraf private myrepo
```

## Access Model

| Location | Private Repos | Public Repos |
|----------|---------------|--------------|
| On tailnet | SSH read/write | SSH read/write |
| External | Not accessible | HTTPS read-only |

## Server Setup

This CLI is designed to work with an ogit server configured with:
- SSH access via tailnet (accepts any key from tailnet IPs)
- HTTPS access for public repos (read-only)
- nginx/caddy reverse proxy with push restrictions

See the server setup documentation for details on configuring your ogit instance.

## License

MIT
