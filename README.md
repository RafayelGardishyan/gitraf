# gitraf

A CLI tool for managing git repositories on a self-hosted ogit server with Tailscale tailnet integration for access control.

## Features

- **Tailnet-aware access control** - Automatic detection of tailnet connection
- **SSH read/write access** - Full access when connected via tailnet
- **HTTPS read-only access** - Public repos accessible externally
- **Static site hosting** - Deploy sites from repos to `{repo}.rafayel.dev`
- **Git LFS support** - S3-compatible storage for large files
- **Simple commands** - list, clone, create, delete, public, private, pages, lfs

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

## Static Site Hosting (Pages)

Deploy static sites from git repositories. Sites are served at `{repo-name}.rafayel.dev`.

```bash
# Enable pages for a repository
gitraf pages enable mysite
# Prompts for: branch, build command, output directory

# List all pages-enabled repos
gitraf pages list

# Check status of a pages site
gitraf pages status mysite

# Force deploy (re-run build)
gitraf pages deploy mysite

# Disable pages
gitraf pages disable mysite
```

### Pages Configuration

When enabling pages, you can configure:
- **Branch**: Which branch to deploy from (default: `main`)
- **Build command**: Optional command like `npm run build` (leave empty for static files)
- **Output directory**: Where the built site is (default: `public`)

### Deployment Flow

1. Push to the configured branch
2. The post-receive hook runs your build command (if configured)
3. Contents of the output directory are deployed to `{repo}.rafayel.dev`

### Example: Static Site

```bash
# Create repo with public/ directory
gitraf create my-blog
gitraf pages enable my-blog
# Branch: main, Build: (empty), Output: public

# Push your static files
git clone git@server:my-blog.git
cd my-blog
mkdir public
echo "<h1>Hello World</h1>" > public/index.html
git add . && git commit -m "Initial site"
git push origin main

# Site is now live at https://my-blog.rafayel.dev
```

### Example: Build with npm

```bash
gitraf pages enable my-vite-app
# Branch: main
# Build: npm run build
# Output: dist

# Push triggers: npm install → npm run build → deploy dist/
```

## Git LFS

Configure Git LFS with S3-compatible storage (AWS S3, Cloudflare R2, etc.):

```bash
# Interactive setup
gitraf lfs setup

# Check LFS status
gitraf lfs status
```

Note: Files over 10MB are rejected unless tracked by LFS.

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
