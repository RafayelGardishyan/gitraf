package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	configDir string
)

const (
	defaultPublicURL  = ""
	defaultTailnetURL = ""
	defaultSSHUser    = "git"
)

// Config represents the gitraf configuration
type Config struct {
	PublicURL  string `json:"public_url"`
	TailnetURL string `json:"tailnet_url"`
	SSHUser    string `json:"ssh_user"`
}

// loadConfig loads the configuration from disk
func loadConfig() Config {
	cfg := Config{
		PublicURL:  defaultPublicURL,
		TailnetURL: defaultTailnetURL,
		SSHUser:    defaultSSHUser,
	}

	configFile := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg
	}

	// Try new format first
	if err := json.Unmarshal(data, &cfg); err == nil {
		if cfg.PublicURL == "" {
			cfg.PublicURL = defaultPublicURL
		}
		if cfg.TailnetURL == "" {
			cfg.TailnetURL = defaultTailnetURL
		}
		if cfg.SSHUser == "" {
			cfg.SSHUser = defaultSSHUser
		}
		return cfg
	}

	// Fallback to old format (single "server" key)
	var oldCfg map[string]string
	if err := json.Unmarshal(data, &oldCfg); err == nil {
		if server, ok := oldCfg["server"]; ok && server != "" {
			cfg.PublicURL = server
		}
	}

	return cfg
}

// saveConfig saves the configuration to disk
func saveConfig(cfg Config) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := filepath.Join(configDir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// isCGNATAddress checks if an IP is in the Tailscale CGNAT range (100.64.0.0/10)
func isCGNATAddress(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 100.64.0.0/10 = 100.64.0.0 - 100.127.255.255
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

// hasTailscaleInterface checks if there's a network interface with a Tailscale CGNAT IP
func hasTailscaleInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && isCGNATAddress(ip) {
				return true
			}
		}
	}
	return false
}

// canReachTailnetHost checks if we can reach the tailnet host
func canReachTailnetHost(host string) bool {
	conn, err := net.DialTimeout("tcp", host+":22", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isTailnetConnected checks if the user is connected to the tailnet
func isTailnetConnected() bool {
	// Method 1: Check for interface with CGNAT IP (fastest)
	if hasTailscaleInterface() {
		return true
	}

	// Method 2: Try to reach the tailnet host (fallback)
	cfg := loadConfig()
	if cfg.TailnetURL != "" {
		return canReachTailnetHost(cfg.TailnetURL)
	}

	return false
}

// requireTailnet returns an error if not connected to tailnet
func requireTailnet() error {
	if !isTailnetConnected() {
		return fmt.Errorf("this operation requires a tailnet connection\n\nConnect with: tailscale up")
	}
	return nil
}

// getSSHHost returns the appropriate SSH host based on network status
func getSSHHost() string {
	cfg := loadConfig()
	if isTailnetConnected() && cfg.TailnetURL != "" {
		return cfg.TailnetURL
	}
	return getHostFromURL(cfg.PublicURL)
}

// getHTTPSURL returns the public HTTPS URL
func getHTTPSURL() string {
	cfg := loadConfig()
	url := strings.TrimSuffix(cfg.PublicURL, "/")
	// Ensure https:// prefix
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return url
}

func main() {
	home, _ := os.UserHomeDir()
	configDir = filepath.Join(home, ".config", "gitraf")

	rootCmd := &cobra.Command{
		Use:   "gitraf",
		Short: "CLI tool for managing git repositories on ogit server",
		Long: `gitraf is a command-line tool for managing git repositories
on your self-hosted ogit git server.

Examples:
  gitraf list                    # List all repositories
  gitraf create my-project       # Create a new repository
  gitraf clone my-project        # Clone a repository
  gitraf delete my-project       # Delete a repository
  gitraf info my-project         # Show repository info`,
	}

	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", "", "Git server URL (default: from config or https://git.rafayel.dev)")

	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(createCmd())
	rootCmd.AddCommand(deleteCmd())
	rootCmd.AddCommand(publicCmd())
	rootCmd.AddCommand(privateCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(authCmd())
	rootCmd.AddCommand(cloneCmd())
	rootCmd.AddCommand(infoCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(lfsCmd())
	rootCmd.AddCommand(pagesCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getServerURL() string {
	if serverURL != "" {
		return strings.TrimSuffix(serverURL, "/")
	}
	return getHTTPSURL()
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all repositories",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			onTailnet := isTailnetConnected()

			// Use tailnet URL if connected (can see all repos)
			var apiURL string
			if onTailnet {
				apiURL = "http://" + cfg.TailnetURL
			} else {
				apiURL = cfg.PublicURL
			}

			resp, err := http.Get(apiURL + "/api/repos")
			if err != nil {
				return fmt.Errorf("failed to connect to server: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
			}

			var repos []string
			if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
				return fmt.Errorf("failed to parse response: %w", err)
			}

			if len(repos) == 0 {
				fmt.Println("No repositories found.")
				return nil
			}

			if onTailnet {
				fmt.Println("Repositories (connected via tailnet - showing all):\n")
			} else {
				fmt.Println("Repositories (public only - connect to tailnet for all):\n")
			}

			httpsURL := getHTTPSURL()
			for _, repo := range repos {
				name := strings.TrimSuffix(repo, ".git")
				fmt.Printf("  %s\n", name)
				if onTailnet {
					fmt.Printf("    SSH (R/W):   git@%s:%s.git\n", cfg.TailnetURL, name)
				}
				fmt.Printf("    HTTPS (R):   %s/%s.git\n", httpsURL, name)
			}
			fmt.Printf("\nTotal: %d repositories\n", len(repos))
			return nil
		},
	}
}

func createCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			cfg := loadConfig()
			host := getSSHHost()

			// Create bare repo via SSH
			createScript := fmt.Sprintf(`
sudo mkdir -p /opt/ogit/data/repos/%s.git && \
cd /opt/ogit/data/repos/%s.git && \
sudo git init --bare && \
sudo chown -R git:git /opt/ogit/data/repos/%s.git
`, name, name, name)

			sshCmd := exec.Command("ssh", host, createScript)
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to create repository: %w", err)
			}

			fmt.Printf("Repository '%s' created successfully.\n\n", name)
			fmt.Println("Clone with SSH (on tailnet):")
			fmt.Printf("  git clone git@%s:%s.git\n", cfg.TailnetURL, name)
			return nil
		},
	}
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a repository via SSH",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			fmt.Printf("Warning: This will permanently delete repository '%s' on host '%s'.\n", name, host)
			fmt.Print("Are you sure you want to continue? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(input)) != "y" {
				fmt.Println("Aborted.")
				return nil
			}

			// 1. Delete the directory
			rmCmd := exec.Command("ssh", host, fmt.Sprintf("sudo rm -rf /opt/ogit/data/repos/%s.git", name))
			rmCmd.Stdout = os.Stdout
			rmCmd.Stderr = os.Stderr
			if err := rmCmd.Run(); err != nil {
				return fmt.Errorf("failed to delete repository directory: %w", err)
			}

			// 2. Restart ogit
			restartCmd := exec.Command("ssh", host, "cd /opt/ogit && sudo docker compose restart")
			restartCmd.Stdout = os.Stdout
			restartCmd.Stderr = os.Stderr
			if err := restartCmd.Run(); err != nil {
				return fmt.Errorf("failed to restart ogit: %w", err)
			}

			fmt.Printf("Repository '%s' deleted successfully.\n", name)
			return nil
		},
	}
}

func publicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "public <repo>",
		Short: "Mark a repository as public (visible externally, but read-only outside tailnet)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			sshCmd := exec.Command("ssh", host, fmt.Sprintf("sudo touch /opt/ogit/data/repos/%s.git/git-daemon-export-ok", name))
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to mark repository as public: %w", err)
			}

			cfg := loadConfig()
			fmt.Printf("Repository '%s' is now public.\n", name)
			fmt.Printf("  External (read-only): %s/%s.git\n", cfg.PublicURL, name)
			fmt.Printf("  Tailnet (read/write): git@%s:%s.git\n", cfg.TailnetURL, name)
			return nil
		},
	}
}

func privateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "private <repo>",
		Short: "Mark a repository as private (only accessible via tailnet)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			sshCmd := exec.Command("ssh", host, fmt.Sprintf("sudo rm -f /opt/ogit/data/repos/%s.git/git-daemon-export-ok", name))
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to mark repository as private: %w", err)
			}

			cfg := loadConfig()
			fmt.Printf("Repository '%s' is now private.\n", name)
			fmt.Printf("Only accessible via tailnet: git@%s:%s.git\n", cfg.TailnetURL, name)
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show network status and available operations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			onTailnet := isTailnetConnected()

			fmt.Println("gitraf Network Status")
			fmt.Println("=====================")
			fmt.Printf("Public URL:  %s\n", cfg.PublicURL)
			fmt.Printf("Tailnet URL: %s\n", cfg.TailnetURL)
			fmt.Println()

			if onTailnet {
				fmt.Println("Status: CONNECTED to tailnet")
				fmt.Println()
				fmt.Println("Available operations:")
				fmt.Println("  - List all repositories (public + private)")
				fmt.Println("  - Clone any repository via SSH")
				fmt.Println("  - Push to any repository")
				fmt.Println("  - Create/delete repositories")
				fmt.Println("  - Change repository visibility (public/private)")
			} else {
				fmt.Println("Status: NOT connected to tailnet")
				fmt.Println()
				fmt.Println("Available operations:")
				fmt.Println("  - List public repositories only")
				fmt.Println("  - Clone public repositories (read-only via HTTPS)")
				fmt.Println()
				fmt.Println("To enable full access, connect to tailnet:")
				fmt.Println("  tailscale up")
			}

			return nil
		},
	}
}

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}

	addKeyCmd := &cobra.Command{
		Use:   "add-key [public-key-path]",
		Short: "Add an SSH public key for external (non-tailnet) authentication",
		Long: `Add an SSH public key for authentication from outside the tailnet.

Note: When connected via tailnet, any SSH key is accepted automatically.
This command is for adding keys that work from external networks.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			keyPath := ""
			if len(args) > 0 {
				keyPath = args[0]
			} else {
				home, _ := os.UserHomeDir()
				keyPath = filepath.Join(home, ".ssh", "id_rsa.pub")
				if _, err := os.Stat(keyPath); os.IsNotExist(err) {
					keyPath = filepath.Join(home, ".ssh", "id_ed25519.pub")
				}
			}

			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("failed to read public key: %w", err)
			}

			host := getSSHHost()

			fmt.Printf("Adding key from %s to %s...\n", keyPath, host)

			sshCmd := exec.Command("ssh", host, fmt.Sprintf("sudo bash -c 'mkdir -p /home/git/.ssh && echo \"%s\" >> /home/git/.ssh/authorized_keys && chown -R git:git /home/git/.ssh && chmod 700 /home/git/.ssh && chmod 600 /home/git/.ssh/authorized_keys'", strings.TrimSpace(string(keyData))))
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr

			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to add key: %w", err)
			}

			fmt.Println("Key added successfully for external access.")
			return nil
		},
	}

	cmd.AddCommand(addKeyCmd)
	return cmd
}

func cloneCmd() *cobra.Command {
	var destDir string
	var forceHTTPS bool

	cmd := &cobra.Command{
		Use:   "clone <name> [destination]",
		Short: "Clone a repository",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg := loadConfig()
			onTailnet := isTailnetConnected()

			dest := name
			if len(args) > 1 {
				dest = args[1]
			}
			if destDir != "" {
				dest = filepath.Join(destDir, dest)
			}

			var repoURL string
			var canWrite bool

			if onTailnet && !forceHTTPS {
				// Use SSH for full access on tailnet
				repoURL = fmt.Sprintf("git@%s:%s.git", cfg.TailnetURL, name)
				canWrite = true
				fmt.Println("Cloning via SSH (read/write access)...")
			} else {
				// Use HTTPS (read-only)
				repoURL = fmt.Sprintf("%s/%s.git", cfg.PublicURL, name)
				canWrite = false
				fmt.Println("Cloning via HTTPS (read-only access)...")
				if !onTailnet {
					fmt.Println("Note: Connect to tailnet for write access.")
				}
			}

			fmt.Printf("Cloning %s into %s...\n", repoURL, dest)

			gitCmd := exec.Command("git", "clone", repoURL, dest)
			gitCmd.Stdout = os.Stdout
			gitCmd.Stderr = os.Stderr
			gitCmd.Stdin = os.Stdin

			if err := gitCmd.Run(); err != nil {
				// If SSH failed on tailnet, try HTTPS as fallback
				if onTailnet && !forceHTTPS {
					fmt.Println("SSH clone failed, trying HTTPS...")
					repoURL = fmt.Sprintf("%s/%s.git", cfg.PublicURL, name)
					gitCmd = exec.Command("git", "clone", repoURL, dest)
					gitCmd.Stdout = os.Stdout
					gitCmd.Stderr = os.Stderr
					gitCmd.Stdin = os.Stdin
					if err := gitCmd.Run(); err != nil {
						return fmt.Errorf("git clone failed: %w", err)
					}
					canWrite = false
				} else {
					return fmt.Errorf("git clone failed: %w", err)
				}
			}

			fmt.Printf("\nCloned successfully into %s\n", dest)
			if !canWrite {
				fmt.Println("(Read-only clone - connect to tailnet to push changes)")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&destDir, "dir", "d", "", "Parent directory for clone")
	cmd.Flags().BoolVar(&forceHTTPS, "https", false, "Force HTTPS clone (read-only)")
	return cmd
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <name>",
		Short: "Show repository information",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg := loadConfig()
			onTailnet := isTailnetConnected()

			// Check if repo exists by trying to access it
			var checkURL string
			if onTailnet {
				checkURL = "http://" + cfg.TailnetURL
			} else {
				checkURL = cfg.PublicURL
			}

			repoURL := fmt.Sprintf("%s/%s.git", checkURL, name)
			resp, err := http.Get(repoURL + "/info/refs?service=git-upload-pack")
			if err != nil {
				return fmt.Errorf("failed to connect to server: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				if !onTailnet {
					return fmt.Errorf("repository '%s' not found (note: private repos require tailnet)", name)
				}
				return fmt.Errorf("repository '%s' not found", name)
			}

			fmt.Printf("Repository: %s\n\n", name)

			if onTailnet {
				fmt.Println("SSH (read/write, tailnet):")
				fmt.Printf("  git@%s:%s.git\n\n", cfg.TailnetURL, name)
			}

			fmt.Println("HTTPS (read-only):")
			fmt.Printf("  %s/%s.git\n\n", cfg.PublicURL, name)

			fmt.Println("Clone command:")
			if onTailnet {
				fmt.Printf("  git clone git@%s:%s.git\n", cfg.TailnetURL, name)
			} else {
				fmt.Printf("  git clone %s/%s.git  (read-only)\n", cfg.PublicURL, name)
			}
			return nil
		},
	}
}

func getHostFromURL(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}
	return u.Hostname()
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage gitraf configuration",
	}

	setCmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: `Set a configuration value. Available keys:
  public_url   - Public HTTPS URL (e.g., https://git.example.com)
  tailnet_url  - Tailnet hostname (e.g., myserver.tail12345.ts.net)
  ssh_user     - SSH user for git operations (default: git)`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			cfg := loadConfig()

			switch key {
			case "public_url":
				cfg.PublicURL = value
			case "tailnet_url":
				cfg.TailnetURL = value
			case "ssh_user":
				cfg.SSHUser = value
			default:
				return fmt.Errorf("unknown config key: %s (available: public_url, tailnet_url, ssh_user)", key)
			}

			if err := saveConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("Set %s = %s\n", key, value)
			return nil
		},
	}

	getCmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			cfg := loadConfig()

			switch key {
			case "public_url":
				fmt.Println(cfg.PublicURL)
			case "tailnet_url":
				fmt.Println(cfg.TailnetURL)
			case "ssh_user":
				fmt.Println(cfg.SSHUser)
			default:
				return fmt.Errorf("unknown config key: %s (available: public_url, tailnet_url, ssh_user)", key)
			}
			return nil
		},
	}

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show all configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			onTailnet := isTailnetConnected()

			fmt.Println("Configuration:")
			fmt.Printf("  public_url:  %s\n", cfg.PublicURL)
			fmt.Printf("  tailnet_url: %s\n", cfg.TailnetURL)
			fmt.Printf("  ssh_user:    %s\n", cfg.SSHUser)
			fmt.Println()
			if onTailnet {
				fmt.Println("Network: Connected to tailnet")
			} else {
				fmt.Println("Network: Not connected to tailnet")
			}
			return nil
		},
	}

	initCmd := &cobra.Command{
		Use:   "init <public_url> <tailnet_url>",
		Short: "Initialize configuration with your server URLs",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := Config{
				PublicURL:  args[0],
				TailnetURL: args[1],
				SSHUser:    defaultSSHUser,
			}

			if err := saveConfig(cfg); err != nil {
				return err
			}

			fmt.Println("Configuration initialized:")
			fmt.Printf("  public_url:  %s\n", cfg.PublicURL)
			fmt.Printf("  tailnet_url: %s\n", cfg.TailnetURL)
			fmt.Printf("  ssh_user:    %s\n", cfg.SSHUser)
			return nil
		},
	}

	cmd.AddCommand(setCmd, getCmd, showCmd, initCmd)
	return cmd
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update gitraf to the latest version",
		Long: `Update gitraf to the latest version from the git repository.
This will download, build, and install the latest version.
Your configuration will NOT be affected.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for Go
			if _, err := exec.LookPath("go"); err != nil {
				return fmt.Errorf("Go is required for updates. Install from https://go.dev/doc/install")
			}

			// Get current binary path
			execPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get executable path: %w", err)
			}
			execPath, err = filepath.EvalSymlinks(execPath)
			if err != nil {
				return fmt.Errorf("failed to resolve executable path: %w", err)
			}

			fmt.Println("Updating gitraf...")
			fmt.Printf("Binary location: %s\n", execPath)

			// Create temp directory
			tmpDir, err := os.MkdirTemp("", "gitraf-update-")
			if err != nil {
				return fmt.Errorf("failed to create temp directory: %w", err)
			}
			defer os.RemoveAll(tmpDir)

			// Clone the repo
			fmt.Println("Downloading latest version...")
			cfg := loadConfig()
			publicURL := cfg.PublicURL
			if publicURL == "" {
				publicURL = "https://git.rafayel.dev"
			}
			// Ensure https:// prefix
			if !strings.HasPrefix(publicURL, "http://") && !strings.HasPrefix(publicURL, "https://") {
				publicURL = "https://" + publicURL
			}
			repoURL := publicURL + "/gitraf.git"

			cloneCmd := exec.Command("git", "clone", "--quiet", repoURL, filepath.Join(tmpDir, "gitraf"))
			cloneCmd.Stdout = os.Stdout
			cloneCmd.Stderr = os.Stderr
			if err := cloneCmd.Run(); err != nil {
				return fmt.Errorf("failed to clone repository: %w", err)
			}

			// Build
			fmt.Println("Building...")
			buildCmd := exec.Command("go", "build", "-o", "gitraf", ".")
			buildCmd.Dir = filepath.Join(tmpDir, "gitraf")
			buildCmd.Stdout = os.Stdout
			buildCmd.Stderr = os.Stderr
			if err := buildCmd.Run(); err != nil {
				return fmt.Errorf("failed to build: %w", err)
			}

			// Replace binary
			fmt.Println("Installing...")
			newBinary := filepath.Join(tmpDir, "gitraf", "gitraf")

			// Copy new binary to old location
			input, err := os.ReadFile(newBinary)
			if err != nil {
				return fmt.Errorf("failed to read new binary: %w", err)
			}

			if err := os.WriteFile(execPath, input, 0755); err != nil {
				// Try with sudo if permission denied
				if os.IsPermission(err) {
					fmt.Println("Permission denied, trying with sudo...")
					cpCmd := exec.Command("sudo", "cp", newBinary, execPath)
					cpCmd.Stdout = os.Stdout
					cpCmd.Stderr = os.Stderr
					if err := cpCmd.Run(); err != nil {
						return fmt.Errorf("failed to install (even with sudo): %w", err)
					}
				} else {
					return fmt.Errorf("failed to install: %w", err)
				}
			}

			fmt.Println("\ngitraf updated successfully!")
			fmt.Println("Your configuration has been preserved.")
			return nil
		},
	}
}

func lfsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lfs",
		Short: "Manage Git LFS configuration",
	}

	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure Git LFS with S3-compatible storage",
		Long: `Configure Git LFS to use S3-compatible storage (AWS S3, Cloudflare R2, etc.).

This will prompt for:
  - S3 endpoint URL (e.g., https://<account-id>.r2.cloudflarestorage.com for R2)
  - Bucket name
  - Access Key ID
  - Secret Access Key
  - Region (optional, default: auto)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			reader := bufio.NewReader(os.Stdin)

			fmt.Println("Git LFS Setup")
			fmt.Println("=============")
			fmt.Println()
			fmt.Println("Supported providers: AWS S3, Cloudflare R2, MinIO, Backblaze B2")
			fmt.Println()

			// Get S3 endpoint
			fmt.Print("S3 Endpoint URL (e.g., https://<account-id>.r2.cloudflarestorage.com): ")
			endpoint, _ := reader.ReadString('\n')
			endpoint = strings.TrimSpace(endpoint)
			if endpoint == "" {
				return fmt.Errorf("endpoint is required")
			}

			// Get bucket name
			fmt.Print("Bucket name: ")
			bucket, _ := reader.ReadString('\n')
			bucket = strings.TrimSpace(bucket)
			if bucket == "" {
				return fmt.Errorf("bucket name is required")
			}

			// Get access key
			fmt.Print("Access Key ID: ")
			accessKey, _ := reader.ReadString('\n')
			accessKey = strings.TrimSpace(accessKey)
			if accessKey == "" {
				return fmt.Errorf("access key is required")
			}

			// Get secret key
			fmt.Print("Secret Access Key: ")
			secretKey, _ := reader.ReadString('\n')
			secretKey = strings.TrimSpace(secretKey)
			if secretKey == "" {
				return fmt.Errorf("secret key is required")
			}

			// Get region (optional)
			fmt.Print("Region (press Enter for 'auto'): ")
			region, _ := reader.ReadString('\n')
			region = strings.TrimSpace(region)
			if region == "" {
				region = "auto"
			}

			// Create config JSON
			lfsConfig := fmt.Sprintf(`{
  "endpoint": "%s",
  "bucket": "%s",
  "access_key": "%s",
  "secret_key": "%s",
  "region": "%s"
}`, endpoint, bucket, accessKey, secretKey, region)

			host := getSSHHost()

			// Write config to server
			fmt.Println("\nSaving LFS configuration to server...")
			writeCmd := exec.Command("ssh", host, fmt.Sprintf("sudo tee /opt/ogit/lfs-config.json << 'EOFCONFIG'\n%s\nEOFCONFIG", lfsConfig))
			writeCmd.Stdout = nil // Suppress output of tee
			writeCmd.Stderr = os.Stderr
			if err := writeCmd.Run(); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			// Set permissions
			chmodCmd := exec.Command("ssh", host, "sudo chmod 600 /opt/ogit/lfs-config.json")
			chmodCmd.Run()

			// Restart LFS server if running
			restartCmd := exec.Command("ssh", host, "sudo systemctl restart gitraf-lfs 2>/dev/null || true")
			restartCmd.Run()

			fmt.Println("\nLFS configuration saved successfully!")
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  1. The LFS server will be configured automatically")
			fmt.Println("  2. Track large files with: git lfs track '*.zip' '*.tar.gz' etc.")
			fmt.Println("  3. Files >10MB will be rejected unless tracked by LFS")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show Git LFS configuration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			host := getSSHHost()

			// Check if LFS config exists
			checkCmd := exec.Command("ssh", host, "cat /opt/ogit/lfs-config.json 2>/dev/null")
			output, err := checkCmd.Output()
			if err != nil {
				fmt.Println("LFS Status: Not configured")
				fmt.Println()
				fmt.Println("Run 'gitraf lfs setup' to configure Git LFS with S3 storage.")
				return nil
			}

			// Parse config to show (hide secrets)
			var config map[string]string
			if err := json.Unmarshal(output, &config); err != nil {
				return fmt.Errorf("failed to parse config: %w", err)
			}

			fmt.Println("LFS Status: Configured")
			fmt.Println()
			fmt.Printf("  Endpoint: %s\n", config["endpoint"])
			fmt.Printf("  Bucket:   %s\n", config["bucket"])
			fmt.Printf("  Region:   %s\n", config["region"])
			if len(config["access_key"]) > 8 {
				fmt.Printf("  Access Key: %s...\n", config["access_key"][:8])
			}
			fmt.Println()

			// Check if LFS server is running
			svcCmd := exec.Command("ssh", host, "systemctl is-active gitraf-lfs 2>/dev/null || echo 'not running'")
			svcOutput, _ := svcCmd.Output()
			svcStatus := strings.TrimSpace(string(svcOutput))
			if svcStatus == "active" {
				fmt.Println("  LFS Server: Running")
			} else {
				fmt.Println("  LFS Server: Not running (integrated into gitraf-server)")
			}

			return nil
		},
	}

	cmd.AddCommand(setupCmd, statusCmd)
	return cmd
}

func pagesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pages",
		Short: "Manage static site hosting for repositories",
		Long: `Deploy static sites from git repositories.

When a repo is enabled for pages, its content is deployed to {repo-name}.rafayel.dev.
Push to the configured branch to trigger deployment.

Examples:
  gitraf pages enable my-site       # Enable pages for a repo
  gitraf pages disable my-site      # Disable pages for a repo
  gitraf pages list                 # List all pages-enabled repos
  gitraf pages status my-site       # Show pages status for a repo`,
	}

	enableCmd := &cobra.Command{
		Use:   "enable <repo>",
		Short: "Enable pages for a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			reader := bufio.NewReader(os.Stdin)

			fmt.Printf("Enabling pages for '%s'...\n\n", name)

			// Interactive prompts for config
			fmt.Print("Branch to deploy from [main]: ")
			branch, _ := reader.ReadString('\n')
			branch = strings.TrimSpace(branch)
			if branch == "" {
				branch = "main"
			}

			fmt.Print("Build command (leave empty for static files): ")
			buildCmd, _ := reader.ReadString('\n')
			buildCmd = strings.TrimSpace(buildCmd)

			fmt.Print("Output directory [public]: ")
			outputDir, _ := reader.ReadString('\n')
			outputDir = strings.TrimSpace(outputDir)
			if outputDir == "" {
				outputDir = "public"
			}

			// Create config JSON - escape any quotes in build command
			buildCmdEscaped := strings.ReplaceAll(buildCmd, `"`, `\"`)
			config := fmt.Sprintf(`{"enabled":true,"branch":"%s","build_command":"%s","output_dir":"%s"}`,
				branch, buildCmdEscaped, outputDir)

			host := getSSHHost()

			// Check if repo exists
			checkCmd := exec.Command("ssh", host, fmt.Sprintf("test -d /opt/ogit/data/repos/%s.git", name))
			if err := checkCmd.Run(); err != nil {
				return fmt.Errorf("repository '%s' not found", name)
			}

			// Write config and link hook
			script := fmt.Sprintf(`
echo '%s' | sudo tee /opt/ogit/data/repos/%s.git/git-pages.json > /dev/null && \
sudo ln -sf /opt/ogit/hooks/post-receive-pages /opt/ogit/data/repos/%s.git/hooks/post-receive && \
sudo chown git:git /opt/ogit/data/repos/%s.git/git-pages.json /opt/ogit/data/repos/%s.git/hooks/post-receive
`, config, name, name, name, name)

			sshCmd := exec.Command("ssh", host, script)
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to enable pages: %w", err)
			}

			fmt.Printf("\nPages enabled for %s!\n", name)
			fmt.Printf("URL: https://%s.rafayel.dev\n\n", name)
			fmt.Printf("Push to the '%s' branch to deploy.\n", branch)
			return nil
		},
	}

	disableCmd := &cobra.Command{
		Use:   "disable <repo>",
		Short: "Disable pages for a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			// Remove config and unlink hook
			script := fmt.Sprintf(`
sudo rm -f /opt/ogit/data/repos/%s.git/git-pages.json && \
sudo rm -f /opt/ogit/data/repos/%s.git/hooks/post-receive
`, name, name)

			sshCmd := exec.Command("ssh", host, script)
			sshCmd.Stderr = os.Stderr
			if err := sshCmd.Run(); err != nil {
				return fmt.Errorf("failed to disable pages: %w", err)
			}

			fmt.Printf("Pages disabled for %s.\n", name)
			fmt.Println("Note: The deployed site will remain until manually deleted.")
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all pages-enabled repositories",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			host := getSSHHost()

			// Find all repos with git-pages.json
			findCmd := exec.Command("ssh", host, "for d in /opt/ogit/data/repos/*.git; do if [ -f \"$d/git-pages.json\" ]; then basename \"$d\" .git; fi; done")
			output, err := findCmd.Output()
			if err != nil {
				return fmt.Errorf("failed to list pages: %w", err)
			}

			repos := strings.TrimSpace(string(output))
			if repos == "" {
				fmt.Println("No pages-enabled repositories found.")
				fmt.Println("\nEnable pages with: gitraf pages enable <repo>")
				return nil
			}

			fmt.Println("Pages-enabled repositories:\n")
			for _, repo := range strings.Split(repos, "\n") {
				repo = strings.TrimSpace(repo)
				if repo != "" {
					fmt.Printf("  %s -> https://%s.rafayel.dev\n", repo, repo)
				}
			}
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status [repo]",
		Short: "Show pages status for a repository",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			host := getSSHHost()

			if len(args) == 0 {
				// Show status for all pages
				findCmd := exec.Command("ssh", host, "for d in /opt/ogit/data/repos/*.git; do if [ -f \"$d/git-pages.json\" ]; then name=$(basename \"$d\" .git); echo \"$name:\"; cat \"$d/git-pages.json\" | jq -r '\"  Branch: \\(.branch // \"main\")\\n  Build: \\(.build_command // \"(none)\")\\n  Output: \\(.output_dir // \"public\")\"'; echo; fi; done")
				output, err := findCmd.Output()
				if err != nil {
					return fmt.Errorf("failed to get status: %w", err)
				}
				if strings.TrimSpace(string(output)) == "" {
					fmt.Println("No pages-enabled repositories.")
					return nil
				}
				fmt.Print(string(output))
				return nil
			}

			name := args[0]

			// Check if pages is enabled
			checkCmd := exec.Command("ssh", host, fmt.Sprintf("cat /opt/ogit/data/repos/%s.git/git-pages.json 2>/dev/null", name))
			output, err := checkCmd.Output()
			if err != nil {
				fmt.Printf("Pages not enabled for '%s'.\n", name)
				fmt.Println("\nEnable with: gitraf pages enable", name)
				return nil
			}

			// Parse and display config
			var config map[string]interface{}
			if err := json.Unmarshal(output, &config); err != nil {
				return fmt.Errorf("failed to parse config: %w", err)
			}

			branch := "main"
			if b, ok := config["branch"].(string); ok && b != "" {
				branch = b
			}
			buildCmd := "(none)"
			if b, ok := config["build_command"].(string); ok && b != "" {
				buildCmd = b
			}
			outputDir := "public"
			if o, ok := config["output_dir"].(string); ok && o != "" {
				outputDir = o
			}

			fmt.Printf("Pages Status: %s\n", name)
			fmt.Println("===================")
			fmt.Printf("URL:          https://%s.rafayel.dev\n", name)
			fmt.Printf("Branch:       %s\n", branch)
			fmt.Printf("Build:        %s\n", buildCmd)
			fmt.Printf("Output Dir:   %s\n", outputDir)

			// Check if site is deployed
			checkDeployCmd := exec.Command("ssh", host, fmt.Sprintf("test -d /opt/ogit/pages/%s/site && echo 'deployed' || echo 'not deployed'", name))
			deployOutput, _ := checkDeployCmd.Output()
			fmt.Printf("Deployed:     %s\n", strings.TrimSpace(string(deployOutput)))

			return nil
		},
	}

	deployCmd := &cobra.Command{
		Use:   "deploy <repo>",
		Short: "Force deploy a pages-enabled repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			// Check if pages is enabled
			checkCmd := exec.Command("ssh", host, fmt.Sprintf("cat /opt/ogit/data/repos/%s.git/git-pages.json 2>/dev/null", name))
			configOutput, err := checkCmd.Output()
			if err != nil {
				return fmt.Errorf("pages not enabled for '%s'", name)
			}

			var config map[string]interface{}
			if err := json.Unmarshal(configOutput, &config); err != nil {
				return fmt.Errorf("failed to parse config: %w", err)
			}

			branch := "main"
			if b, ok := config["branch"].(string); ok && b != "" {
				branch = b
			}

			fmt.Printf("Deploying %s from branch %s...\n", name, branch)

			// Trigger deployment by running the hook manually
			script := fmt.Sprintf(`
cd /opt/ogit/data/repos/%s.git && \
echo "0000000 HEAD refs/heads/%s" | sudo -u git /opt/ogit/hooks/post-receive-pages
`, name, branch)

			sshCmd := exec.Command("ssh", host, script)
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			return sshCmd.Run()
		},
	}

	logsCmd := &cobra.Command{
		Use:   "logs <repo>",
		Short: "Show recent deploy output for a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireTailnet(); err != nil {
				return err
			}

			name := args[0]
			host := getSSHHost()

			// Check if site directory exists and show info
			script := fmt.Sprintf(`
if [ -d /opt/ogit/pages/%s/site ]; then
    echo "Site directory: /opt/ogit/pages/%s/site"
    echo "Contents:"
    ls -la /opt/ogit/pages/%s/site 2>/dev/null | head -20
else
    echo "No deployment found for %s"
fi
`, name, name, name, name)

			sshCmd := exec.Command("ssh", host, script)
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			return sshCmd.Run()
		},
	}

	cmd.AddCommand(enableCmd, disableCmd, listCmd, statusCmd, deployCmd, logsCmd)
	return cmd
}
