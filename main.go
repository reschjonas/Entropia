package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"entropia/internal/app"
	"entropia/internal/config"
	"entropia/internal/discovery"
	"entropia/internal/logger"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.3-e2e"

	rootCmd = &cobra.Command{
		Use:   "entropia",
		Short: "Post-quantum end-to-end encrypted terminal chat",
		Long: `Entropia - A decentralized, post-quantum end-to-end encrypted terminal chat application
that supports both local (LAN) and global (Internet) connections.

CONNECTION MODES:
• Local Network (mDNS): Automatic peer discovery on the same LAN
• Global Network (Direct): Manual IP address connections across the Internet

🔐 SECURITY FEATURES:
• CRYSTALS-Kyber-1024 for quantum-safe key exchange
• CRYSTALS-DILITHIUM-5 for message authentication
• ChaCha20-Poly1305 for authenticated symmetric encryption
• Perfect forward secrecy with automatic key rotation
• Cryptographic peer identity verification

🌐 NETWORK TRANSPORT:
Entropia uses QUIC to establish a reliable and secure transport channel.
The application-layer post-quantum cryptography is layered on top of QUIC's
TLS 1.3 encryption for defense-in-depth. QUIC can operate over any IP network
including:
• Local Area Networks (automatic discovery)
• Internet connections (manual addressing)
• VPN tunnels and overlay networks
• NAT traversal for home networks`,
		Version: version,
	}

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new E2E encrypted chat room and listen for connections",
		Long: `Create a new chat room and listen for peers to join.

WHAT THIS DOES:
• Generates a cryptographically secure 32-character room ID
• Starts listening on a UDP port for incoming connections
• Detects your external IP address for global connections
• Advertises on local network via mDNS for automatic discovery
• Displays your identity fingerprint for out-of-band verification

CONNECTION OPTIONS FOR PEERS:
• Local network: Peers can join with just the Room ID (auto-discovery)
• Global network: Share your external IP:port address with peers

SECURITY NOTE: Always verify identity fingerprints through a trusted channel!`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate()
		},
	}

	joinCmd = &cobra.Command{
		Use:   "join <room-id>",
		Short: "Join an existing E2E encrypted chat room (automatic discovery)",
		Long: `Join an existing chat room using automatic peer discovery.

AUTOMATIC DISCOVERY:
Entropia will automatically find and connect to the room creator using:
• mDNS discovery (local networks)
• UDP broadcast discovery (local networks) 
• Global discovery (future enhancement)

USAGE EXAMPLES:
  entropia join Entropia_ABC123XYZ789              # Automatic discovery
  entropia join Entropia_ABC123XYZ789 192.168.1.5:8080    # Manual override

DISCOVERY FEATURES:
• Fast discovery (usually connects within 5-10 seconds)
• Multiple simultaneous discovery methods for reliability
• Works across different network types and configurations
• No IP addresses needed - just the Room ID

TROUBLESHOOTING:
If automatic discovery fails:
• Ensure the room creator is running
• Check firewall settings on both devices
• Try manual connection with IP:port if needed

SECURITY NOTE: Always verify identity fingerprints before trusting messages!`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			roomID := args[0]
			remote := ""
			if len(args) == 2 {
				remote = args[1]
			}
			return runJoin(roomID, remote)
		},
	}

	// CLI global flags
	logLevelFlag string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "", "Set log level (debug, info, warn, error). Overrides $ENTROPIA_LOG_LEVEL")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if logLevelFlag != "" {
			// apply user-provided level
			lvl := logger.ParseLevel(logLevelFlag)
			logger.SetLevel(lvl)
			logger.L().Info("Log level set via CLI flag", "level", logLevelFlag)
		}
	}

	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(joinCmd)
}

func main() {
	// silence all logging to keep chat interface clean
	log.SetOutput(io.Discard)
	log.SetFlags(0)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCreate() error {
	cfg := config.DefaultConfig()
	ctx := context.Background()

	// handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
	}()

	entApp, err := app.NewEntropia(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize Entropia: %w", err)
	}
	defer entApp.Close()

	// show identity fingerprint
	fingerprint, err := entApp.GetPeerFingerprint()
	if err != nil {
		return fmt.Errorf("failed to get identity fingerprint: %w", err)
	}

	roomID, err := entApp.CreateRoom(ctx)
	if err != nil {
		return fmt.Errorf("failed to create room: %w", err)
	}

	// start DHT node for discovery
	dhtServer, err := discovery.StartDHTNode(cfg.Discovery.BTDHTPort)
	if err != nil {
		logger.L().Warn("DHT node startup failed", "err", err)
	}

	// start multiple discovery services for max discoverability
	go discovery.Advertise(ctx, roomID, entApp.GetListenPort())               // mDNS
	go discovery.StartDiscoveryResponder(ctx, roomID, entApp.GetListenPort()) // broadcast responder
	if dhtServer != nil {
		go discovery.AnnounceDHT(ctx, dhtServer, roomID, entApp.GetListenPort()) // DHT
	}

	// get external IP for user display
	externalAddr, err := discovery.GetExternalIP()
	if err != nil {
		logger.L().Warn("Could not determine external IP", "err", err)
	}

	logger.L().Info("Room created", "room_id", roomID, "fingerprint", fingerprint, "listen_port", entApp.GetListenPort(), "external_addr", externalAddr)
	logger.L().Info("Starting chat interface")

	return entApp.StartChatInterface(ctx)
}

func runJoin(roomID, remoteAddr string) error {
	cfg := config.DefaultConfig()
	ctx := context.Background()

	// handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
	}()

	entApp, err := app.NewEntropia(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize Entropia: %w", err)
	}
	defer entApp.Close()

	// show identity fingerprint
	fingerprint, err := entApp.GetPeerFingerprint()
	if err != nil {
		return fmt.Errorf("failed to get identity fingerprint: %w", err)
	}

	// always use automatic discovery unless address is explicitly provided
	if remoteAddr == "" {
		logger.L().Info("Auto-discovering peer", "room", roomID[:8])

		// start dht node for discovery
		dhtServer, err := discovery.StartDHTNode(cfg.Discovery.BTDHTPort)
		if err != nil {
			logger.L().Warn("Failed to start DHT node", "err", err)
		}

		// use fast automatic discovery
		addr, err := discovery.AutoDiscovery(ctx, roomID, dhtServer)
		if err != nil {
			return fmt.Errorf("automatic discovery failed: %w\n\n💡 TROUBLESHOOTING:\n   • Make sure the room creator is running\n   • Check firewall settings\n   • Try manual connection: entropia join %s <ip:port>", err, roomID)
		}

		remoteAddr = addr
		logger.L().Info("Peer found", "addr", remoteAddr)
	} else {
		logger.L().Info("Using manual remote address", "addr", remoteAddr)
	}

	logger.L().Info("Joining room", "room_id", roomID, "fingerprint", fingerprint, "remote_addr", remoteAddr)
	logger.L().Info("Initiating secure handshake")

	if err := entApp.JoinRoom(ctx, roomID, remoteAddr); err != nil {
		return fmt.Errorf("failed to join room: %w", err)
	}

	return entApp.StartChatInterface(ctx)
}
