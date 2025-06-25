package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"quantterm/internal/app"
	"quantterm/internal/config"
	"quantterm/internal/discovery"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.0-e2e"

	rootCmd = &cobra.Command{
		Use:   "quantterm",
		Short: "Post-quantum end-to-end encrypted terminal chat",
		Long: `QuantTerm - A decentralized, post-quantum end-to-end encrypted terminal chat application
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
QuantTerm uses UDP with WireGuard-style encapsulation for reliability and
performance. It can operate over any IP network including:
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
QuantTerm will automatically find and connect to the room creator using:
• mDNS discovery (local networks)
• UDP broadcast discovery (local networks) 
• Global discovery (future enhancement)

USAGE EXAMPLES:
  quantterm join QuantTerm_ABC123XYZ789              # Automatic discovery
  quantterm join QuantTerm_ABC123XYZ789 192.168.1.5:8080    # Manual override

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
)

func init() {
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

	quantApp, err := app.NewQuantTerm(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize QuantTerm: %w", err)
	}
	defer quantApp.Close()

	// show identity fingerprint
	fingerprint, err := quantApp.GetPeerFingerprint()
	if err != nil {
		return fmt.Errorf("failed to get identity fingerprint: %w", err)
	}

	roomID, err := quantApp.CreateRoom(ctx)
	if err != nil {
		return fmt.Errorf("failed to create room: %w", err)
	}

	// start multiple discovery services for max discoverability
	go discovery.Advertise(ctx, roomID, quantApp.GetListenPort())               // mDNS
	go discovery.StartDiscoveryResponder(ctx, roomID, quantApp.GetListenPort()) // broadcast responder

	// get external IP and advertise globally
	externalAddr, err := discovery.AdvertiseWithExternalIP(ctx, roomID, quantApp.GetListenPort())
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not determine external IP: %v\n", err)
		fmt.Printf("   Local network discovery will still work\n")
	}

	fmt.Printf("🔐 QuantTerm E2E Encrypted Room Created\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📱 Room ID: %s\n", roomID)
	fmt.Printf("🔑 Your Identity Fingerprint: %s\n", fingerprint)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if externalAddr != "" {
		fmt.Printf("🌐 Global Address: %s\n", externalAddr)
	}

	fmt.Printf("🏠 Local Port: %d\n", quantApp.GetListenPort())
	fmt.Printf("📡 Discovery Services: mDNS + Broadcast + Global\n")
	fmt.Printf("💡 Peers can join with just the Room ID (automatic discovery)\n")
	fmt.Printf("⚠️  Verify fingerprints through a trusted channel\n")
	fmt.Printf("⚡ Starting secure chat interface...\n\n")

	return quantApp.StartChatInterface(ctx)
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

	quantApp, err := app.NewQuantTerm(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize QuantTerm: %w", err)
	}
	defer quantApp.Close()

	// show identity fingerprint
	fingerprint, err := quantApp.GetPeerFingerprint()
	if err != nil {
		return fmt.Errorf("failed to get identity fingerprint: %w", err)
	}

	// always use automatic discovery unless address is explicitly provided
	if remoteAddr == "" {
		fmt.Printf("🔍 Auto-discovering peer for room %s...\n", roomID[:8])
		fmt.Printf("   - Trying: mDNS, Broadcast, Global discovery\n")

		// use fast automatic discovery
		addr, err := discovery.AutoDiscovery(ctx, roomID)
		if err != nil {
			return fmt.Errorf("automatic discovery failed: %w\n\n💡 TROUBLESHOOTING:\n   • Make sure the room creator is running\n   • Check firewall settings\n   • Try manual connection: quantterm join %s <ip:port>", err, roomID)
		}

		remoteAddr = addr
		fmt.Printf("✅ Found peer: %s\n", remoteAddr)
	} else {
		// validate the provided address
		fmt.Printf("🔗 Using manual address: %s\n", remoteAddr)
	}

	// show connection info
	fmt.Printf("🔍 Joining E2E Encrypted Room: %s\n", roomID)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("🔑 Your Identity Fingerprint: %s\n", fingerprint)
	fmt.Printf("📍 Connecting to: %s\n", remoteAddr)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("🔍 Initiating secure handshake...\n")
	fmt.Printf("⚠️  Verify peer fingerprints before trusting messages\n\n")

	if err := quantApp.JoinRoom(ctx, roomID, remoteAddr); err != nil {
		return fmt.Errorf("failed to join room: %w", err)
	}

	return quantApp.StartChatInterface(ctx)
}
