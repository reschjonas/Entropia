package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"time"

	"entropia/internal/config"
	"entropia/internal/crypto"
	"entropia/internal/network"
	"entropia/internal/room"
	"entropia/internal/ui"
)

// Entropia is the main application state
type Entropia struct {
	config      *config.Config
	peerID      string
	currentRoom *room.Room

	// core components
	pqCrypto   *crypto.PQCrypto
	network    network.Network
	terminalUI *ui.TerminalUI

	// runtime state
	isRunning  bool
	listenPort int

	// sync
	stopChan chan struct{}
}

// NewEntropia creates a new Entropia instance
func NewEntropia(cfg *config.Config) (*Entropia, error) {
	// generate a random peer ID for this session
	peerID, err := generatePeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer ID: %w", err)
	}

	// set up post-quantum crypto
	pqCrypto, err := crypto.NewPQCrypto()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cryptography: %w", err)
	}

	// find a port we can use
	listenPort, err := findAvailablePort(cfg.Network.MinPort, cfg.Network.MaxPort)
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}

	return &Entropia{
		config:     cfg,
		peerID:     peerID,
		pqCrypto:   pqCrypto,
		listenPort: listenPort,
		stopChan:   make(chan struct{}),
	}, nil
}

// CreateRoom creates a new chat room and starts listening
func (qt *Entropia) CreateRoom(ctx context.Context) (string, error) {
	newRoom, err := room.NewRoom("Entropia E2E Chat", "Post-quantum encrypted chat room", qt.config.Network.MaxPeers, false)
	if err != nil {
		return "", fmt.Errorf("failed to create room: %w", err)
	}

	qt.currentRoom = newRoom

	if err := qt.initializeComponents(ctx, true, ""); err != nil {
		return "", fmt.Errorf("failed to initialize components: %w", err)
	}

	if err := qt.startServices(ctx); err != nil {
		return "", fmt.Errorf("failed to start services: %w", err)
	}

	return newRoom.ID, nil
}

// JoinRoom joins an existing chat room
func (qt *Entropia) JoinRoom(ctx context.Context, roomID string, remoteAddr string) error {
	if !room.ValidateRoomID(roomID) {
		return fmt.Errorf("invalid room ID format")
	}

	qt.currentRoom = &room.Room{
		ID:       roomID,
		Name:     "Entropia E2E Chat",
		MaxPeers: qt.config.Network.MaxPeers,
	}

	// joiner connects to the room creator
	if err := qt.initializeComponents(ctx, false, remoteAddr); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	if err := qt.startServices(ctx); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	return nil
}

// StartChatInterface starts the terminal UI and message handling
func (qt *Entropia) StartChatInterface(ctx context.Context) error {
	// start background handlers
	go qt.handleMessages(ctx)
	go qt.handlePeerEvents(ctx)
	go qt.handleSecurityEvents(ctx)
	go qt.handleNetworkErrors(ctx)

	// start the UI (this blocks until quit)
	return qt.terminalUI.Start(ctx)
}

// Close shuts down the application
func (qt *Entropia) Close() {
	if !qt.isRunning {
		return
	}

	qt.isRunning = false
	close(qt.stopChan)

	if qt.terminalUI != nil {
		qt.terminalUI.Stop()
	}

	if qt.network != nil {
		qt.network.Stop()
	}
}

// initialize all the components we need
func (qt *Entropia) initializeComponents(ctx context.Context, isListener bool, remoteAddr string) error {
	var err error

	qt.network, err = network.NewNetwork(
		ctx,
		qt.peerID,
		qt.currentRoom.ID,
		qt.listenPort,
		qt.pqCrypto,
		isListener,
		remoteAddr,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize network transport: %w", err)
	}

	qt.terminalUI = ui.NewTerminalUI(qt.currentRoom.ID, qt.config.UI.MaxMessageHistory)

	return nil
}

// start up networking and discovery
func (qt *Entropia) startServices(ctx context.Context) error {
	qt.isRunning = true

	if err := qt.network.Start(ctx); err != nil {
		return fmt.Errorf("failed to start network transport: %w", err)
	}

	return nil
}

// handle sending and receiving encrypted messages
func (qt *Entropia) handleMessages(ctx context.Context) {
	sendChan := qt.terminalUI.GetSendChannel()
	receiveChan := qt.network.GetIncomingMessages()

	for {
		select {
		case <-ctx.Done():
			return
		case <-qt.stopChan:
			return
		case message := <-sendChan:
			// send encrypted message to verified peers
			if err := qt.network.SendMessage(ctx, message); err != nil {
				qt.terminalUI.AddSystemMessage(fmt.Sprintf("❌ Failed to send E2E encrypted message: %v", err))
			}
		case receivedMsg := <-receiveChan:
			// show the verified message in UI
			qt.terminalUI.HandleReceivedMessage(receivedMsg)
		}
	}
}

// handle peer connection events
func (qt *Entropia) handlePeerEvents(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-qt.stopChan:
			return
		case <-ticker.C:
			// update peer status in the UI
			connectedPeers := qt.network.GetConnectedPeers()
			verifiedPeers := qt.pqCrypto.GetVerifiedPeers()

			qt.terminalUI.UpdatePeersString(connectedPeers)
			qt.terminalUI.UpdateVerifiedPeerCount(len(verifiedPeers))
		}
	}
}

// handle security events and fingerprint displays
func (qt *Entropia) handleSecurityEvents(ctx context.Context) {
	fingerprintTicker := time.NewTicker(60 * time.Second)
	keyRotationCheckTicker := time.NewTicker(1 * time.Minute) // check every minute
	defer fingerprintTicker.Stop()
	defer keyRotationCheckTicker.Stop()

	var lastShownFingerprints map[string]string

	for {
		select {
		case <-ctx.Done():
			return
		case <-qt.stopChan:
			return
		case <-fingerprintTicker.C:
			// show peer fingerprints for verification
			currentFingerprints := qt.getPeerFingerprints()

			// only show if something changed
			if !equalStringMaps(lastShownFingerprints, currentFingerprints) && len(currentFingerprints) > 0 {
				qt.terminalUI.ShowPeerFingerprints(currentFingerprints)
				lastShownFingerprints = currentFingerprints
			}

		case <-keyRotationCheckTicker.C:
			// attempt key rotation for forward secrecy
			if qt.network == nil {
				continue
			}

			rotated, err := qt.network.ForceKeyRotation()
			if err != nil {
				qt.terminalUI.AddSecurityMessage(fmt.Sprintf("❌ Key rotation error: %v", err))
				continue
			}
			if rotated {
				qt.terminalUI.ShowKeyRotationEvent()
			}
		}
	}
}

// get fingerprints for all known peers
func (qt *Entropia) getPeerFingerprints() map[string]string {
	fingerprints := make(map[string]string)

	verifiedPeers := qt.pqCrypto.GetVerifiedPeers()
	for _, peerID := range verifiedPeers {
		if fingerprint, err := qt.pqCrypto.GetPeerFingerprint(peerID); err == nil {
			fingerprints[peerID] = fingerprint
		}
	}

	return fingerprints
}

// check if two string maps are the same
func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		if b[k] != v {
			return false
		}
	}

	return true
}

// generate a random peer ID for this session
func generatePeerID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// findAvailablePort iterates through a shuffled range of ports and returns the first one that is available on both TCP and UDP.
func findAvailablePort(minPort, maxPort int) (int, error) {
	ports := make([]int, 0, maxPort-minPort+1)
	for i := minPort; i <= maxPort; i++ {
		ports = append(ports, i)
	}

	// shuffle ports to reduce collisions when running multiple instances
	mathrand.Seed(time.Now().UnixNano())
	mathrand.Shuffle(len(ports), func(i, j int) {
		ports[i], ports[j] = ports[j], ports[i]
	})

	for _, port := range ports {
		if isPortAvailable(port) {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available port found in range %d-%d", minPort, maxPort)
}

// isPortAvailable checks if a port is available on both TCP and UDP.
func isPortAvailable(port int) bool {
	addr := fmt.Sprintf(":%d", port)

	// check UDP
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return false
	}
	defer udpConn.Close()

	// check TCP
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return false
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return false
	}
	defer tcpListener.Close()

	return true
}

// GetPeerFingerprint returns our cryptographic fingerprint
func (qt *Entropia) GetPeerFingerprint() (string, error) {
	return qt.pqCrypto.GetIdentityFingerprint()
}

// GetRoomInfo returns info about the current room
func (qt *Entropia) GetRoomInfo() *room.Room {
	return qt.currentRoom
}

// GetListenPort returns the port we're listening on
func (qt *Entropia) GetListenPort() int {
	return qt.listenPort
}

// GetConnectedPeerCount returns how many peers are connected
func (qt *Entropia) GetConnectedPeerCount() int {
	if qt.network == nil {
		return 0
	}
	return len(qt.network.GetConnectedPeers())
}

// GetVerifiedPeerCount returns how many peers are verified
func (qt *Entropia) GetVerifiedPeerCount() int {
	if qt.pqCrypto == nil {
		return 0
	}
	return len(qt.pqCrypto.GetVerifiedPeers())
}

// GetNetworkStatus returns current network and encryption status
func (qt *Entropia) GetNetworkStatus() map[string]interface{} {
	status := map[string]interface{}{
		"peer_id":         qt.peerID,
		"listen_port":     qt.listenPort,
		"room_id":         "",
		"connected_peers": 0,
		"verified_peers":  0,
		"e2e_encryption":  false,
		"is_running":      qt.isRunning,
	}

	if qt.currentRoom != nil {
		status["room_id"] = qt.currentRoom.ID
	}

	if qt.network != nil {
		status["connected_peers"] = len(qt.network.GetConnectedPeers())
	}

	if qt.pqCrypto != nil {
		verifiedPeers := len(qt.pqCrypto.GetVerifiedPeers())
		status["verified_peers"] = verifiedPeers
		status["e2e_encryption"] = verifiedPeers > 0
	}

	return status
}

// GetSecuritySummary returns a summary of our security features
func (qt *Entropia) GetSecuritySummary() map[string]interface{} {
	summary := map[string]interface{}{
		"encryption_algorithms": map[string]string{
			"key_exchange": "CRYSTALS-Kyber-1024",
			"signatures":   "CRYSTALS-DILITHIUM-5",
			"symmetric":    "ChaCha20-Poly1305",
		},
		"security_features": []string{
			"Post-quantum cryptography",
			"Perfect forward secrecy",
			"Message authentication",
			"Peer verification",
			"Key rotation",
		},
		"threat_resistance": []string{
			"Quantum computer attacks",
			"Man-in-the-middle attacks",
			"Message tampering",
			"Replay attacks",
			"Passive eavesdropping",
		},
	}

	if qt.pqCrypto != nil {
		if fingerprint, err := qt.pqCrypto.GetIdentityFingerprint(); err == nil {
			summary["identity_fingerprint"] = fingerprint
		}
	}

	return summary
}

// handleNetworkErrors listens for async errors from the transport layer
func (qt *Entropia) handleNetworkErrors(ctx context.Context) {
	if qt.network == nil {
		return
	}

	errChan := qt.network.GetErrorChannel()
	for {
		select {
		case <-ctx.Done():
			return
		case <-qt.stopChan:
			return
		case err := <-errChan:
			if err == nil {
				continue
			}
			if qt.terminalUI != nil {
				qt.terminalUI.AddSystemMessage(fmt.Sprintf("⚠️  Network error: %v", err))
			}
		}
	}
}
