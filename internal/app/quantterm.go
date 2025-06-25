package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"quantterm/internal/config"
	"quantterm/internal/crypto"
	"quantterm/internal/network"
	"quantterm/internal/room"
	"quantterm/internal/ui"
)

// QuantTerm is the main application state
type QuantTerm struct {
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

// NewQuantTerm creates a new QuantTerm instance
func NewQuantTerm(cfg *config.Config) (*QuantTerm, error) {
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

	return &QuantTerm{
		config:     cfg,
		peerID:     peerID,
		pqCrypto:   pqCrypto,
		listenPort: listenPort,
		stopChan:   make(chan struct{}),
	}, nil
}

// CreateRoom creates a new chat room and starts listening
func (qt *QuantTerm) CreateRoom(ctx context.Context) (string, error) {
	newRoom, err := room.NewRoom("QuantTerm E2E Chat", "Post-quantum encrypted chat room", qt.config.Network.MaxPeers, false)
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
func (qt *QuantTerm) JoinRoom(ctx context.Context, roomID string, remoteAddr string) error {
	if !room.ValidateRoomID(roomID) {
		return fmt.Errorf("invalid room ID format")
	}

	qt.currentRoom = &room.Room{
		ID:       roomID,
		Name:     "QuantTerm E2E Chat",
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
func (qt *QuantTerm) StartChatInterface(ctx context.Context) error {
	// start background handlers
	go qt.handleMessages(ctx)
	go qt.handlePeerEvents(ctx)
	go qt.handleSecurityEvents(ctx)

	// start the UI (this blocks until quit)
	return qt.terminalUI.Start(ctx)
}

// Close shuts down the application
func (qt *QuantTerm) Close() {
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
func (qt *QuantTerm) initializeComponents(ctx context.Context, isListener bool, remoteAddr string) error {
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
func (qt *QuantTerm) startServices(ctx context.Context) error {
	qt.isRunning = true

	if err := qt.network.Start(ctx); err != nil {
		return fmt.Errorf("failed to start network transport: %w", err)
	}

	return nil
}

// handle sending and receiving encrypted messages
func (qt *QuantTerm) handleMessages(ctx context.Context) {
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
func (qt *QuantTerm) handlePeerEvents(ctx context.Context) {
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
func (qt *QuantTerm) handleSecurityEvents(ctx context.Context) {
	fingerprintTicker := time.NewTicker(60 * time.Second)
	defer fingerprintTicker.Stop()

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
		}
	}
}

// get fingerprints for all known peers
func (qt *QuantTerm) getPeerFingerprints() map[string]string {
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

// find an available port in the given range
func findAvailablePort(minPort, maxPort int) (int, error) {
	// just pick a random port for now
	// TODO: actually check if it's available
	portRange := maxPort - minPort + 1
	randomOffset, err := rand.Int(rand.Reader, big.NewInt(int64(portRange)))
	if err != nil {
		return 0, err
	}

	return minPort + int(randomOffset.Int64()), nil
}

// GetPeerFingerprint returns our cryptographic fingerprint
func (qt *QuantTerm) GetPeerFingerprint() (string, error) {
	return qt.pqCrypto.GetIdentityFingerprint()
}

// GetRoomInfo returns info about the current room
func (qt *QuantTerm) GetRoomInfo() *room.Room {
	return qt.currentRoom
}

// GetListenPort returns the port we're listening on
func (qt *QuantTerm) GetListenPort() int {
	return qt.listenPort
}

// GetConnectedPeerCount returns how many peers are connected
func (qt *QuantTerm) GetConnectedPeerCount() int {
	if qt.network == nil {
		return 0
	}
	return len(qt.network.GetConnectedPeers())
}

// GetVerifiedPeerCount returns how many peers are verified
func (qt *QuantTerm) GetVerifiedPeerCount() int {
	if qt.pqCrypto == nil {
		return 0
	}
	return len(qt.pqCrypto.GetVerifiedPeers())
}

// GetNetworkStatus returns current network and encryption status
func (qt *QuantTerm) GetNetworkStatus() map[string]interface{} {
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
func (qt *QuantTerm) GetSecuritySummary() map[string]interface{} {
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
