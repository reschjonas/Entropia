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
	"entropia/internal/discovery"
	"entropia/internal/logger"
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
	pqCrypto *crypto.PQCrypto
	network  network.Network
	gui      *ui.WebviewUI

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

// StartGUILifecycle starts the new GUI-driven application flow
func (e *Entropia) StartGUILifecycle(ctx context.Context) error {
	e.gui = ui.NewWebviewUI(e)
	return e.gui.Start(ctx)
}

// CreateRoom creates a new chat room and starts listening
func (e *Entropia) CreateRoom(ctx context.Context) (string, error) {
	newRoom, err := room.NewRoom("Entropia Chat", "Post-quantum encrypted chat room", e.config.Network.MaxPeers, false)
	if err != nil {
		return "", fmt.Errorf("failed to create room: %w", err)
	}

	e.currentRoom = newRoom

	if err := e.initializeComponents(ctx, true, ""); err != nil {
		return "", fmt.Errorf("failed to initialize components: %w", err)
	}

	if err := e.startServices(ctx); err != nil {
		return "", fmt.Errorf("failed to start services: %w", err)
	}

	// start background handlers now that room exists
	go e.handleMessages(ctx)
	go e.handlePeerEvents(ctx)
	go e.handleSecurityEvents(ctx)
	go e.handleNetworkErrors(ctx)

	return newRoom.ID, nil
}

// JoinRoom joins an existing chat room
func (e *Entropia) JoinRoom(ctx context.Context, roomID string, remoteAddr string) error {
	if !room.ValidateRoomID(roomID) {
		return fmt.Errorf("invalid room ID format")
	}

	// If remote address is not provided, start auto-discovery
	if remoteAddr == "" {
		logger.L().Info("Auto-discovering peer", "room", roomID)
		dhtServer, err := discovery.StartDHTNode(e.config.Discovery.BTDHTPort)
		if err != nil {
			logger.L().Warn("Failed to start DHT node for discovery", "err", err)
		}
		addr, err := discovery.AutoDiscovery(ctx, roomID, dhtServer)
		if err != nil {
			return fmt.Errorf("auto-discovery failed: %w", err)
		}
		remoteAddr = addr
		logger.L().Info("Peer found via auto-discovery", "addr", remoteAddr)
	}

	e.currentRoom = &room.Room{
		ID:       roomID,
		Name:     "Entropia E2E Chat",
		MaxPeers: e.config.Network.MaxPeers,
	}

	if err := e.initializeComponents(ctx, false, remoteAddr); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	if err := e.startServices(ctx); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	go e.handleMessages(ctx)
	go e.handlePeerEvents(ctx)
	go e.handleSecurityEvents(ctx)
	go e.handleNetworkErrors(ctx)

	return nil
}

// Close shuts down the application
func (e *Entropia) Close() {
	if !e.isRunning {
		return
	}

	e.isRunning = false
	close(e.stopChan)

	if e.gui != nil {
		e.gui.Stop()
	}

	if e.network != nil {
		e.network.Stop()
	}
}

// initialize all the components we need
func (e *Entropia) initializeComponents(ctx context.Context, isListener bool, remoteAddr string) error {
	var err error

	e.network, err = network.NewNetwork(
		ctx,
		e.peerID,
		e.currentRoom.ID,
		e.listenPort,
		e.pqCrypto,
		isListener,
		remoteAddr,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize network transport: %w", err)
	}
	return nil
}

// start up networking and discovery
func (e *Entropia) startServices(ctx context.Context) error {
	e.isRunning = true

	if err := e.network.Start(ctx); err != nil {
		return fmt.Errorf("failed to start network transport: %w", err)
	}

	// If we are the creator, we need to start discovery services
	if e.network.IsListener() {
		roomID := e.currentRoom.ID
		listenPort := e.listenPort
		dhtServer, err := discovery.StartDHTNode(e.config.Discovery.BTDHTPort)
		if err != nil {
			logger.L().Warn("DHT node startup failed", "err", err)
		}

		go discovery.Advertise(ctx, roomID, listenPort)
		go discovery.StartDiscoveryResponder(ctx, roomID, listenPort)
		if dhtServer != nil {
			go discovery.AnnounceDHT(ctx, dhtServer, roomID, listenPort)
		}
	}

	return nil
}

// handle receiving encrypted messages
func (e *Entropia) handleMessages(ctx context.Context) {
	receiveChan := e.network.GetIncomingMessages()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case receivedMsg := <-receiveChan:
			// show the verified message in UI
			if e.gui != nil {
				e.gui.AddMessage(receivedMsg.SenderID, receivedMsg.Message, receivedMsg.Timestamp, false, true)
			}
		}
	}
}

// handle peer connection events
func (e *Entropia) handlePeerEvents(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case <-ticker.C:
			if e.gui != nil {
				e.gui.PushFullStateUpdate()
			}
		}
	}
}

// handle security events and fingerprint displays
func (e *Entropia) handleSecurityEvents(ctx context.Context) {
	fingerprintTicker := time.NewTicker(60 * time.Second)
	keyRotationCheckTicker := time.NewTicker(1 * time.Minute)
	defer fingerprintTicker.Stop()
	defer keyRotationCheckTicker.Stop()

	var lastShownFingerprints map[string]string

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case <-fingerprintTicker.C:
			currentFingerprints := e.getPeerFingerprints()
			if !equalStringMaps(lastShownFingerprints, currentFingerprints) && len(currentFingerprints) > 0 {
				if e.gui != nil {
					e.gui.ShowPeerFingerprints(currentFingerprints)
				}
				lastShownFingerprints = currentFingerprints
			}

		case <-keyRotationCheckTicker.C:
			if e.network == nil {
				continue
			}
			rotated, err := e.network.ForceKeyRotation()
			if err != nil {
				if e.gui != nil {
					e.gui.AddSecurityMessage(fmt.Sprintf("Key rotation error: %v", err))
				}
				continue
			}
			if rotated && e.gui != nil {
				e.gui.AddSecurityMessage("Forward secrecy: Keys rotated, re-establishing secure channels.")
			}
		}
	}
}

// get fingerprints for all known peers
func (e *Entropia) getPeerFingerprints() map[string]string {
	fingerprints := make(map[string]string)
	if e.pqCrypto == nil {
		return fingerprints
	}
	verifiedPeers := e.pqCrypto.GetVerifiedPeers()
	for _, peerID := range verifiedPeers {
		if fingerprint, err := e.pqCrypto.GetPeerFingerprint(peerID); err == nil {
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

// findAvailablePort iterates and returns an available port.
func findAvailablePort(minPort, maxPort int) (int, error) {
	ports := make([]int, 0, maxPort-minPort+1)
	for i := minPort; i <= maxPort; i++ {
		ports = append(ports, i)
	}
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

func isPortAvailable(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return false
	}
	defer udpConn.Close()
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

// --- AppController interface methods ---

// SendMessage sends a message over the network.
func (e *Entropia) SendMessage(ctx context.Context, message string) error {
	if e.network == nil {
		return fmt.Errorf("not connected to a room")
	}
	return e.network.SendMessage(ctx, message)
}

// GetPeerFingerprint returns our cryptographic fingerprint
func (e *Entropia) GetPeerFingerprint() (string, error) {
	if e.pqCrypto == nil {
		return "", fmt.Errorf("crypto not initialized")
	}
	return e.pqCrypto.GetIdentityFingerprint()
}

// GetRoomInfo returns info about the current room
func (e *Entropia) GetRoomInfo() *room.Room {
	return e.currentRoom
}

// GetListenPort returns the port we're listening on
func (e *Entropia) GetListenPort() int {
	return e.listenPort
}

// GetNetworkStatus returns current network and encryption status
func (e *Entropia) GetNetworkStatus() map[string]interface{} {
	status := map[string]interface{}{
		"peer_id":         e.peerID,
		"listen_port":     e.listenPort,
		"room_id":         "",
		"connected_peers": 0,
		"verified_peers":  0,
		"e2e_encryption":  false,
		"is_running":      e.isRunning,
	}

	if e.currentRoom != nil {
		status["room_id"] = e.currentRoom.ID
	}

	if e.network != nil {
		status["connected_peers"] = len(e.network.GetConnectedPeers())
	}

	if e.pqCrypto != nil {
		verifiedPeers := len(e.pqCrypto.GetVerifiedPeers())
		status["verified_peers"] = verifiedPeers
		status["e2e_encryption"] = verifiedPeers > 0
	}

	return status
}

// GetSecuritySummary returns a summary of our security features
func (e *Entropia) GetSecuritySummary() map[string]interface{} {
	summary := map[string]interface{}{
		"encryption_algorithms": map[string]string{
			"key_exchange": "CRYSTALS-Kyber-1024",
			"signatures":   "CRYSTALS-DILITHIUM-5",
			"symmetric":    "ChaCha20-Poly1305",
		},
	}
	if e.pqCrypto != nil {
		if fingerprint, err := e.pqCrypto.GetIdentityFingerprint(); err == nil {
			summary["identity_fingerprint"] = fingerprint
		}
	}
	return summary
}

// handleNetworkErrors listens for async errors from the transport layer
func (e *Entropia) handleNetworkErrors(ctx context.Context) {
	if e.network == nil {
		return
	}
	errChan := e.network.GetErrorChannel()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case err := <-errChan:
			if err == nil {
				continue
			}
			if e.gui != nil {
				e.gui.AddNetworkError(err)
			}
		}
	}
}

// IsListener returns true if the network is in listening mode
func (e *Entropia) IsListener() bool {
	if e.network == nil {
		return false
	}
	return e.network.IsListener()
}
