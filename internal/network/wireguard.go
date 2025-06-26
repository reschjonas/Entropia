package network

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"quantterm/internal/crypto"
)

// wgMessage is what we send over the UDP socket
// payload is hex-encoded, serialized crypto structures
type wgMessage struct {
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Timestamp int64  `json:"timestamp"`
	SenderID  string `json:"sender_id"`
}

// WireguardNetwork is a small UDP transport meant to run inside a WireGuard tunnel
// one peer listens on UDP, the other sends datagrams to that port
// WireGuard handles confidentiality/integrity, we focus on reliable delivery and post-quantum crypto
type WireguardNetwork struct {
	localPeerID string
	roomID      string
	pqCrypto    *crypto.PQCrypto

	ctx    context.Context
	cancel context.CancelFunc

	isListener bool
	listenPort int
	remoteAddr string // dial target for joiner

	incomingMessages chan *crypto.MessagePayload

	conn      *net.UDPConn
	connMutex sync.RWMutex

	peersMutex   sync.RWMutex
	connectedIDs []string

	// for joiner we cache resolved remote UDP address
	remoteUDPAddr *net.UDPAddr

	// state tracking to prevent message spam
	announcementSent bool
	keyExchangeSent  map[string]bool
	keyExchangeMutex sync.RWMutex
}

// NewWireguardNetwork creates the transport but doesn't start goroutines until Start
func NewWireguardNetwork(ctx context.Context, peerID, roomID string, listenPort int, pq *crypto.PQCrypto, isListener bool, remoteAddr string) (*WireguardNetwork, error) {
	netCtx, cancel := context.WithCancel(ctx)

	wn := &WireguardNetwork{
		localPeerID:      peerID,
		roomID:           roomID,
		pqCrypto:         pq,
		ctx:              netCtx,
		cancel:           cancel,
		isListener:       isListener,
		listenPort:       listenPort,
		remoteAddr:       remoteAddr,
		incomingMessages: make(chan *crypto.MessagePayload, 100),
		keyExchangeSent:  make(map[string]bool),
	}
	return wn, nil
}

// Start sets up the UDP socket and launches the reader goroutine
func (wn *WireguardNetwork) Start(ctx context.Context) error {
	// we maintain our own context for independent cancellation
	_ = ctx

	var err error
	if wn.isListener {
		err = wn.listenUDP()
	} else {
		err = wn.dialUDP()
	}
	if err != nil {
		return err
	}

	// joiner knows the remote address and can send announcement immediately
	if !wn.isListener {
		if err := wn.sendPeerAnnouncement(); err != nil {
			return err
		}
	}

	go wn.readLoop()

	return nil
}

// Stop closes the socket and cancels background work
func (wn *WireguardNetwork) Stop() {
	wn.cancel()
	wn.connMutex.Lock()
	if wn.conn != nil {
		wn.conn.Close()
	}
	wn.connMutex.Unlock()
}

// SendMessage encrypts and sends a chat message to the peer
func (wn *WireguardNetwork) SendMessage(ctx context.Context, message string) error {
	wn.connMutex.RLock()
	conn := wn.conn
	remoteAddr := wn.remoteUDPAddr
	wn.connMutex.RUnlock()
	if conn == nil {
		return fmt.Errorf("connection not established")
	}

	wn.peersMutex.RLock()
	if len(wn.connectedIDs) == 0 {
		wn.peersMutex.RUnlock()
		return fmt.Errorf("no verified peer connected")
	}
	peerID := wn.connectedIDs[0]
	wn.peersMutex.RUnlock()

	encMsg, err := wn.pqCrypto.EncryptMessageForPeer(message, peerID, wn.localPeerID)
	if err != nil {
		return err
	}
	msgBytes, err := crypto.SerializeEncryptedMessage(encMsg)
	if err != nil {
		return err
	}

	wrapper := wgMessage{
		Type:      "message",
		Payload:   hex.EncodeToString(msgBytes),
		Timestamp: time.Now().Unix(),
		SenderID:  wn.localPeerID,
	}
	fmt.Printf("🔍 Sending message to peer %s, payload size: %d bytes\n", peerID[:8], len(msgBytes))
	return wn.writeWrapper(wrapper, remoteAddr)
}

func (wn *WireguardNetwork) GetIncomingMessages() <-chan *crypto.MessagePayload {
	return wn.incomingMessages
}

func (wn *WireguardNetwork) GetConnectedPeers() []string {
	wn.peersMutex.RLock()
	defer wn.peersMutex.RUnlock()
	return append([]string(nil), wn.connectedIDs...)
}

func (wn *WireguardNetwork) listenUDP() error {
	// prefer IPv4 for better local network compatibility
	// only use IPv6 if remote address looks like IPv6
	var network string
	var addr *net.UDPAddr

	if wn.remoteAddr != "" && strings.Contains(wn.remoteAddr, ":") && strings.Count(wn.remoteAddr, ":") > 1 {
		// remote address looks like IPv6
		network = "udp6"
		addr = &net.UDPAddr{IP: net.IPv6unspecified, Port: wn.listenPort}
	} else {
		// default to IPv4 for better local network compatibility
		network = "udp4"
		addr = &net.UDPAddr{IP: net.IPv4zero, Port: wn.listenPort}
	}

	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s %s: %w", network, addr, err)
	}

	wn.connMutex.Lock()
	wn.conn = conn
	wn.connMutex.Unlock()

	fmt.Printf("📡 Listening on UDP %s:%d (WireGuard)\n", addr.IP, wn.listenPort)
	return nil
}

func (wn *WireguardNetwork) dialUDP() error {
	if wn.remoteAddr == "" {
		return fmt.Errorf("remote address required for joiner")
	}

	// resolve the remote address
	rAddr, err := net.ResolveUDPAddr("udp", wn.remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve remote address %s: %w", wn.remoteAddr, err)
	}

	// determine local address type based on remote address
	var localAddr *net.UDPAddr
	if rAddr.IP.To4() != nil {
		// remote is IPv4, use IPv4 local address
		localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	} else {
		// remote is IPv6, use IPv6 local address
		localAddr = &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}
	}

	conn, err := net.DialUDP("udp", localAddr, rAddr)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", wn.remoteAddr, err)
	}

	wn.connMutex.Lock()
	wn.conn = conn
	wn.remoteUDPAddr = rAddr
	wn.connMutex.Unlock()

	fmt.Printf("✅ Connected to peer via WireGuard (%s)\n", rAddr.String())
	return nil
}

func (wn *WireguardNetwork) readLoop() {
	wn.connMutex.RLock()
	conn := wn.conn
	wn.connMutex.RUnlock()
	if conn == nil {
		return
	}

	buf := make([]byte, 64*1024) // UDP max safe size

	for {
		select {
		case <-wn.ctx.Done():
			return
		default:
		}

		// set read timeout to prevent blocking forever
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// check if it's a timeout and continue
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// other errors mean connection is broken
			fmt.Printf("🔌 Connection error: %v\n", err)
			return
		}

		// cache the remote address once we see the first datagram
		if wn.remoteUDPAddr == nil {
			wn.connMutex.Lock()
			wn.remoteUDPAddr = addr
			wn.connMutex.Unlock()
			fmt.Printf("📡 Established connection with %s\n", addr.String())
		}

		// parse JSON
		data := buf[:n]
		var wrapper wgMessage
		if err := json.Unmarshal(data, &wrapper); err != nil {
			// log invalid messages for debugging
			fmt.Printf("🔍 Received invalid message from %s: %v\n", addr, err)
			continue
		}
		fmt.Printf("🔍 Received %s message from %s, size: %d bytes\n", wrapper.Type, addr, n)
		wn.handleWrapper(wrapper)
	}
}

func (wn *WireguardNetwork) writeWrapper(w wgMessage, addr *net.UDPAddr) error {
	wn.connMutex.RLock()
	conn := wn.conn
	remoteAddr := wn.remoteUDPAddr
	isListener := wn.isListener
	wn.connMutex.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection closed")
	}

	data, _ := json.Marshal(w)

	// for joiner (DialUDP creates connected socket): use Write()
	if !isListener {
		_, err := conn.Write(data)
		return err
	}

	// for listener (ListenUDP creates unconnected socket): use WriteToUDP()
	// use provided address first, fall back to cached remote address
	targetAddr := addr
	if targetAddr == nil {
		targetAddr = remoteAddr
	}

	if targetAddr == nil {
		return fmt.Errorf("no remote address available for listener")
	}

	_, err := conn.WriteToUDP(data, targetAddr)
	return err
}

func (wn *WireguardNetwork) handleWrapper(w wgMessage) {
	switch w.Type {
	case "announcement":
		wn.handlePeerAnnouncement(w)
	case "keyexchange":
		wn.handleKeyExchange(w)
	case "message":
		wn.handleEncryptedChat(w)
	}
}

func (wn *WireguardNetwork) handlePeerAnnouncement(w wgMessage) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		return
	}
	announcement, err := crypto.DeserializePeerAnnouncement(bytesPayload)
	if err != nil {
		return
	}
	if err := wn.pqCrypto.ProcessPeerAnnouncement(announcement); err != nil {
		fmt.Printf("❌ Invalid peer announcement: %v\n", err)
		return
	}

	// track remote peer ID
	wn.peersMutex.Lock()
	wn.connectedIDs = []string{announcement.PeerID}
	wn.peersMutex.Unlock()

	// reply with our own announcement only if we haven't sent one yet (listener case)
	if !wn.announcementSent {
		if err := wn.sendPeerAnnouncement(); err == nil {
			wn.announcementSent = true
		}
	}

	// start key exchange only if we haven't done it for this peer yet
	wn.keyExchangeMutex.Lock()
	alreadySent := wn.keyExchangeSent[announcement.PeerID]
	if !alreadySent {
		wn.keyExchangeSent[announcement.PeerID] = true
	}
	wn.keyExchangeMutex.Unlock()

	if !alreadySent {
		if err := wn.sendKeyExchange(announcement.PeerID); err != nil {
			fmt.Printf("❌ Key exchange failed: %v\n", err)
			// reset the flag so we can try again later
			wn.keyExchangeMutex.Lock()
			wn.keyExchangeSent[announcement.PeerID] = false
			wn.keyExchangeMutex.Unlock()
		}
	}
}

func (wn *WireguardNetwork) handleKeyExchange(w wgMessage) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		return
	}
	keyEx, err := crypto.DeserializeKeyExchange(bytesPayload)
	if err != nil {
		return
	}
	if err := wn.pqCrypto.ProcessKeyExchange(keyEx); err != nil {
		fmt.Printf("❌ Invalid key exchange: %v\n", err)
		return
	}
	fmt.Printf("🔐 Secure channel established with peer %s\n", keyEx.SenderID[:8])
}

func (wn *WireguardNetwork) handleEncryptedChat(w wgMessage) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		fmt.Printf("🔍 Message decode error: %v\n", err)
		return
	}
	encMsg, err := crypto.DeserializeEncryptedMessage(bytesPayload)
	if err != nil {
		fmt.Printf("🔍 Message deserialization error: %v\n", err)
		return
	}
	payload, err := wn.pqCrypto.DecryptMessageFromPeer(encMsg)
	if err != nil {
		fmt.Printf("🔍 Message decryption error: %v\n", err)
		return
	}
	select {
	case wn.incomingMessages <- payload:
	default:
		fmt.Printf("🔍 Message channel full, dropping message\n")
	}
}

// send our signed identity to the remote side
func (wn *WireguardNetwork) sendPeerAnnouncement() error {
	announcement, err := wn.pqCrypto.CreatePeerAnnouncement(wn.localPeerID)
	if err != nil {
		return err
	}
	bytesPayload, err := crypto.SerializePeerAnnouncement(announcement)
	if err != nil {
		return err
	}
	wrapper := wgMessage{
		Type:      "announcement",
		Payload:   hex.EncodeToString(bytesPayload),
		Timestamp: time.Now().Unix(),
		SenderID:  wn.localPeerID,
	}

	// always pass the remote address for announcements to ensure delivery
	err = wn.writeWrapper(wrapper, wn.remoteUDPAddr)
	if err == nil {
		wn.announcementSent = true
	}
	return err
}

func (wn *WireguardNetwork) sendKeyExchange(peerID string) error {
	keyEx, err := wn.pqCrypto.InitiateKeyExchange(peerID, wn.localPeerID)
	if err != nil {
		return err
	}
	bytesPayload, err := crypto.SerializeKeyExchange(keyEx)
	if err != nil {
		return err
	}
	wrapper := wgMessage{
		Type:      "keyexchange",
		Payload:   hex.EncodeToString(bytesPayload),
		Timestamp: time.Now().Unix(),
		SenderID:  wn.localPeerID,
	}

	// always pass the remote address for key exchange to ensure delivery
	return wn.writeWrapper(wrapper, wn.remoteUDPAddr)
}

// ForceKeyRotation performs a forward-secrecy key rotation and re-initiates the
// post-quantum handshake with every connected peer. It returns true if a
// rotation occurred (i.e. the interval elapsed) and false if no rotation was
// required.
func (wn *WireguardNetwork) ForceKeyRotation() (bool, error) {
	// Step 1: rotate our own cryptographic material
	rotated, err := wn.pqCrypto.RotateKeys()
	if err != nil || !rotated {
		return rotated, err
	}

	// Step 2: re-key with every connected peer
	wn.peersMutex.RLock()
	peerIDs := append([]string(nil), wn.connectedIDs...)
	wn.peersMutex.RUnlock()

	var aggErr error

	// allow new key exchanges for these peers
	wn.keyExchangeMutex.Lock()
	for _, pid := range peerIDs {
		wn.keyExchangeSent[pid] = false
	}
	wn.keyExchangeMutex.Unlock()

	for _, peerID := range peerIDs {
		if err := wn.sendKeyExchange(peerID); err != nil {
			// collect the first error – we still try others
			if aggErr == nil {
				aggErr = err
			}
		}
	}

	// Informational log – keep transport aware
	if len(peerIDs) > 0 {
		fmt.Printf("🔄 Keys rotated – re-established secrets with %d peer(s)\n", len(peerIDs))
	}

	return rotated, aggErr
}
