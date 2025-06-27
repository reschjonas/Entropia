package network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"quantterm/internal/crypto"

	"github.com/quic-go/quic-go"
)

// message is what we send over the QUIC stream
// payload is hex-encoded, serialized crypto structures
type message struct {
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Timestamp int64  `json:"timestamp"`
	SenderID  string `json:"sender_id"`
}

// QuicNetwork is a transport that uses QUIC for reliable, secure, and multiplexed communication.
type QuicNetwork struct {
	localPeerID string
	roomID      string
	pqCrypto    *crypto.PQCrypto

	ctx    context.Context
	cancel context.CancelFunc

	isListener bool
	listenPort int
	remoteAddr string

	incomingMessages chan *crypto.MessagePayload

	conn      quic.Connection
	connMutex sync.RWMutex

	peersMutex   sync.RWMutex
	connectedIDs []string

	// state tracking to prevent message spam
	announcementSent bool
	keyExchangeSent  map[string]bool
	keyExchangeMutex sync.RWMutex
}

// NewQuicNetwork creates the transport but doesn't start goroutines until Start
func NewQuicNetwork(ctx context.Context, peerID, roomID string, listenPort int, pq *crypto.PQCrypto, isListener bool, remoteAddr string) (*QuicNetwork, error) {
	netCtx, cancel := context.WithCancel(ctx)

	qn := &QuicNetwork{
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
	return qn, nil
}

// Start sets up the QUIC connection and launches the reader goroutine
func (qn *QuicNetwork) Start(ctx context.Context) error {
	if qn.isListener {
		return qn.listenQUIC()
	}
	return qn.dialQUIC()
}

// Stop closes the connection and cancels background work
func (qn *QuicNetwork) Stop() {
	qn.cancel()
	qn.connMutex.Lock()
	if qn.conn != nil {
		qn.conn.CloseWithError(0, "closing")
	}
	qn.connMutex.Unlock()
}

// SendMessage encrypts and sends a chat message to the peer
func (qn *QuicNetwork) SendMessage(ctx context.Context, msg string) error {
	qn.connMutex.RLock()
	conn := qn.conn
	qn.connMutex.RUnlock()
	if conn == nil {
		return fmt.Errorf("connection not established")
	}

	qn.peersMutex.RLock()
	if len(qn.connectedIDs) == 0 {
		qn.peersMutex.RUnlock()
		return fmt.Errorf("no verified peer connected")
	}
	peerID := qn.connectedIDs[0]
	qn.peersMutex.RUnlock()

	encMsg, err := qn.pqCrypto.EncryptMessageForPeer(msg, peerID, qn.localPeerID)
	if err != nil {
		return err
	}
	msgBytes, err := crypto.SerializeEncryptedMessage(encMsg)
	if err != nil {
		return err
	}

	wrapper := message{
		Type:      "message",
		Payload:   hex.EncodeToString(msgBytes),
		Timestamp: time.Now().Unix(),
		SenderID:  qn.localPeerID,
	}
	fmt.Printf("🔍 Sending message to peer %s, payload size: %d bytes\n", peerID[:8], len(msgBytes))
	return qn.writeWrapper(wrapper)
}

func (qn *QuicNetwork) GetIncomingMessages() <-chan *crypto.MessagePayload {
	return qn.incomingMessages
}

func (qn *QuicNetwork) GetConnectedPeers() []string {
	qn.peersMutex.RLock()
	defer qn.peersMutex.RUnlock()
	return append([]string(nil), qn.connectedIDs...)
}

func (qn *QuicNetwork) listenQUIC() error {
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to generate TLS config: %w", err)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", qn.listenPort)
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	fmt.Printf("📡 Listening on QUIC %s\n", addr)

	go qn.acceptLoop(listener)

	return nil
}

func (qn *QuicNetwork) acceptLoop(listener *quic.Listener) {
	defer listener.Close()
	// accept one connection for our 1-to-1 chat
	conn, err := listener.Accept(qn.ctx)
	if err != nil {
		fmt.Printf("🔌 Failed to accept connection: %v\n", err)
		return
	}

	qn.connMutex.Lock()
	qn.conn = conn
	qn.connMutex.Unlock()
	fmt.Printf("🤝 Peer connected from %s\n", conn.RemoteAddr().String())

	// joiner knows the remote address and can send announcement immediately
	// listener should send announcement after getting a connection
	if err := qn.sendPeerAnnouncement(); err != nil {
		fmt.Printf("❌ Failed to send peer announcement: %v\n", err)
	}

	qn.readLoop(conn)
}

func (qn *QuicNetwork) dialQUIC() error {
	if qn.remoteAddr == "" {
		return fmt.Errorf("remote address required for joiner")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // we use our own PQCrypto on top
		NextProtos:         []string{"quantterm-chat"},
	}

	conn, err := quic.DialAddr(qn.ctx, qn.remoteAddr, tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", qn.remoteAddr, err)
	}

	qn.connMutex.Lock()
	qn.conn = conn
	qn.connMutex.Unlock()

	fmt.Printf("✅ Connected to peer via QUIC (%s)\n", conn.RemoteAddr().String())

	// joiner knows the remote address and can send announcement immediately
	if err := qn.sendPeerAnnouncement(); err != nil {
		return err
	}

	go qn.readLoop(conn)

	return nil
}

func (qn *QuicNetwork) readLoop(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(qn.ctx)
		if err != nil {
			fmt.Printf("🔌 Connection error: %v\n", err)
			qn.Stop()
			return
		}
		go qn.handleStream(stream)
	}
}

func (qn *QuicNetwork) handleStream(stream quic.Stream) {
	defer stream.Close()
	decoder := json.NewDecoder(stream)
	var wrapper message
	if err := decoder.Decode(&wrapper); err != nil {
		fmt.Printf("🔍 Received invalid message: %v\n", err)
		return
	}
	fmt.Printf("🔍 Received %s message from %s, size: %d bytes\n", wrapper.Type, wrapper.SenderID[:8], len(wrapper.Payload))
	qn.handleWrapper(wrapper)
}

func (qn *QuicNetwork) writeWrapper(w message) error {
	qn.connMutex.RLock()
	conn := qn.conn
	qn.connMutex.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection closed")
	}

	stream, err := conn.OpenStreamSync(qn.ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	encoder := json.NewEncoder(stream)
	return encoder.Encode(w)
}

func (qn *QuicNetwork) handleWrapper(w message) {
	switch w.Type {
	case "announcement":
		qn.handlePeerAnnouncement(w)
	case "keyexchange":
		qn.handleKeyExchange(w)
	case "message":
		qn.handleEncryptedChat(w)
	}
}

func (qn *QuicNetwork) handlePeerAnnouncement(w message) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		return
	}
	announcement, err := crypto.DeserializePeerAnnouncement(bytesPayload)
	if err != nil {
		return
	}
	if err := qn.pqCrypto.ProcessPeerAnnouncement(announcement); err != nil {
		fmt.Printf("❌ Invalid peer announcement: %v\n", err)
		return
	}

	qn.peersMutex.Lock()
	qn.connectedIDs = []string{announcement.PeerID}
	qn.peersMutex.Unlock()

	if !qn.announcementSent {
		if err := qn.sendPeerAnnouncement(); err == nil {
			qn.announcementSent = true
		}
	}

	qn.keyExchangeMutex.Lock()
	alreadySent := qn.keyExchangeSent[announcement.PeerID]
	if !alreadySent {
		qn.keyExchangeSent[announcement.PeerID] = true
	}
	qn.keyExchangeMutex.Unlock()

	if !alreadySent {
		if err := qn.sendKeyExchange(announcement.PeerID); err != nil {
			fmt.Printf("❌ Key exchange failed: %v\n", err)
			qn.keyExchangeMutex.Lock()
			qn.keyExchangeSent[announcement.PeerID] = false
			qn.keyExchangeMutex.Unlock()
		}
	}
}

func (qn *QuicNetwork) handleKeyExchange(w message) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		return
	}
	keyEx, err := crypto.DeserializeKeyExchange(bytesPayload)
	if err != nil {
		return
	}
	if err := qn.pqCrypto.ProcessKeyExchange(keyEx); err != nil {
		fmt.Printf("❌ Invalid key exchange: %v\n", err)
		return
	}
	fmt.Printf("🔐 Secure channel established with peer %s\n", keyEx.SenderID[:8])
}

func (qn *QuicNetwork) handleEncryptedChat(w message) {
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
	payload, err := qn.pqCrypto.DecryptMessageFromPeer(encMsg)
	if err != nil {
		fmt.Printf("🔍 Message decryption error: %v\n", err)
		return
	}
	select {
	case qn.incomingMessages <- payload:
	default:
		fmt.Printf("🔍 Message channel full, dropping message\n")
	}
}

func (qn *QuicNetwork) sendPeerAnnouncement() error {
	announcement, err := qn.pqCrypto.CreatePeerAnnouncement(qn.localPeerID)
	if err != nil {
		return err
	}
	bytesPayload, err := crypto.SerializePeerAnnouncement(announcement)
	if err != nil {
		return err
	}
	wrapper := message{
		Type:      "announcement",
		Payload:   hex.EncodeToString(bytesPayload),
		Timestamp: time.Now().Unix(),
		SenderID:  qn.localPeerID,
	}

	err = qn.writeWrapper(wrapper)
	if err == nil {
		qn.announcementSent = true
	}
	return err
}

func (qn *QuicNetwork) sendKeyExchange(peerID string) error {
	keyEx, err := qn.pqCrypto.InitiateKeyExchange(peerID, qn.localPeerID)
	if err != nil {
		return err
	}
	bytesPayload, err := crypto.SerializeKeyExchange(keyEx)
	if err != nil {
		return err
	}
	wrapper := message{
		Type:      "keyexchange",
		Payload:   hex.EncodeToString(bytesPayload),
		Timestamp: time.Now().Unix(),
		SenderID:  qn.localPeerID,
	}
	return qn.writeWrapper(wrapper)
}

func (qn *QuicNetwork) ForceKeyRotation() (bool, error) {
	rotated, err := qn.pqCrypto.RotateKeys()
	if err != nil || !rotated {
		return rotated, err
	}

	qn.peersMutex.RLock()
	peerIDs := append([]string(nil), qn.connectedIDs...)
	qn.peersMutex.RUnlock()

	var aggErr error

	qn.keyExchangeMutex.Lock()
	for _, pid := range peerIDs {
		qn.keyExchangeSent[pid] = false
	}
	qn.keyExchangeMutex.Unlock()

	for _, peerID := range peerIDs {
		if err := qn.sendKeyExchange(peerID); err != nil {
			if aggErr == nil {
				aggErr = err
			}
		}
	}

	if len(peerIDs) > 0 {
		fmt.Printf("🔄 Keys rotated – re-established secrets with %d peer(s)\n", len(peerIDs))
	}

	return rotated, aggErr
}

// generateTLSConfig sets up a ephemeral, self-signed TLS config for the QUIC listener
func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"QuantTerm"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:   []string{"quantterm-chat"},
	}, nil
}
