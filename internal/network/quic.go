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

	"entropia/internal/crypto"
	"entropia/internal/logger"

	"crypto/sha256"

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

	// asynchronous error reporting
	errorChan chan error

	conn      quic.Connection
	connMutex sync.RWMutex

	peersMutex   sync.RWMutex
	connectedIDs []string

	// state tracking to prevent message spam
	announcementSent bool
	keyExchangeSent  map[string]bool
	keyExchangeMutex sync.RWMutex

	// certificate fingerprints
	localCertFingerprint string
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
		errorChan:        make(chan error, 10),
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
	logger.L().Debug("Sending message", "peer", peerID[:8], "size", len(msgBytes))
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

func (qn *QuicNetwork) GetErrorChannel() <-chan error {
	return qn.errorChan
}

func (qn *QuicNetwork) sendError(err error) {
	select {
	case qn.errorChan <- err:
	default:
		// channel full; drop to avoid blocking inside critical paths
	}
}

func (qn *QuicNetwork) listenQUIC() error {
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to generate TLS config: %w", err)
	}

	// compute fingerprint of our first certificate
	if len(tlsConfig.Certificates) > 0 && len(tlsConfig.Certificates[0].Certificate) > 0 {
		fp := sha256.Sum256(tlsConfig.Certificates[0].Certificate[0])
		qn.localCertFingerprint = hex.EncodeToString(fp[:])
	}

	addr := fmt.Sprintf("0.0.0.0:%d", qn.listenPort)
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	logger.L().Info("Listening on QUIC", "addr", addr)

	go qn.acceptLoop(listener)

	return nil
}

func (qn *QuicNetwork) acceptLoop(listener *quic.Listener) {
	defer listener.Close()
	// accept one connection for our 1-to-1 chat
	conn, err := listener.Accept(qn.ctx)
	if err != nil {
		logger.L().Error("Accept error", "err", err)
		qn.sendError(err)
		return
	}

	qn.connMutex.Lock()
	qn.conn = conn
	qn.connMutex.Unlock()
	logger.L().Info("Peer connected", "remote", conn.RemoteAddr().String())

	// joiner knows the remote address and can send announcement immediately
	// listener should send announcement after getting a connection
	if err := qn.sendPeerAnnouncement(); err != nil {
		logger.L().Error("Peer announcement send failed", "err", err)
	}

	qn.readLoop(conn)
}

func (qn *QuicNetwork) dialQUIC() error {
	if qn.remoteAddr == "" {
		return fmt.Errorf("remote address required for joiner")
	}

	tlsCfg, err := generateTLSConfig()
	if err != nil {
		return err
	}
	tlsCfg.InsecureSkipVerify = true // still skip PKI validation

	if len(tlsCfg.Certificates) > 0 && len(tlsCfg.Certificates[0].Certificate) > 0 {
		fp := sha256.Sum256(tlsCfg.Certificates[0].Certificate[0])
		qn.localCertFingerprint = hex.EncodeToString(fp[:])
	}

	conn, err := quic.DialAddr(qn.ctx, qn.remoteAddr, tlsCfg, nil)
	if err != nil {
		qn.sendError(err)
		return fmt.Errorf("failed to dial %s: %w", qn.remoteAddr, err)
	}

	qn.connMutex.Lock()
	qn.conn = conn
	qn.connMutex.Unlock()

	logger.L().Info("Dialed peer", "remote", conn.RemoteAddr().String())

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
			logger.L().Error("Connection stream error", "err", err)
			qn.sendError(err)
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
		logger.L().Warn("Invalid message", "err", err)
		return
	}
	logger.L().Debug("Received wrapper", "type", wrapper.Type, "from", wrapper.SenderID[:8], "size", len(wrapper.Payload))
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
		qn.sendError(err)
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
		logger.L().Warn("Invalid peer announcement", "err", err)
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
			logger.L().Error("Key exchange failed", "err", err)
			qn.keyExchangeMutex.Lock()
			qn.keyExchangeSent[announcement.PeerID] = false
			qn.keyExchangeMutex.Unlock()
		}
	}

	// verify remote certificate hash matches announced fingerprint
	tlsState := qn.conn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) > 0 {
		hash := sha256.Sum256(tlsState.PeerCertificates[0].Raw)
		remoteFp := hex.EncodeToString(hash[:])
		if remoteFp != announcement.TLSCertFingerprint {
			logger.L().Warn("TLS certificate fingerprint mismatch; possible MITM")
			qn.sendError(fmt.Errorf("tls fingerprint mismatch"))
			return
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
		logger.L().Warn("Invalid key exchange", "err", err)
		return
	}
	logger.L().Info("Secure channel established", "peer", keyEx.SenderID[:8])
}

func (qn *QuicNetwork) handleEncryptedChat(w message) {
	bytesPayload, err := hex.DecodeString(w.Payload)
	if err != nil {
		logger.L().Warn("Message decode error", "err", err)
		return
	}
	encMsg, err := crypto.DeserializeEncryptedMessage(bytesPayload)
	if err != nil {
		logger.L().Warn("Message deserialization error", "err", err)
		return
	}
	payload, err := qn.pqCrypto.DecryptMessageFromPeer(encMsg)
	if err != nil {
		logger.L().Warn("Message decryption error", "err", err)
		return
	}
	select {
	case qn.incomingMessages <- payload:
	default:
		logger.L().Warn("Incoming message channel full; dropping")
	}
}

func (qn *QuicNetwork) sendPeerAnnouncement() error {
	announcement, err := qn.pqCrypto.CreatePeerAnnouncement(qn.localPeerID, qn.localCertFingerprint)
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
		logger.L().Info("Keys rotated", "peers", len(peerIDs))
	}

	return rotated, aggErr
}

// IsListener returns true if the network is a listener (creator)
func (qn *QuicNetwork) IsListener() bool {
	return qn.isListener
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
			Organization: []string{"Entropia"},
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
		NextProtos:   []string{"entropia-chat"},
	}, nil
}
