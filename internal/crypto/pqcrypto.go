package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign"
	mode5 "github.com/cloudflare/circl/sign/dilithium/mode5"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidKeySize    = errors.New("invalid key size")
	ErrInvalidNonceSize  = errors.New("invalid nonce size")
	ErrPeerNotFound      = errors.New("peer not found")
	ErrInvalidHandshake  = errors.New("invalid handshake")
	ErrKeyRotationFailed = errors.New("key rotation failed")
)

// message types for our protocol
const (
	MessageTypeChat             = 1
	MessageTypeKeyExchange      = 2
	MessageTypeKeyRotation      = 3
	MessageTypePeerAnnouncement = 4
)

// PQCrypto handles all post-quantum crypto operations
type PQCrypto struct {
	// Kyber for key exchange
	kemScheme kem.Scheme

	// Dilithium5 signature scheme from CIRCL generic interface
	sigScheme sign.Scheme

	// our long-term identity keys
	identityKEMPrivateKey kem.PrivateKey
	identityKEMPublicKey  kem.PublicKey
	identitySigPrivateKey sign.PrivateKey
	identitySigPublicKey  sign.PublicKey

	// ephemeral keys for forward secrecy
	ephemeralKEMPrivateKey kem.PrivateKey
	ephemeralKEMPublicKey  kem.PublicKey

	// peer state tracking
	peers      map[string]*PeerCryptoState
	peersMutex sync.RWMutex

	// key rotation
	keyRotationInterval time.Duration
	lastKeyRotation     time.Time
}

// PeerCryptoState holds crypto state for each peer
type PeerCryptoState struct {
	PeerID                string
	IdentityKEMPublicKey  []byte
	IdentitySigPublicKey  []byte
	CurrentSharedSecret   []byte
	PreviousSharedSecret  []byte // for forward secrecy during rotation
	LastMessageTime       time.Time
	LastKeyRotation       time.Time
	Verified              bool // whether we've verified this peer
	TrustFingerprint      string
	EphemeralKEMPublicKey []byte // newly tracked peer ephemeral key
}

// KeyExchangeMessage is for the handshake
type KeyExchangeMessage struct {
	Version            uint8     `json:"version"`
	Type               uint8     `json:"type"`
	SenderID           string    `json:"sender_id"`
	IdentityKEMPubKey  []byte    `json:"identity_kem_pub_key"`
	IdentitySigPubKey  []byte    `json:"identity_sig_pub_key"`
	EphemeralKEMPubKey []byte    `json:"ephemeral_kem_pub_key"`
	KEMCiphertext      []byte    `json:"kem_ciphertext"`
	Signature          []byte    `json:"signature"`
	Timestamp          time.Time `json:"timestamp"`
	Nonce              []byte    `json:"nonce"`
}

// EncryptedMessage is for encrypted chat messages
type EncryptedMessage struct {
	Version          uint8     `json:"version"`
	Type             uint8     `json:"type"`
	SenderID         string    `json:"sender_id"`
	RecipientID      string    `json:"recipient_id"`
	Signature        []byte    `json:"signature"`
	EncryptedPayload []byte    `json:"encrypted_payload"`
	Timestamp        time.Time `json:"timestamp"`
	KeyRotationEpoch uint64    `json:"key_rotation_epoch"` // for forward secrecy
	Salt             []byte    `json:"salt"`               // public salt for HKDF
}

// MessagePayload is the decrypted message content
type MessagePayload struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	SenderID  string    `json:"sender_id"`
	MessageID string    `json:"message_id"`
}

// PeerAnnouncement is for broadcasting our identity
type PeerAnnouncement struct {
	Version            uint8     `json:"version"`
	Type               uint8     `json:"type"`
	PeerID             string    `json:"peer_id"`
	IdentityKEMPubKey  []byte    `json:"identity_kem_pub_key"`
	IdentitySigPubKey  []byte    `json:"identity_sig_pub_key"`
	TrustFingerprint   string    `json:"trust_fingerprint"`
	TLSCertFingerprint string    `json:"tls_cert_fp"`
	Signature          []byte    `json:"signature"`
	Timestamp          time.Time `json:"timestamp"`
}

// NewPQCrypto creates a new post-quantum crypto instance
func NewPQCrypto() (*PQCrypto, error) {
	pq := &PQCrypto{
		kemScheme:           kyber1024.Scheme(),
		sigScheme:           mode5.Scheme(),
		peers:               make(map[string]*PeerCryptoState),
		keyRotationInterval: 15 * time.Minute, // rotate keys every 15 minutes
		lastKeyRotation:     time.Now(),
	}

	// generate our identity keys
	if err := pq.generateIdentityKeyPairs(); err != nil {
		return nil, fmt.Errorf("failed to generate identity keys: %w", err)
	}

	// generate initial ephemeral keys
	if err := pq.generateEphemeralKeyPairs(); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keys: %w", err)
	}

	return pq, nil
}

// generate our long-term identity keys
func (pq *PQCrypto) generateIdentityKeyPairs() error {
	// generate Kyber key pair for key exchange
	kemPub, kemPriv, err := pq.kemScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	pq.identityKEMPublicKey = kemPub
	pq.identityKEMPrivateKey = kemPriv

	// generate Dilithium key pair for signatures
	sigPub, sigPriv, err := pq.sigScheme.GenerateKey()
	if err != nil {
		return err
	}
	pq.identitySigPublicKey = sigPub
	pq.identitySigPrivateKey = sigPriv

	return nil
}

// generate ephemeral keys for forward secrecy
func (pq *PQCrypto) generateEphemeralKeyPairs() error {
	kemPub, kemPriv, err := pq.kemScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	pq.ephemeralKEMPublicKey = kemPub
	pq.ephemeralKEMPrivateKey = kemPriv
	return nil
}

// GetIdentityPublicKeys returns our identity public keys
func (pq *PQCrypto) GetIdentityPublicKeys() ([]byte, []byte) {
	kemPubBytes, _ := pq.identityKEMPublicKey.MarshalBinary()
	sigPubBytes, _ := pq.identitySigPublicKey.MarshalBinary()
	return kemPubBytes, sigPubBytes
}

// GetEphemeralKEMPublicKey returns our current ephemeral key
func (pq *PQCrypto) GetEphemeralKEMPublicKey() []byte {
	kemPubBytes, _ := pq.ephemeralKEMPublicKey.MarshalBinary()
	return kemPubBytes
}

// CreatePeerAnnouncement creates a signed announcement of our identity
func (pq *PQCrypto) CreatePeerAnnouncement(peerID string, certFingerprint string) (*PeerAnnouncement, error) {
	kemPubBytes, sigPubBytes := pq.GetIdentityPublicKeys()
	fingerprint, err := pq.GetIdentityFingerprint()
	if err != nil {
		return nil, err
	}

	announcement := &PeerAnnouncement{
		Version:            1,
		Type:               MessageTypePeerAnnouncement,
		PeerID:             peerID,
		IdentityKEMPubKey:  kemPubBytes,
		IdentitySigPubKey:  sigPubBytes,
		TrustFingerprint:   fingerprint,
		TLSCertFingerprint: certFingerprint,
		Timestamp:          time.Now(),
	}

	// sign it
	signData, err := getSignableDataForPeerAnnouncement(announcement)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize announcement for signing: %w", err)
	}
	signature := pq.sigScheme.Sign(pq.identitySigPrivateKey, signData, nil)
	announcement.Signature = signature

	return announcement, nil
}

// ProcessPeerAnnouncement handles incoming peer announcements
func (pq *PQCrypto) ProcessPeerAnnouncement(announcement *PeerAnnouncement) error {
	// verify the signature
	signData, err := getSignableDataForPeerAnnouncement(announcement)
	if err != nil {
		return fmt.Errorf("failed to serialize announcement for verification: %w", err)
	}

	// convert signature public key
	sigPub, err := pq.sigScheme.UnmarshalBinaryPublicKey(announcement.IdentitySigPubKey)
	if err != nil {
		return ErrInvalidKeySize
	}

	if !pq.sigScheme.Verify(sigPub, signData, announcement.Signature, nil) {
		return ErrInvalidSignature
	}

	// store peer info
	pq.peersMutex.Lock()
	defer pq.peersMutex.Unlock()

	if peer, exists := pq.peers[announcement.PeerID]; exists {
		// update existing peer
		peer.IdentityKEMPublicKey = announcement.IdentityKEMPubKey
		peer.IdentitySigPublicKey = announcement.IdentitySigPubKey
		peer.TrustFingerprint = announcement.TrustFingerprint
	} else {
		// create new peer
		pq.peers[announcement.PeerID] = &PeerCryptoState{
			PeerID:               announcement.PeerID,
			IdentityKEMPublicKey: announcement.IdentityKEMPubKey,
			IdentitySigPublicKey: announcement.IdentitySigPubKey,
			TrustFingerprint:     announcement.TrustFingerprint,
			LastMessageTime:      time.Now(),
			Verified:             true, // signature verified
		}
	}

	return nil
}

// InitiateKeyExchange starts key exchange with a peer
func (pq *PQCrypto) InitiateKeyExchange(peerID string, senderID string) (*KeyExchangeMessage, error) {
	pq.peersMutex.RLock()
	peer, exists := pq.peers[peerID]
	pq.peersMutex.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	// unmarshal peer's identity KEM public key
	peerIdentityKEMPub, err := pq.kemScheme.UnmarshalBinaryPublicKey(peer.IdentityKEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer KEM key: %w", err)
	}

	// decide which peer public key to encapsulate to – prefer peer's *ephemeral* key when we have one
	var peerKEMPub kem.PublicKey
	if len(peer.EphemeralKEMPublicKey) > 0 {
		// we already know a recent ephemeral key for this peer – use it for forward secrecy
		peerKEMPub, err = pq.kemScheme.UnmarshalBinaryPublicKey(peer.EphemeralKEMPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal peer ephemeral KEM key: %w", err)
		}
	} else {
		peerKEMPub = peerIdentityKEMPub
	}

	// do key encapsulation with chosen key
	ciphertext, sharedSecret, err := pq.kemScheme.Encapsulate(peerKEMPub)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	// get our public keys
	identityKEMPubBytes, identitySigPubBytes := pq.GetIdentityPublicKeys()
	ephemeralKEMPubBytes := pq.GetEphemeralKEMPublicKey()

	// generate nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// use consistent timestamp for key rotation epoch
	now := time.Now()

	keyExchange := &KeyExchangeMessage{
		Version:            1,
		Type:               MessageTypeKeyExchange,
		SenderID:           senderID,
		IdentityKEMPubKey:  identityKEMPubBytes,
		IdentitySigPubKey:  identitySigPubBytes,
		EphemeralKEMPubKey: ephemeralKEMPubBytes,
		KEMCiphertext:      ciphertext,
		Timestamp:          now,
		Nonce:              nonce,
	}

	// sign the key exchange message
	signData, err := getSignableDataForKeyExchange(keyExchange)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key exchange for signing: %w", err)
	}
	signature := pq.sigScheme.Sign(pq.identitySigPrivateKey, signData, nil)
	keyExchange.Signature = signature

	// store the shared secret
	pq.peersMutex.Lock()
	peer.CurrentSharedSecret = sharedSecret
	peer.LastKeyRotation = now
	peer.LastMessageTime = now
	pq.peersMutex.Unlock()

	return keyExchange, nil
}

// ProcessKeyExchange handles incoming key exchange messages
func (pq *PQCrypto) ProcessKeyExchange(keyExchange *KeyExchangeMessage) error {
	// verify signature
	signData, err := getSignableDataForKeyExchange(keyExchange)
	if err != nil {
		return fmt.Errorf("failed to serialize key exchange for verification: %w", err)
	}

	sigPub, err := pq.sigScheme.UnmarshalBinaryPublicKey(keyExchange.IdentitySigPubKey)
	if err != nil {
		return ErrInvalidKeySize
	}

	if !pq.sigScheme.Verify(sigPub, signData, keyExchange.Signature, nil) {
		return ErrInvalidSignature
	}

	// validate ciphertext size
	expectedSize := pq.kemScheme.CiphertextSize()
	actualSize := len(keyExchange.KEMCiphertext)
	if actualSize != expectedSize {
		return fmt.Errorf("invalid ciphertext size: expected %d, got %d", expectedSize, actualSize)
	}

	// First try with our identity private key (legacy)
	sharedSecret, err := pq.kemScheme.Decapsulate(pq.identityKEMPrivateKey, keyExchange.KEMCiphertext)
	if err != nil {
		// If that fails, attempt with our *current ephemeral* private key – this allows peers
		// to encapsulate to our short-lived key for stronger forward secrecy.
		sharedSecret, err = pq.kemScheme.Decapsulate(pq.ephemeralKEMPrivateKey, keyExchange.KEMCiphertext)
		if err != nil {
			return fmt.Errorf("failed to decapsulate: %w", err)
		}
	}

	// use sender's timestamp as the agreed key rotation epoch
	rotationTime := keyExchange.Timestamp
	if rotationTime.IsZero() {
		rotationTime = time.Now()
	}

	// store or update peer info
	pq.peersMutex.Lock()
	defer pq.peersMutex.Unlock()

	if peer, exists := pq.peers[keyExchange.SenderID]; exists {
		// update stored peer data
		peer.EphemeralKEMPublicKey = keyExchange.EphemeralKEMPubKey
		// only update if this is a newer key rotation or we have no secret yet
		if len(peer.CurrentSharedSecret) == 0 || rotationTime.After(peer.LastKeyRotation) {
			// keep previous secret for messages in flight
			peer.PreviousSharedSecret = peer.CurrentSharedSecret
			peer.CurrentSharedSecret = sharedSecret
			peer.LastKeyRotation = rotationTime
		} else if rotationTime.Before(peer.LastKeyRotation) {
			// older epoch - keep as previous secret for compatibility
			peer.PreviousSharedSecret = sharedSecret
		}
		peer.Verified = true
	} else {
		// create new peer
		pq.peers[keyExchange.SenderID] = &PeerCryptoState{
			PeerID:                keyExchange.SenderID,
			IdentityKEMPublicKey:  keyExchange.IdentityKEMPubKey,
			IdentitySigPublicKey:  keyExchange.IdentitySigPubKey,
			EphemeralKEMPublicKey: keyExchange.EphemeralKEMPubKey,
			CurrentSharedSecret:   sharedSecret,
			LastKeyRotation:       rotationTime,
			LastMessageTime:       time.Now(),
			Verified:              true,
		}
	}

	return nil
}

// EncryptMessageForPeer encrypts a message for a specific peer
func (pq *PQCrypto) EncryptMessageForPeer(message, peerID, senderID string) (*EncryptedMessage, error) {
	pq.peersMutex.RLock()
	peer, exists := pq.peers[peerID]
	pq.peersMutex.RUnlock()

	if !exists || len(peer.CurrentSharedSecret) == 0 {
		return nil, ErrPeerNotFound
	}

	// create message payload
	messageID := generateMessageID()
	payload := MessagePayload{
		Timestamp: time.Now(),
		Message:   message,
		SenderID:  senderID,
		MessageID: messageID,
	}

	// serialize payload
	payloadBytes, err := SerializePayload(payload)
	if err != nil {
		return nil, err
	}

	// generate random salt for HKDF
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// prepare message header (without payload yet) so we can compute AAD
	encMsg := &EncryptedMessage{
		Version:          1,
		Type:             MessageTypeChat,
		SenderID:         senderID,
		RecipientID:      peerID,
		Timestamp:        time.Now(),
		KeyRotationEpoch: uint64(peer.LastKeyRotation.Unix()),
		Salt:             salt,
	}

	// derive encryption key from shared secret
	encKey, err := deriveKeyWithSalt(peer.CurrentSharedSecret, salt, "message_encryption", 32)
	if err != nil {
		return nil, err
	}

	cipher, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	// make random nonce
	nonce := make([]byte, cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aad, err := getAADForEncryptedHeader(encMsg)
	if err != nil {
		return nil, err
	}

	encryptedPayload := cipher.Seal(nonce, nonce, payloadBytes, aad)
	encMsg.EncryptedPayload = encryptedPayload

	// sign the message
	signData, err := getSignableDataForEncryptedMessage(encMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message for signing: %w", err)
	}
	signature := pq.sigScheme.Sign(pq.identitySigPrivateKey, signData, nil)
	encMsg.Signature = signature

	return encMsg, nil
}

// DecryptMessageFromPeer decrypts a message from a peer
func (pq *PQCrypto) DecryptMessageFromPeer(encMsg *EncryptedMessage) (*MessagePayload, error) {
	pq.peersMutex.RLock()
	peer, exists := pq.peers[encMsg.SenderID]
	pq.peersMutex.RUnlock()

	if !exists {
		return nil, ErrPeerNotFound
	}

	// verify signature
	signData, err := getSignableDataForEncryptedMessage(encMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message for verification: %w", err)
	}

	sigPub, err := pq.sigScheme.UnmarshalBinaryPublicKey(peer.IdentitySigPublicKey)
	if err != nil {
		return nil, ErrInvalidKeySize
	}

	if !pq.sigScheme.Verify(sigPub, signData, encMsg.Signature, nil) {
		return nil, ErrInvalidSignature
	}

	// choose the right shared secret based on key rotation epoch
	var sharedSecret []byte
	currentEpoch := uint64(peer.LastKeyRotation.Unix())

	if encMsg.KeyRotationEpoch == currentEpoch {
		sharedSecret = peer.CurrentSharedSecret
	} else if len(peer.PreviousSharedSecret) > 0 {
		sharedSecret = peer.PreviousSharedSecret
	} else {
		return nil, ErrDecryptionFailed
	}

	// derive decryption key
	var decKey []byte
	if len(encMsg.Salt) > 0 {
		decKey, err = deriveKeyWithSalt(sharedSecret, encMsg.Salt, "message_encryption", 32)
	} else {
		decKey, err = deriveKey(sharedSecret, "message_encryption", 32) // legacy messages
	}
	if err != nil {
		return nil, err
	}

	// create ChaCha20-Poly1305 cipher
	cipher, err := chacha20poly1305.NewX(decKey)
	if err != nil {
		return nil, err
	}

	// extract nonce and encrypted data
	if len(encMsg.EncryptedPayload) < cipher.NonceSize() {
		return nil, ErrInvalidNonceSize
	}

	nonce := encMsg.EncryptedPayload[:cipher.NonceSize()]
	ciphertext := encMsg.EncryptedPayload[cipher.NonceSize():]

	// decrypt payload
	aad, err := getAADForEncryptedHeader(encMsg)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// deserialize payload
	payload, err := DeserializePayload(payloadBytes)
	if err != nil {
		return nil, err
	}

	// update peer's last message time
	pq.peersMutex.Lock()
	peer.LastMessageTime = time.Now()
	pq.peersMutex.Unlock()

	return payload, nil
}

// RotateKeys rotates the cryptographic material for forward secrecy.
// It returns a boolean that is true when a rotation was performed
// and false if the rotation interval has not yet elapsed.
func (pq *PQCrypto) RotateKeys() (bool, error) {
	now := time.Now()
	if now.Sub(pq.lastKeyRotation) < pq.keyRotationInterval {
		return false, nil // rotation not due yet
	}

	// generate new ephemeral keys
	if err := pq.generateEphemeralKeyPairs(); err != nil {
		return false, ErrKeyRotationFailed
	}

	pq.peersMutex.Lock()
	defer pq.peersMutex.Unlock()

	// for each peer, rotate their keys
	for _, peer := range pq.peers {
		// move current to previous
		peer.PreviousSharedSecret = peer.CurrentSharedSecret
		// clear current (will be re-established through new key exchange)
		peer.CurrentSharedSecret = nil
	}

	pq.lastKeyRotation = now
	return true, nil
}

// GetVerifiedPeers returns verified peer IDs
func (pq *PQCrypto) GetVerifiedPeers() []string {
	pq.peersMutex.RLock()
	defer pq.peersMutex.RUnlock()

	var peers []string
	for peerID, peer := range pq.peers {
		if peer.Verified && len(peer.CurrentSharedSecret) > 0 {
			peers = append(peers, peerID)
		}
	}
	return peers
}

// GetPeerFingerprint returns the trust fingerprint for a peer
func (pq *PQCrypto) GetPeerFingerprint(peerID string) (string, error) {
	pq.peersMutex.RLock()
	defer pq.peersMutex.RUnlock()

	if peer, exists := pq.peers[peerID]; exists {
		return peer.TrustFingerprint, nil
	}
	return "", ErrPeerNotFound
}

// GetIdentityFingerprint returns our identity fingerprint
func (pq *PQCrypto) GetIdentityFingerprint() (string, error) {
	kemPubBytes, _ := pq.identityKEMPublicKey.MarshalBinary()
	sigPubBytes, _ := pq.identitySigPublicKey.MarshalBinary()

	hash := sha256.New()
	hash.Write(kemPubBytes)
	hash.Write(sigPubBytes)

	fingerprint := hash.Sum(nil)
	return hex.EncodeToString(fingerprint[:16]), nil // first 16 bytes as hex
}

// serialize announcement for signing (without signature field)
func getSignableDataForPeerAnnouncement(announcement *PeerAnnouncement) ([]byte, error) {
	announcementToSign := *announcement
	announcementToSign.Signature = nil
	return SerializePeerAnnouncement(&announcementToSign)
}

// serialize key exchange for signing
func getSignableDataForKeyExchange(keyExchange *KeyExchangeMessage) ([]byte, error) {
	keyExchangeToSign := *keyExchange
	keyExchangeToSign.Signature = nil
	return SerializeKeyExchange(&keyExchangeToSign)
}

// serialize encrypted message for signing
func getSignableDataForEncryptedMessage(encMsg *EncryptedMessage) ([]byte, error) {
	msgToSign := *encMsg
	msgToSign.Signature = nil
	return SerializeEncryptedMessage(&msgToSign)
}

// derive key from shared secret using HKDF
func deriveKey(sharedSecret []byte, info string, length int) ([]byte, error) {
	// use deterministic salt
	saltHash := sha256.New()
	saltHash.Write(sharedSecret)
	saltHash.Write([]byte(info))
	saltHash.Write([]byte("salt"))
	salt := saltHash.Sum(nil)

	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))

	key := make([]byte, length)
	if _, err := hkdf.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// deriveKeyWithSalt derives a key from shared secret and *explicit* random salt.
// This replaces deriveKey for new messages while keeping compatibility with
// legacy ciphertexts that have no salt field.
func deriveKeyWithSalt(sharedSecret []byte, salt []byte, info string, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, length)
	if _, err := hkdf.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// generate a unique message ID
func generateMessageID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getAADForEncryptedHeader returns JSON of header fields (no payload nor signature) for AEAD additional data
func getAADForEncryptedHeader(encMsg *EncryptedMessage) ([]byte, error) {
	header := struct {
		Version          uint8     `json:"version"`
		Type             uint8     `json:"type"`
		SenderID         string    `json:"sender_id"`
		RecipientID      string    `json:"recipient_id"`
		Timestamp        time.Time `json:"timestamp"`
		KeyRotationEpoch uint64    `json:"key_rotation_epoch"`
		Salt             []byte    `json:"salt"`
	}{
		Version:          encMsg.Version,
		Type:             encMsg.Type,
		SenderID:         encMsg.SenderID,
		RecipientID:      encMsg.RecipientID,
		Timestamp:        encMsg.Timestamp,
		KeyRotationEpoch: encMsg.KeyRotationEpoch,
		Salt:             encMsg.Salt,
	}
	return json.Marshal(header)
}
