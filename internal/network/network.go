package network

import (
	"context"

	"entropia/internal/crypto"
)

// Network is the common interface for all transport layers
type Network interface {
	// start the network transport and message handling
	Start(ctx context.Context) error

	// stop the network transport
	Stop()

	// encrypt and send a message to all verified peers
	SendMessage(ctx context.Context, message string) error

	// get the channel for incoming messages
	GetIncomingMessages() <-chan *crypto.MessagePayload

	// get the list of connected peer IDs
	GetConnectedPeers() []string

	// ForceKeyRotation triggers an immediate key rotation and re-establishes
	// fresh shared secrets with all connected peers. It returns a boolean that
	// indicates whether a rotation actually took place.
	ForceKeyRotation() (bool, error)

	// get the channel where the transport reports asynchronous errors
	GetErrorChannel() <-chan error

	// IsListener returns true if the network is a listener (creator)
	IsListener() bool
}

// NewNetwork returns a QUIC-based transport.
// if isListener is true (room creator) it listens, otherwise dials remoteAddr
func NewNetwork(ctx context.Context, peerID, roomID string, listenPort int, pqCrypto *crypto.PQCrypto, isListener bool, remoteAddr string) (Network, error) {
	return NewQuicNetwork(ctx, peerID, roomID, listenPort, pqCrypto, isListener, remoteAddr)
}
