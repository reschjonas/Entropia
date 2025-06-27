package discovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/anacrolix/dht/v2"
	"github.com/anacrolix/torrent"
)

// StartDHTNode creates and starts a DHT server.
func StartDHTNode(port int) (*dht.Server, error) {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for dht: %w", err)
	}

	config := dht.NewDefaultServerConfig()
	config.Conn = conn
	config.NoSecurity = true // a public DHT node
	s, err := dht.NewServer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dht server: %w", err)
	}
	go s.Bootstrap()
	return s, nil
}

// AnnounceDHT announces our presence on the DHT for a given room ID.
func AnnounceDHT(ctx context.Context, server *dht.Server, roomID string, listenPort int) {
	infoHash := getInfoHash(roomID)
	ticker := time.NewTicker(3 * time.Minute) // announce periodically
	defer ticker.Stop()

	for {
		fmt.Printf("📢 Announcing room %s on DHT...\n", roomID[:8])
		_, err := server.Announce(infoHash, listenPort, true)
		if err != nil {
			fmt.Printf("⚠️ DHT announcement failed: %v\n", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			fmt.Println("🛑 Stopping DHT announcement.")
			return
		}
	}
}

// LookupDHT finds peers for a given room ID from the DHT.
func LookupDHT(ctx context.Context, server *dht.Server, roomID string, timeout time.Duration) (string, error) {
	infoHash := getInfoHash(roomID)
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ann, err := server.AnnounceTraversal(infoHash)
	if err != nil {
		return "", fmt.Errorf("failed to start dht traversal: %w", err)
	}
	defer ann.Close()

	for {
		select {
		case <-lookupCtx.Done():
			return "", fmt.Errorf("dht lookup timed out after %s", timeout)
		case peers := <-ann.Peers:
			for _, peer := range peers.Peers {
				if peer.Port == 0 {
					continue // skip peers that don't report a port
				}
				addr := net.TCPAddr{IP: peer.IP, Port: peer.Port}
				fmt.Printf("✅ Found peer via DHT: %s\n", addr.String())
				return addr.String(), nil
			}
		}
	}
}

// getInfoHash converts a roomID into a torrent.InfoHash.
func getInfoHash(roomID string) torrent.InfoHash {
	// Using the existing InfoHash function from the room package
	// is fine, but we need to convert it to the right type.
	// For simplicity here, we'll just hash it directly.
	h := sha256.Sum256([]byte(roomID))
	var ih torrent.InfoHash
	copy(ih[:], h[:20])
	return ih
}
