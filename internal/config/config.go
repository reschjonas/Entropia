package config

import (
	"time"
)

// Config holds all app configuration
type Config struct {
	// Network configuration
	Network NetworkConfig

	// Cryptography configuration
	Crypto CryptoConfig

	// UI configuration
	UI UIConfig

	// Discovery configuration
	Discovery DiscoveryConfig
}

// NetworkConfig holds networking settings
type NetworkConfig struct {
	// port range for listening
	MinPort int
	MaxPort int

	// connection timeouts
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// max peers per room
	MaxPeers int
}

// CryptoConfig holds crypto settings
type CryptoConfig struct {
	// post-quantum algorithms we use
	KEMAlgorithm       string
	SignatureAlgorithm string
	SymmetricAlgorithm string

	// how often to rotate keys
	KeyRotationInterval time.Duration
}

// UIConfig holds UI settings
type UIConfig struct {
	// terminal display options
	EnableColors      bool
	MessageTimestamps bool
	ShowTypingStatus  bool
	MaxMessageHistory int

	// input settings
	InputBufferSize int
}

// DiscoveryConfig holds peer discovery settings
type DiscoveryConfig struct {
	// mDNS settings
	EnableMDNS   bool
	MDNSInterval time.Duration

	// BitTorrent DHT settings
	EnableBTDHT bool
	BTDHTPort   int

	// DNS TXT settings
	EnableDNS bool
	DNSServer string

	// STUN settings
	STUNServers []string

	// how long to wait for discovery
	DiscoveryTimeout time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			MinPort:        8000,
			MaxPort:        9000,
			ConnectTimeout: 30 * time.Second,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxPeers:       10,
		},
		Crypto: CryptoConfig{
			KEMAlgorithm:        "Kyber1024",
			SignatureAlgorithm:  "DILITHIUM5",
			SymmetricAlgorithm:  "ChaCha20-Poly1305",
			KeyRotationInterval: 1 * time.Hour,
		},
		UI: UIConfig{
			EnableColors:      true,
			MessageTimestamps: true,
			ShowTypingStatus:  true,
			MaxMessageHistory: 1000,
			InputBufferSize:   4096,
		},
		Discovery: DiscoveryConfig{
			EnableMDNS:   true,
			MDNSInterval: 5 * time.Second,
			EnableBTDHT:  true,
			BTDHTPort:    6881,
			EnableDNS:    true,
			DNSServer:    "8.8.8.8:53",
			STUNServers: []string{
				"stun.l.google.com:19302",
				"stun1.l.google.com:19302",
				"stun2.l.google.com:19302",
			},
			DiscoveryTimeout: 60 * time.Second,
		},
	}
}
