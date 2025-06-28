package ui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"quantterm/internal/crypto"
)

// TerminalUI is the simple terminal interface with E2E encryption indicators
type TerminalUI struct {
	// state
	roomID          string
	verifiedPeers   int
	totalPeers      int
	encryptionLevel string
	maxMessages     int

	// channels
	sendChan chan string
	stopChan chan struct{}

	// sync
	inputMux  sync.Mutex
	outputMux sync.Mutex

	// input handling
	inputReader *bufio.Reader
	inputReady  chan struct{}
}

// ChatMessage represents a chat message for display
type ChatMessage struct {
	Sender    string
	Message   string
	Timestamp time.Time
	IsLocal   bool
	Verified  bool // whether the sender's identity is verified
}

// NewTerminalUI creates a new terminal UI instance with E2E encryption indicators
func NewTerminalUI(roomID string, maxMessages int) *TerminalUI {
	ui := &TerminalUI{
		roomID:          roomID,
		maxMessages:     maxMessages,
		encryptionLevel: "None",
		sendChan:        make(chan string, 10),
		stopChan:        make(chan struct{}),
		inputReader:     bufio.NewReader(os.Stdin),
		inputReady:      make(chan struct{}),
	}

	ui.showWelcomeMessage()
	return ui
}

// show a compact welcome message and let user know we're waiting for handshake
func (ui *TerminalUI) showWelcomeMessage() {
	ui.outputMux.Lock()
	defer ui.outputMux.Unlock()

	fmt.Printf("\nQuantTerm — Secure Chat\n")
	fmt.Printf("Room: %s\n", ui.roomID)
	fmt.Printf("Waiting for secure handshake… (peers will appear automatically)\n")
	fmt.Printf("Press Ctrl+C to quit at any time.\n\n")
}

// Start starts the terminal UI
func (ui *TerminalUI) Start(ctx context.Context) error {
	// start input handler
	go ui.handleInput(ctx)

	// keep running until context is cancelled
	<-ctx.Done()
	return nil
}

// Stop stops the terminal UI
func (ui *TerminalUI) Stop() {
	close(ui.stopChan)
}

// handle user input from stdin with encryption requirements
func (ui *TerminalUI) handleInput(ctx context.Context) {
	// wait until at least one peer is verified before accepting input
	// prevents users from typing messages that can't be delivered yet
	handshakeDone := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ui.stopChan:
			return
		default:
			// only allow chatting once handshake is complete
			if ui.verifiedPeers == 0 {
				time.Sleep(200 * time.Millisecond)
				continue
			}

			// print the prompt the first time a secure channel is ready
			if !handshakeDone {
				ui.outputMux.Lock()
				fmt.Print("> ")
				ui.outputMux.Unlock()
				handshakeDone = true
			}

			// read input from stdin
			ui.inputMux.Lock()
			text, err := ui.inputReader.ReadString('\n')
			ui.inputMux.Unlock()

			if err != nil {
				// print prompt again on error
				fmt.Print("> ")
				continue
			}

			text = strings.TrimSpace(text)
			if text != "" {
				// send message (we know verifiedPeers > 0)
				select {
				case ui.sendChan <- text:
					ui.AddMessage("You", text, time.Now(), true, true)
				case <-time.After(1 * time.Second):
					ui.AddSystemMessage("❌ Failed to send message (timeout)")
					fmt.Print("> ")
				}
			} else {
				// empty input, just show prompt again
				fmt.Print("> ")
			}
		}
	}
}

// GetSendChannel returns the channel for outgoing messages
func (ui *TerminalUI) GetSendChannel() <-chan string {
	return ui.sendChan
}

// AddMessage adds a new message to the chat with verification status
func (ui *TerminalUI) AddMessage(sender, message string, timestamp time.Time, isLocal, verified bool) {
	ui.outputMux.Lock()
	defer ui.outputMux.Unlock()

	timeStr := timestamp.Format("15:04:05")

	// clear current line and move to beginning
	fmt.Print("\r\033[K")

	if isLocal {
		fmt.Printf("[%s] 📤 You 🔐✅: %s\n", timeStr, message)
	} else {
		senderDisplay := sender
		if len(senderDisplay) > 8 {
			senderDisplay = senderDisplay[:8] + "..."
		}

		verificationIcon := "✅" // verified
		if !verified {
			verificationIcon = "❌" // not verified
		}

		fmt.Printf("[%s] 📥 %s 🔐%s: %s\n", timeStr, senderDisplay, verificationIcon, message)
	}

	// print prompt for next input
	fmt.Print("> ")
}

// AddSystemMessage adds a system message with enhanced formatting
func (ui *TerminalUI) AddSystemMessage(message string) {
	ui.outputMux.Lock()
	defer ui.outputMux.Unlock()

	// clear current line and move to beginning
	fmt.Print("\r\033[K")

	timeStr := time.Now().Format("15:04:05")
	fmt.Printf("[%s] 🔧 System: %s\n", timeStr, message)
	fmt.Print("> ")
}

// AddSecurityMessage adds a security-related message with special formatting
func (ui *TerminalUI) AddSecurityMessage(message string) {
	ui.outputMux.Lock()
	defer ui.outputMux.Unlock()

	// clear current line and move to beginning
	fmt.Print("\r\033[K")

	timeStr := time.Now().Format("15:04:05")
	fmt.Printf("[%s] 🛡️  Security: %s\n", timeStr, message)
	fmt.Print("> ")
}

// UpdatePeerCount updates the connected peer count
func (ui *TerminalUI) UpdatePeerCount(count int) {
	ui.totalPeers = count
	// we don't print a noisy message for every peer change, just update status
	ui.updateEncryptionStatus()
}

// UpdateVerifiedPeerCount updates the verified peer count
func (ui *TerminalUI) UpdateVerifiedPeerCount(count int) {
	oldVerifiedCount := ui.verifiedPeers
	ui.verifiedPeers = count

	// only inform user when secure channel becomes available the first time
	// or when it drops to zero again
	if oldVerifiedCount == 0 && count > 0 {
		ui.AddSecurityMessage("🟢 Handshake complete — you can start chatting securely.")
	} else if oldVerifiedCount > 0 && count == 0 {
		ui.AddSecurityMessage("🔴 All peers lost — waiting for handshake…")
	}

	ui.updateEncryptionStatus()
}

// update the encryption level display
func (ui *TerminalUI) updateEncryptionStatus() {
	if ui.verifiedPeers > 0 {
		ui.encryptionLevel = fmt.Sprintf("E2E Active (%d peers)", ui.verifiedPeers)
	} else if ui.totalPeers > 0 {
		ui.encryptionLevel = "Handshaking..."
	} else {
		ui.encryptionLevel = "No Peers"
	}
}

// UpdatePeers updates the peer list display with enhanced information
func (ui *TerminalUI) UpdatePeers(peers []string) {
	oldTotal := ui.totalPeers
	ui.totalPeers = len(peers)

	if ui.totalPeers > oldTotal {
		ui.AddSystemMessage(fmt.Sprintf("🔍 New peer discovered. Total: %d (Handshaking...)", ui.totalPeers))
	} else if ui.totalPeers < oldTotal {
		ui.AddSystemMessage(fmt.Sprintf("🔌 Peer disconnected. Total: %d", ui.totalPeers))
	}

	ui.updateEncryptionStatus()
}

// UpdatePeersString is an alias for UpdatePeers for string peer IDs
func (ui *TerminalUI) UpdatePeersString(peers []string) {
	ui.UpdatePeers(peers)
}

// ShowPeerFingerprints displays peer fingerprints for verification
func (ui *TerminalUI) ShowPeerFingerprints(peerFingerprints map[string]string) {
	if len(peerFingerprints) == 0 {
		return
	}

	ui.outputMux.Lock()
	defer ui.outputMux.Unlock()

	// clear current line and move to beginning
	fmt.Print("\r\033[K")

	fmt.Printf("\n🔑 PEER VERIFICATION FINGERPRINTS:\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	for peerID, fingerprint := range peerFingerprints {
		shortID := peerID
		if len(shortID) > 8 {
			shortID = shortID[:8] + "..."
		}
		fmt.Printf("👤 %s: %s\n", shortID, fingerprint)
	}
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("💡 Verify these fingerprints with your peers through a separate channel\n")
	fmt.Printf("⚠️  Only trust messages from verified peers\n\n")
	fmt.Print("> ")
}

// ShowKeyRotationEvent displays key rotation information
func (ui *TerminalUI) ShowKeyRotationEvent() {
	ui.AddSecurityMessage("🔄 Forward secrecy: Keys rotated, re-establishing secure channels")
}

// ShowHandshakeComplete displays handshake completion
func (ui *TerminalUI) ShowHandshakeComplete(peerID, fingerprint string) {
	shortID := peerID
	if len(shortID) > 8 {
		shortID = shortID[:8] + "..."
	}
	ui.AddSecurityMessage(fmt.Sprintf("🤝 Handshake completed with %s (fingerprint: %s)", shortID, fingerprint[:16]))
}

// return a shortened room ID for display
func (ui *TerminalUI) getShortRoomID() string {
	if len(ui.roomID) > 20 {
		return ui.roomID[:8] + "..." + ui.roomID[len(ui.roomID)-8:]
	}
	return ui.roomID
}

// HandleReceivedMessage handles a message received from the network
func (ui *TerminalUI) HandleReceivedMessage(msg *crypto.MessagePayload) {
	senderID := msg.SenderID
	if len(senderID) > 8 {
		senderID = senderID[:8]
	}

	// all messages that reach here are verified (signature checked)
	ui.AddMessage(senderID, msg.Message, msg.Timestamp, false, true)
}

// GetSecurityStatus returns current security status information
func (ui *TerminalUI) GetSecurityStatus() map[string]interface{} {
	return map[string]interface{}{
		"encryption_level": ui.encryptionLevel,
		"verified_peers":   ui.verifiedPeers,
		"total_peers":      ui.totalPeers,
		"e2e_active":       ui.verifiedPeers > 0,
	}
}
