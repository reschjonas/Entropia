package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"sync"
	"time"

	"entropia/internal/logger"
	"entropia/internal/room"

	webview "github.com/webview/webview_go"
	"golang.design/x/clipboard"
)

// AppController defines the interface the UI uses to interact with the main application.
type AppController interface {
	CreateRoom(ctx context.Context) (string, error)
	JoinRoom(ctx context.Context, roomID string, remoteAddr string) error
	GetRoomInfo() *room.Room
	GetListenPort() int
	GetPeerFingerprint() (string, error)
	GetSecuritySummary() map[string]interface{}
	GetNetworkStatus() map[string]interface{}
	SendMessage(ctx context.Context, message string) error
}

// WebviewUI is the web-based GUI for Entropia.
type WebviewUI struct {
	app AppController
	wv  webview.WebView

	stopChan chan struct{}
	mu       sync.Mutex
}

// NewWebviewUI creates a new web-based UI instance.
func NewWebviewUI(app AppController) *WebviewUI {
	return &WebviewUI{
		app:      app,
		stopChan: make(chan struct{}),
	}
}

// Start creates and runs the webview GUI.
func (ui *WebviewUI) Start(ctx context.Context) error {
	w := webview.New(true)
	ui.wv = w
	defer w.Destroy()

	w.SetTitle("Entropia")
	w.SetSize(1280, 800, webview.HintNone)

	chatHTML, err := fs.ReadFile(EmbeddedFS, "chat.html")
	if err != nil {
		return fmt.Errorf("failed to read embedded chat.html: %w", err)
	}
	w.SetHtml(string(chatHTML))

	if err := ui.bindFunctions(ctx); err != nil {
		return fmt.Errorf("failed to bind functions: %w", err)
	}

	go func() {
		select {
		case <-ctx.Done():
			w.Terminate()
		case <-ui.stopChan:
			w.Terminate()
		}
	}()

	w.Run()
	return nil
}

// Stop terminates the UI.
func (ui *WebviewUI) Stop() {
	close(ui.stopChan)
}

// bindFunctions binds Go functions to be callable from the webview's JavaScript context.
func (ui *WebviewUI) bindFunctions(ctx context.Context) error {
	if err := ui.wv.Bind("handleCreate", func() {
		ui.runJS("setConnectionStatus('Creating room, please wait...', false)")
		_, err := ui.app.CreateRoom(ctx)
		if err != nil {
			logger.L().Error("Failed to create room", "err", err)
			ui.runJS(fmt.Sprintf("setConnectionStatus('Error: %s', true)", err.Error()))
			return
		}
		roomInfo := ui.app.GetRoomInfo()
		roomInfoJSON, _ := json.Marshal(roomInfo)
		ui.runJS(fmt.Sprintf("onRoomConnected(%s)", string(roomInfoJSON)))
		ui.PushSettingsUpdate()
	}); err != nil {
		return err
	}

	if err := ui.wv.Bind("handleJoin", func(roomID, remoteAddr string) {
		ui.runJS(fmt.Sprintf("setConnectionStatus('Joining room %s...', false)", roomID))
		if err := ui.app.JoinRoom(ctx, roomID, remoteAddr); err != nil {
			logger.L().Error("Failed to join room", "err", err)
			ui.runJS(fmt.Sprintf("setConnectionStatus('Error: %s', true)", err.Error()))
			return
		}
		roomInfo := ui.app.GetRoomInfo()
		roomInfoJSON, _ := json.Marshal(roomInfo)
		ui.runJS(fmt.Sprintf("onRoomConnected(%s)", string(roomInfoJSON)))
		ui.PushSettingsUpdate()
	}); err != nil {
		return err
	}

	if err := ui.wv.Bind("sendMessage", func(msg string) {
		if err := ui.app.SendMessage(ctx, msg); err != nil {
			log.Printf("Error sending message: %v", err)
			return
		}
		// Self-display the message
		ui.AddMessage("You", msg, time.Now(), true, true)
	}); err != nil {
		return err
	}

	if err := ui.wv.Bind("copyToClipboard", func(text string) {
		err := clipboard.Init()
		if err != nil {
			logger.L().Error("Failed to initialize clipboard", "err", err)
			ui.AddNetworkError(fmt.Errorf("clipboard not available: %w", err))
			return
		}
		clipboard.Write(clipboard.FmtText, []byte(text))
	}); err != nil {
		return err
	}

	if err := ui.wv.Bind("uiReady", func() {
		ui.PushSettingsUpdate()
	}); err != nil {
		return err
	}

	return nil
}

func (ui *WebviewUI) runJS(js string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if ui.wv == nil {
		return
	}
	ui.wv.Dispatch(func() {
		ui.wv.Eval(js)
	})
}

// PushConnectionStatusUpdate sends the latest connection status to the UI.
func (ui *WebviewUI) PushConnectionStatusUpdate() {
	ui.updateConnectionStatus()
}

// PushSettingsUpdate sends the latest settings and identity info to the UI.
func (ui *WebviewUI) PushSettingsUpdate() {
	ui.updateSettingsPane()
}

// PushFullStateUpdate sends all relevant app state to the UI.
// DEPRECATED: Use PushConnectionStatusUpdate and PushSettingsUpdate instead for better performance.
func (ui *WebviewUI) PushFullStateUpdate() {
	ui.updateSettingsPane()
	ui.updateConnectionStatus()
}

func (ui *WebviewUI) updateSettingsPane() {
	fingerprint, _ := ui.app.GetPeerFingerprint()
	securitySummary := ui.app.GetSecuritySummary()
	algos := securitySummary["encryption_algorithms"].(map[string]string)

	settings := map[string]interface{}{
		"identity_fingerprint": fingerprint,
		"kem_algo":             algos["key_exchange"],
		"sig_algo":             algos["signatures"],
		"sym_algo":             algos["symmetric"],
	}

	if room := ui.app.GetRoomInfo(); room != nil {
		settings["room_id"] = room.ID
	}
	if port := ui.app.GetListenPort(); port != 0 {
		settings["listen_port"] = port
	}

	settingsJSON, _ := json.Marshal(settings)
	ui.runJS(fmt.Sprintf("updateSettings(%s)", string(settingsJSON)))
}

func (ui *WebviewUI) updateConnectionStatus() {
	status := ui.app.GetNetworkStatus()
	connectedPeers := status["connected_peers"].(int)
	verifiedPeers := status["verified_peers"].(int)
	ui.runJS(fmt.Sprintf("updateStatus(%d, %d)", connectedPeers, verifiedPeers))
}

// AddMessage adds a new message to the chat display.
func (ui *WebviewUI) AddMessage(sender, message string, timestamp time.Time, isLocal, verified bool) {
	senderJSON, _ := json.Marshal(sender)
	messageJSON, _ := json.Marshal(message)
	ui.runJS(fmt.Sprintf("addMessage(%s, %s, %v, %v)", string(senderJSON), string(messageJSON), isLocal, verified))
}

// AddSystemMessage adds a system message to the chat display.
func (ui *WebviewUI) AddSystemMessage(message string) {
	msgJSON, _ := json.Marshal(message)
	ui.runJS(fmt.Sprintf("addSystemMessage(%s, 'system')", string(msgJSON)))
}

// AddSecurityMessage adds a security-related message.
func (ui *WebviewUI) AddSecurityMessage(message string) {
	msgJSON, _ := json.Marshal(message)
	ui.runJS(fmt.Sprintf("addSystemMessage(%s, 'security')", string(msgJSON)))
}

// AddNetworkError displays a network error.
func (ui *WebviewUI) AddNetworkError(err error) {
	msgJSON, _ := json.Marshal(err.Error())
	ui.runJS(fmt.Sprintf("addSystemMessage(%s, 'error')", string(msgJSON)))
}

// ShowPeerFingerprints displays peer fingerprints for verification.
func (ui *WebviewUI) ShowPeerFingerprints(fingerprints map[string]string) {
	fpJSON, _ := json.Marshal(fingerprints)
	ui.runJS(fmt.Sprintf("showPeerFingerprints(%s)", string(fpJSON)))
}
