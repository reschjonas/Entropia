package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/anacrolix/dht/v2"
)

// GetExternalIP returns our external IP using STUN or HTTP services
func GetExternalIP() (string, error) {
	// try HTTP first (faster)
	if ip, err := getIPFromHTTP(); err == nil {
		return ip, nil
	}

	// fall back to STUN
	return getIPFromSTUN()
}

// get external IP using HTTP services
func getIPFromHTTP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ipinfo.io/ip",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			ip := strings.TrimSpace(string(body))
			if ip != "" {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("failed to get external IP from HTTP services")
}

// get external IP using STUN
func getIPFromSTUN() (string, error) {
	// use dummy port since we only need the IP
	addr, err := ExternalUDPAddr(12345)
	if err != nil {
		return "", err
	}

	// extract just the IP part
	parts := strings.Split(addr, ":")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid address format: %s", addr)
	}

	return parts[0], nil
}

// IsLocalAddress checks if an IP is on the local network
func IsLocalAddress(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// check IPv4 private ranges
	if parsedIP.To4() != nil {
		return parsedIP.IsLoopback() ||
			parsedIP.IsPrivate() ||
			parsedIP.IsLinkLocalUnicast()
	}

	// check IPv6 local ranges
	return parsedIP.IsLoopback() ||
		parsedIP.IsLinkLocalUnicast() ||
		parsedIP.IsPrivate()
}

// ClassifyConnection figures out connection type based on addresses
func ClassifyConnection(localIP, remoteAddr string) string {
	if remoteAddr == "" {
		return "discovery"
	}

	// extract IP from address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// assume it's just an IP without port
		host = remoteAddr
	}

	if IsLocalAddress(host) {
		return "local"
	}

	return "global"
}

// ValidateAddress does basic validation on network addresses
func ValidateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %s", addr)
	}

	// validate IP address
	if net.ParseIP(host) == nil {
		// try to resolve hostname
		_, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("invalid IP address or hostname: %s", host)
		}
	}

	// validate port
	if port == "" {
		return fmt.Errorf("port is required")
	}

	return nil
}

// AutoDiscovery tries multiple discovery methods simultaneously
func AutoDiscovery(ctx context.Context, roomID string, dhtServer *dht.Server) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// collect results from different discovery methods
	results := make(chan string, 3)
	errors := make(chan error, 3)

	// start multiple discovery methods
	go func() {
		// local network discovery (mDNS) - usually fastest
		if addr, err := Lookup(ctx, roomID, 8*time.Second); err == nil {
			results <- addr
		} else {
			errors <- fmt.Errorf("mDNS: %w", err)
		}
	}()

	go func() {
		// global discovery via DHT
		if dhtServer != nil {
			if addr, err := LookupDHT(ctx, dhtServer, roomID, 15*time.Second); err == nil {
				results <- addr
			} else {
				errors <- fmt.Errorf("dht: %w", err)
			}
		} else {
			errors <- fmt.Errorf("dht: server not initialized")
		}
	}()

	go func() {
		// broadcast discovery on local network
		if addr, err := BroadcastDiscovery(ctx, roomID, 10*time.Second); err == nil {
			results <- addr
		} else {
			errors <- fmt.Errorf("broadcast: %w", err)
		}
	}()

	// wait for first success or all failures
	var errorList []error
	for i := 0; i < 3; i++ {
		select {
		case addr := <-results:
			return addr, nil
		case err := <-errors:
			errorList = append(errorList, err)
		case <-ctx.Done():
			return "", fmt.Errorf("discovery timeout after 30s")
		}
	}

	// all methods failed
	return "", fmt.Errorf("all discovery methods failed: %v", errorList)
}

// BroadcastDiscovery sends UDP broadcasts to find peers on local networks
func BroadcastDiscovery(ctx context.Context, roomID string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// create UDP socket for broadcast
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// create discovery message
	discoveryMsg := map[string]interface{}{
		"type":    "quantterm_discovery",
		"room_id": roomID,
		"version": "2.0",
	}

	msgBytes, _ := json.Marshal(discoveryMsg)

	// broadcast to common private network ranges
	broadcastAddrs := []string{
		"192.168.255.255:19847", // common home networks
		"10.255.255.255:19847",  // corporate networks
		"172.31.255.255:19847",  // AWS VPC default
	}

	// send broadcasts every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// listen for responses
	responsesChan := make(chan string, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}

				var response map[string]interface{}
				if err := json.Unmarshal(buf[:n], &response); err != nil {
					continue
				}

				if response["type"] == "quantterm_response" && response["room_id"] == roomID {
					if port, ok := response["port"].(float64); ok {
						responsesChan <- fmt.Sprintf("%s:%d", addr.IP.String(), int(port))
						return
					}
				}
			}
		}
	}()

	// send initial broadcasts
	for _, broadcastAddr := range broadcastAddrs {
		if addr, err := net.ResolveUDPAddr("udp4", broadcastAddr); err == nil {
			conn.WriteToUDP(msgBytes, addr)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("broadcast discovery timeout")
		case addr := <-responsesChan:
			return addr, nil
		case <-ticker.C:
			// send periodic broadcasts
			for _, broadcastAddr := range broadcastAddrs {
				if addr, err := net.ResolveUDPAddr("udp4", broadcastAddr); err == nil {
					conn.WriteToUDP(msgBytes, addr)
				}
			}
		}
	}
}

// StartDiscoveryResponder starts a service that responds to broadcast requests
func StartDiscoveryResponder(ctx context.Context, roomID string, port int) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 19847})
	if err != nil {
		return err
	}
	defer conn.Close()

	go func() {
		defer conn.Close()
		buf := make([]byte, 1024)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}

				var request map[string]interface{}
				if err := json.Unmarshal(buf[:n], &request); err != nil {
					continue
				}

				if request["type"] == "quantterm_discovery" && request["room_id"] == roomID {
					// send response with our port
					response := map[string]interface{}{
						"type":    "quantterm_response",
						"room_id": roomID,
						"port":    port,
						"version": "2.0",
					}

					if responseBytes, err := json.Marshal(response); err == nil {
						conn.WriteToUDP(responseBytes, addr)
					}
				}
			}
		}
	}()

	return nil
}
