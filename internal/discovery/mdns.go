package discovery

import (
	"context"
	"fmt"
	"time"

	"entropia/internal/room"

	"github.com/grandcat/zeroconf"
)

// Advertise announces our room on the local network via mDNS
func Advertise(ctx context.Context, roomID string, port int) error {
	serviceType := serviceTypeForRoom(roomID)

	server, err := zeroconf.Register(roomID, serviceType, "local.", port, []string{fmt.Sprintf("room=%s", roomID)}, nil)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		server.Shutdown()
	}()
	return nil
}

// Lookup tries to find someone hosting this room on the local network
func Lookup(ctx context.Context, roomID string, timeout time.Duration) (string, error) {
	serviceType := serviceTypeForRoom(roomID)

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return "", err
	}

	entries := make(chan *zeroconf.ServiceEntry)
	browseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := resolver.Browse(browseCtx, serviceType, "local.", entries); err != nil {
		return "", err
	}

	for {
		select {
		case e := <-entries:
			// prefer IPv4 but take whatever we get
			if len(e.AddrIPv4) > 0 {
				return fmt.Sprintf("%s:%d", e.AddrIPv4[0].String(), e.Port), nil
			}
			if len(e.AddrIPv6) > 0 {
				return fmt.Sprintf("[%s]:%d", e.AddrIPv6[0].String(), e.Port), nil
			}
		case <-time.After(timeout):
			return "", fmt.Errorf("peer not found via mDNS")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// make a unique service name for each room
func serviceTypeForRoom(roomID string) string {
	hash := room.GetDiscoveryHash(roomID)
	return fmt.Sprintf("_entropia_%s._udp", hash)
}
