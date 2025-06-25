package discovery

import (
	"fmt"
	"net"

	"github.com/pion/stun"
)

// ExternalUDPAddr gets our external IP:port by asking a STUN server
func ExternalUDPAddr(localPort int) (string, error) {
	// use Google's public STUN server
	conn, err := net.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	c, err := stun.NewClient(conn)
	if err != nil {
		return "", err
	}
	defer c.Close()

	var xorAddr stun.XORMappedAddress
	if err := c.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			err = getErr
		}
	}); err != nil {
		return "", err
	}

	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", xorAddr.IP.String(), xorAddr.Port), nil
}
