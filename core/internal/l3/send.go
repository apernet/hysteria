package l3

import (
	"errors"
	"sync/atomic"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

// Send carries one IP packet as one or more QUIC datagrams.
// An empty packet or one larger than the L3 maximum is dropped.
// When the first datagram is too big for the current path, the packet is
// split into even pieces that fit MaxDatagramPayloadSize.
func Send(sendDatagram func([]byte) error, next *atomic.Uint32, ip []byte) error {
	if len(ip) == 0 || len(ip) > protocol.L3MaxPacketSize {
		return nil
	}
	id := next.Add(1)
	err := sendDatagram(protocol.AppendL3Fragment(nil, id, 0, 1, ip))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	parts := protocol.SplitL3(id, ip, int(tooLarge.MaxDatagramPayloadSize))
	if len(parts) == 0 {
		return err
	}
	for _, part := range parts {
		if err := sendDatagram(part); err != nil {
			return err
		}
	}
	return nil
}
