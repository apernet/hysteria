package client

import (
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	internalppp "github.com/apernet/hysteria/core/v2/internal/ppp"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
)

func (c *clientImpl) PPP(dataStreams int) (*PPPConn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	if err := protocol.WritePPPRequest(stream, dataStreams); err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	ok, msg, serverDS, err := protocol.ReadPPPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}

	if serverDS > 0 {
		// Multi-stream mode: open N data streams
		rawStreams := make([]*quic.Stream, 0, serverDS)
		for i := 0; i < serverDS; i++ {
			ds, err := c.conn.OpenStream()
			if err != nil {
				for _, s := range rawStreams {
					_ = s.Close()
				}
				_ = stream.Close()
				return nil, wrapIfConnectionClosed(err)
			}
			hdr := quicvarint.Append(nil, protocol.FrameTypePPPData)
			hdr = quicvarint.Append(hdr, uint64(i))
			if _, err := ds.Write(hdr); err != nil {
				_ = ds.Close()
				for _, s := range rawStreams {
					_ = s.Close()
				}
				_ = stream.Close()
				return nil, wrapIfConnectionClosed(err)
			}
			rawStreams = append(rawStreams, ds)
		}

		dataIO := internalppp.NewMultiStreamIO(rawStreams, nil)
		return &PPPConn{
			ControlStream: &utils.QStream{Stream: stream.Stream},
			Data:          dataIO,
			closeFn: func() error {
				_ = dataIO.Close()
				return stream.Close()
			},
		}, nil
	}

	// Datagram mode
	if c.dispatcher == nil {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: "PPP datagram mode requires PPPMode in client config"}
	}

	c.dispatcher.pppCh = make(chan []byte, 256)
	c.dispatcher.pppActive.Store(true)
	dataIO := internalppp.NewDatagramIO(c.conn, c.dispatcher.pppCh)

	return &PPPConn{
		ControlStream: &utils.QStream{Stream: stream.Stream},
		Data:          dataIO,
		closeFn: func() error {
			c.dispatcher.pppActive.Store(false)
			_ = dataIO.Close()
			return stream.Close()
		},
	}, nil
}
