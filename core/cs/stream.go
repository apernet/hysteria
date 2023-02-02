package cs

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
)

// qStream is a wrapper of quic.Stream that handles Close() correctly.
// quic-go's quic.Stream.Close() only closes the write side of the stream,
// NOT the read side. This would cause the pipe(s) to hang at Read() even
// after the stream is supposedly "closed".
// Ref: https://github.com/libp2p/go-libp2p/blob/master/p2p/transport/quic/stream.go
type qStream struct {
	Stream quic.Stream
}

func (s *qStream) StreamID() quic.StreamID {
	return s.Stream.StreamID()
}

func (s *qStream) Read(p []byte) (n int, err error) {
	return s.Stream.Read(p)
}

func (s *qStream) CancelRead(code quic.StreamErrorCode) {
	s.Stream.CancelRead(code)
}

func (s *qStream) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *qStream) Write(p []byte) (n int, err error) {
	return s.Stream.Write(p)
}

func (s *qStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func (s *qStream) CancelWrite(code quic.StreamErrorCode) {
	s.Stream.CancelWrite(code)
}

func (s *qStream) Context() context.Context {
	return s.Stream.Context()
}

func (s *qStream) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}

func (s *qStream) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}
