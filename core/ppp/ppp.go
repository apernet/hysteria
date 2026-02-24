package ppp

// PPPDataIO abstracts PPP data frame transport.
// Two implementations exist: datagram-based (QUIC datagrams) and
// multi-stream-based (N parallel QUIC streams with per-flow hashing).
type PPPDataIO interface {
	SendData(frame []byte) error
	ReceiveData() ([]byte, error)
	Close() error
}
