package pppbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

// DialFn is called by the Bridge to establish a PPP session.
// It returns the control stream, data I/O, a close function, and an error.
// Return permanentDialError to stop retry attempts.
type DialFn func() (control io.ReadWriteCloser, data ppp.PPPDataIO, closeFn func(), err error)

// permanentDialError wraps errors that should not be retried.
type permanentDialError struct{ err error }

func (e permanentDialError) Error() string { return e.err.Error() }
func (e permanentDialError) Unwrap() error { return e.err }

// Bridge manages a child process connected to a Hysteria2 PPP session.
// Control frames (LCP, IPCP, etc.) flow as HDLC on the control stream.
// Data frames (IPv4, IPv6) flow via PPPDataIO (datagrams or multi-stream).
type Bridge struct {
	PPPDPath string
	PPPDArgs []string
	Sudo     bool
	Logger   *zap.Logger

	session atomic.Pointer[bridgeSession]
	dialCh  chan txFrame
}

type bridgeSession struct {
	control io.ReadWriteCloser
	data    ppp.PPPDataIO
	done    chan struct{} // closed when session ends (first RX error or child exit)
}

type txFrame struct {
	hdlcFrame []byte // raw HDLC bytes (for control stream)
	rawPPP    []byte // decoded PPP payload (for data.SendData)
	isControl bool
}

func (b *Bridge) startChild(ctx context.Context) (
	reader io.Reader, writer io.WriteCloser, cleanup func(), waitFn func() error, err error,
) {
	name := b.PPPDPath
	args := b.PPPDArgs
	if b.Sudo {
		args = append([]string{name}, args...)
		name = "sudo"
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr

	reader, writer, cleanup, err = b.startProcess(cmd)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to start process: %w", err)
	}
	b.Logger.Info("PPP bridge child started",
		zap.Int("pid", cmd.Process.Pid), zap.String("io", bridgeIOMode))

	waitFn = func() error {
		waitErr := cmd.Wait()
		b.Logger.Debug("PPP bridge child exited", zap.Error(waitErr))
		return waitErr
	}
	return
}

// Run starts a child process and bridges it to PPP sessions obtained via dialFn.
// It returns when the child exits or a permanent error occurs.
// The caller decides whether to restart (e.g. client Serve loop).
func (b *Bridge) Run(ctx context.Context, dialFn DialFn) (runErr error) {
	childReader, childWriter, cleanup, waitFn, err := b.startChild(ctx)
	if err != nil {
		return err
	}

	b.dialCh = make(chan txFrame, 1)
	childDone := make(chan struct{})
	go func() {
		b.txLoop(childReader)
		close(childDone)
	}()

	defer func() {
		cleanup()   // close pty/pipe -> child gets SIGHUP/EOF
		<-childDone // wait for txLoop goroutine to fully exit
		if waitErr := waitFn(); runErr == nil {
			runErr = waitErr
		}
	}()

	var writeMu sync.Mutex

	for {
		select {
		case frame, ok := <-b.dialCh:
			if !ok {
				return nil // child exited; defer captures exit status via waitFn()
			}

			control, data, closeFn, err := b.dialWithRetry(ctx, dialFn, childDone)
			if err != nil {
				return err
			}

			sess := b.startSession(control, data, childWriter, &writeMu, frame, childDone)

			select {
			case <-sess.done:
			case <-childDone:
			case <-ctx.Done():
			}

			b.session.Store(nil)
			closeFn()

			select {
			case <-childDone:
				return nil
			default:
			}

		case <-childDone:
			return nil

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// txLoop reads HDLC from the child, classifies frames, and routes them
// to the active session (bridge mode) or signals a dial (waiting mode).
// It runs for the entire child lifetime.
func (b *Bridge) txLoop(childReader io.Reader) {
	defer close(b.dialCh)
	buf := make([]byte, 16384)
	var hdlcBuf []byte
	var sendErrCount uint64

	for {
		n, err := childReader.Read(buf)
		if n > 0 {
			if ce := b.Logger.Check(zap.DebugLevel, "pppd->network raw"); ce != nil {
				ce.Write(zap.Int("bytes", n), zap.String("hex", hexHead(buf[:n])))
			}
			hdlcBuf = append(hdlcBuf, buf[:n]...)
			for {
				frame, rest, ok := extractHDLCFrame(hdlcBuf)
				if !ok {
					break
				}
				hdlcBuf = rest

				rawPPP, decErr := decodeHDLCFramePayload(frame)
				if decErr != nil {
					if ce := b.Logger.Check(zap.DebugLevel, "HDLC decode error"); ce != nil {
						ce.Write(zap.Error(decErr))
					}
					continue
				}
				isCtrl := isControlFrame(rawPPP)
				if !isCtrl {
					isCtrl = isMPWithControlPayload(rawPPP)
				}
				tf := txFrame{hdlcFrame: frame, rawPPP: rawPPP, isControl: isCtrl}

				sess := b.session.Load()
				if sess != nil {
					if isCtrl {
						if ce := b.Logger.Check(zap.DebugLevel, "TX control frame"); ce != nil {
							ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
						}
						if _, err := sess.control.Write(frame); err != nil {
							b.Logger.Warn("control.Write failed", zap.Error(err), zap.Int("bytes", len(frame)))
						}
					} else {
						if ce := b.Logger.Check(zap.DebugLevel, "TX data frame"); ce != nil {
							ce.Write(zap.Int("bytes", len(rawPPP)), zap.String("hex", hexHead(rawPPP)))
						}
						if err := sess.data.SendData(rawPPP); err != nil {
							if sendErrCount == 0 {
								b.Logger.Warn("SendData failed", zap.Error(err), zap.Int("bytes", len(rawPPP)))
							} else if ce := b.Logger.Check(zap.DebugLevel, "SendData failed"); ce != nil {
								ce.Write(zap.Error(err), zap.Uint64("count", sendErrCount))
							}
							sendErrCount++
						}
					}
				} else {
					if isCtrl && isLCPConfigRequest(rawPPP) {
						select {
						case b.dialCh <- tf:
						default:
						}
					} else {
						if ce := b.Logger.Check(zap.DebugLevel, "discarding frame in waiting mode"); ce != nil {
							ce.Write(zap.Bool("control", isCtrl), zap.String("hex", hexHead(rawPPP)))
						}
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// isLCPConfigRequest returns true if rawPPP is an LCP Configure-Request.
func isLCPConfigRequest(rawPPP []byte) bool {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off+3 > len(rawPPP) {
		return false
	}
	proto := binary.BigEndian.Uint16(rawPPP[off : off+2])
	if proto != pppProtoLCP {
		return false
	}
	return rawPPP[off+2] == lcpConfigRequest
}

func (b *Bridge) startSession(
	control io.ReadWriteCloser, data ppp.PPPDataIO,
	childWriter io.WriteCloser, writeMu *sync.Mutex,
	initial txFrame, childDone <-chan struct{},
) *bridgeSession {
	sess := &bridgeSession{control: control, data: data, done: make(chan struct{})}
	errCh := make(chan error, 2)

	if initial.isControl {
		if _, err := control.Write(initial.hdlcFrame); err != nil {
			b.Logger.Warn("initial control.Write failed", zap.Error(err))
		}
	} else {
		if err := data.SendData(initial.rawPPP); err != nil {
			b.Logger.Warn("initial SendData failed", zap.Error(err))
		}
	}

	b.session.Store(sess)

	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := control.Read(buf)
			if n > 0 {
				if ce := b.Logger.Check(zap.DebugLevel, "RX control->pppd"); ce != nil {
					ce.Write(zap.Int("bytes", n), zap.String("hex", hexHead(buf[:n])))
				}
				writeMu.Lock()
				if _, werr := childWriter.Write(buf[:n]); werr != nil {
					writeMu.Unlock()
					b.Logger.Warn("childWriter.Write failed (control)", zap.Error(werr))
					errCh <- werr
					return
				}
				writeMu.Unlock()
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		hdlcEncodeBuf := make([]byte, 0, 4096)
		for {
			frame, err := data.ReceiveData()
			if err != nil {
				errCh <- err
				return
			}
			if ce := b.Logger.Check(zap.DebugLevel, "RX data->pppd"); ce != nil {
				ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
			}
			hdlcEncodeBuf = EncodeHDLCTo(frame, hdlcEncodeBuf)
			writeMu.Lock()
			if _, werr := childWriter.Write(hdlcEncodeBuf); werr != nil {
				writeMu.Unlock()
				b.Logger.Warn("childWriter.Write failed (data)", zap.Error(werr))
				errCh <- werr
				return
			}
			writeMu.Unlock()
		}
	}()

	go func() {
		select {
		case err := <-errCh:
			b.Logger.Warn("PPP session error", zap.Error(err))
		case <-childDone:
			b.Logger.Debug("PPP session ended (child exited)")
		}
		close(sess.done)
	}()

	return sess
}

func (b *Bridge) dialWithRetry(
	ctx context.Context, dialFn DialFn, childDone <-chan struct{},
) (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
	backoff := 1 * time.Second
	for {
		control, data, closeFn, err := dialFn()
		if err == nil {
			return control, data, closeFn, nil
		}
		if isPermanentDialError(err) {
			return nil, nil, nil, err
		}
		b.Logger.Warn("PPP dial failed, retrying",
			zap.Error(err), zap.Duration("backoff", backoff))
		select {
		case <-time.After(backoff):
			backoff = min(backoff*2, 30*time.Second)
		case <-childDone:
			return nil, nil, nil, errors.New("child exited during dial")
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		}
	}
}

func isPermanentDialError(err error) bool {
	var pe permanentDialError
	if errors.As(err, &pe) {
		return true
	}
	var ce coreErrs.ClosedError
	return errors.As(err, &ce)
}
