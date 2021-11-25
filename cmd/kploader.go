package main

import (
	"crypto/tls"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

const (
	keypairReloadInterval = 10 * time.Minute
)

type keypairLoader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func newKeypairLoader(certPath, keyPath string) (*keypairLoader, error) {
	result := &keypairLoader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	go func() {
		for {
			time.Sleep(keypairReloadInterval)
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": err,
					"cert":  certPath,
					"key":   keyPath,
				}).Warning("Failed to reload keypair")
				continue
			}
			result.certMu.Lock()
			result.cert = &cert
			result.certMu.Unlock()
		}
	}()
	return result, nil
}

func (kpr *keypairLoader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}
