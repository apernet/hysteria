package main

import (
	"crypto/tls"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

type keypairLoader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func newKeypairLoader(certPath, keyPath string) (*keypairLoader, error) {
	loader := &keypairLoader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	loader.cert = &cert
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				switch event.Op {
				case fsnotify.Create, fsnotify.Write, fsnotify.Rename, fsnotify.Chmod:
					logrus.WithFields(logrus.Fields{
						"file": event.Name,
					}).Info("Keypair change detected, reloading...")
					if err := loader.load(); err != nil {
						logrus.WithFields(logrus.Fields{
							"error": err,
						}).Error("Failed to reload keypair")
					} else {
						logrus.Info("Keypair successfully reloaded")
					}
				case fsnotify.Remove:
					_ = watcher.Add(event.Name) // Workaround for vim
					// https://github.com/fsnotify/fsnotify/issues/92
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logrus.WithFields(logrus.Fields{
					"error": err,
				}).Error("Failed to watch keypair files for changes")
			}
		}
	}()
	err = watcher.Add(certPath)
	if err != nil {
		_ = watcher.Close()
		return nil, err
	}
	err = watcher.Add(keyPath)
	if err != nil {
		_ = watcher.Close()
		return nil, err
	}
	return loader, nil
}

func (kpr *keypairLoader) load() error {
	cert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	kpr.cert = &cert
	kpr.certMu.Unlock()
	return nil
}

func (kpr *keypairLoader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}
